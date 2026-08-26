import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import {
  ACK_STORAGE_PREFIX,
  CLAIM_STORAGE_PREFIX,
  OPERATION_STORAGE_PREFIX,
  PENDING_RETENTION_MS,
  StorageProofError,
  acknowledgementStorageName,
  buildOperationRequest,
  claimStorageName,
  createIdempotencyKey,
  createLifecycleGuard,
  formatUtcDate,
  isCanonicalIdempotencyKey,
  listPendingClaims,
  listPendingMutations,
  parseCredentialDelivery,
  parseUpdateAccess,
  persistAcknowledgementOperation,
  persistClaimOperation,
  persistMutationOperation,
  postJson,
  readAcknowledgementOperation,
  readClaimOperation,
  readMutationOperation,
  readSetupRoute,
  removePendingOperations,
} from "../dist/setup/app.mjs";

const root = new URL("../", import.meta.url);
const output = new URL("../dist/setup/", import.meta.url);
const fixedNow = Date.parse("2026-08-10T00:00:00.000Z");

test("idempotency keys canonically encode 32 random bytes", () => {
  const bytes = Uint8Array.from({ length: 32 }, (_, index) => index);
  const cryptoSource = { getRandomValues(target) { target.set(bytes); return target; } };
  const key = createIdempotencyKey(cryptoSource);
  assert.equal(key.length, 43);
  assert.match(key, /^[A-Za-z0-9_-]{43}$/u);
  assert.equal(Buffer.from(key, "base64url").length, 32);
  assert.equal(isCanonicalIdempotencyKey(`${key}=`), false);
});

test("claim operations remain independent and expire after the last attempt", () => {
  const storage = new FakeStorage();
  const first = deterministicKey(1);
  const second = deterministicKey(2);
  persistClaimOperation(storage, first, fixedNow - PENDING_RETENTION_MS + 1);
  persistClaimOperation(storage, second, fixedNow - 1_000);

  assert.deepEqual(
    listPendingClaims(storage, fixedNow).map((entry) => entry.idempotencyKey),
    [second, first],
  );
  persistClaimOperation(storage, first, fixedNow);
  assert.equal(readClaimOperation(storage, first).lastAttemptAt, fixedNow);

  assert.deepEqual(
    listPendingClaims(storage, fixedNow + PENDING_RETENTION_MS).map((entry) => entry.idempotencyKey),
    [],
  );
  assert.equal(storage.getItem(`${CLAIM_STORAGE_PREFIX}${first}`), null);
  assert.equal(storage.getItem(`${CLAIM_STORAGE_PREFIX}${second}`), null);
});

test("legacy offer claim retries migrate without losing an open-tab recovery reference", () => {
  const storage = new FakeStorage();
  const key = deterministicKey(24);
  const legacyName = `${CLAIM_STORAGE_PREFIX}annual_access_1_year_offer_v1.${key}`;
  storage.setItem(legacyName, JSON.stringify({
    idempotency_key: key,
    last_attempt_at: new Date(fixedNow).toISOString(),
  }));

  assert.deepEqual(listPendingClaims(storage, fixedNow), [{
    idempotencyKey: key,
    lastAttemptAt: fixedNow,
  }]);
  assert.notEqual(storage.getItem(legacyName), null);
  assert.notEqual(storage.getItem(claimStorageName(key)), null);
  removePendingOperations(storage, key);
  assert.equal(storage.getItem(legacyName), null);
  assert.equal(storage.getItem(claimStorageName(key)), null);
});

test("renewal and reissue retries are isolated and retain no submitted secret", () => {
  const storage = new FakeStorage();
  const renewalKey = deterministicKey(21);
  const reissueKey = deterministicKey(22);
  persistMutationOperation(storage, "renew", renewalKey, fixedNow);
  persistMutationOperation(storage, "reissue", reissueKey, fixedNow - 1_000);

  assert.equal(readMutationOperation(storage, "renew", renewalKey).operation, "renew");
  assert.equal(readMutationOperation(storage, "reissue", reissueKey).operation, "reissue");
  assert.deepEqual(listPendingMutations(storage, "renew", fixedNow), [{
    operation: "renew",
    idempotencyKey: renewalKey,
    lastAttemptAt: fixedNow,
  }]);
  assert.deepEqual(listPendingMutations(storage, "reissue", fixedNow).map((entry) => entry.idempotencyKey), [reissueKey]);
  const serialized = [...storage.values()].join("\n");
  assert.doesNotMatch(serialized, /license|purchase|recovery|credential|token/u);
  assert.equal(storage.getItem(`${OPERATION_STORAGE_PREFIX}renew.${renewalKey}`) !== null, true);
});

test("public setup routes allow only fixed operations", () => {
  assert.deepEqual(readSetupRoute({ search: "" }), { operation: "claim" });
  assert.deepEqual(readSetupRoute({ search: "?action=renew" }), { operation: "renew" });
  assert.deepEqual(readSetupRoute({ search: "?action=status" }), { operation: "status" });
  assert.deepEqual(readSetupRoute({ search: "?action=replace" }), { operation: "reissue" });
  for (const search of [
    "?offer=annual_access_3_year_offer_v1",
    "?offer=buyer_selected_years",
    "?action=renew&offer=annual_access_1_year_offer_v1",
    "?action=unknown",
    "?license_key=secret",
    "?action=status&action=renew",
  ]) {
    assert.equal(readSetupRoute({ search }), null);
  }
});

test("each setup operation emits only its exact service request fields", () => {
  const idempotencyKey = deterministicKey(23);
  const common = {
    idempotencyKey,
    purchaseKey: "purchase-key",
    recoveryCredential: "recovery-secret",
  };
  assert.deepEqual(buildOperationRequest("claim", common), {
    idempotency_key: idempotencyKey,
    license_key: "purchase-key",
  });
  assert.deepEqual(buildOperationRequest("renew", common), {
    idempotency_key: idempotencyKey,
    license_key: "purchase-key",
    recovery_credential: "recovery-secret",
  });
  assert.deepEqual(buildOperationRequest("status", common), {
    recovery_credential: "recovery-secret",
  });
  assert.deepEqual(buildOperationRequest("reissue", common), {
    idempotency_key: idempotencyKey,
    recovery_credential: "recovery-secret",
  });
  assert.throws(() => buildOperationRequest("future-operation", common), /invalid_setup_operation/u);
});

test("update-access responses are bounded to canonical state and UTC date", () => {
  const instant = "2029-08-03T00:00:00.000Z";
  assert.deepEqual(parseUpdateAccess({
    status: "succeeded",
    update_access: { state: "active", updates_through: instant },
  }, true), { state: "active", updatesThrough: instant });
  assert.deepEqual(parseUpdateAccess({
    status: "succeeded",
    update_access: { updates_through: instant },
  }), { updatesThrough: instant });
  assert.deepEqual(parseUpdateAccess({
    status: "succeeded",
    update_access: { state: "expired", updates_through: null },
  }, true), { state: "expired", updatesThrough: null });
  assert.equal(formatUtcDate(instant), "August 3, 2029");
  for (const payload of [
    { status: "succeeded", update_access: { updates_through: instant } },
    { status: "succeeded", update_access: { state: "future", updates_through: instant } },
    { status: "succeeded", update_access: { state: "active", updates_through: "2029-08-03" } },
    { status: "succeeded", update_access: { state: "active", updates_through: null } },
    { status: "failed", update_access: { state: "active", updates_through: instant } },
  ]) {
    assert.equal(parseUpdateAccess(payload, true), null);
  }
});

test("durability must be proven by exact storage read-back", () => {
  const key = deterministicKey(3);
  const storage = new FakeStorage({ corruptReads: true });
  assert.throws(() => persistClaimOperation(storage, key, fixedNow), StorageProofError);
});

test("acknowledgement uses a separate stable key and no delivery secret storage", () => {
  const storage = new FakeStorage();
  const claimKey = deterministicKey(4);
  const acknowledgementKey = deterministicKey(5);
  persistClaimOperation(storage, claimKey, fixedNow);
  persistAcknowledgementOperation(storage, claimKey, acknowledgementKey, fixedNow);

  assert.notEqual(claimKey, acknowledgementKey);
  assert.equal(readAcknowledgementOperation(storage, claimKey).idempotencyKey, acknowledgementKey);
  const serialized = storage.getItem(acknowledgementStorageName(claimKey));
  assert.equal(serialized.includes("delivery"), false);
  assert.equal(serialized.includes("recovery"), false);

  removePendingOperations(storage, claimKey);
  assert.equal(storage.getItem(`${CLAIM_STORAGE_PREFIX}${claimKey}`), null);
  assert.equal(storage.getItem(`${ACK_STORAGE_PREFIX}${claimKey}`), null);
});

test("lifecycle invalidation aborts work and rejects late handlers", () => {
  const guard = createLifecycleGuard();
  const first = guard.begin();
  assert.equal(guard.isCurrent(first.epoch), true);
  guard.invalidate();
  assert.equal(first.signal.aborted, true);
  assert.equal(guard.isCurrent(first.epoch), false);
  const second = guard.begin();
  assert.equal(guard.isCurrent(second.epoch), true);
  assert.equal(guard.isCurrent(first.epoch), false);
});

test("claim transport refuses redirects and omits credentials", async () => {
  const calls = [];
  const fetchImplementation = async (url, options) => {
    calls.push({ url, options });
    return new Response(JSON.stringify({ error: "provider_unavailable" }), {
      status: 503,
      headers: { "Content-Type": "application/json" },
    });
  };
  const controller = new AbortController();
  const value = { idempotency_key: deterministicKey(6), license_key: "purchase-key" };
  const result = await postJson(
    fetchImplementation,
    "https://extensions.pie-menu-editor.com/v1/claims/gumroad",
    value,
    controller.signal,
  );
  assert.equal(result.response.status, 503);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].options.redirect, "error");
  assert.equal(calls[0].options.mode, "cors");
  assert.equal(calls[0].options.credentials, "omit");
  assert.equal(calls[0].options.cache, "no-store");
  assert.equal(calls[0].options.referrerPolicy, "no-referrer");
  assert.deepEqual(JSON.parse(calls[0].options.body), value);
});

test("claim transport cancels a chunked response before it exceeds the byte limit", async () => {
  let cancelled = false;
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array(20_000));
      controller.enqueue(new Uint8Array(20_000));
    },
    cancel() { cancelled = true; },
  });
  const fetchImplementation = async () => new Response(body, {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
  await assert.rejects(
    postJson(
      fetchImplementation,
      "https://extensions.pie-menu-editor.com/v1/claims/gumroad",
      { idempotency_key: deterministicKey(7), license_key: "purchase-key" },
      new AbortController().signal,
    ),
    /response_too_large/u,
  );
  assert.equal(cancelled, true);
});

test("only an exact delivered response exposes credential fields", () => {
  const delivered = parseCredentialDelivery({
    status: "succeeded",
    delivery: {
      status: "delivered",
      delivery_id: "delivery-id",
      repository_token: "repository-token",
      recovery_secret: "recovery-secret",
    },
  });
  assert.deepEqual(delivered, {
    kind: "delivered",
    deliveryId: "delivery-id",
    repositoryToken: "repository-token",
    recoverySecret: "recovery-secret",
  });
  for (const payload of [
    null,
    { status: "succeeded", delivery: null },
    { status: "succeeded", delivery: { status: "delivered" } },
    { status: "succeeded", delivery: { status: "future_status", repository_token: "secret" } },
    { status: "failed", delivery: { status: "delivered", repository_token: "secret" } },
  ]) {
    assert.notEqual(parseCredentialDelivery(payload).kind, "delivered");
  }
});

test("generated setup output pins final script and style bytes", async () => {
  const [html, headers, application] = await Promise.all([
    readFile(new URL("index.html", output), "utf8"),
    readFile(new URL("_headers", output), "utf8"),
    readFile(new URL("app.mjs", output), "utf8"),
  ]);
  const applicationHash = `sha384-${createHash("sha384").update(application, "utf8").digest("base64")}`;
  const style = html.match(/<style>([\s\S]*?)<\/style>/u)?.[1];
  assert.equal(typeof style, "string");
  const styleHash = `sha256-${createHash("sha256").update(style, "utf8").digest("base64")}`;

  assert.match(html, new RegExp(`integrity="${escapeRegExp(applicationHash)}"`, "u"));
  assert.match(headers, new RegExp(`script-src '${escapeRegExp(applicationHash)}'`, "u"));
  assert.match(headers, new RegExp(`style-src '${escapeRegExp(styleHash)}'`, "u"));
  assert.match(html, /data-cfasync="false"/u);
  assert.doesNotMatch(headers, /unsafe-inline|'self'/u);
  assert.doesNotMatch(`${html}${headers}`, /__[A-Z0-9_]+__/u);
});

test("generated output is isolated, exact-origin, and deny-by-default", async () => {
  const [html, headers, application, files, sourceFiles] = await Promise.all([
    readFile(new URL("index.html", output), "utf8"),
    readFile(new URL("_headers", output), "utf8"),
    readFile(new URL("app.mjs", output), "utf8"),
    readdir(output),
    readdir(new URL("credential-setup/", root)),
  ]);

  assert.deepEqual(files.sort(), ["_headers", "app.mjs", "index.html"]);
  assert.equal(sourceFiles.some((name) => /\.(?:html|m?js)$/u.test(name)), false);
  assert.match(html, /name="pme-setup-origin" content="https:\/\/setup\.pie-menu-editor\.com"/u);
  assert.match(html, /name="pme-service-origin" content="https:\/\/extensions\.pie-menu-editor\.com"/u);
  assert.match(headers, /connect-src https:\/\/extensions\.pie-menu-editor\.com(?:;|\n)/u);
  assert.match(headers, /Cache-Control: private, no-store, no-transform/u);
  assert.match(headers, /default-src 'none'/u);
  assert.match(headers, /form-action 'none'/u);
  assert.match(headers, /worker-src 'none'/u);
  assert.match(headers, /frame-ancestors 'none'/u);
  assert.match(headers, /Cross-Origin-Opener-Policy: same-origin/u);
  assert.match(headers, /Strict-Transport-Security: max-age=31536000/u);
  assert.doesNotMatch(html, /WIP|example-token|example-recovery/u);
  assert.doesNotMatch(html, /<form\b/u);
  assert.doesNotMatch(html, /discard-button|Discard selected retry/u);
  assert.match(html, /id="setup-title">Set up PME-F/u);
  assert.match(html, /data-operation="claim"/u);
  assert.match(html, /data-operation="renew"/u);
  assert.match(html, /data-operation="status"/u);
  assert.match(html, /data-operation="reissue"/u);
  assert.doesNotMatch(html, /annual_access_|(?:1|3)[ -]year offer/iu);
  assert.match(html, /id="verification-panel"/u);
  assert.match(html, /id="result-panel"[^>]*hidden/u);
  assert.match(html, /id="after-setup-panel"[^>]*hidden/u);
  assert.match(application, /verificationPanel\.hidden = true/u);
  assert.match(application, /repositoryUrl: `\$\{serviceOrigin\}\/v1\/index\.json`/u);
  assert.match(application, /renewalUrl: `\$\{serviceOrigin\}\/v1\/renewals\/gumroad`/u);
  assert.match(application, /reissueUrl: `\$\{serviceOrigin\}\/v1\/recovery\/reissue`/u);
  assert.match(application, /statusUrl: `\$\{serviceOrigin\}\/v1\/update-access\/status`/u);
  assert.match(application, /setupTitle\.textContent = "Save your Repository access"/u);
  assert.match(application, /setupTitle\.textContent = "Setup complete"/u);
  assert.doesNotMatch(application, /Setup was already completed/u);
  assert.doesNotMatch(application, /PUBLIC_OFFER_CODES|offerCode|offer_code/u);
  assert.doesNotMatch(application, /localStorage.*(?:license|purchase|recovery|credential|token)/iu);
  assert.doesNotMatch(application, /(?:location|history)\.(?:assign|replace|pushState|replaceState)/u);

  await assert.rejects(readFile(new URL("setup/index.html", root), "utf8"), { code: "ENOENT" });
});

test("staging build is fail-closed until its fixed service origin is supplied", () => {
  const result = spawnSync(
    process.execPath,
    ["tools/build-setup.mjs", "--target", "staging", "--output", "dist/staging-test"],
    { cwd: new URL("../", import.meta.url), encoding: "utf8", env: { ...process.env, PME_SETUP_STAGING_SERVICE_ORIGIN: "" } },
  );
  assert.notEqual(result.status, 0);
  assert.match(`${result.stderr}${result.stdout}`, /service origin is required/u);
});

test("staging build pins one fixed staging setup and service origin", async () => {
  const stagingServiceOrigin = "https://extensions-staging.pie-menu-editor.com";
  const result = spawnSync(
    process.execPath,
    ["tools/build-setup.mjs", "--target", "staging", "--output", "dist/staging-test"],
    {
      cwd: new URL("../", import.meta.url),
      encoding: "utf8",
      env: { ...process.env, PME_SETUP_STAGING_SERVICE_ORIGIN: stagingServiceOrigin },
    },
  );
  assert.equal(result.status, 0, `${result.stderr}${result.stdout}`);
  const [html, headers] = await Promise.all([
    readFile(new URL("../dist/staging-test/index.html", import.meta.url), "utf8"),
    readFile(new URL("../dist/staging-test/_headers", import.meta.url), "utf8"),
  ]);
  assert.match(html, /content="https:\/\/setup-staging\.pie-menu-editor\.com"/u);
  assert.match(html, new RegExp(`content="${escapeRegExp(stagingServiceOrigin)}"`, "u"));
  assert.match(headers, new RegExp(`connect-src ${escapeRegExp(stagingServiceOrigin)}(?:;|\\n)`, "u"));
  assert.doesNotMatch(`${html}${headers}`, /https:\/\/setup\.pie-menu-editor\.com/u);
  assert.doesNotMatch(`${html}${headers}`, /connect-src https:\/\/extensions\.pie-menu-editor\.com(?:;|\n)/u);
});

test("build rejects unknown arguments instead of inferring a target", () => {
  const result = spawnSync(
    process.execPath,
    ["tools/build-setup.mjs", "--target", "production", "--preview-branch", "main"],
    { cwd: new URL("../", import.meta.url), encoding: "utf8" },
  );
  assert.notEqual(result.status, 0);
  assert.match(`${result.stderr}${result.stdout}`, /unknown argument/u);
});

function deterministicKey(fill) {
  return Buffer.alloc(32, fill).toString("base64url");
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

class FakeStorage {
  #values = new Map();
  #corruptReads;

  constructor({ corruptReads = false } = {}) {
    this.#corruptReads = corruptReads;
  }

  get length() { return this.#values.size; }
  values() { return this.#values.values(); }
  key(index) { return [...this.#values.keys()][index] ?? null; }
  getItem(name) {
    const value = this.#values.get(name) ?? null;
    return this.#corruptReads && value !== null ? `${value}x` : value;
  }
  setItem(name, value) { this.#values.set(String(name), String(value)); }
  removeItem(name) { this.#values.delete(String(name)); }
}
