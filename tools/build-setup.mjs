import { createHash } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const sourceRoot = resolve(repositoryRoot, "credential-setup");
const defaultOutput = resolve(repositoryRoot, "dist", "setup");

validateArguments();
const target = argumentValue("--target");
if (target !== "production" && target !== "staging") {
  throw new Error("--target must be exactly production or staging");
}

const requestedOutput = argumentValue("--output");
const outputRoot = requestedOutput === null
  ? defaultOutput
  : resolve(repositoryRoot, requestedOutput);
const distRelative = relative(resolve(repositoryRoot, "dist"), outputRoot);
if (isAbsolute(distRelative) || distRelative === "" || distRelative.startsWith("..")) {
  throw new Error("setup output must be a child of the repository dist directory");
}

const setupOrigin = target === "production"
  ? "https://setup.pie-menu-editor.com"
  : "https://setup-staging.pie-menu-editor.com";
const serviceOrigin = target === "production"
  ? "https://extensions.pie-menu-editor.com"
  : process.env.PME_SETUP_STAGING_SERVICE_ORIGIN;

assertCanonicalHttpsOrigin(setupOrigin, "setup origin");
assertCanonicalHttpsOrigin(serviceOrigin, "service origin");
if (setupOrigin === serviceOrigin) throw new Error("setup and service origins must be distinct");

const [template, style, application] = await Promise.all([
  readFile(resolve(sourceRoot, "index.template.html.txt"), "utf8"),
  readFile(resolve(sourceRoot, "style.source.css.txt"), "utf8"),
  readFile(resolve(sourceRoot, "app.source.js.txt"), "utf8"),
]);

const applicationIntegrity = digest("sha384", application);
const styleIntegrity = digest("sha256", style);
const html = replaceExactlyOnce(
  replaceExactlyOnce(
    replaceExactlyOnce(
      replaceExactlyOnce(template, "__SETUP_ORIGIN__", setupOrigin, true),
      "__SERVICE_ORIGIN__",
      serviceOrigin,
      true,
    ),
    "__INLINE_STYLE__",
    style,
  ),
  "__APP_INTEGRITY__",
  applicationIntegrity,
);

const contentSecurityPolicy = [
  "default-src 'none'",
  "base-uri 'none'",
  `connect-src ${serviceOrigin}`,
  "form-action 'none'",
  "frame-ancestors 'none'",
  "frame-src 'none'",
  "img-src 'none'",
  "font-src 'none'",
  "manifest-src 'none'",
  "media-src 'none'",
  "object-src 'none'",
  `script-src '${applicationIntegrity}'`,
  "script-src-attr 'none'",
  `style-src '${styleIntegrity}'`,
  "style-src-attr 'none'",
  "worker-src 'none'",
].join("; ");

const headers = `/*
  Cache-Control: private, no-store, no-transform
  Content-Security-Policy: ${contentSecurityPolicy}
  Cross-Origin-Opener-Policy: same-origin
  Cross-Origin-Resource-Policy: same-origin
  Permissions-Policy: accelerometer=(), camera=(), geolocation=(), microphone=(), payment=(), usb=()
  Referrer-Policy: no-referrer
  Strict-Transport-Security: max-age=31536000
  X-Content-Type-Options: nosniff
  X-Frame-Options: DENY
  X-Robots-Tag: noindex, nofollow, noarchive
`;

await rm(outputRoot, { recursive: true, force: true });
await mkdir(outputRoot, { recursive: true });
await Promise.all([
  writeFile(resolve(outputRoot, "index.html"), html, "utf8"),
  writeFile(resolve(outputRoot, "app.mjs"), application, "utf8"),
  writeFile(resolve(outputRoot, "_headers"), headers, "utf8"),
]);

function argumentValue(name) {
  const index = process.argv.indexOf(name);
  if (index < 0) return null;
  const value = process.argv[index + 1];
  if (typeof value !== "string" || value.length === 0 || value.startsWith("--")) {
    throw new Error(`${name} requires a value`);
  }
  if (process.argv.indexOf(name, index + 1) >= 0) throw new Error(`${name} may appear only once`);
  return value;
}

function validateArguments() {
  const allowed = new Set(["--target", "--output"]);
  const seen = new Set();
  for (let index = 2; index < process.argv.length; index += 2) {
    const name = process.argv[index];
    const value = process.argv[index + 1];
    if (!allowed.has(name)) throw new Error(`unknown argument: ${name ?? "<missing>"}`);
    if (seen.has(name)) throw new Error(`${name} may appear only once`);
    if (typeof value !== "string" || value.length === 0 || value.startsWith("--")) {
      throw new Error(`${name} requires a value`);
    }
    seen.add(name);
  }
}

function assertCanonicalHttpsOrigin(value, label) {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${label} is required`);
  const url = new URL(value);
  if (
    url.protocol !== "https:"
    || url.origin !== value
    || url.pathname !== "/"
    || url.search !== ""
    || url.hash !== ""
    || url.username !== ""
    || url.password !== ""
  ) {
    throw new Error(`${label} must be one canonical HTTPS origin`);
  }
}

function digest(algorithm, value) {
  return `${algorithm}-${createHash(algorithm).update(value, "utf8").digest("base64")}`;
}

function replaceExactlyOnce(value, marker, replacement, replaceAll = false) {
  const occurrences = value.split(marker).length - 1;
  const expected = replaceAll ? occurrences : 1;
  if (occurrences === 0 || (!replaceAll && occurrences !== expected)) {
    throw new Error(`template marker ${marker} has an unexpected occurrence count`);
  }
  return replaceAll ? value.replaceAll(marker, replacement) : value.replace(marker, replacement);
}
