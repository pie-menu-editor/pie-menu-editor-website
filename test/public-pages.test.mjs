import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

test("public pages expose one canonical access and privacy policy", async () => {
  const [home, access, setupTemplate] = await Promise.all([
    readFile(new URL("index.html", root), "utf8"),
    readFile(new URL("access.html", root), "utf8"),
    readFile(new URL("credential-setup/index.template.html.txt", root), "utf8"),
  ]);

  assert.match(home, /href="\/access"/u);
  assert.match(setupTemplate, /href="https:\/\/pie-menu-editor\.com\/access"/u);
  assert.match(access, /rel="canonical" href="https:\/\/pie-menu-editor\.com\/access"/u);
  assert.match(access, /one calendar year/u);
  assert.match(access, /2027-08-11T20:35:05\.557Z/u);
  assert.match(access, /does not stop working/u);
  assert.match(access, /retained for 80 days/u);
  assert.match(access, /does not require a PME account, device registration, or DRM/u);
  assert.doesNotMatch(access, /pme_(?:rt|rc)_[A-Za-z0-9_-]+/u);
});
