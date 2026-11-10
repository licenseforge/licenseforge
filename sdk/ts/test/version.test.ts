// SDK_VERSION (sent to the server and in the User-Agent) is the package's version.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { SDK_VERSION } from "../src/index.js";

test("SDK_VERSION is the package.json version", () => {
  const pkg = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8"));
  assert.equal(SDK_VERSION, `ts/${pkg.version}`);
});
