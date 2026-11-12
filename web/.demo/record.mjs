// Records the dashboard demo for the website. Local only, never committed.
import { chromium } from "@playwright/test";
import { readFileSync, mkdirSync } from "node:fs";

const base = "https://lf-e2e.192.168.49.2.nip.io";
const out = process.argv[2];
const invite = readFileSync(process.argv[3], "utf8").match(/\/invite#token=\S+/)?.[0];
const tenant = process.argv[5], tenantID = process.argv[4];
const browser = await chromium.launch({ args: ["--host-resolver-rules=MAP *.nip.io 192.168.49.2"] });
const size = { width: 1440, height: 900 };

// Sign in and accept the invitation off camera.
const setup = await browser.newContext({ ignoreHTTPSErrors: true, viewport: size });
let p = await setup.newPage();
await p.goto(base + "/");
await p.getByRole("link", { name: "Continue to sign in" }).click();
await p.locator("#username").fill("admin");
await p.locator("#password").fill("licenseforge");
await p.locator("#kc-login").click();
await p.waitForURL((u) => !u.hostname.startsWith("kc"));
const mine = await p.evaluate(() => fetch("/api/v1/me/tenants").then((r) => r.json()));
if (!mine.items.some((t) => t.slug === tenant)) {
  await p.goto(base + invite);
  await p.getByRole("button", { name: "Accept invitation" }).click();
  await p.waitForURL(new RegExp("/t/" + tenant));
}
const state = await setup.storageState();
await setup.close();

mkdirSync(out, { recursive: true });
const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: size, storageState: state, recordVideo: { dir: out, size }, colorScheme: "dark" });
// A visible cursor: the recording shows no pointer otherwise.
await ctx.addInitScript(() => {
  addEventListener("DOMContentLoaded", () => {
    const c = document.createElement("div");
    c.style.cssText = "position:fixed;z-index:2147483647;width:18px;height:18px;border-radius:50%;background:rgba(255,140,50,.85);box-shadow:0 0 0 4px rgba(255,140,50,.25);pointer-events:none;left:-40px;top:-40px;transform:translate(-50%,-50%);transition:left .35s ease,top .35s ease,transform .15s";
    document.body.appendChild(c);
    addEventListener("mousemove", (e) => { c.style.left = e.clientX + "px"; c.style.top = e.clientY + "px"; }, true);
    addEventListener("mousedown", () => (c.style.transform = "translate(-50%,-50%) scale(.7)"), true);
    addEventListener("mouseup", () => (c.style.transform = "translate(-50%,-50%)"), true);
  });
});
p = await ctx.newPage();
const pause = (ms) => p.waitForTimeout(ms);
const click = async (loc) => { const b = await loc.boundingBox(); if (b) { await p.mouse.move(b.x + b.width / 2, b.y + b.height / 2, { steps: 12 }); await pause(250); } await loc.click(); await pause(350); };
const type = async (loc, text) => { await click(loc); await loc.pressSequentially(text, { delay: 55 }); await pause(200); };

// 1. Signing key.
await p.goto(`${base}/t/${tenant}/settings/signing-keys`);
await pause(1200);
const gen = p.getByRole("button", { name: "Generate key" });
if (await gen.count()) {
  await click(gen.first());
  await click(p.getByRole("dialog").getByRole("button", { name: "Generate key" }));
  await pause(1500);
}
await p.mouse.wheel(0, 400); await pause(1200); await p.mouse.wheel(0, -400);

// 2. Product, features, plan.
await p.goto(`${base}/t/${tenant}/products`); await pause(800);
await click(p.getByRole("button", { name: "New product" }));
await type(p.getByLabel(/^Slug/), "acme-db");
await type(p.getByLabel("Name", { exact: true }), "Acme DB");
await click(p.getByRole("button", { name: "Create product" }));
await click(p.getByRole("link", { name: "Acme DB" }));
for (const [k, n] of [["sso", "Single sign-on"], ["audit_export", "Audit export"]]) {
  await click(p.getByRole("button", { name: "New feature" }));
  await type(p.getByLabel(/^Key/), k);
  await type(p.getByLabel("Name", { exact: true }), n);
  await click(p.getByRole("button", { name: "Create", exact: true }));
}
for (const [s, n] of [["standard", "Standard"], ["enterprise", "Enterprise"]]) {
  await click(p.getByRole("button", { name: "New plan" }));
  await type(p.getByLabel(/^Slug/), s);
  await type(p.getByLabel("Name", { exact: true }), n);
  await type(p.getByLabel(/^Term/), "12");
  await click(p.getByRole("button", { name: "Create", exact: true }));
}
await click(p.getByRole("checkbox", { name: "Single sign-on in Enterprise" }));
await click(p.getByRole("checkbox", { name: "Audit export in Enterprise" }));
await click(p.getByRole("button", { name: "Save changes" }));
await pause(1000);

// 3. Customer and license.
await p.goto(`${base}/t/${tenant}/customers`); await pause(600);
await click(p.getByRole("button", { name: "New customer" }));
await type(p.getByLabel("Name", { exact: true }), "Contoso Ltd");
await click(p.getByRole("button", { name: "Create customer" }));
await pause(600);
await p.goto(`${base}/t/${tenant}/licenses`); await pause(600);
await click(p.getByRole("button", { name: "Issue license" }));
const d = p.getByRole("dialog");
await d.locator('select[name="product_id"]').selectOption({ label: "Acme DB" }); await pause(400);
await d.locator('select[name="customer_id"]').selectOption({ label: "Contoso Ltd" }); await pause(400);
await d.locator('select[name="plan_id"]').selectOption({ label: "Enterprise (enterprise)" }); await pause(400);
await click(d.getByRole("button", { name: "Issue license" }));
const key = await p.getByRole("textbox", { name: "License key" }).inputValue();
await pause(2500);

// 4. Two machines activate with the SDK's call (off screen), then show them.
await p.evaluate(async ({ tenantID, key }) => {
  for (const [host, n] of [["db-prod-1", "a"], ["db-prod-2", "b"]]) {
    const fp = "sha256:" + n.repeat(64);
    await fetch(`/api/v1/activation/tenants/${tenantID}/activate`, { method: "POST", headers: { Authorization: "License " + key, "Content-Type": "application/json" },
      body: JSON.stringify({ fingerprint: fp, fp_source: "machine-id", hostname: host, app_version: "4.2.0" }) });
  }
}, { tenantID, key });
await p.keyboard.press("Escape"); await pause(300);
await p.reload(); await pause(800);
await click(p.getByRole("row").filter({ hasText: "Contoso Ltd" }).first().getByRole("button").first());
await pause(2500);
await p.mouse.wheel(0, 500); await pause(1800);
await p.keyboard.press("Escape");

// 5. Overview and audit log.
await p.goto(`${base}/t/${tenant}`); await pause(2200);
await p.goto(`${base}/t/${tenant}/settings/audit`); await pause(2500);
await ctx.close();
await browser.close();
console.log("done");
