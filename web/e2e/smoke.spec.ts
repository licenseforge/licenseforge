import { readFileSync } from "node:fs";
import { expect, test } from "@playwright/test";

// The vendor's first license through the real dashboard (ADR-0041): sign in
// through Keycloak, build a catalog, issue, and get the key shown once.
test("a vendor issues their first license from the dashboard", async ({ page }, info) => {
  const { inviteTokenFile, tenant } = info.config.metadata as { inviteTokenFile: string; tenant: string };
  const run = Math.random().toString(36).slice(2, 8);

  // Sign in through the identity provider's form.
  await page.goto("/");
  await page.getByRole("link", { name: "Continue to sign in" }).click();
  await page.locator("#username").fill("admin");
  await page.locator("#password").fill("licenseforge");
  await page.locator("#kc-login").click();
  await page.waitForURL((u) => !u.hostname.startsWith("kc"));

  // Owner of the seeded tenant: accept its invitation on a fresh environment.
  // From the page, as the dashboard does (Playwright's own request client
  // wouldn't use the browser's host mapping).
  const tenants = (await page.evaluate(() => fetch("/api/v1/me/tenants").then((r) => r.json()))) as { items: { slug: string }[] };
  if (!tenants.items.some((t) => t.slug === tenant)) {
    await page.goto(`/invite#token=${readFileSync(inviteTokenFile, "utf8").trim()}`);
    await page.getByRole("button", { name: "Accept invitation" }).click();
    await page.waitForURL(new RegExp(`/t/${tenant}`));
  }

  // A product, with an on/off feature and a plan.
  await page.goto(`/t/${tenant}/products`);
  await page.getByRole("button", { name: "New product" }).click();
  await page.getByLabel("Slug").fill(`ui-${run}`);
  await page.getByLabel("Name").fill(`UI ${run}`);
  await page.getByRole("button", { name: "Create product" }).click();
  await page.getByRole("link", { name: `UI ${run}` }).click();
  await expect(page.getByRole("heading", { name: `UI ${run}` })).toBeVisible();

  await page.getByRole("button", { name: "New feature" }).click();
  await page.getByLabel("Key").fill("sso");
  await page.getByLabel("Name").fill("SSO");
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await expect(page.getByRole("cell", { name: "sso", exact: true })).toBeVisible();

  await page.getByRole("button", { name: "New plan" }).click();
  await page.getByLabel("Slug").fill("pro");
  await page.getByLabel("Name").fill("Pro");
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await expect(page.getByRole("cell", { name: "pro", exact: true })).toBeVisible();

  // The feature × plan matrix: Pro includes SSO.
  await page.getByRole("checkbox", { name: "SSO in Pro" }).check();
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect(page.getByText("Saved.")).toBeVisible();

  // A customer, then the license, picked from lists.
  await page.goto(`/t/${tenant}/customers`);
  await page.getByRole("button", { name: "New customer" }).click();
  await page.getByLabel("Name").fill(`Customer ${run}`);
  await page.getByRole("button", { name: "Create customer" }).click();
  await expect(page.getByRole("cell", { name: `Customer ${run}` })).toBeVisible();

  await page.goto(`/t/${tenant}/licenses`);
  await page.getByRole("button", { name: "Issue license" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.locator('select[name="product_id"]').selectOption({ label: `UI ${run}` });
  await dialog.locator('select[name="customer_id"]').selectOption({ label: `Customer ${run}` });
  await dialog.locator('select[name="plan_id"]').selectOption({ label: "Pro (pro)" });
  await dialog.getByRole("button", { name: "Issue license" }).click();

  // The key, shown once.
  await expect(page.getByRole("dialog", { name: "Copy the license key" })).toBeVisible();
  await expect(page.getByRole("textbox", { name: "License key" })).toHaveValue(/^LF-[A-Z2-7-]+$/);
});
