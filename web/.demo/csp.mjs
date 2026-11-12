import { chromium } from "@playwright/test";
const b = await chromium.launch(); const p = await b.newPage();
const errs = []; p.on("console", (m) => errs.push(m.type() + ": " + m.text())); p.on("pageerror", (e) => errs.push(e.message));
await p.goto("http://127.0.0.1:8766/"); await p.waitForTimeout(1500);
await p.evaluate(() => document.getElementById("demo").scrollIntoView()); await p.waitForTimeout(2500);
console.log({ js: await p.evaluate(() => document.documentElement.className), playing: await p.evaluate(() => !document.querySelector("video").paused && document.querySelector("video").currentTime > 0), errs });
const r = await p.goto("http://127.0.0.1:8766/licenseforge/sdk/go/online?go-get=1"); console.log("404 status", r.status(), (await r.text()).includes('name="go-import"'));
await b.close();
