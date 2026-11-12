import { chromium } from "@playwright/test";
const b = await chromium.launch();
const p = await b.newPage({ viewport: { width: 390, height: 844 } });
await p.goto("http://127.0.0.1:8765/"); await p.waitForTimeout(1500);
console.log("overflow", await p.evaluate(() => document.documentElement.scrollWidth - innerWidth));
console.log(await p.evaluate(() => [...document.querySelectorAll("body *")].filter((e) => !e.closest("pre") && e.getBoundingClientRect().right > innerWidth + 1).slice(0, 8).map((e) => e.tagName + "." + e.className + " " + Math.round(e.getBoundingClientRect().right))));
await b.close();
