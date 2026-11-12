import { chromium } from "@playwright/test";
const out = process.argv[2];
const b = await chromium.launch();
for (const [name, vp] of [["desktop", { width: 1440, height: 900 }], ["mobile", { width: 390, height: 844 }]]) {
  const p = await b.newPage({ viewport: vp, deviceScaleFactor: 1 });
  const errs = []; p.on("pageerror", (e) => errs.push(e.message)); p.on("console", (m) => m.type() === "error" && errs.push(m.text()));
  await p.goto("http://127.0.0.1:8765/");
  await p.waitForTimeout(2500);
  await p.screenshot({ path: `${out}/${name}-hero.png` });
  // scroll through to trigger reveals
  const H = await p.evaluate(() => document.documentElement.scrollHeight);
  for (let y = 0; y < H; y += 400) { await p.evaluate((y) => scrollTo(0, y), y); await p.waitForTimeout(120); }
  for (const id of ["problems", "how", "demo", "try", "pricing", "features"]) {
    await p.evaluate((id) => document.getElementById(id).scrollIntoView({ behavior: "instant" }), id);
    await p.waitForTimeout(1300);
    await p.screenshot({ path: `${out}/${name}-${id}.png` });
  }
  // a later problem step
  await p.evaluate(() => document.querySelector('[data-step="1"] h3').scrollIntoView({ behavior: "instant", block: "end" }));
  await p.waitForTimeout(2200);
  await p.screenshot({ path: `${out}/${name}-step1.png` });
  const overflow = await p.evaluate(() => document.documentElement.scrollWidth - innerWidth);
  console.log(name, "errors:", errs, "h-overflow:", overflow);
}
await b.close();
