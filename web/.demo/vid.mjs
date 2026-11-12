import { chromium } from "@playwright/test";
const b = await chromium.launch(); const p = await b.newPage();
await p.goto("http://127.0.0.1:8766/"); await p.waitForTimeout(800);
await p.evaluate(() => document.querySelector("video").scrollIntoView({block:"center"})); await p.waitForTimeout(3000);
console.log(await p.evaluate(() => { const v = document.querySelector("video"); return { paused: v.paused, t: v.currentTime, rs: v.readyState, err: v.error && v.error.code, src: v.currentSrc, webm: v.canPlayType('video/webm; codecs="vp9"'), mp4: v.canPlayType("video/mp4") }; }));
await b.close();
