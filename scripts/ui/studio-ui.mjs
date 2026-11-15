// Studio's page in a real Chrome, against a running Studio (scripts/smoke/office.py starts
// one and calls this).
//
//   node studio-ui.mjs <studio url> <email> <password> <screenshot dir>
//
// Signs in, makes and edits a record in two apps from the generated forms, checks that a
// personal field is masked until Reveal, that record text cannot inject markup, and that
// the page fits a phone-sized screen.
import { chromium } from "playwright-core";
import { mkdirSync } from "node:fs";
import { join } from "node:path";

const [URL_, EMAIL, PASSWORD, OUT] = process.argv.slice(2);
mkdirSync(OUT, { recursive: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const browser = await chromium.launch({ channel: "chrome", headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
const problems = [];
const RUN = Date.now().toString(36);
let expected401 = 1; // the page asks who is signed in before anyone is
page.on("pageerror", (e) => problems.push("pageerror: " + e.message));
page.on("console", (m) => {
  if (!["error", "warning"].includes(m.type())) return;
  if (m.text().includes("401") && expected401-- > 0) return;
  problems.push(m.type() + ": " + m.text());
});
const shot = (n) => page.screenshot({ path: join(OUT, n + ".png") });
const step = async (name, fn) => { try { await fn(); console.log("ok  ", name); } catch (e) { problems.push(name + ": " + e.message.split("\n")[0]); console.log("FAIL", name, e.message.split("\n")[0]); } };

await step("sign in", async () => {
  await page.goto(URL_);
  await page.locator("input[name=email]").fill(EMAIL);
  await page.locator("input[name=password]").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await page.getByRole("button", { name: "notebook", exact: true }).waitFor();
  await shot("studio-01-apps");
});

const TITLE = `<img src=x onerror=window.__xss=1> made in Studio ${RUN}`;
const EDITED = `edited in Studio ${RUN}`;
const NAME = `Dana ${RUN}`;
await step("notebook: make a record from the generated form", async () => {
  await page.getByRole("button", { name: "notebook", exact: true }).click();
  await page.getByRole("button", { name: "Notebooks" }).click();
  await page.getByRole("button", { name: "New" }).click();
  await page.locator("form input[type=text]").first().fill(TITLE);
  await page.getByRole("button", { name: "Create" }).click();
  await page.getByRole("cell", { name: TITLE, exact: true }).waitFor();
  await shot("studio-02-notebooks");
});
await step("record text is shown as text, never run", async () => {
  await sleep(300);
  if (await page.evaluate(() => window.__xss)) throw new Error("script ran");
  if ((await page.locator("img[src=x]").count()) !== 0) throw new Error("an element was made from the text");
});
await step("notebook: edit it", async () => {
  await page.getByRole("cell", { name: TITLE, exact: true }).click();
  const input = page.locator("form input[type=text]").first();
  await input.fill(EDITED);
  await page.getByRole("button", { name: "Save" }).click();
  await page.getByRole("cell", { name: EDITED, exact: true }).waitFor();
});
await step("Falak.me: a personal field is masked until Reveal", async () => {
  await page.getByRole("button", { name: "falakme", exact: true }).click();
  await page.getByRole("button", { name: "Profiles" }).click();
  await page.getByRole("button", { name: "New" }).click();
  const fields = page.locator("form input[type=text]");
  await fields.nth(0).fill(NAME);
  await fields.nth(1).fill("Lives at 12 Secret Street");
  await page.getByRole("button", { name: "Create" }).click();
  await page.getByRole("cell", { name: NAME, exact: true }).waitFor();
  await page.getByRole("cell", { name: NAME, exact: true }).click();
  const bio = page.locator("form input[type=text]").nth(1);
  const masked = await bio.inputValue();
  if (!masked.includes("•") || masked.includes("Secret")) throw new Error("not masked: " + masked);
  await shot("studio-03-masked");
  await page.getByRole("button", { name: "Reveal" }).click();
  await page.waitForFunction(() => [...document.querySelectorAll("form input[type=text]")].some((i) => i.value.includes("Secret Street")));
  await shot("studio-04-revealed");
});

const phone = await browser.newPage({ viewport: { width: 390, height: 800 } });
phone.on("pageerror", (e) => problems.push("phone pageerror: " + e.message));
await step("phone: sign in and the lists fit the width", async () => {
  await phone.goto(URL_);
  await phone.locator("input[name=email]").fill(EMAIL);
  await phone.locator("input[name=password]").fill(PASSWORD);
  await phone.getByRole("button", { name: "Sign in", exact: true }).click();
  await phone.getByRole("button", { name: "notebook", exact: true }).waitFor();
  await phone.getByRole("button", { name: "Notebooks" }).click();
  await phone.getByRole("cell", { name: EDITED, exact: true }).waitFor();
  const over = await phone.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  await phone.screenshot({ path: join(OUT, "studio-phone.png") });
  if (over > 1) throw new Error(`the list is ${over}px wider than the screen`);
});

await browser.close();
console.log(problems.length ? "PROBLEMS:\n" + problems.join("\n") : "studio ui: all steps passed, no console errors");
process.exit(problems.length ? 1 : 0);
