// Office's console in a real Chrome: first-run setup, every tab, sign out and in, a person
// who is not an administrator, and the same pages on a phone-sized screen.
//
//   cd scripts/ui && npm ci
//   node office-ui.mjs <falak-office binary> <screenshot dir>
//
// Needs Chrome (the `chrome` channel). Exits 1 on any failed step or any console error
// other than the two refusals the steps cause on purpose.
import { chromium } from "playwright-core";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import net from "node:net";

const [BIN, OUT] = process.argv.slice(2);
mkdirSync(OUT, { recursive: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const freePort = () => new Promise((res) => { const s = net.createServer().listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => res(p)); }); });

const PORT = await freePort();
const data = mkdtempSync(join(tmpdir(), "office-ui-"));
const office = spawn(BIN, ["serve", "--port", String(PORT), "--data", data], { stdio: ["ignore", "pipe", "pipe"] });
let log = "";
office.stdout.on("data", (d) => (log += d));
office.stderr.on("data", (d) => (log += d));
let setupUrl = null;
for (let i = 0; i < 100 && !setupUrl; i++) { await sleep(100); setupUrl = (log.match(/http:\/\/(?:localhost|127\.0\.0\.1):\d+\/\?setup=[0-9a-f]+/) || [])[0] || null; }
if (!setupUrl) { console.log("no setup URL in:\n" + log); office.kill(); process.exit(1); }

const browser = await chromium.launch({ channel: "chrome", headless: true });
const problems = [];
const step = async (name, fn) => { try { await fn(); console.log("ok  ", name); } catch (e) { problems.push(name + ": " + e.message.split("\n")[0]); console.log("FAIL", name, e.message.split("\n")[0]); } };
const PASSWORD = "correct horse battery staple";

// Two refusals are expected: the wrong setup code, and a non-administrator opening the console.
let expected403 = 0;
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
page.on("pageerror", (e) => problems.push("pageerror: " + e.message));
page.on("console", (m) => {
  if (m.type() !== "error" && m.type() !== "warning") return;
  if (m.text().includes("403") && expected403-- > 0) return;
  problems.push(m.type() + ": " + m.text());
});
const shot = (name) => page.screenshot({ path: join(OUT, name + ".png") });

await step("the setup page opens with the code filled in", async () => {
  await page.goto(setupUrl);
  await page.getByRole("heading", { name: "Set up Falak Office" }).waitFor();
  if ((await page.locator("input[name=token]").inputValue()).length < 20) throw new Error("code not filled in");
  await shot("01-setup");
});
await step("setup creates the administrator and signs in", async () => {
  await page.locator("input[name=email]").fill("owner@example.com");
  await page.locator("input[name=password]").fill(PASSWORD);
  await page.locator("input[name=again]").fill(PASSWORD);
  await page.getByRole("button", { name: "Create the administrator" }).click();
  await page.getByText("Failed sign-ins").waitFor();
  await shot("02-overview");
});
await step("a second setup attempt is refused", async () => {
  expected403++;
  const r = await page.evaluate(async () => (await fetch("/v1/_office/setup", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token: "x", email: "a@b.co", password: "correct horse battery staple" }) })).status);
  if (r !== 403) throw new Error("status " + r);
});
await step("Apps: make an enrollment code", async () => {
  await page.getByRole("button", { name: "Apps" }).click();
  await page.locator("input[name=app]").fill("notebook");
  await page.getByRole("button", { name: "Make an enrollment code" }).click();
  await page.getByText("falak office enroll").waitFor();
  await shot("03-apps");
});
await step("People: add a person", async () => {
  await page.getByRole("button", { name: "People" }).click();
  await page.locator("input[name=email]").fill("sam@example.com");
  await page.locator("input[name=password]").fill("another long password 1");
  await page.getByRole("button", { name: "Add person" }).click();
  await page.getByRole("cell", { name: "sam@example.com" }).waitFor();
  await shot("04-people");
});
await step("Access", async () => { await page.getByRole("button", { name: "Access" }).click(); await page.getByRole("heading", { name: "Access" }).waitFor(); await shot("05-access"); });
await step("Sign-in", async () => { await page.getByRole("button", { name: "Sign-in" }).click(); await page.getByRole("heading", { name: "Sign-in" }).waitFor(); await shot("06-signin"); });
await step("Keys: rotate the signing key", async () => {
  await page.getByRole("button", { name: "Keys and revocation" }).click();
  await page.getByRole("button", { name: "Rotate the signing key" }).click();
  await page.getByText("Rotated.").waitFor();
  await shot("07-keys");
});
await step("Activity shows what happened", async () => {
  await page.getByRole("button", { name: "Activity" }).click();
  await page.getByRole("cell", { name: "key_rotated" }).waitFor();
  await shot("08-activity");
});
await step("a person made up as text cannot inject markup", async () => {
  await page.getByRole("button", { name: "People" }).click();
  await page.locator("input[name=email]").fill("<img src=x onerror=window.__xss=1>@example.com");
  await page.locator("input[name=password]").fill("another long password 1");
  await page.getByRole("button", { name: "Add person" }).click();
  await sleep(500);
  if (await page.evaluate(() => window.__xss)) throw new Error("script ran");
});
await step("sign out and back in", async () => {
  await page.getByRole("button", { name: "Sign out" }).click();
  await page.getByRole("heading", { name: "Sign in to Office" }).waitFor();
  await page.locator("input[name=email]").fill("owner@example.com");
  await page.locator("input[name=password]").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await page.getByText("Failed sign-ins").waitFor();
});

// A phone-sized screen: nothing may run off the side.
const phone = await browser.newPage({ viewport: { width: 390, height: 800 } });
phone.on("pageerror", (e) => problems.push("phone pageerror: " + e.message));
await step("phone: sign in and every tab fits the width", async () => {
  await phone.goto(`http://127.0.0.1:${PORT}/`);
  await phone.locator("input[name=email]").fill("owner@example.com");
  await phone.locator("input[name=password]").fill(PASSWORD);
  await phone.getByRole("button", { name: "Sign in", exact: true }).click();
  await phone.getByText("Failed sign-ins").waitFor();
  for (const tab of ["Overview", "Apps", "People", "Access", "Sign-in", "Keys and revocation", "Activity"]) {
    await phone.getByRole("button", { name: tab, exact: true }).click();
    await sleep(250);
    const over = await phone.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    if (over > 1) throw new Error(`${tab} is ${over}px wider than the screen`);
    await phone.screenshot({ path: join(OUT, `phone-${tab.replace(/\W+/g, "-").toLowerCase()}.png`) });
  }
});

await step("an ordinary person is not let into the console", async () => {
  expected403++;
  await page.getByRole("button", { name: "Sign out" }).click();
  await page.locator("input[name=email]").fill("sam@example.com");
  await page.locator("input[name=password]").fill("another long password 1");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await page.getByText("not an administrator").waitFor();
  await shot("09-not-admin");
});

await browser.close();
office.kill();
console.log(problems.length ? "PROBLEMS:\n" + problems.join("\n") : "office ui: all steps passed, no console errors");
process.exit(problems.length ? 1 : 0);
