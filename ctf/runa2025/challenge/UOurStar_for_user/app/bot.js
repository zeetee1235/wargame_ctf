const puppeteer = require('puppeteer');
const USERNAME  = 'admin';
const PASSWORD  = process.env.ADMINPASS || 'fake_password';

let browser;
const ctxMap = new Map();
const MAX_CTX = 200;
const TTL_MS = 30 * 60 * 1000; // 30 minutes

async function getBrowser() {
    if (!browser) browser = await puppeteer.launch({
        args: [
            '--no-sandbox',
            '--disable-dev-shm-usage',
            '--ignore-certificate-errors',
        ], 
    });
    return browser;
}

// Get or create a browser context for the given reporterId (LRU eviction & TTL)
// It's not important to you!
async function getContext(reporterId) {
    const browser = await getBrowser();
    const now = Date.now();

    for (const [k, v] of ctxMap) if (now - v.last > TTL_MS) {
        await v.ctx.close().catch(()=>{});
        ctxMap.delete(k);
    }

    if (ctxMap.size > MAX_CTX) {
        const old = [...ctxMap.entiries()].sort((a, b) => a[1].last - b[1].last)[0];
        await old[1].ctx.close().catch(()=>{});
        ctxMap.delete(old[0]);
    } 

    if (ctxMap.has(reporterId)) {
        ctxMap.get(reporterId).last = now;
        return ctxMap.get(reporterId).ctx;
    }

    const ctx = await browser.createBrowserContext();
    ctxMap.set(reporterId, { ctx, last: now });
    return ctx;
}

async function ensureLoggedIn(page) {
    await page.goto(`http://uourstar:5000/auth/login`, { timeout: 3000, waitUntil: "domcontentloaded" });
    if (!(await page.$('form[action="/auth/login"] [name="username"]'))) return; // already logged in
    await page.type('form[action="/auth/login"] [name="username"]', USERNAME);
    await page.type('form[action="/auth/login"] [name="password"]', PASSWORD);
    await Promise.all([
        page.click('form[action="/auth/login"] button[type="submit"]'),
        page.waitForNavigation({ timeout: 3000, waitUntil: 'networkidle0' })
    ]);
    console.log(`[+] Logged in as ${USERNAME}`);
}

async function visit({ reporterId, username }) {
    const ctx = await getContext(reporterId);
    const page = await ctx.newPage();
    let result = true;

    try {
        await ensureLoggedIn(page);
        await page.goto(`http://uourstar:5000/user/profile/${username}`, { timeout: 3000, waitUntil: "domcontentloaded" });
        const button = await page.$('#copyProfileBtn');
        await Promise.all([
            button.click(),
            page.waitForNetworkIdle({ idleTime: 800, timeout: 3000 }).catch(()=>{})
        ]);
    } catch (error) {
        console.error(`Error while visiting url ===>  ${error}`);
        result = false;
    } finally {
        await page.close();
        return result;
    }
}

module.exports = { visit };