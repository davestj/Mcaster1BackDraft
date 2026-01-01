/**
 * Mcaster1BackDraft — Full Page Visual Test
 * Tests all 12 pages in desktop view, captures screenshots.
 */
const puppeteer = require('puppeteer');
const path = require('path');

const BASE = 'https://127.0.0.1:8862';
const SCREENSHOTS = path.join(__dirname, 'screenshots');
const CREDS = { username: 'dstjohn', password: 'DUMMY_MARIADB_PWD_SET_VIA_VAULT' };

const PAGES = [
    { url: '/login.php',       name: 'login',       auth: false },
    { url: '/dashboard.php',   name: 'dashboard',   auth: true },
    { url: '/threats.php',     name: 'threats',      auth: true },
    { url: '/agents.php',      name: 'agents',       auth: true },
    { url: '/analytics.php',   name: 'analytics',    auth: true },
    { url: '/rules.php',       name: 'rules',        auth: true },
    { url: '/sites.php',       name: 'sites',        auth: true },
    { url: '/pages.php',       name: 'pages',        auth: true },
    { url: '/logs.php',        name: 'logs',         auth: true },
    { url: '/performance.php', name: 'performance',  auth: true },
    { url: '/users.php',       name: 'users',        auth: true },
    { url: '/settings.php',    name: 'settings',     auth: true },
];

let passed = 0, failed = 0;

(async () => {
    console.log('╔══════════════════════════════════════════════════════╗');
    console.log('║  BACKDRAFT — ALL PAGES VISUAL TEST (Desktop 1920)  ║');
    console.log('╚══════════════════════════════════════════════════════╝\n');

    const browser = await puppeteer.launch({
        headless: 'new',
        args: ['--no-sandbox', '--disable-setuid-sandbox', '--ignore-certificate-errors'],
    });

    // Login first
    const loginPage = await browser.newPage();
    await loginPage.setViewport({ width: 1920, height: 1080 });
    await loginPage.goto(BASE + '/login.php', { waitUntil: 'networkidle2', timeout: 10000 });
    await loginPage.type('#username', CREDS.username);
    await loginPage.type('#password', CREDS.password);
    await Promise.all([
        loginPage.waitForNavigation({ waitUntil: 'networkidle2', timeout: 10000 }).catch(() => {}),
        loginPage.click('.btn-login'),
    ]);
    await new Promise(r => setTimeout(r, 1500));
    const cookies = await loginPage.cookies();
    await loginPage.close();
    console.log('  ✅  Logged in, got ' + cookies.length + ' cookies\n');

    for (const pg of PAGES) {
        const page = await browser.newPage();
        await page.setViewport({ width: 1920, height: 1080 });
        if (pg.auth) await page.setCookie(...cookies);

        try {
            await page.goto(BASE + pg.url, { waitUntil: 'networkidle2', timeout: 10000 });
            await new Promise(r => setTimeout(r, 1500));

            const title = await page.title();
            const status = title.includes('BackDraft') || title.includes('Login');

            // Check for PHP errors in page content
            const bodyText = await page.evaluate(() => document.body.innerText);
            const hasError = bodyText.includes('Fatal error') || bodyText.includes('Parse error') || bodyText.includes('Warning:');

            // Check no horizontal scroll
            const hasHScroll = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);

            await page.screenshot({ path: path.join(SCREENSHOTS, `all-${pg.name}.png`), fullPage: false });

            if (status && !hasError) {
                console.log(`  ✅  ${pg.name.padEnd(14)} — "${title.substring(0, 50)}" ${hasHScroll ? '⚠️ h-scroll' : '✓ no h-scroll'}`);
                passed++;
            } else {
                console.log(`  ❌  ${pg.name.padEnd(14)} — ${hasError ? 'PHP ERROR' : 'bad title: ' + title}`);
                failed++;
            }
        } catch (e) {
            console.log(`  ❌  ${pg.name.padEnd(14)} — ${e.message}`);
            failed++;
        }

        await page.close();
    }

    await browser.close();

    console.log(`\n╔══════════════════════════════════════════════════════╗`);
    console.log(`║  RESULTS: ${passed} passed, ${failed} failed${' '.repeat(Math.max(0, 30 - String(passed).length - String(failed).length))}║`);
    console.log(`╚══════════════════════════════════════════════════════╝`);

    process.exit(failed > 0 ? 1 : 0);
})();
