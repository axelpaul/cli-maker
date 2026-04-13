import { chromium, type Browser, type BrowserContext, type Page } from "playwright";

export interface BrowserSession {
	browser: Browser;
	context: BrowserContext;
	page: Page;
}

export async function launchBrowser(opts: {
	headless?: boolean;
}): Promise<BrowserSession> {
	const browser = await chromium.launch({
		headless: opts.headless ?? false,
	});
	const context = await browser.newContext({
		viewport: { width: 1280, height: 800 },
		userAgent:
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	});
	const page = await context.newPage();
	return { browser, context, page };
}

export async function navigateTo(page: Page, url: string): Promise<void> {
	await page.goto(url, { waitUntil: "domcontentloaded", timeout: 30_000 });
}

export async function closeBrowser(session: BrowserSession): Promise<void> {
	await session.browser.close();
}
