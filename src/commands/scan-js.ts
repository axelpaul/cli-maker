import { writeFileSync } from "node:fs";
import { closeBrowser, launchBrowser, navigateTo } from "../lib/browser.ts";
import { scanJsBundles } from "../lib/js-scanner.ts";
import { log, output, outputError } from "../lib/output.ts";

export interface ScanJsOptions {
	url: string;
	outputFile: string | null;
}

export async function scanJs(opts: ScanJsOptions): Promise<void> {
	if (!opts.url) {
		outputError("--url is required. Usage: cli-maker scan-js --url <url>");
	}

	log(`Scanning JS bundles at ${opts.url}...`);
	const session = await launchBrowser({ headless: true });

	try {
		await navigateTo(session.page, opts.url);
	} catch (err) {
		await closeBrowser(session);
		outputError(`Failed to navigate to ${opts.url}: ${err}`);
	}

	// Wait for page to fully load (scripts might load lazily)
	await session.page.waitForLoadState("networkidle").catch(() => {});

	const results = await scanJsBundles(session.page, opts.url);
	await closeBrowser(session);

	log(`\nScanned ${results.bundlesScanned} bundles, found ${results.discoveredPaths.length} API paths:`);
	for (const path of results.discoveredPaths) {
		log(`  [${path.confidence}%] ${path.pattern}`);
	}

	if (results.baseUrls.length > 0) {
		log(`\nBase URLs found:`);
		for (const url of results.baseUrls) {
			log(`  ${url}`);
		}
	}

	if (opts.outputFile) {
		writeFileSync(opts.outputFile, JSON.stringify(results, null, 2));
		log(`\nResults written to ${opts.outputFile}`);
	} else {
		output(results);
	}
}
