import { writeFileSync } from "node:fs";
import { closeBrowser, launchBrowser, navigateTo } from "../lib/browser.ts";
import { deduplicateEndpoints } from "../lib/dedup.ts";
import { attachInterceptor } from "../lib/interceptor.ts";
import { log, logInline, output, outputError } from "../lib/output.ts";
import type { ApiSpec } from "../lib/types.ts";

export interface SniffOptions {
	url: string;
	captureBodies: boolean;
	allowDomains: string[];
	blockDomains: string[];
	outputFile: string | null;
	headless: boolean;
}

export async function sniff(opts: SniffOptions): Promise<void> {
	if (!opts.url) {
		outputError("--url is required. Usage: cli-maker sniff --url <url>");
	}

	log(`Opening browser at ${opts.url}...`);
	const session = await launchBrowser({ headless: opts.headless });

	const interceptor = attachInterceptor(session.page, {
		captureBodies: opts.captureBodies,
		noiseFilter: {
			allowDomains: opts.allowDomains.length > 0 ? opts.allowDomains : undefined,
			blockDomains: opts.blockDomains.length > 0 ? opts.blockDomains : undefined,
		},
	});

	const startTime = Date.now();

	try {
		await navigateTo(session.page, opts.url);
	} catch (err) {
		await closeBrowser(session);
		outputError(`Failed to navigate to ${opts.url}: ${err}`);
	}

	log("Monitoring network traffic...");
	log("Browse the site and perform the actions you want to capture.");
	log("Press Enter when done (or close the browser).\n");

	// Wait for Enter keypress or browser close
	await new Promise<void>((resolve) => {
		let resolved = false;
		const done = () => {
			if (resolved) return;
			resolved = true;
			resolve();
		};

		// Enter key in terminal
		process.stdin.setRawMode?.(false);
		process.stdin.resume();
		process.stdin.once("data", done);

		// Browser closed by user
		session.page.on("close", done);
		session.context.on("close", done);
	});

	log("Stopping capture...");

	interceptor.stop();
	const exchanges = interceptor.getExchanges();
	const filteredCount = interceptor.getFilteredCount();
	const sessionDuration = Date.now() - startTime;

	await closeBrowser(session);

	// Deduplicate
	const endpoints = deduplicateEndpoints(exchanges);

	log(`\nCaptured ${exchanges.length} requests, ${endpoints.length} unique API endpoints:`);
	for (const ep of endpoints) {
		log(`  ${ep.method.padEnd(6)} ${ep.pathPattern}`);
	}

	const spec: ApiSpec = {
		version: "1",
		generatedAt: new Date().toISOString(),
		targetUrl: opts.url,
		targetDomain: new URL(opts.url).hostname,
		endpoints,
		auth: null,
		jsScanResults: null,
		metadata: {
			sessionDuration,
			totalRequestsCaptured: exchanges.length,
			totalRequestsFiltered: filteredCount,
			capturedBodies: opts.captureBodies,
		},
	};

	if (opts.outputFile) {
		writeFileSync(opts.outputFile, JSON.stringify(spec, null, 2));
		log(`\nSpec written to ${opts.outputFile}`);
	} else {
		output(spec);
	}
}
