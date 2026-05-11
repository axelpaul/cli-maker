import { writeFileSync } from "node:fs";
import { profileAuth } from "../lib/auth-detect.ts";
import { closeBrowser, launchBrowser, navigateTo } from "../lib/browser.ts";
import { deduplicateEndpoints } from "../lib/dedup.ts";
import { attachInterceptor } from "../lib/interceptor.ts";
import { log, output, outputError } from "../lib/output.ts";
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
	log("Press Enter (or Ctrl+C) when done.\n");

	await new Promise<void>((resolve) => {
		let resolved = false;
		const done = () => {
			if (resolved) return;
			resolved = true;
			resolve();
		};

		process.stdin.setRawMode?.(false);
		process.stdin.resume();
		process.stdin.on("data", (chunk) => {
			const s = chunk.toString();
			if (s.includes("\n") || s.includes("\r")) done();
		});
		session.page.on("close", done);
		session.context.on("close", done);
		session.browser.on("disconnected", done);

		let sigintCount = 0;
		process.on("SIGINT", () => {
			sigintCount++;
			if (sigintCount === 1) done();
			else process.exit(130);
		});
	});

	log("Stopping capture...");

	interceptor.stop();
	const exchanges = interceptor.getExchanges();
	const filteredCount = interceptor.getFilteredCount();
	const sessionDuration = Date.now() - startTime;

	const endpoints = deduplicateEndpoints(exchanges);
	const auth = profileAuth(exchanges);

	const spec: ApiSpec = {
		version: "1",
		generatedAt: new Date().toISOString(),
		targetUrl: opts.url,
		targetDomain: new URL(opts.url).hostname,
		endpoints,
		auth: auth.mechanism === "unknown" ? null : auth,
		jsScanResults: null,
		metadata: {
			sessionDuration,
			totalRequestsCaptured: exchanges.length,
			totalRequestsFiltered: filteredCount,
			capturedBodies: opts.captureBodies,
		},
	};

	// Write spec BEFORE closing browser, in case close hangs.
	if (opts.outputFile) {
		writeFileSync(opts.outputFile, JSON.stringify(spec, null, 2));
		log(`Spec written to ${opts.outputFile}`);
	} else {
		output(spec);
	}

	log(`\nCaptured ${exchanges.length} requests, ${endpoints.length} unique endpoints:`);
	for (const ep of endpoints) {
		log(`  ${ep.method.padEnd(6)} ${ep.pathPattern}`);
	}
	log(`Auth: ${auth.mechanism} (${auth.confidence}% confidence)`);

	await Promise.race([
		closeBrowser(session).catch(() => {}),
		new Promise<void>((r) => setTimeout(r, 5000)),
	]);
}
