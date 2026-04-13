import type { Page } from "playwright";
import type { DiscoveredPath, JsScanResult } from "./types.ts";

// Patterns that look like API paths
const API_PATH_PATTERNS: RegExp[] = [
	// Explicit API paths
	/["'`](\/api\/v?\d*\/[a-zA-Z0-9/_-]+)["'`]/g,
	/["'`](\/rest\/[a-zA-Z0-9/_-]+)["'`]/g,
	/["'`](\/graphql[a-zA-Z0-9/_-]*)["'`]/g,
	/["'`](\/v[1-9]\d*\/[a-zA-Z0-9/_-]+)["'`]/g,
	// Primo/Alma specific (for leitir.is and similar)
	/["'`](\/primaws\/[a-zA-Z0-9/_-]+)["'`]/g,
	// Generic paths with common API prefixes
	/["'`](\/(?:auth|login|oauth|token|users?|account|search|catalog)\/[a-zA-Z0-9/_-]*)["'`]/g,
];

// Full URL patterns
const URL_PATTERN = /["'`](https?:\/\/[a-zA-Z0-9.-]+(?::\d+)?\/[a-zA-Z0-9/._?&=-]+)["'`]/g;

// Config object patterns (assignments to API-related variables)
const CONFIG_PATTERNS: RegExp[] = [
	/(?:apiUrl|baseUrl|API_BASE|API_URL|apiBase|apiEndpoint|BASE_URL|SERVER_URL)\s*[:=]\s*["'`]([^"'`]+)["'`]/gi,
];

function extractContext(source: string, matchIndex: number, length: number): string {
	const start = Math.max(0, matchIndex - 40);
	const end = Math.min(source.length, matchIndex + length + 40);
	return source.slice(start, end).replace(/\n/g, " ").trim();
}

function scoreConfidence(path: string, context: string): number {
	let score = 50;
	// Higher confidence for explicit API paths
	if (/^\/api\//.test(path)) score += 20;
	if (/^\/rest\//.test(path)) score += 20;
	if (/^\/v\d+\//.test(path)) score += 15;
	if (/^\/primaws\//.test(path)) score += 25;
	// Lower confidence for generic-looking paths
	if (path.split("/").length <= 2) score -= 10;
	// Higher if near fetch/axios/request calls
	if (/fetch|axios|request|http|ajax/i.test(context)) score += 15;
	return Math.min(100, Math.max(0, score));
}

export async function scanJsBundles(page: Page, targetUrl: string): Promise<JsScanResult> {
	const discovered = new Map<string, DiscoveredPath>();
	const baseUrls = new Set<string>();
	let bundlesScanned = 0;

	// Get all script URLs from the page
	const scriptUrls = await page.evaluate(() => {
		const scripts = document.querySelectorAll("script[src]");
		return Array.from(scripts).map((s) => (s as HTMLScriptElement).src);
	});

	// Also get inline scripts
	const inlineScripts = await page.evaluate(() => {
		const scripts = document.querySelectorAll("script:not([src])");
		return Array.from(scripts)
			.map((s) => s.textContent ?? "")
			.filter((t) => t.length > 100);
	});

	// Fetch and scan each external script
	for (const scriptUrl of scriptUrls) {
		try {
			const response = await page.evaluate(async (url) => {
				const res = await fetch(url);
				return res.text();
			}, scriptUrl);

			if (response) {
				scanSource(response, scriptUrl, discovered, baseUrls);
				bundlesScanned++;
			}
		} catch {
			// Script fetch failed, skip
		}
	}

	// Scan inline scripts
	for (const script of inlineScripts) {
		scanSource(script, `${targetUrl} (inline)`, discovered, baseUrls);
		bundlesScanned++;
	}

	return {
		url: targetUrl,
		bundlesScanned,
		discoveredPaths: [...discovered.values()].sort((a, b) => b.confidence - a.confidence),
		baseUrls: [...baseUrls],
	};
}

function scanSource(
	source: string,
	sourceUrl: string,
	discovered: Map<string, DiscoveredPath>,
	baseUrls: Set<string>,
): void {
	// Scan for API paths
	for (const pattern of API_PATH_PATTERNS) {
		// Reset lastIndex for global regex
		pattern.lastIndex = 0;
		let match: RegExpExecArray | null;
		while ((match = pattern.exec(source)) !== null) {
			const path = match[1]!;
			if (!discovered.has(path)) {
				discovered.set(path, {
					pattern: path,
					source: sourceUrl,
					context: extractContext(source, match.index, match[0].length),
					confidence: scoreConfidence(path, extractContext(source, match.index, match[0].length)),
				});
			}
		}
	}

	// Scan for full URLs
	URL_PATTERN.lastIndex = 0;
	let urlMatch: RegExpExecArray | null;
	while ((urlMatch = URL_PATTERN.exec(source)) !== null) {
		const fullUrl = urlMatch[1]!;
		try {
			const parsed = new URL(fullUrl);
			// Only keep URLs that look like API endpoints (not static assets)
			if (
				!parsed.pathname.match(/\.(js|css|png|jpg|svg|woff|ico|html)$/) &&
				parsed.pathname.length > 1
			) {
				baseUrls.add(`${parsed.protocol}//${parsed.host}`);
				const path = parsed.pathname;
				if (!discovered.has(path)) {
					discovered.set(path, {
						pattern: path,
						source: sourceUrl,
						context: extractContext(source, urlMatch.index, urlMatch[0].length),
						confidence: scoreConfidence(
							path,
							extractContext(source, urlMatch.index, urlMatch[0].length),
						),
					});
				}
			}
		} catch {
			// not a valid URL
		}
	}

	// Scan for config assignments
	for (const pattern of CONFIG_PATTERNS) {
		pattern.lastIndex = 0;
		let configMatch: RegExpExecArray | null;
		while ((configMatch = pattern.exec(source)) !== null) {
			const value = configMatch[1]!;
			if (value.startsWith("http")) {
				baseUrls.add(value);
			}
		}
	}
}
