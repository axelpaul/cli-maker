import type { Page, Request } from "playwright";
import { isNoise, type NoiseFilterOptions } from "./noise-filter.ts";
import type { CapturedExchange, CapturedRequest, CapturedResponse } from "./types.ts";

const MAX_BODY_SIZE = 1_048_576; // 1MB
const BODY_READ_TIMEOUT_MS = 5_000;

async function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
	let t: ReturnType<typeof setTimeout> | undefined;
	try {
		return await Promise.race([
			p,
			new Promise<T>((_, reject) => {
				t = setTimeout(() => reject(new Error("timeout")), ms);
			}),
		]);
	} finally {
		if (t) clearTimeout(t);
	}
}

export interface InterceptorOptions {
	captureBodies?: boolean;
	noiseFilter: NoiseFilterOptions;
}

export interface InterceptorHandle {
	attachToPage(page: Page): void;
	getExchanges(): CapturedExchange[];
	getFilteredCount(): number;
	stop(): void;
}

export function attachInterceptor(initialPage: Page, opts: InterceptorOptions): InterceptorHandle {
	const exchanges: CapturedExchange[] = [];
	const pending = new Map<Request, { captured: CapturedRequest; startTime: number }>();
	const attachedPages = new Set<Page>();
	let filteredCount = 0;
	let stopped = false;

	function onRequest(request: Request): void {
		if (stopped) return;

		const url = request.url();
		const resourceType = request.resourceType();

		if (isNoise(url, resourceType, opts.noiseFilter)) {
			filteredCount++;
			return;
		}

		const headers: Record<string, string> = {};
		for (const [k, v] of Object.entries(request.headers())) {
			headers[k] = v;
		}

		const captured: CapturedRequest = {
			url,
			method: request.method(),
			headers,
			postData: request.postData(),
			resourceType,
			timestamp: Date.now(),
		};

		pending.set(request, { captured, startTime: Date.now() });
	}

	async function onRequestFinished(request: Request): Promise<void> {
		if (stopped) return;

		const entry = pending.get(request);
		if (!entry) return;
		pending.delete(request);

		try {
			const response = await request.response();
			if (!response) {
				exchanges.push({
					request: entry.captured,
					response: null,
					duration: Date.now() - entry.startTime,
				});
				return;
			}

			const headers: Record<string, string> = {};
			try {
				for (const [k, v] of Object.entries(await response.allHeaders())) {
					headers[k] = v;
				}
			} catch {
				// Headers no longer available; continue with empty set
			}

			let body: string | null = null;
			let bodySize = 0;

			if (opts.captureBodies) {
				try {
					const buffer = await withTimeout(response.body(), BODY_READ_TIMEOUT_MS);
					bodySize = buffer.length;
					if (bodySize <= MAX_BODY_SIZE) {
						body = buffer.toString("utf-8");
					}
				} catch {
					// Body not available, timed out, or page navigated away mid-read
				}
			}

			const captured: CapturedResponse = {
				status: response.status(),
				statusText: response.statusText(),
				headers,
				body,
				bodySize,
				mimeType: headers["content-type"] ?? "",
			};

			exchanges.push({
				request: entry.captured,
				response: captured,
				duration: Date.now() - entry.startTime,
			});
		} catch {
			// Request invalidated (page navigated, context closed). Drop silently.
		}
	}

	function onRequestFailed(request: Request): void {
		if (stopped) return;
		const entry = pending.get(request);
		if (!entry) return;
		pending.delete(request);
		exchanges.push({
			request: entry.captured,
			response: null,
			duration: Date.now() - entry.startTime,
		});
	}

	function attachToPage(page: Page): void {
		if (stopped || attachedPages.has(page)) return;
		attachedPages.add(page);
		page.on("request", onRequest);
		page.on("requestfinished", (r) => void onRequestFinished(r));
		page.on("requestfailed", onRequestFailed);
	}

	attachToPage(initialPage);

	return {
		attachToPage,
		getExchanges() {
			return exchanges;
		},
		getFilteredCount() {
			return filteredCount;
		},
		stop() {
			stopped = true;
			for (const page of attachedPages) {
				page.removeListener("request", onRequest);
			}
		},
	};
}
