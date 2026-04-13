import type { Page, Request, Response } from "playwright";
import { isNoise, type NoiseFilterOptions } from "./noise-filter.ts";
import type { CapturedExchange, CapturedRequest, CapturedResponse } from "./types.ts";

const MAX_BODY_SIZE = 1_048_576; // 1MB

export interface InterceptorOptions {
	captureBodies?: boolean;
	noiseFilter: NoiseFilterOptions;
}

export interface InterceptorHandle {
	getExchanges(): CapturedExchange[];
	getFilteredCount(): number;
	stop(): void;
}

export function attachInterceptor(page: Page, opts: InterceptorOptions): InterceptorHandle {
	const exchanges: CapturedExchange[] = [];
	const pending = new Map<Request, { captured: CapturedRequest; startTime: number }>();
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

	async function onResponse(response: Response): Promise<void> {
		if (stopped) return;

		const request = response.request();
		const entry = pending.get(request);
		if (!entry) return;
		pending.delete(request);

		const headers: Record<string, string> = {};
		for (const [k, v] of Object.entries(await response.allHeaders())) {
			headers[k] = v;
		}

		let body: string | null = null;
		let bodySize = 0;

		if (opts.captureBodies) {
			try {
				const buffer = await response.body();
				bodySize = buffer.length;
				if (bodySize <= MAX_BODY_SIZE) {
					body = buffer.toString("utf-8");
				}
			} catch {
				// Response body unavailable (e.g. redirects, streaming)
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
	}

	page.on("request", onRequest);
	page.on("response", (r) => void onResponse(r));

	return {
		getExchanges() {
			return exchanges;
		},
		getFilteredCount() {
			return filteredCount;
		},
		stop() {
			stopped = true;
			page.removeListener("request", onRequest);
		},
	};
}
