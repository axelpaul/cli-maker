import type {
	ApiEndpoint,
	CapturedExchange,
	PathParameter,
	QueryParameter,
	RequestBodyField,
} from "./types.ts";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MONGO_ID_RE = /^[0-9a-f]{24}$/i;
const NUMERIC_RE = /^\d+$/;

function isLikelyId(segment: string): boolean {
	if (NUMERIC_RE.test(segment)) return true;
	if (UUID_RE.test(segment)) return true;
	if (MONGO_ID_RE.test(segment)) return true;
	return false;
}

function inferParamName(segments: string[], paramIndex: number): string {
	const prev = segments[paramIndex - 1];
	if (prev) {
		// "/users/123" → :userId, "/items/abc" → :itemId
		const singular = prev.endsWith("s") ? prev.slice(0, -1) : prev;
		return `${singular}Id`;
	}
	return `param${paramIndex}`;
}

interface ParsedUrl {
	origin: string;
	pathname: string;
	segments: string[];
	queryParams: Record<string, string>;
}

function parseUrl(url: string): ParsedUrl | null {
	try {
		const u = new URL(url);
		const segments = u.pathname.split("/").filter(Boolean);
		const queryParams: Record<string, string> = {};
		for (const [k, v] of u.searchParams) {
			queryParams[k] = v;
		}
		return { origin: u.origin, pathname: u.pathname, segments, queryParams };
	} catch {
		return null;
	}
}

// Standard browser headers to strip from endpoint signatures
const NOISE_HEADERS = new Set([
	"accept-encoding",
	"accept-language",
	"cache-control",
	"connection",
	"host",
	"origin",
	"pragma",
	"referer",
	"sec-ch-ua",
	"sec-ch-ua-mobile",
	"sec-ch-ua-platform",
	"sec-fetch-dest",
	"sec-fetch-mode",
	"sec-fetch-site",
	"sec-fetch-user",
	"upgrade-insecure-requests",
	"user-agent",
	"dnt",
	"cookie",
]);

function cleanHeaders(headers: Record<string, string>): Record<string, string> {
	const cleaned: Record<string, string> = {};
	for (const [k, v] of Object.entries(headers)) {
		if (!NOISE_HEADERS.has(k.toLowerCase())) {
			cleaned[k.toLowerCase()] = v;
		}
	}
	return cleaned;
}

function parseBody(body: string | null, contentType: string | null): Record<string, unknown> | null {
	if (!body) return null;
	if (contentType?.includes("application/json")) {
		try {
			const parsed = JSON.parse(body);
			if (typeof parsed === "object" && parsed !== null) return parsed as Record<string, unknown>;
		} catch {
			return null;
		}
	}
	if (contentType?.includes("application/x-www-form-urlencoded")) {
		const result: Record<string, unknown> = {};
		for (const [k, v] of new URLSearchParams(body)) {
			result[k] = v;
		}
		return result;
	}
	return null;
}

function flattenFields(
	obj: Record<string, unknown>,
	prefix = "",
): { path: string; value: unknown; type: string }[] {
	const results: { path: string; value: unknown; type: string }[] = [];
	for (const [key, value] of Object.entries(obj)) {
		const path = prefix ? `${prefix}.${key}` : key;
		if (Array.isArray(value)) {
			results.push({ path, value, type: "array" });
		} else if (typeof value === "object" && value !== null) {
			results.push(...flattenFields(value as Record<string, unknown>, path));
		} else {
			results.push({ path, value, type: typeof value === "number" ? "number" : "string" });
		}
	}
	return results;
}

interface GroupKey {
	method: string;
	origin: string;
	segmentCount: number;
}

function groupKeyStr(k: GroupKey): string {
	return `${k.method}|${k.origin}|${k.segmentCount}`;
}

export function deduplicateEndpoints(exchanges: CapturedExchange[]): ApiEndpoint[] {
	// Pass 1: group by (method, origin, segmentCount)
	const groups = new Map<string, { parsed: ParsedUrl; exchange: CapturedExchange }[]>();

	for (const ex of exchanges) {
		const parsed = parseUrl(ex.request.url);
		if (!parsed) continue;
		const key = groupKeyStr({
			method: ex.request.method,
			origin: parsed.origin,
			segmentCount: parsed.segments.length,
		});
		let group = groups.get(key);
		if (!group) {
			group = [];
			groups.set(key, group);
		}
		group.push({ parsed, exchange: ex });
	}

	// Pass 2: within each group, detect dynamic segments
	const endpoints: ApiEndpoint[] = [];
	const mergedGroups = new Map<string, { parsed: ParsedUrl; exchange: CapturedExchange }[]>();

	for (const group of groups.values()) {
		if (group.length === 0) continue;
		const segCount = group[0]!.parsed.segments.length;
		const dynamicPositions = new Set<number>();

		for (let i = 0; i < segCount; i++) {
			const values = new Set(group.map((g) => g.parsed.segments[i]));
			if (values.size > 1) {
				// Multiple distinct values at this position — check if they look like IDs
				const allIds = [...values].every((v) => v !== undefined && isLikelyId(v));
				if (allIds) {
					dynamicPositions.add(i);
				}
			}
		}

		// Build path pattern and re-key
		for (const item of group) {
			const patternSegments = item.parsed.segments.map((seg, i) => {
				if (dynamicPositions.has(i)) {
					return `:${inferParamName(item.parsed.segments, i)}`;
				}
				return seg;
			});
			const pathPattern = `/${patternSegments.join("/")}`;
			const mergeKey = `${item.exchange.request.method}|${item.parsed.origin}|${pathPattern}`;

			let merged = mergedGroups.get(mergeKey);
			if (!merged) {
				merged = [];
				mergedGroups.set(mergeKey, merged);
			}
			merged.push(item);
		}
	}

	// Pass 3: merge within each deduplicated group
	for (const group of mergedGroups.values()) {
		if (group.length === 0) continue;

		const first = group[0]!;
		const method = first.exchange.request.method;
		const segCount = first.parsed.segments.length;

		// Build path pattern
		const dynamicPositions = new Map<number, string[]>();
		for (let i = 0; i < segCount; i++) {
			const values = [...new Set(group.map((g) => g.parsed.segments[i]!))];
			if (values.length > 1 && values.every(isLikelyId)) {
				dynamicPositions.set(i, values);
			}
		}

		const patternSegments = first.parsed.segments.map((seg, i) => {
			if (dynamicPositions.has(i)) {
				return `:${inferParamName(first.parsed.segments, i)}`;
			}
			return seg;
		});
		const pathPattern = `/${patternSegments.join("/")}`;

		// Path params
		const pathParams: PathParameter[] = [];
		for (const [pos, examples] of dynamicPositions) {
			pathParams.push({
				position: pos,
				name: inferParamName(first.parsed.segments, pos),
				examples: examples.slice(0, 5),
			});
		}

		// Query params
		const allQueryKeys = new Set<string>();
		for (const item of group) {
			for (const key of Object.keys(item.parsed.queryParams)) {
				allQueryKeys.add(key);
			}
		}
		const queryParams: QueryParameter[] = [];
		for (const key of allQueryKeys) {
			const examples = [
				...new Set(
					group.map((g) => g.parsed.queryParams[key]).filter((v): v is string => v != null),
				),
			];
			queryParams.push({
				name: key,
				required: examples.length === group.length,
				examples: examples.slice(0, 5),
			});
		}

		// Request headers (intersection of cleaned headers)
		const headerSets = group.map((g) => cleanHeaders(g.exchange.request.headers));
		const commonHeaders: Record<string, string> = {};
		if (headerSets.length > 0) {
			const firstHeaders = headerSets[0]!;
			for (const [k, v] of Object.entries(firstHeaders)) {
				if (headerSets.every((h) => k in h)) {
					commonHeaders[k] = v;
				}
			}
		}

		// Request body fields
		const contentType = first.exchange.request.headers["content-type"] ?? null;
		const bodyFields = new Map<string, RequestBodyField>();
		for (const item of group) {
			const parsed = parseBody(item.exchange.request.postData, contentType);
			if (!parsed) continue;
			for (const field of flattenFields(parsed)) {
				const existing = bodyFields.get(field.path);
				if (existing) {
					if (!existing.types.includes(field.type)) existing.types.push(field.type);
					if (existing.examples.length < 3) existing.examples.push(field.value);
				} else {
					bodyFields.set(field.path, {
						path: field.path,
						types: [field.type],
						examples: [field.value],
					});
				}
			}
		}

		// Response info
		const responseStatuses = [
			...new Set(group.map((g) => g.exchange.response?.status).filter((s): s is number => s != null)),
		];
		const responseContentType = first.exchange.response?.mimeType ?? null;

		// Response body sample
		let responseBodySample: unknown = null;
		for (const item of group) {
			if (item.exchange.response?.body) {
				try {
					responseBodySample = JSON.parse(item.exchange.response.body);
				} catch {
					responseBodySample = item.exchange.response.body;
				}
				break;
			}
		}

		endpoints.push({
			method,
			pathPattern,
			pathParams,
			queryParams,
			requestHeaders: commonHeaders,
			requestContentType: contentType,
			requestBodyFields: [...bodyFields.values()],
			responseStatuses,
			responseContentType,
			responseBodySample,
			exampleCount: group.length,
			examples: group.slice(0, 3).map((g) => g.exchange),
		});
	}

	// Sort: method priority then path
	const methodOrder: Record<string, number> = { GET: 0, POST: 1, PUT: 2, PATCH: 3, DELETE: 4 };
	endpoints.sort((a, b) => {
		const ma = methodOrder[a.method] ?? 5;
		const mb = methodOrder[b.method] ?? 5;
		if (ma !== mb) return ma - mb;
		return a.pathPattern.localeCompare(b.pathPattern);
	});

	return endpoints;
}
