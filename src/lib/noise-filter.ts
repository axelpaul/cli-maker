const BLOCKED_DOMAINS = new Set([
	// Analytics
	"google-analytics.com",
	"analytics.google.com",
	"www.googletagmanager.com",
	"googletagmanager.com",
	"stats.g.doubleclick.net",
	"hotjar.com",
	"static.hotjar.com",
	"script.hotjar.com",
	"mixpanel.com",
	"api.mixpanel.com",
	"cdn.mxpnl.com",
	"heapanalytics.com",
	"cdn.heapanalytics.com",
	"segment.io",
	"api.segment.io",
	"cdn.segment.com",
	"amplitude.com",
	"api.amplitude.com",
	"plausible.io",
	"clarity.ms",
	// Advertising
	"doubleclick.net",
	"googlesyndication.com",
	"googleadservices.com",
	"adservice.google.com",
	"pagead2.googlesyndication.com",
	"facebook.net",
	"connect.facebook.net",
	// Error tracking
	"sentry.io",
	"browser.sentry-cdn.com",
	"bugsnag.com",
	"logrocket.com",
	// CDNs (static assets only)
	"cdnjs.cloudflare.com",
	"cdn.jsdelivr.net",
	"unpkg.com",
	"ajax.googleapis.com",
	// Fonts
	"fonts.googleapis.com",
	"fonts.gstatic.com",
	"use.typekit.net",
	"use.fontawesome.com",
	// Social widgets
	"platform.twitter.com",
	"syndication.twitter.com",
	"platform.linkedin.com",
	// Chat widgets
	"widget.intercom.io",
	"js.intercomcdn.com",
	"embed.tawk.to",
	"crisp.chat",
	// Consent banners
	"cookiebot.com",
	"consentmanager.net",
	"cdn.cookielaw.org",
	// Book metadata / external lookups
	"books.google.com",
	"syndetics.com",
]);

const BLOCKED_RESOURCE_TYPES = new Set([
	"document",
	"image",
	"media",
	"font",
	"stylesheet",
	"script",
	"manifest",
	"other",
]);

const BLOCKED_PATH_PATTERNS: RegExp[] = [
	// Static file extensions
	/\.(png|jpg|jpeg|gif|svg|ico|webp|avif|woff2?|ttf|eot|css|map|js|mjs|ts|jsx|tsx)(\?|$)/i,
	/\/favicon/i,
	// Framework static asset paths
	/\/_next\/(static|image)\//,
	/\/static\/(js|css|media|chunks)\//,
	/\/assets\/(js|css)\//,
	/\/dist\//,
	/\/lib\/bower_components\//,
	// SPA/framework discovery paths (Primo/Alma, Angular, etc.)
	/\/discovery\/(lib|custom)\//,
	/\/discovery\/login/,
	// Dev server noise
	/\/webpack-hmr/,
	/\/__webpack_dev_server/,
	/\/sockjs-node/,
	/\/hot-update\./,
	// Service workers and manifests
	/\/service-worker\.js/,
	/\/sw\.js$/,
	/\/manifest\.json$/,
	/\/robots\.txt$/,
	/\/sitemap\.xml$/,
	// HTML pages (we want API calls, not page navigations)
	/\.html(\?|$)/i,
	// Proxy rewrites to external services
	/\/exl_rewrite\//,
];

export interface NoiseFilterOptions {
	allowDomains?: string[];
	blockDomains?: string[];
	includeStaticAssets?: boolean;
}

function domainMatches(hostname: string, domain: string): boolean {
	return hostname === domain || hostname.endsWith(`.${domain}`);
}

export function isNoise(
	url: string,
	resourceType: string,
	opts: NoiseFilterOptions,
): boolean {
	// Resource type filter
	if (!opts.includeStaticAssets && BLOCKED_RESOURCE_TYPES.has(resourceType)) {
		return true;
	}

	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		return true;
	}

	const hostname = parsed.hostname;

	// Allowlist mode: anything not on allowlist is noise
	if (opts.allowDomains?.length) {
		if (!opts.allowDomains.some((d) => domainMatches(hostname, d))) {
			return true;
		}
	}

	// Domain blocklist
	for (const d of BLOCKED_DOMAINS) {
		if (domainMatches(hostname, d)) return true;
	}
	if (opts.blockDomains) {
		for (const d of opts.blockDomains) {
			if (domainMatches(hostname, d)) return true;
		}
	}

	// Path pattern blocklist
	for (const pattern of BLOCKED_PATH_PATTERNS) {
		if (pattern.test(parsed.pathname + parsed.search)) return true;
	}

	return false;
}
