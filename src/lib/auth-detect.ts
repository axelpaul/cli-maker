import type { AuthDetails, AuthProfile, CapturedExchange } from "./types.ts";

const JWT_RE = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/;

const CREDENTIAL_FIELDS = new Set([
	"password",
	"passwd",
	"pass",
	"pwd",
	"secret",
	"credential",
	"credentials",
]);

function hasCredentialField(body: string | null, contentType: string | undefined): string[] {
	if (!body) return [];
	const fields: string[] = [];

	if (contentType?.includes("application/json")) {
		try {
			const parsed = JSON.parse(body) as Record<string, unknown>;
			for (const key of Object.keys(parsed)) {
				if (CREDENTIAL_FIELDS.has(key.toLowerCase())) fields.push(key);
			}
		} catch {
			// not valid json
		}
	} else if (contentType?.includes("application/x-www-form-urlencoded")) {
		for (const [key] of new URLSearchParams(body)) {
			if (CREDENTIAL_FIELDS.has(key.toLowerCase())) fields.push(key);
		}
	}
	return fields;
}

function getFormFields(body: string | null, contentType: string | undefined): string[] {
	if (!body) return [];
	if (contentType?.includes("application/json")) {
		try {
			return Object.keys(JSON.parse(body) as Record<string, unknown>);
		} catch {
			return [];
		}
	}
	if (contentType?.includes("application/x-www-form-urlencoded")) {
		return [...new URLSearchParams(body).keys()];
	}
	return [];
}

// ─── Detector: AWS Cognito ──────────────────────────────────────

function detectCognito(exchanges: CapturedExchange[]): AuthProfile | null {
	for (const ex of exchanges) {
		const url = ex.request.url;
		const match = url.match(/cognito-idp\.([a-z0-9-]+)\.amazonaws\.com/);
		if (!match) continue;

		const region = match[1]!;
		const target = ex.request.headers["x-amz-target"] ?? "";
		let authFlow = "unknown";
		let clientId: string | null = null;
		let userPoolId: string | null = null;

		if (ex.request.postData) {
			try {
				const body = JSON.parse(ex.request.postData) as Record<string, unknown>;
				if (typeof body.AuthFlow === "string") authFlow = body.AuthFlow;
				if (typeof body.ClientId === "string") clientId = body.ClientId;
				if (typeof body.UserPoolId === "string") userPoolId = body.UserPoolId;
			} catch {
				// not json
			}
		}

		const isInitiateAuth = target.includes("InitiateAuth");
		const hasAuthResult = ex.response?.body?.includes("AuthenticationResult") ?? false;

		return {
			mechanism: "aws-cognito",
			confidence: isInitiateAuth && hasAuthResult ? 95 : 80,
			details: {
				mechanism: "aws-cognito",
				loginUrl: url,
				tokenEndpoint: null,
				cognitoEndpoint: url,
				userPoolId,
				clientId,
				region,
				authFlow,
			},
		};
	}
	return null;
}

// ─── Detector: Audkenni / island.is ─────────────────────────────

function detectAudkenni(exchanges: CapturedExchange[]): AuthProfile | null {
	const audkenniDomains = ["audkenni.is", "island.is", "innskraning.island.is"];
	const redirectChain: string[] = [];
	let idpUrl: string | null = null;
	let callbackUrl: string | null = null;

	for (const ex of exchanges) {
		const url = ex.request.url;
		try {
			const parsed = new URL(url);
			const isIdp = audkenniDomains.some(
				(d) => parsed.hostname === d || parsed.hostname.endsWith(`.${d}`),
			);
			if (isIdp) {
				idpUrl = url;
				redirectChain.push(url);
			}
		} catch {
			continue;
		}

		// Check for redirect back from IdP
		const location = ex.response?.headers["location"];
		if (location && idpUrl) {
			try {
				const locParsed = new URL(location);
				const isCallback = !audkenniDomains.some(
					(d) => locParsed.hostname === d || locParsed.hostname.endsWith(`.${d}`),
				);
				if (isCallback) {
					callbackUrl = location;
					redirectChain.push(location);
				}
			} catch {
				// relative URL
			}
		}
	}

	if (!idpUrl) return null;

	return {
		mechanism: "audkenni-island-is",
		confidence: callbackUrl ? 90 : 60,
		details: {
			mechanism: "audkenni-island-is",
			loginUrl: idpUrl,
			tokenEndpoint: null,
			idpUrl,
			callbackUrl,
			redirectChain,
		},
	};
}

// ─── Detector: SAML ─────────────────────────────────────────────

function detectSaml(exchanges: CapturedExchange[]): AuthProfile | null {
	let idpUrl: string | null = null;
	let spUrl: string | null = null;
	let acsUrl: string | null = null;
	let hasSamlResponse = false;

	for (const ex of exchanges) {
		const url = ex.request.url;
		const postData = ex.request.postData ?? "";

		// Check URL params and post data for SAML artifacts
		if (url.includes("SAMLRequest") || postData.includes("SAMLRequest")) {
			idpUrl = url;
		}
		if (url.includes("SAMLResponse") || postData.includes("SAMLResponse")) {
			spUrl = url;
			hasSamlResponse = true;
			// The URL receiving the SAMLResponse is the ACS
			acsUrl = url;
		}
	}

	if (!idpUrl && !hasSamlResponse) return null;

	return {
		mechanism: "saml",
		confidence: hasSamlResponse ? 95 : 70,
		details: {
			mechanism: "saml",
			loginUrl: idpUrl,
			tokenEndpoint: null,
			idpUrl: idpUrl ?? "unknown",
			spUrl: spUrl ?? "unknown",
			assertionConsumerServiceUrl: acsUrl,
		},
	};
}

// ─── Detector: OAuth2/OIDC ──────────────────────────────────────

// Known OIDC provider URL patterns
const OIDC_PROVIDER_PATTERNS = [
	// Keycloak
	/\/auth\/realms\/[^/]+\/protocol\/openid-connect/,
	/\/realms\/[^/]+\/protocol\/openid-connect/,
	// Microsoft Entra / Azure AD
	/login\.microsoftonline\.com/,
	/login\.microsoft\.com/,
	/sts\.windows\.net/,
	// Auth0
	/\.auth0\.com\/authorize/,
	// Okta
	/\.okta\.com\/oauth2/,
	/\.oktapreview\.com\/oauth2/,
	// Google
	/accounts\.google\.com\/o\/oauth2/,
	// Generic
	/\/\.well-known\/openid-configuration/,
];

function extractOAuth2Params(urlStr: string): {
	authorizeEndpoint: string;
	clientId: string | null;
	responseType: string | null;
	redirectUri: string | null;
	scopes: string[];
} | null {
	try {
		const parsed = new URL(urlStr);
		const params = parsed.searchParams;
		if (params.has("client_id") && params.has("response_type")) {
			return {
				authorizeEndpoint: `${parsed.origin}${parsed.pathname}`,
				clientId: params.get("client_id"),
				responseType: params.get("response_type"),
				redirectUri: params.get("redirect_uri"),
				scopes: params.get("scope")?.split(/[+ ]/) ?? [],
			};
		}
	} catch {
		// invalid URL
	}
	return null;
}

function detectOAuth2(exchanges: CapturedExchange[]): AuthProfile | null {
	let authorizeEndpoint: string | null = null;
	let tokenEndpoint: string | null = null;
	let clientId: string | null = null;
	let responseType: string | null = null;
	let redirectUri: string | null = null;
	const scopes: string[] = [];
	const providerHints: string[] = [];

	for (const ex of exchanges) {
		const url = ex.request.url;

		// Check request URLs for OAuth2 params
		const fromUrl = extractOAuth2Params(url);
		if (fromUrl) {
			authorizeEndpoint = fromUrl.authorizeEndpoint;
			clientId = fromUrl.clientId;
			responseType = fromUrl.responseType;
			redirectUri = fromUrl.redirectUri;
			scopes.push(...fromUrl.scopes);
		}

		// Check redirect Location headers for OAuth2 params (critical for SSO flows)
		const location = ex.response?.headers["location"];
		if (location) {
			const fromLocation = extractOAuth2Params(location);
			if (fromLocation) {
				authorizeEndpoint = fromLocation.authorizeEndpoint;
				clientId = fromLocation.clientId;
				responseType = fromLocation.responseType;
				redirectUri = fromLocation.redirectUri;
				scopes.push(...fromLocation.scopes);
			}
		}

		// Check for known OIDC provider patterns in URLs and redirects
		const urlsToCheck = [url, location].filter((u): u is string => u != null);
		for (const u of urlsToCheck) {
			for (const pattern of OIDC_PROVIDER_PATTERNS) {
				if (pattern.test(u)) {
					providerHints.push(u);
				}
			}
		}

		// Detect token endpoint
		try {
			const postData = ex.request.postData ?? "";
			if (postData.includes("grant_type=") && ex.request.method === "POST") {
				const parsed = new URL(url);
				tokenEndpoint = `${parsed.origin}${parsed.pathname}`;
			}
		} catch {
			// invalid URL
		}
	}

	if (!authorizeEndpoint && !tokenEndpoint && providerHints.length === 0) return null;

	let confidence = 40;
	if (authorizeEndpoint && tokenEndpoint) confidence = 95;
	else if (authorizeEndpoint && clientId) confidence = 85;
	else if (providerHints.length > 0 && (authorizeEndpoint || clientId)) confidence = 80;
	else if (providerHints.length >= 2) confidence = 75;
	else if (providerHints.length === 1) confidence = 60;

	return {
		mechanism: "oauth2-oidc",
		confidence,
		details: {
			mechanism: "oauth2-oidc",
			loginUrl: authorizeEndpoint ?? providerHints[0] ?? null,
			tokenEndpoint: tokenEndpoint ?? "unknown",
			authorizeEndpoint: authorizeEndpoint ?? "unknown",
			clientId,
			responseType: responseType ?? "unknown",
			scopes: [...new Set(scopes)],
			redirectUri,
		},
	};
}

// ─── Detector: JWT Form Login ───────────────────────────────────

function detectJwtFormLogin(exchanges: CapturedExchange[]): AuthProfile | null {
	// Look for a POST with credential fields
	for (const ex of exchanges) {
		if (ex.request.method !== "POST") continue;

		const contentType = ex.request.headers["content-type"];
		const credFields = hasCredentialField(ex.request.postData, contentType);
		if (credFields.length === 0) continue;

		// Check if response body contains a JWT
		let tokenPath: string | null = null;
		if (ex.response?.body) {
			// Direct JWT in body
			if (JWT_RE.test(ex.response.body)) {
				// Try to find the JSON key containing the JWT
				try {
					const parsed = JSON.parse(ex.response.body) as Record<string, unknown>;
					for (const [key, value] of Object.entries(parsed)) {
						if (typeof value === "string" && JWT_RE.test(value)) {
							tokenPath = key;
							break;
						}
					}
				} catch {
					tokenPath = "body";
				}
			}
		}

		// Check if subsequent requests gained a Bearer header
		let bearerAppeared = false;
		const loginTime = ex.request.timestamp;
		for (const later of exchanges) {
			if (later.request.timestamp <= loginTime) continue;
			const auth = later.request.headers["authorization"] ?? "";
			if (auth.startsWith("Bearer ")) {
				bearerAppeared = true;
				break;
			}
		}

		if (!tokenPath && !bearerAppeared) continue;

		const formFields = getFormFields(ex.request.postData, contentType);

		return {
			mechanism: "jwt-form-login",
			confidence: tokenPath ? 90 : bearerAppeared ? 70 : 50,
			details: {
				mechanism: "jwt-form-login",
				loginUrl: ex.request.url,
				tokenEndpoint: null,
				formFields,
				contentType: contentType ?? "unknown",
				tokenPath: tokenPath ?? "unknown",
				tokenUsage: bearerAppeared ? "bearer-header" : "unknown",
			},
		};
	}
	return null;
}

// ─── Detector: Session Cookie ───────────────────────────────────

function detectSessionCookie(exchanges: CapturedExchange[]): AuthProfile | null {
	for (const ex of exchanges) {
		if (ex.request.method !== "POST") continue;

		const contentType = ex.request.headers["content-type"];
		const credFields = hasCredentialField(ex.request.postData, contentType);
		if (credFields.length === 0) continue;

		// Check for Set-Cookie in response
		const setCookie = ex.response?.headers["set-cookie"];
		if (!setCookie) continue;

		// Make sure no Bearer token appears later (that would be JWT, not session)
		const loginTime = ex.request.timestamp;
		let hasBearerLater = false;
		for (const later of exchanges) {
			if (later.request.timestamp <= loginTime) continue;
			const auth = later.request.headers["authorization"] ?? "";
			if (auth.startsWith("Bearer ")) {
				hasBearerLater = true;
				break;
			}
		}
		if (hasBearerLater) continue;

		// Extract cookie name
		const cookieMatch = setCookie.match(/^([^=]+)=/);
		const cookieName = cookieMatch?.[1] ?? "unknown";
		let cookieDomain = "";
		try {
			cookieDomain = new URL(ex.request.url).hostname;
		} catch {
			// ignore
		}

		// Check if cookie is reused in subsequent requests
		let cookieReused = false;
		for (const later of exchanges) {
			if (later.request.timestamp <= loginTime) continue;
			const cookie = later.request.headers["cookie"] ?? "";
			if (cookie.includes(cookieName)) {
				cookieReused = true;
				break;
			}
		}

		return {
			mechanism: "session-cookie",
			confidence: cookieReused ? 80 : 50,
			details: {
				mechanism: "session-cookie",
				loginUrl: ex.request.url,
				tokenEndpoint: null,
				cookieName,
				cookieDomain,
				loginMethod: `${ex.request.method} ${contentType ?? ""}`,
				formFields: getFormFields(ex.request.postData, contentType),
			},
		};
	}
	return null;
}

// ─── Detector: Basic Auth ───────────────────────────────────────

function detectBasicAuth(exchanges: CapturedExchange[]): AuthProfile | null {
	const protectedPaths: string[] = [];
	let realm = "";

	for (const ex of exchanges) {
		// Check for WWW-Authenticate: Basic
		const wwwAuth = ex.response?.headers["www-authenticate"] ?? "";
		if (wwwAuth.toLowerCase().startsWith("basic")) {
			const realmMatch = wwwAuth.match(/realm="([^"]+)"/i);
			if (realmMatch) realm = realmMatch[1]!;
			try {
				protectedPaths.push(new URL(ex.request.url).pathname);
			} catch {
				// ignore
			}
		}

		// Check for Authorization: Basic in requests
		const auth = ex.request.headers["authorization"] ?? "";
		if (auth.startsWith("Basic ")) {
			return {
				mechanism: "basic-auth",
				confidence: 95,
				details: {
					mechanism: "basic-auth",
					loginUrl: null,
					tokenEndpoint: null,
					realm,
					protectedPaths,
				},
			};
		}
	}

	if (protectedPaths.length > 0) {
		return {
			mechanism: "basic-auth",
			confidence: 85,
			details: {
				mechanism: "basic-auth",
				loginUrl: null,
				tokenEndpoint: null,
				realm,
				protectedPaths,
			},
		};
	}

	return null;
}

// ─── Detector: API Key ──────────────────────────────────────────

function detectApiKey(exchanges: CapturedExchange[]): AuthProfile | null {
	const API_KEY_HEADERS = [
		"x-api-key",
		"api-key",
		"apikey",
		"x-auth-token",
		"x-access-token",
	];

	// Check for consistent API key header across multiple requests
	const headerCounts = new Map<string, Map<string, number>>();
	for (const ex of exchanges) {
		for (const headerName of API_KEY_HEADERS) {
			const value = ex.request.headers[headerName];
			if (value) {
				let valueCounts = headerCounts.get(headerName);
				if (!valueCounts) {
					valueCounts = new Map();
					headerCounts.set(headerName, valueCounts);
				}
				valueCounts.set(value, (valueCounts.get(value) ?? 0) + 1);
			}
		}
	}

	for (const [headerName, valueCounts] of headerCounts) {
		for (const [value, count] of valueCounts) {
			if (count >= 3) {
				return {
					mechanism: "api-key",
					confidence: 70,
					details: {
						mechanism: "api-key",
						loginUrl: null,
						tokenEndpoint: null,
						keyLocation: "header",
						keyName: headerName,
						keyPrefix: value.slice(0, 8),
					},
				};
			}
		}
	}

	// Check for consistent query param with long value
	const queryKeyCounts = new Map<string, Map<string, number>>();
	for (const ex of exchanges) {
		try {
			const url = new URL(ex.request.url);
			for (const [key, value] of url.searchParams) {
				if (value.length >= 20) {
					let valueCounts = queryKeyCounts.get(key);
					if (!valueCounts) {
						valueCounts = new Map();
						queryKeyCounts.set(key, valueCounts);
					}
					valueCounts.set(value, (valueCounts.get(value) ?? 0) + 1);
				}
			}
		} catch {
			continue;
		}
	}

	for (const [keyName, valueCounts] of queryKeyCounts) {
		for (const [value, count] of valueCounts) {
			if (count >= 3) {
				return {
					mechanism: "api-key",
					confidence: 50,
					details: {
						mechanism: "api-key",
						loginUrl: null,
						tokenEndpoint: null,
						keyLocation: "query",
						keyName,
						keyPrefix: value.slice(0, 8),
					},
				};
			}
		}
	}

	return null;
}

// ─── Orchestrator ───────────────────────────────────────────────

const detectors: Array<(exchanges: CapturedExchange[]) => AuthProfile | null> = [
	detectCognito,
	detectAudkenni,
	detectSaml,
	detectOAuth2,
	detectJwtFormLogin,
	detectSessionCookie,
	detectBasicAuth,
	detectApiKey,
];

export function profileAuth(exchanges: CapturedExchange[]): AuthProfile {
	const results: AuthProfile[] = [];

	for (const detect of detectors) {
		const result = detect(exchanges);
		if (result) results.push(result);
	}

	if (results.length === 0) {
		return {
			mechanism: "unknown",
			confidence: 0,
			details: {
				mechanism: "unknown",
				loginUrl: null,
				tokenEndpoint: null,
				notes: "No recognized auth pattern detected in captured traffic",
			} as AuthDetails,
		};
	}

	// Return highest confidence
	results.sort((a, b) => b.confidence - a.confidence);
	return results[0]!;
}
