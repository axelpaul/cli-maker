import type { AudkenniDetails, AuthDetails, AuthProfile, CapturedExchange } from "./types.ts";

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

/** Recursively collect all field names from a nested object */
function collectDeepFieldNames(obj: unknown, fields: string[] = []): string[] {
	if (obj && typeof obj === "object" && !Array.isArray(obj)) {
		for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
			fields.push(key);
			collectDeepFieldNames(value, fields);
		}
	} else if (Array.isArray(obj)) {
		for (const item of obj) collectDeepFieldNames(item, fields);
	}
	return fields;
}

/** For GraphQL requests, extract deep field names from variables + the query text */
function getGraphQLFields(body: string | null, contentType: string | undefined): {
	deepFields: string[];
	queryText: string;
	operationName: string;
} {
	const empty = { deepFields: [], queryText: "", operationName: "" };
	if (!body || !contentType?.includes("application/json")) return empty;
	try {
		const parsed = JSON.parse(body) as Record<string, unknown>;
		if (typeof parsed.query !== "string") return empty;
		const deepFields = collectDeepFieldNames(parsed.variables);
		return {
			deepFields,
			queryText: parsed.query as string,
			operationName: (typeof parsed.operationName === "string" ? parsed.operationName : ""),
		};
	} catch {
		return empty;
	}
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

const AUDKENNI_AUTH_TYPES = new Set(["sim", "app", "card", "audkennisapp"]);

// Cookies to ignore when guessing the session cookie name (trackers, etc.)
const COOKIE_IGNORE_RE = /^(_ga|_gid|_gat|_fbp|_hj|_pk|amp_|ajs_|optimizely|hubspot|mp_|intercom)/i;

interface BffSignals {
	startEndpoint: string | null;
	pollEndpoint: string | null;
	authTypes: string[];
	startBodyFields: string[];
	sessionCookieName: string | null;
}

function detectAudkenniBff(exchanges: CapturedExchange[]): BffSignals | null {
	let startEndpoint: string | null = null;
	let pollEndpoint: string | null = null;
	const authTypes = new Set<string>();
	const startBodyFields = new Set<string>();
	let sessionCookieName: string | null = null;
	let lastFlowTimestamp = 0;

	for (const ex of exchanges) {
		if (ex.request.method !== "POST") continue;
		const ct = ex.request.headers["content-type"];
		if (!ct?.includes("application/json")) continue;
		if (!ex.request.postData) continue;

		let body: Record<string, unknown>;
		try {
			body = JSON.parse(ex.request.postData) as Record<string, unknown>;
		} catch {
			continue;
		}

		const authTypeValue = typeof body.authType === "string" ? body.authType.toLowerCase() : null;
		const hasAuthType = authTypeValue !== null && AUDKENNI_AUTH_TYPES.has(authTypeValue);
		const hasPhoneOrSsn = "phoneNumber" in body || "ssn" in body || "kennitala" in body;
		const hasAuthRequestId = "authRequestId" in body;

		if (hasAuthType && hasPhoneOrSsn) {
			startEndpoint = ex.request.url;
			authTypes.add(body.authType as string);
			for (const f of Object.keys(body)) startBodyFields.add(f);
			lastFlowTimestamp = Math.max(lastFlowTimestamp, ex.request.timestamp);
		}

		if (hasAuthRequestId) {
			pollEndpoint = ex.request.url;
			lastFlowTimestamp = Math.max(lastFlowTimestamp, ex.request.timestamp);
		}
	}

	if (!startEndpoint && !pollEndpoint) return null;

	// Look for the session cookie set during or just after the flow
	for (const ex of exchanges) {
		const setCookie = ex.response?.headers["set-cookie"];
		if (!setCookie) continue;
		if (ex.request.url === startEndpoint || ex.request.url === pollEndpoint) {
			const m = setCookie.match(/^([^=]+)=/);
			if (m && !COOKIE_IGNORE_RE.test(m[1]!)) {
				sessionCookieName = m[1]!;
				break;
			}
		}
	}

	// Fallback: pick the first non-tracker cookie present on a request after the flow
	if (!sessionCookieName && lastFlowTimestamp > 0) {
		for (const ex of exchanges) {
			if (ex.request.timestamp <= lastFlowTimestamp) continue;
			const cookieHeader = ex.request.headers["cookie"];
			if (!cookieHeader) continue;
			for (const pair of cookieHeader.split(/;\s*/)) {
				const name = pair.split("=")[0]?.trim();
				if (name && !COOKIE_IGNORE_RE.test(name)) {
					sessionCookieName = name;
					break;
				}
			}
			if (sessionCookieName) break;
		}
	}

	return {
		startEndpoint,
		pollEndpoint,
		authTypes: [...authTypes],
		startBodyFields: [...startBodyFields],
		sessionCookieName,
	};
}

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

	const bff = detectAudkenniBff(exchanges);

	if (!idpUrl && !bff) return null;

	const flow: "redirect" | "bff-proxied" = idpUrl ? "redirect" : "bff-proxied";

	let confidence: number;
	if (idpUrl && callbackUrl) confidence = 90;
	else if (idpUrl) confidence = 60;
	else if (bff?.startEndpoint && bff.pollEndpoint) confidence = 85;
	else if (bff?.startEndpoint || bff?.pollEndpoint) confidence = 65;
	else confidence = 50;

	const details: AudkenniDetails = {
		mechanism: "audkenni-island-is",
		flow,
		loginUrl: idpUrl ?? bff?.startEndpoint ?? null,
		tokenEndpoint: null,
		idpUrl,
		callbackUrl,
		redirectChain,
	};

	if (bff) {
		if (bff.startEndpoint) details.startEndpoint = bff.startEndpoint;
		if (bff.pollEndpoint) details.pollEndpoint = bff.pollEndpoint;
		if (bff.authTypes.length > 0) details.authTypes = bff.authTypes;
		if (bff.startBodyFields.length > 0) details.startBodyFields = bff.startBodyFields;
		if (bff.sessionCookieName) details.sessionCookieName = bff.sessionCookieName;
	}

	return {
		mechanism: "audkenni-island-is",
		confidence,
		details,
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

// ─── Detector: SMS / OTP ────────────────────────────────────────

// Broad keywords indicating this is an OTP-related flow
const OTP_FLOW_KEYWORDS = [
	"otp", "onetime", "onetimepassword", "one_time_password",
	"sms_code", "smscode", "one_time",
];

// Exact field names that indicate the verify/code-submit step (NOT substring-matched)
const VERIFY_EXACT_FIELDS = new Set([
	"code", "otp", "pin", "passcode", "otpcode", "sms_code", "smscode",
	"verificationcode", "verification_code", "one_time_code",
]);

const PHONE_FIELD_KEYWORDS = [
	"phone", "mobile", "tel", "telephone", "msisdn", "cellphone",
	"identifier",
];

// URL path segments that suggest SMS/OTP flow
const PHONE_PATH_RE = /\/(send[-_]?sms|send[-_]?otp|send[-_]?code|phone[-_]?login|request[-_]?otp|sms[-_]?auth|phone[-_]?auth|login[-_]?phone|send[-_]?verification)/i;
const VERIFY_PATH_RE = /\/(verify[-_]?(sms|otp|code|phone)?|confirm[-_]?(sms|otp|code|phone)?|validate[-_]?(sms|otp|code|phone)?|check[-_]?(sms|otp|code|phone)?|sms[-_]?verify|otp[-_]?verify|code[-_]?verify)/i;

// Broad OTP signal in GraphQL query/operation text
const OTP_QUERY_TEXT_RE = /onetimepassword|one.?time.?password|otp|sms.?code|verification.?code|phone.?verification/i;

// Phone number value pattern (international format)
const PHONE_VALUE_RE = /^\+\d{7,15}$/;

function fieldMatchesAny(field: string, keywords: string[]): boolean {
	const lower = field.toLowerCase();
	if (keywords.includes(lower)) return true;
	return keywords.some((kw) => lower.includes(kw));
}

/** Check if any nested variable value looks like a phone number */
function hasPhoneValue(obj: unknown): boolean {
	if (typeof obj === "string") return PHONE_VALUE_RE.test(obj);
	if (obj && typeof obj === "object") {
		for (const v of Object.values(obj as Record<string, unknown>)) {
			if (hasPhoneValue(v)) return true;
		}
	}
	return false;
}

/** Check if any deep field name exactly matches a verify-step field */
function hasVerifyField(fields: string[]): boolean {
	return fields.some((f) => VERIFY_EXACT_FIELDS.has(f.toLowerCase()));
}

/** Check if the request is part of an OTP flow (broad signal) */
function isOtpFlowRequest(fields: string[], gql: { deepFields: string[]; queryText: string; operationName: string }): boolean {
	// Check form fields
	if (fields.some((f) => fieldMatchesAny(f, OTP_FLOW_KEYWORDS))) return true;
	// Check deep GraphQL field names
	if (gql.deepFields.some((f) => fieldMatchesAny(f, OTP_FLOW_KEYWORDS))) return true;
	// Check query text / operation name
	if (OTP_QUERY_TEXT_RE.test(gql.queryText) || OTP_QUERY_TEXT_RE.test(gql.operationName)) return true;
	return false;
}

function detectSmsOtp(exchanges: CapturedExchange[]): AuthProfile | null {
	let phoneEndpoint: string | null = null;
	let verifyEndpoint: string | null = null;
	let phoneFields: string[] = [];
	let codeFields: string[] = [];

	for (const ex of exchanges) {
		if (ex.request.method !== "POST") continue;
		const contentType = ex.request.headers["content-type"];
		const fields = getFormFields(ex.request.postData, contentType);
		const url = ex.request.url;
		let pathname = "";
		try { pathname = new URL(url).pathname; } catch { /* ignore */ }

		const gql = getGraphQLFields(ex.request.postData, contentType);
		const allFields = gql.queryText ? gql.deepFields : fields;

		// Is this request part of an OTP flow at all?
		const otpFlow = isOtpFlowRequest(fields, gql);

		// Is this the verify/code-submit step? (exact field name match)
		const isVerifyStep = hasVerifyField(allFields);

		// Does this request contain a phone number?
		const hasPhone = allFields.some((f) => fieldMatchesAny(f, PHONE_FIELD_KEYWORDS))
			|| (gql.queryText ? (() => {
				try {
					const parsed = JSON.parse(ex.request.postData!) as Record<string, unknown>;
					return hasPhoneValue(parsed.variables);
				} catch { return false; }
			})() : false);

		// Does the response contain a JWT? (verify step should yield a token)
		const responseHasJwt = ex.response?.body ? JWT_RE.test(ex.response.body) : false;

		const phonePathMatch = PHONE_PATH_RE.test(pathname);
		const verifyPathMatch = VERIFY_PATH_RE.test(pathname);

		// Classify: verify step = has a "code" field, or response has JWT + is OTP flow, or URL path matches
		if (isVerifyStep || (otpFlow && responseHasJwt) || (verifyPathMatch && allFields.length > 0)) {
			verifyEndpoint = url;
			codeFields = allFields;
		}
		// Phone step = has phone signal in an OTP flow, without being the verify step
		else if ((otpFlow && hasPhone) || (phonePathMatch && !verifyPathMatch)) {
			phoneEndpoint = url;
			phoneFields = allFields;
		}
	}

	if (!phoneEndpoint && !verifyEndpoint) return null;

	let confidence = 40;
	if (phoneEndpoint && verifyEndpoint) confidence = 90;
	else if (verifyEndpoint) confidence = 70;
	else if (phoneEndpoint) confidence = 50;

	// Check if a JWT appeared in the verify response or subsequent requests
	let tokenUsage: "bearer-header" | "cookie" | "unknown" = "unknown";
	if (verifyEndpoint) {
		const verifyEx = exchanges.find((e) => e.request.url === verifyEndpoint && e.response?.body && JWT_RE.test(e.response.body));
		if (verifyEx) {
			tokenUsage = "bearer-header";
			if (confidence < 90) confidence = 85;
		}
	}
	if (tokenUsage === "unknown" && verifyEndpoint) {
		const verifyTime = exchanges.find((e) => e.request.url === verifyEndpoint)?.request.timestamp ?? 0;
		for (const later of exchanges) {
			if (later.request.timestamp <= verifyTime) continue;
			const auth = later.request.headers["authorization"] ?? "";
			if (auth.startsWith("Bearer ")) {
				tokenUsage = "bearer-header";
				if (confidence < 90) confidence = 85;
				break;
			}
		}
	}

	return {
		mechanism: "sms-otp",
		confidence,
		details: {
			mechanism: "sms-otp",
			loginUrl: phoneEndpoint,
			tokenEndpoint: verifyEndpoint,
			phoneEndpoint,
			verifyEndpoint,
			phoneFields,
			codeFields,
			tokenUsage,
		},
	};
}

// ─── Detector: API Key ──────────────────────────────────────────

const API_KEY_HEADERS = [
	"x-api-key",
	"api-key",
	"apikey",
	"x-auth-token",
	"x-access-token",
];

// For query params: only consider params whose name suggests an API key
const API_KEY_PARAM_NAME_RE = /key|token|auth|secret|credential|access|apikey/i;

// API keys look like hex, base64, or alphanumeric strings
const KEY_LIKE_RE = /^[a-zA-Z0-9_\-+/.=]+$/;

function detectApiKey(exchanges: CapturedExchange[]): AuthProfile | null {
	// Check for consistent API key header across multiple requests
	const headerCounts = new Map<string, Map<string, number>>();
	for (const ex of exchanges) {
		for (const headerName of API_KEY_HEADERS) {
			const value = ex.request.headers[headerName];
			if (value && KEY_LIKE_RE.test(value)) {
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

	// Check for consistent query param with long key-like value
	// Only consider params whose name suggests an API key to avoid tracking param false positives
	const queryKeyCounts = new Map<string, Map<string, number>>();
	for (const ex of exchanges) {
		try {
			const url = new URL(ex.request.url);
			for (const [key, value] of url.searchParams) {
				if (
					value.length >= 20 &&
					API_KEY_PARAM_NAME_RE.test(key) &&
					KEY_LIKE_RE.test(value)
				) {
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
	detectSmsOtp,
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
