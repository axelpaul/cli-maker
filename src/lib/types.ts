// ─── Raw Capture ────────────────────────────────────────────────

export interface CapturedRequest {
	url: string;
	method: string;
	headers: Record<string, string>;
	postData: string | null;
	resourceType: string;
	timestamp: number;
}

export interface CapturedResponse {
	status: number;
	statusText: string;
	headers: Record<string, string>;
	body: string | null;
	bodySize: number;
	mimeType: string;
}

export interface CapturedExchange {
	request: CapturedRequest;
	response: CapturedResponse | null;
	duration: number;
}

// ─── Parsed Endpoints ───────────────────────────────────────────

export interface PathParameter {
	position: number;
	name: string;
	examples: string[];
}

export interface QueryParameter {
	name: string;
	required: boolean;
	examples: string[];
}

export interface RequestBodyField {
	path: string;
	types: string[];
	examples: unknown[];
}

export interface ApiEndpoint {
	method: string;
	pathPattern: string;
	pathParams: PathParameter[];
	queryParams: QueryParameter[];
	requestHeaders: Record<string, string>;
	requestContentType: string | null;
	requestBodyFields: RequestBodyField[];
	responseStatuses: number[];
	responseContentType: string | null;
	responseBodySample: unknown;
	exampleCount: number;
	examples: CapturedExchange[];
}

// ─── Auth Detection ─────────────────────────────────────────────

export type AuthMechanism =
	| "jwt-form-login"
	| "aws-cognito"
	| "audkenni-island-is"
	| "oauth2-oidc"
	| "saml"
	| "session-cookie"
	| "basic-auth"
	| "api-key"
	| "unknown";

export interface AuthProfile {
	mechanism: AuthMechanism;
	confidence: number;
	details: AuthDetails;
}

export interface AuthDetailsBase {
	mechanism: AuthMechanism;
	loginUrl: string | null;
	tokenEndpoint: string | null;
}

export interface JwtFormLoginDetails extends AuthDetailsBase {
	mechanism: "jwt-form-login";
	formFields: string[];
	contentType: string;
	tokenPath: string;
	tokenUsage: "bearer-header" | "cookie" | "unknown";
}

export interface AwsCognitoDetails extends AuthDetailsBase {
	mechanism: "aws-cognito";
	cognitoEndpoint: string;
	userPoolId: string | null;
	clientId: string | null;
	region: string;
	authFlow: string;
}

export interface AudkenniDetails extends AuthDetailsBase {
	mechanism: "audkenni-island-is";
	idpUrl: string;
	callbackUrl: string | null;
	redirectChain: string[];
}

export interface OAuth2Details extends AuthDetailsBase {
	mechanism: "oauth2-oidc";
	authorizeEndpoint: string;
	tokenEndpoint: string;
	clientId: string | null;
	responseType: string;
	scopes: string[];
	redirectUri: string | null;
}

export interface SamlDetails extends AuthDetailsBase {
	mechanism: "saml";
	idpUrl: string;
	spUrl: string;
	assertionConsumerServiceUrl: string | null;
}

export interface SessionCookieDetails extends AuthDetailsBase {
	mechanism: "session-cookie";
	cookieName: string;
	cookieDomain: string;
	loginMethod: string;
	formFields: string[];
}

export interface BasicAuthDetails extends AuthDetailsBase {
	mechanism: "basic-auth";
	realm: string;
	protectedPaths: string[];
}

export interface ApiKeyDetails extends AuthDetailsBase {
	mechanism: "api-key";
	keyLocation: "header" | "query";
	keyName: string;
	keyPrefix: string | null;
}

export type AuthDetails =
	| JwtFormLoginDetails
	| AwsCognitoDetails
	| AudkenniDetails
	| OAuth2Details
	| SamlDetails
	| SessionCookieDetails
	| BasicAuthDetails
	| ApiKeyDetails
	| (AuthDetailsBase & { mechanism: "unknown"; notes: string });

// ─── JS Bundle Scanner ──────────────────────────────────────────

export interface DiscoveredPath {
	pattern: string;
	source: string;
	context: string;
	confidence: number;
}

export interface JsScanResult {
	url: string;
	bundlesScanned: number;
	discoveredPaths: DiscoveredPath[];
	baseUrls: string[];
}

// ─── Output Spec ────────────────────────────────────────────────

export interface ApiSpec {
	version: "1";
	generatedAt: string;
	targetUrl: string;
	targetDomain: string;
	endpoints: ApiEndpoint[];
	auth: AuthProfile | null;
	jsScanResults: JsScanResult | null;
	metadata: {
		sessionDuration: number;
		totalRequestsCaptured: number;
		totalRequestsFiltered: number;
		capturedBodies: boolean;
	};
}
