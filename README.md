# cli-maker

Reverse-engineer website APIs using Playwright and generate structured specs for CLI generation.

Point cli-maker at any website, browse it, and get a complete API spec — endpoints, auth mechanism, request/response shapes — ready to feed into a CLI generator.

## Install

```bash
bun install
bun link
```

Requires Playwright's Chromium browser:

```bash
npx playwright install chromium
```

## Commands

### `sniff` — Capture API calls

Opens a browser, intercepts all XHR/fetch traffic while you browse, then outputs a deduplicated API spec.

```bash
cli-maker sniff --url https://example.com
```

Browse the site, perform the actions you want to capture, then press **Enter** (or close the browser) to stop.

| Flag | Description |
|---|---|
| `--url` | Target URL (required) |
| `--capture-bodies` | Include response bodies in the spec |
| `--allow-domain` | Only capture from these domains (repeatable) |
| `--block-domain` | Block additional domains (repeatable) |
| `--output <file>` | Write spec to file instead of stdout |
| `--headless` | Run browser without a window |

### `auth-profile` — Detect authentication mechanism

Watches network traffic during a login flow and identifies the auth pattern.

```bash
cli-maker auth-profile --url https://example.com
```

Navigate to login, authenticate, then press **Enter**.

Detects:

- **JWT form login** — POST credentials, JWT in response, Bearer header
- **AWS Cognito** — SRP protocol via cognito-idp endpoints
- **Audkenni / island.is** — Icelandic national eID redirects
- **OAuth2 / OIDC** — Authorization code and implicit flows
- **SAML** — SAMLRequest/SAMLResponse redirect chains
- **Session cookies** — Set-Cookie after credential POST
- **Basic auth** — WWW-Authenticate headers
- **API keys** — Consistent key headers or query params

Each detection includes a confidence score and typed details (endpoints, fields, token paths).

### `scan-js` — Extract API paths from JS bundles

Downloads and scans all JavaScript bundles for hardcoded API paths, URLs, and config objects. Runs headless — no interaction needed.

```bash
cli-maker scan-js --url https://example.com
```

Finds paths like `/api/v1/users`, `/rest/priv/myaccount`, config assignments like `apiUrl = "..."`, and full URLs embedded in the source.

## Output format

All commands output a structured JSON spec (`ApiSpec`):

```json
{
  "version": "1",
  "targetUrl": "https://example.com",
  "targetDomain": "example.com",
  "endpoints": [
    {
      "method": "GET",
      "pathPattern": "/api/v1/users/:userId",
      "pathParams": [{ "position": 3, "name": "userId", "examples": ["123"] }],
      "queryParams": [{ "name": "lang", "required": true, "examples": ["en"] }],
      "requestHeaders": { "authorization": "Bearer ..." },
      "responseStatuses": [200],
      "responseContentType": "application/json"
    }
  ],
  "auth": {
    "mechanism": "jwt-form-login",
    "confidence": 90,
    "details": { ... }
  },
  "metadata": {
    "totalRequestsCaptured": 47,
    "totalRequestsFiltered": 120
  }
}
```

When piped (non-TTY), output is compact JSON. Use `--pretty` to force human-readable output, or `--json` to force JSON in a terminal.

## Noise filtering

The sniffer automatically filters out:

- Analytics and tracking (Google Analytics, Hotjar, Mixpanel, Sentry, etc.)
- Static assets (JS, CSS, images, fonts, media)
- Page navigations (HTML documents)
- Framework internals (webpack HMR, Next.js static, bower_components)
- Ad networks, social widgets, chat widgets, consent banners

Use `--allow-domain` to narrow capture to specific API domains.

## Agent usage

cli-maker is designed for both humans and AI agents. In JSON mode (default when piped), `cli-maker help` outputs a machine-readable command schema that agents can use for tool registration:

```bash
cli-maker help | jq '.commands[].name'
```

The output spec contains everything needed to generate a typed API client: endpoint signatures, auth flow details, request/response shapes, and concrete examples.

## Development

```bash
bun run dev          # watch mode
bun run check        # lint + typecheck
bun build --compile src/index.ts --outfile cli-maker  # standalone binary
```
