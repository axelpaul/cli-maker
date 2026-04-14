# cli-maker

Tool for reverse-engineering website APIs using Playwright, then generating CLIs from the discovered specs.

## Commands

```bash
cli-maker sniff --url <url>          # Capture XHR/fetch traffic (interactive browser)
cli-maker auth-profile --url <url>   # Detect auth mechanism
cli-maker scan-js --url <url>        # Extract API paths from JS bundles (headless)
```

All commands support `--output <file>` to save results. Press Enter or close browser to stop sniff/auth-profile.

## Project structure

```
src/
├── index.ts              # Entry point, hand-rolled arg parsing
├── commands/             # sniff, auth-profile, scan-js
└── lib/
    ├── types.ts          # ApiSpec, AuthProfile, CapturedExchange, etc.
    ├── browser.ts        # Playwright browser lifecycle
    ├── interceptor.ts    # Request/response capture
    ├── noise-filter.ts   # Filter analytics, static assets, fonts, etc.
    ├── dedup.ts          # Endpoint deduplication, path param detection
    ├── auth-detect.ts    # 9 auth detectors with confidence scoring
    ├── js-scanner.ts     # Regex scan JS bundles for API paths
    ├── output.ts         # TTY-aware JSON/pretty output
    └── config.ts         # Config directory (~/.cli-maker/)
```

## Auth detectors

JWT form login, AWS Cognito, Audkenni/island.is, OAuth2/OIDC (Keycloak, Entra, Auth0, Okta), SAML, SMS/OTP, session cookies, basic auth, API keys.

## Typical workflow

1. `cli-maker scan-js --url <site>` — discover API paths from JS bundles
2. `cli-maker sniff --url <site> --capture-bodies --output spec.json` — browse and capture
3. `cli-maker auth-profile --url <site> --output auth.json` — detect auth
4. Use the spec + auth profile to generate a CLI with the cli-creator skill

## Tech

- Bun/TypeScript, Playwright for browser automation
- Zero CLI parsing deps (hand-rolled getFlag/hasFlag)
- TTY-aware: JSON when piped, human-readable in terminal

## Conventions

- Do not add Co-Authored-By lines to commits
- Follow cli-creator skill patterns for generated CLIs
