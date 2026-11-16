# Zasp UI foundations

This redesign applies the supplied Aegis demo specifications to Zasp. The kit is a visual reference, not verified official Wiz brand guidance. Product routes, capability checks, authentication, API schemas, data readers and mutation behavior stay in their existing modules.

## Shared implementation

- `app/design-tokens.css` contains the kit's exact light and dark palettes, self-hosted Roboto 400/500/700, component measurements and compatibility aliases for existing features.
- `app/globals.css` consumes those tokens in the existing component rules. Cards are flat; overlays retain elevation. Provider artwork has independent sizing from stroked UI icons.
- `ThemeControl` uses `zasp.theme` in local storage, initializes before paint, follows the system preference until a choice is saved, and synchronizes other tabs. Storage failures still permit a change in the current tab.
- `ZaspProductionApp` preserves the 24 capability-filtered destinations. It adds icons, a skip link and a mobile navigation drawer using the existing focus trapping, Escape and restoration behavior.
- `ProviderLogo` uses fixed 24px slots with a separate shrinking text column. Supplied or maintained SVG marks preserve vendor colors; monochrome dark assets are explicit SVG variants. Unknown providers use a resource glyph, not an imitation logo.
- `BrandLogo` uses the supplied blue (`4.png`) and white (`3.png`) wordmarks from `Zasp Logo Design.zip`. SVG viewports frame the unmodified source PNGs and preserve their proportions; source SHA-256 digests are recorded in `public/brand/SOURCES.json`. The active app theme selects the same artwork in headers, session states and sign-in screens.
- Shared tabs support arrow, Home and End keys. Direct table children of a `Card` receive an internal scrolling container. Session and audit filters use a shared responsive grid.

## Browser review

Run the development app on port 3000 with the repository's usual Node version:

```sh
npm run dev -- --hostname 0.0.0.0 --port 3000
```

The optional visual review runner requires Playwright and a Chromium executable. It does not add a production dependency:

```sh
npm install --prefix /tmp/zasp-ui-browser playwright --no-audit --no-fund
ZASP_PLAYWRIGHT_MODULE=/tmp/zasp-ui-browser/node_modules/playwright/index.mjs \
ZASP_CHROMIUM=/usr/bin/chromium \
node scripts/ui-review/capture.mjs
```

`ZASP_UI_REVIEW_ORIGIN` can select another local development URL. Output goes to the ignored `outputs/aegis-review` directory:

- `walkthrough.html`: self-contained slideshow with embedded screenshots, screen/theme/viewport selectors, keyboard arrows, fullscreen, image download, fit width and fit image modes. Both modes retain intrinsic image proportions.
- `manifest.json`: source routes, viewport and image dimensions, visible alerts, browser failures and interaction assertions.
- `screenshots/`: the original PNG captures.

The runner covers every production route at 1920×1080, 1440×1000, 1024×768 and 390×844 in both themes. Additional captures cover tab sections, a detail drawer, filtered results, selected filters, loading, API failure, sign-in, callback failure and mobile navigation. It checks page overflow and image loading, exercises filtering and retries, verifies dialog focus behavior, and tests persistence of the theme choice.

The browser receives synthetic Zasp API responses from `scripts/ui-review/fixtures.mjs`; those fixtures are never imported by the app. Every non-GET API request in the review context is refused. These screenshots verify rendering and browser interactions, not live sign-in, authorization enforcement, provider connections or backend mutations.

## Verification in this workspace

All stages of `npm run verify` were verified successfully, with the release-runtime test passing on an isolated retry after a cold compilation timeout. Both full repository-history secret scans passed. The complete Vitest suite passes: 270 files and 2,908 tests. Repository-wide lint passes after removing an unused test helper and expressing the same two-space workflow assertion with a regex quantifier. Production build, TypeScript and focused shell/theme checks also pass. The regular CI platform selection (77 Go packages with the race detector), guardrail latency check, API feature suite, signed notification regressions and runtime profile diagnostics pass.

Local verification uses the pinned Node/npm versions, Go 1.26.8 for release-runtime checks, and installed Helm and PostgreSQL 18 fixture tools, including `pgcrypto`. A temporary process reaper outside the repository handles orphaned native subprocesses in this container; test assertions and production code were not changed for that environment issue.

The shared desktop browser could not initialize (`the gaas-browser node_repl sandbox cannot be disabled`). Browser screenshots and interactions use headless Chromium against the running app.

## Asset sources

Roboto and the base provider SVGs retain the kit's license notices under `public/licenses`. Additional Kubernetes, Okta, Salesforce, Slack and GitLab marks come from Devicon. Atlassian and Databricks marks come from the maintained `gilbarbara/logos` collection, with its CC0 notice. Brand marks remain owned by their respective vendors.
