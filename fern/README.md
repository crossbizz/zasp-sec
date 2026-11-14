# Documentation site and SDKs (Fern)

This directory holds the configuration of two things that are built from the
API contract, `openapi/openapi.yaml`, with [Fern](https://buildwithfern.com):

- the documentation site: guides, concept pages, integration pages and an API
  reference of all 190 operations;
- the SDKs under `sdks/`: TypeScript, Python, Go and Java clients for the 116
  operations an API token may call.

## Files

| File | What it is |
| --- | --- |
| `fern.config.json` | The Fern organization (`zasp`) and the pinned CLI version |
| `generators.yml` | The API definition and the four SDK generators |
| `openapi-overrides.yml` | Generated. Tags, SDK names, pagination and the token audience for each operation |
| `openapi-overlays.yml` | Hand-written. The few shapes of the contract Fern cannot read as written |
| `docs.yml` | The site: navigation, tabs and the API reference layout |
| `docs/pages/` | The pages of the site |
| `scripts/` | The scripts behind the npm commands below |

The contract is never edited for Fern. Everything Fern needs beyond it is in
the overrides and the overlay.

## Commands

Run them from the repository root.

Validate the configuration, the pages and the links:

```bash
npm run docs:check
```

Rebuild `openapi-overrides.yml` after a change to the contract:

```bash
npm run docs:overrides
```

Publish a preview of the site and print its address:

```bash
npm run docs:preview
```

This needs the token and network access to Fern. In the authoring environment
it failed for lack of that access; see "Publishing for real".

Generate the SDKs again, with Fern's cloud generators (not run in the authoring
environment; the form with `--local` under "The SDKs" was):

```bash
npm run sdk:generate
```

Compile the TypeScript and Go SDKs and run their smoke tests:

```bash
npm run sdk:test
```

The Fern CLI is not a dependency of this repository. The scripts fetch the
pinned version with `npx`.

To look at the site on your machine while you write:

```bash
node fern/scripts/fern.mjs docs dev
```

It prints the address it serves the site at, API reference included.

## What `docs:check` checks

1. `openapi-overrides.yml` is current: every operation of the contract has a
   tag, an SDK group and a method name. A new operation that is not listed in
   `scripts/build-openapi-overrides.mjs` fails the check.
2. The user guide cites only labels and messages that exist in the web
   application (`scripts/check-ui-labels.mjs`). In
   `docs/getting-started/user.md`, a name in bold is a label of the
   application and a sentence in double quotes is a message it shows.
3. `fern check`: the API definition, `generators.yml`, `docs.yml`, and every
   page parses as MDX.
4. `fern docs broken-links`: links between pages resolve.

None of these needs a token or the network. `fern check` prints one warning
without network access: it cannot compare redirects with a published site.

## The token

The Fern CLI reads its token from the environment variable `FERN_TOKEN`.

- Supply it in the environment of the command. If only `FERN_API_KEY` is set,
  `scripts/fern.mjs` passes its value on as `FERN_TOKEN`.
- Never write it to a file and never commit it. Nothing in this repository
  stores it.
- `docs:check`, `sdk:test` and `sdk:generate -- --local` need no token.
- `docs:preview`, publishing the site, and `sdk:generate` with Fern's cloud
  generators need it, and they need network access to `buildwithfern.com` and
  its subdomains.

The token belongs to a Fern organization. `fern.config.json` names the
organization `zasp`. Whether the token belongs to that organization has not
been confirmed: that needs a call to Fern, which the authoring environment's
network policy refused. If it belongs to another organization, change
`organization` in `fern.config.json` and the first part of the instance `url`
in `docs.yml` to match.

## Writing pages

Pages are MDX. Three rules keep `docs:check` green:

- An angle bracket or a brace outside code is parsed as markup. Put
  placeholders in code: `` `<account>` ``.
- An HTML comment does not parse. Use `{/* ... */}`.
- Link to another page by its path on the site, for example
  `/concepts/mcp-governance`. Paths are set by the `slug` values in `docs.yml`.

### The two getting-started guides

Each has one source.

- **User guide**: `docs/getting-started/user.md` in the repository. `docs.yml`
  uses that file as a page, so it is not copied.
- **Administrator guide**: `docs/getting-started/administrator.md`. Until that
  file is merged, the site shows a short summary,
  `docs/pages/getting-started/administrator.mdx`. To wire the full guide in,
  change the page's `path` in `docs.yml` to
  `../docs/getting-started/administrator.md` and delete the summary. The
  comment marked `ADMIN-GUIDE-SOURCE` in the summary says the same. Then run
  `npm run docs:check`, because the guide is then parsed as MDX.

## The API reference

The contract has no tags. `scripts/build-openapi-overrides.mjs` gives every
operation:

- a tag, which names its section;
- `x-fern-sdk-group-name` and `x-fern-sdk-method-name`, so that
  `listAgents` becomes `client.agents.list()`;
- `x-fern-audiences: [api-token]` when an API token may call it;
- `x-fern-pagination` when it returns a cursor;
- a sentence in its description when only a browser session may call it.

`docs.yml` then arranges the 37 groups into nine sections.

Two things to know about the rendered reference:

- Every operation shows bearer authentication, because Fern takes one
  authentication scheme for the API. The description of a browser-only
  operation says that an API token is refused.
- The API explorer is hidden. A deployment has its own address, so the
  reference has no server to send a request to.

## The SDKs

`generators.yml` has one group per language, each with output to the local file
system. Nothing is published to npm, PyPI, Maven Central or a repository.

| Group | Generator | Output |
| --- | --- | --- |
| `typescript-sdk` | `fernapi/fern-typescript-sdk` | `sdks/typescript/src` |
| `python-sdk` | `fernapi/fern-python-sdk` | `sdks/python/src/zasp` |
| `go-sdk` | `fernapi/fern-go-sdk` | `sdks/go` |
| `java-sdk` | `fernapi/fern-java-sdk` | `sdks/java` |

The alias `sdks` runs all four.

Generated code is committed, so that a change to the contract shows as a change
to the SDKs in review, and so that the SDKs can be installed from a checkout.
It is excluded from the repository's ESLint and TypeScript checks. Each SDK's
hand-written files (build file, README, smoke test) are listed in
`sdks/README.md`.

There are two ways to generate.

With Fern's cloud generators. Needs `FERN_TOKEN` and network access to Fern:

```bash
npm run sdk:generate
```

On your machine. Needs a running Docker daemon and no token. The CLI pulls the
generator images from Docker Hub:

```bash
npm run sdk:generate -- --local
```

One group only:

```bash
npm run sdk:generate -- --group python-sdk --local
```

After generating, the script formats the Go module with `gofmt`, because the
generator's output is not gofmt-clean.

### How the committed SDKs were generated

The committed SDKs were generated with `fern generate --local`, by the official
generator images at the versions pinned in `generators.yml`.

The authoring environment had no Docker daemon and no network access to Fern's
cloud. The generator images were therefore fetched from Docker Hub as file
systems and run under `chroot`, with a small stand-in for the `docker run`
command that the CLI calls. The generators and their input were unchanged. That
stand-in is not part of this repository. With Docker, the command above does
the same.

## Publishing for real

Nothing below has been done. The owner decides when.

### The documentation site

1. Make sure the token's organization matches `fern.config.json`.
2. Publish a preview and review it:

   ```bash
   npm run docs:preview
   ```

3. Publish to the address in `docs.yml` (`zasp.docs.buildwithfern.com`):

   ```bash
   node fern/scripts/fern.mjs generate --docs
   ```

4. For your own domain, add it under the instance and follow Fern's domain
   setup, which gives you the DNS records to create:

   ```yaml
   instances:
     - url: zasp.docs.buildwithfern.com
       custom-domain: docs.example.com
   ```

These commands were not run successfully in the authoring environment: its
network policy refuses `buildwithfern.com`.

### The SDKs

To publish an SDK to a registry, change the generator's `output` in
`generators.yml` from the local file system to the registry, and supply the
registry's token through the environment:

```yaml
output:
  location: npm
  package-name: "@zasp/sdk"
  token: ${NPM_TOKEN}
```

| Language | `location` | Needs |
| --- | --- | --- |
| TypeScript | `npm` | An npm token and the package name |
| Python | `pypi` | A PyPI token, or trusted publishing, and the package name |
| Java | `maven` | Maven Central credentials, a signing key and the coordinate |
| Go | A `github` block with a repository | A repository for the module; Go modules are published by tagging it |

Decide first whether the SDKs stay in this repository or move to one
repository per language. A Go module is fetched by its repository path, so the
module path in `generators.yml` (`importPath`) must match where it is
published.

The option names above are from Fern's `generators.yml` reference. Publishing
was not tried.

### Continuous integration

`.github/workflows/docs-and-sdks.yml` is a sketch. It runs only when started by
hand, and it publishes only when asked to:

- it always runs `docs:check` and `sdk:test`;
- with the input `publish_preview`, it publishes a preview of the site;
- with the input `publish_docs`, it publishes the site.

It needs the repository secret `FERN_TOKEN` for the two publishing steps. To
run the check on every pull request, add a `pull_request` trigger to it.

## Where Fern's format was looked up

The configuration follows Fern's documentation as of November 2026, read from
the documentation's public source repository, and was validated with the
`fern-api` CLI at the version in `fern.config.json`. Fern now also offers a
newer SDK configuration file, `sdk-config.yml`, and calls the `groups` of
`generators.yml` the legacy form. The legacy form is fully supported and is
what this directory uses.
