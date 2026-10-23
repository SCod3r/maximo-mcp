# Changelog

All notable changes to this project will be documented in this file.

## [1.4.0] - 2026-10-23
### Security
- All Maximo requests go through one wrapper that never follows redirects. Node's `fetch` had been forwarding the `apikey` header to SSO/identity-provider redirect targets. The wrapper only contacts the `MAXIMO_URL` origin, refuses plain http to non-local hosts, times out, and reports HTML login pages and internal-CA TLS errors clearly.
- `.env` is loaded only from the server's own folder; a `.env` in the client's working directory could previously enable writes or redirect the API key.
- Object Structures are now limited by default to core work/asset structures; `*` opts into all. Related-object clauses (`rel.…`, nested `{…}` selects) are blocked unless `MAXIMO_ALLOW_RELATED_QUERIES=true`.
- Write payloads may not contain Maximo control keys. `create_record` no longer sends `x-method-override: BULK`, and an empty `MAXIMO_ALLOWED_ACTIONS` now means no actions.
- `get_schema_details` no longer returns sample record values, and `list_object_structures` only lists allowed structures.
- Demo proxy:
  - Requires a per-launch token, held in an HttpOnly SameSite=Strict cookie.
  - Forwards only allowlisted request headers and applies the shared Object Structure allowlist and related-query block.
  - Rejects double-encoded and absolute-form request targets, and does not relay upstream redirects.
  - Sends a strict CSP with every static file.
- Demo pages use vendored, checksummed copies of Tailwind (browser build 4.3.3), lucide 1.61.0 and swagger-ui 5.34.0 instead of loading them from public CDNs. The Carbon stylesheet is pinned.
- Tool output is capped (`MAXIMO_MAX_OUTPUT_CHARS`), and failed live schema fetches are retried at most every 5 minutes.
- Docs and examples run the reviewed local clone (`npm ci --omit=dev --ignore-scripts`, `node maximo-mcp-server.js`) instead of `npx`, which installs the unhardened npm release. Node 22 is pinned, and `engines` requires Node 20 or later.

## [1.3.0] - 2026-10-22
### Security
- Validate `objectStructure` on every tool. Unvalidated names allowed path traversal (e.g. `../../oslc/...`) and query-string injection, sending API-key-authenticated requests to arbitrary Maximo endpoints.
- Write tools (`create_record`, `update_record`, `run_action`) are now disabled by default; enable with `MAXIMO_ENABLE_WRITES=true`. `run_action` is limited to `MAXIMO_ALLOWED_ACTIONS` (default `changeStatus`). Optional `MAXIMO_ALLOWED_OBJECT_STRUCTURES` allowlist.
- Added MCP tool annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`) so clients can require confirmation for writes.
- Escape all Maximo data in `render_carbon_table` / `render_carbon_details` (stored XSS) and add a restrictive CSP; pinned the Carbon stylesheet version.
- `query_maximo` now returns JSON by default (`formatted: false`), with a notice marking record contents as untrusted.
- Clamp `pageSize` (`MAXIMO_MAX_PAGE_SIZE`, default 100); validate record IDs, action names and JSON payloads.
- Stop logging record payloads and full request URLs; `get_instance_details` no longer returns the instance URL.
- Demo proxy: verify TLS by default, bind to 127.0.0.1, drop `Access-Control-Allow-Origin: *`, reject non-localhost Host headers and cross-site requests, proxy only `/maximo/api/os/*` (GET unless writes are enabled), inject the API key server-side, strip browser cookies, and stop serving the project root.
- Demo pages: escape Maximo data inserted via `innerHTML`, remove inline `onclick` URL interpolation, pin the lucide CDN version, remove a hard-coded customer hostname.
- CI: pin `mcp-publisher` to v1.8.1 with SHA-256 verification and SHA-pin `actions/checkout`.
- Dependencies: `@modelcontextprotocol/sdk` 1.32.1, `http-proxy-middleware` 3.0.7, `express` 4.22.3; `npm audit fix`.
- Stopped tracking stale build outputs (`.smithery/`, `.vsix`, `vscode-extension/out/`) that were already in `.gitignore`.

### Fixed
- `get_instance_details` always reported "Unknown" because `query_maximo` returned HTML by default.

### Added
- Security unit and integration tests (Jest + supertest) replacing the placeholder tests.

## [1.2.1] - 2026-09-16
### Changed
- Refreshed the documentation date shown on the npm package page.
- Aligned the VS Code extensions onto the same version line as the MCP server, so `maximo-mcp-server`, IBM Maximo MCP for AI and Maximo API Explorer all report 1.2.1.

## [1.2.0] - 2026-09-16
### Added
- `create_record` — create Work Orders, Assets and Service Requests via REST POST.
- `update_record` — partially update any Maximo record by ID.
- `run_action` — trigger Maximo business actions such as status changes and approvals.
- `SmartValidator` pre-flight validation: OSLC syntax checks, fuzzy field matching, site and worktype validation, and status transition checks.

### Fixed
- `renderCarbonDetails` was truncated and left the file unparseable, which prevented the server from starting.
- The server reported a hardcoded version of 1.0.0 regardless of the released version.

## [1.0.2] - 2026-02-05
### Changed
- Documentation improvements and path standardization for easier installation.
- Updated documentation dates.

## [1.0.0] - 2026-02-03
### Added
- Initial release of Maximo MCP Server.
