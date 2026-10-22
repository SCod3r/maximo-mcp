# Changelog

All notable changes to this project will be documented in this file.

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
