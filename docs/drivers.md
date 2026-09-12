# Lua Driver Engine

`ezcap` executes observability helper scripts through an internal Lua runtime inside the daemon.
Scripts are untrusted and are treated as privileged input: every script must be validated,
isolated, and rate limited before it can observe or emit events.

## Directory layout

- `src/drivers/driver_engine.hpp|cpp` — discovery, lifecycle orchestration, and supervision.
- `src/drivers/lua/sandbox.hpp|cpp` — hardened Lua state with budgets and restricted standard library.
- `src/drivers/lua/manifests/` — manifest parser, allowlist checks, and optional hash pinning.
- `src/drivers/lua/bindings/lezcap.hpp|cpp` — the `lezcap` Lua API exposed to scripts.
- `scripts/lua/` — first-party bundled drivers and manifests.

## Runtime boundaries

- The driver engine is a **daemon-internal** component; neither the extension nor the native host talks to it directly.
- Scripts receive **already-redacted** normalized events, and they cannot access raw packet capture handles.
- The engine is the only owner of:
  - sandbox creation,
  - policy snapshots,
  - backend status/event sink wiring,
  - fault and quarantine handling.

## File discovery and manifest loading

`DriverEngine::discover_manifests()` scans each configured allowlisted directory and loads files matching
`.manifest.json` from those directories only. Invalid manifests are skipped and logged.

`DriverEngine::load_from_manifest_text()` follows deterministic steps:

1. Parse and validate manifest JSON (`DriverManifest::parse`).
2. Enforce manifest `script` path allowlist (`path_within_allowlist`) when allowdirs are configured.
3. Read script with safe I/O (`read_script_safely`):
   - `open(..., O_RDONLY|O_CLOEXEC|O_NOFOLLOW)`,
   - regular file check,
   - max size `256 KiB` (`kMaxScriptBytes`),
   - canonical path check via `/proc/self/fd/<fd>` to reduce TOCTOU path abuse.
4. Optional integrity verification (`script_sha256`) via `verify_script_hash`.
5. Create `DriverInstance`, build sandbox, register `lezcap`, load script text, execute it, call `on_load(ctx)`.

## Manifest contract

The manifest schema is defined in `protocol/drivers/manifest.schema.json`.

Required fields:

- `name` — `[a-zA-Z0-9-]{1,64}`, unique identifier.
- `version` — semantic-like `x.y[.z]`.
- `script` — path of the script file.

Optional fields:

- `description` (max 512 chars).
- `script_sha256` (lowercase 64 hex chars, optional integrity pin).
- `capabilities` (max 16 entries; accepted values listed below).
- `event_types` (max 16 event names, each max 32 chars).
- `max_endpoints` (0..64).
- `max_subscriptions` (0..64).

Capabilities recognized by the parser and binding gate:

- `events`, `capture`, `dns`, `process`, `policy`, `endpoint`, `spec`, `log`, `util`, `status`.
- Missing capability means the related module is absent from `lezcap` entirely.

## Driver state machine

`src/drivers/driver_engine.hpp` defines five states:

- `Discovered` — manifest validated but script not loaded.
- `Loaded` — script loaded, `on_load` succeeded.
- `Started` — `on_start` succeeded.
- `Quarantined` — fault threshold exceeded.
- `Failed` — irrecoverable validation/runtime load failure.

## Lifecycle (exact call order)

For each driver:

1. `load()`:
   - create sandbox,
   - register `lezcap` bindings based on capability,
   - compile source text only (`load_source`),
   - execute chunk to register callbacks,
   - call mandatory `on_load(ctx)` where `ctx` includes:
     - `name`, `version`,
     - `capabilities` (all requested and granted modules),
     - `event_types` (manifest subscription list, when present).
2. `start()`:
   - call optional `on_start(ctx)` via protected call.
3. `on_event(event)`:
   - optional callback, only invoked when event is allowed by subscriptions/filters.
4. `stop()`:
   - optional `on_stop(ctx)` under protected call,
   - destroy sandbox and return instance to spent state.

`on_load` is mandatory and must be a function; `on_start`, `on_event`, `on_stop` are optional.
Any missing optional callback is ignored safely.

## Sandbox and isolation model

Implemented in `src/drivers/lua/sandbox.cpp`.

- One fresh `lua_State` per script; states are never reused.
- Curated library loading:
  - `base`, `string`, `table`, `math`.
  - Dangerous globals removed from `_G`: `io`, `os`, `package`, `debug`, `require`, `dofile`,
    `loadfile`, `ffi`, `jit`, `collectgarbage`, `newproxy`, `load`, `loadstring`, `bit`.
  - `string.dump` is removed.
- Bytecode rejection: scripts whose source starts with `0x1B` are rejected (`sandbox.bytecode_rejected`).
- Instruction budget via hook; instruction counter is reset per callback.
- Wall-clock budget per callback.
- Custom allocator enforces hard Lua heap ceiling.
- `lua_pcall` with host error handler for every host-triggered callback.

Default sandbox budgets (`EngineLimits::sandbox_budgets` defaults via `SandboxBudgets`):

- Memory: `1 MiB`
- Max string: `8 KiB`
- Instructions: `2,000,000` per callback
- Wall clock: `200 ms` per callback

## Event delivery to scripts

`DriverInstance::on_event()` applies filtering in two stages:

1. **Manifest subscription filter** (`event_types` in manifest) — if set, only those event types reach the script.
2. **Runtime capture filters** (`lezcap.capture.register_filter`) — each filter is a reduction:
   - `event_type` (exact match),
   - `transport` (`tcp|udp|icmp`),
   - `min_confidence` (minimum normalized confidence; converted to permille internally).

Scripts receive a Lua event table with metadata-only fields derived from `ezcap::Event`:

- Core: `event_id`, `event_type`, `source`, `timestamp`, `confidence`, optional `correlation_id`, `redacted`.
- `process` table: `pid`, `name`, optional `uid`.
- `network` table: `transport`, optional `direction`, `local_address`, `local_port`,
  `remote_address`, `remote_port`, `dns_query_name`, optional `dns_response_code`, `interface`.
- `browser` table: `tab_id`, `url`, `title`.

## `lezcap` API surface (binding modules)

All bindings validate argument shapes and return `(ok, err)` by Lua conventions used in this codebase.

- `lezcap.util`
  - `now_ms() -> number` — Unix time in milliseconds.
  - `now_rfc3339() -> string`
  - `sha256_hex(value) -> hex string`
  - `base64_encode(value) -> string`
  - `truncate(s, limit?) -> string`

- `lezcap.log`
  - `info`, `warn`, `error`, `debug` (bounded message logging).

- `lezcap.endpoint`
  - `declare(descriptor)` where required fields are `name`, `namespace`, `version`, `kind`, `summary`.
  - `metadata_only` is enforced to `true`; `false` is rejected.
  - request/response schema accepted only as a constrained schema subset.
  - descriptor count is bounded by driver limits.

- `lezcap.spec`
  - `list_formats() -> { "openapi-3.1", "asyncapi-2", "json-schema" }` (actual list from specgen registry).
  - `generate(format, endpoints)` returns spec text as a string; at most 256 endpoints per call and output cap is 512 KiB.

- `lezcap.capture`
  - `register_filter({ event_type?, transport?, min_confidence? }) -> (ok, err)`.

- `lezcap.policy`
  - `query() -> string` returns policy snapshot JSON.

- `lezcap.event`
  - `emit(event_table)` validates JSON conversion, rate limits by driver, and drops over limit.
  - Event payload cap: 32 KiB.

- `lezcap.status`
  - `backends() -> table|string` status snapshot.

- `lezcap.dns`, `lezcap.process`
  - present as empty namespaces when capability is granted.

## Limits and fault handling

Engine-level defaults (`EngineLimits`):

- `max_concurrent_scripts = 16`
- `max_endpoints_per_driver = 8`
- `max_subscriptions_per_driver = 16`
- `max_events_per_second_per_driver = 64`
- `fault_threshold = 3`
- sandbox budgets (see above)

Driver limits are effectively:

- endpoints and subscriptions: `min(engine_default, manifest_declared_value)`.
- event emission rate: engine default per driver.

On each script fault:

- increment fault counter and warn-log;
- sleep backoff: `25ms * 2^(faults-1)`, capped at `8000ms`;
- quarantine when `faults >= fault_threshold`.

Quarantined drivers are not auto-reloaded by this subsystem.

## Error handling behavior

- Parsing/validation failures produce descriptive error text and keep daemon running.
- Runtime faults in callbacks are converted to structured error codes/messages:
  - sandbox/runtime compile/runtime/budget failures,
  - module argument validation errors,
  - limit and policy errors.
- Script runtime panics are treated as fatal for that Lua state and abort the process only via host panic path.
- `on_stop` faults do not prevent teardown.

## Security notes (metadata-only guarantees)

- Scripts cannot enable payload capture, disable redaction, or access raw packet bytes via this surface.
- File/network/process privileges are not exposed through `lezcap`.
- Integrity pinning (`script_sha256`) and allowlisted script locations are part of load-time trust controls.
- The runtime is hardened around defensive parsing, bounded sizes, capped budgets, capability-only bindings, and strict API validation.

## Authoring a driver

1. Add a manifest JSON with required fields and optional limits/capabilities.
2. Write source text Lua with callbacks:
   - required: `on_load(ctx)`; optional: `on_start`, `on_event`, `on_stop`.
3. Place manifest in an allowlisted driver directory.
4. Reference script path in manifest and configure `script_sha256` when possible.
5. Request only required capabilities.

Example first-party driver files exist at:

- `scripts/lua/dns-summary.lua`
- `scripts/lua/dns-summary.manifest.json`

## Reference protocol files

- `protocol/drivers/manifest.schema.json`
- `protocol/drivers/endpoint.schema.json`
- Endpoint validation path: `specgen::parse_endpoint_descriptor`.
