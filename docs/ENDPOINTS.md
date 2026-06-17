# Claude Code Network Traffic Reference

Derived from captured request/response pairs via Hudsucker MITM proxy.

## Log Format

Logs are written to a directory (one `.json` file per request/response, sequentially numbered):

```
/tmp/out/
  0000.json   # first captured request
  0001.json   # second captured request
  0002.json   # first response, etc.
```

Enable with:
```bash
BLEEP_LOG_PATH=/tmp/out BLEEP_LOG_REQUESTS=1 cargo run --bin bleep-gateway -- --api-key <key>
```

### Request file structure

```json
{
  "type": "request",
  "ts": "2026-03-22T23:56:11.522671+00:00",
  "method": "POST",
  "uri": "https://api.anthropic.com/v1/messages?beta=true",
  "body": { ... },
  "redacted": ["email-address"]
}
```

### Response file structure

```json
{
  "type": "response",
  "ts": "2026-03-22T23:56:14.515944+00:00",
  "status": 200,
  "body": { ... }
}
```

### Body encoding rules

| Source bytes | Logged as |
|---|---|
| Empty | `null` |
| Gzip-compressed (magic `1f 8b`) | Decompressed, then re-evaluated |
| Valid JSON | Parsed object (nested inline, no escaping) |
| Valid UTF-8 text (SSE, version strings) | Plain string |
| Binary (protobuf, etc.) | `"<binary N bytes>"` |

---

## Traffic Overview

| Method  | Count | Purpose                                    |
|---------|-------|--------------------------------------------|
| CONNECT | ~58   | TLS tunnel establishment (HTTPS proxy)     |
| POST    | ~58   | Inference, telemetry, MCP protocol, events |
| GET     | ~20   | Config, feature flags, version checks      |

| Status | Count | Meaning                        |
|--------|-------|--------------------------------|
| 200    | 32    | OK                             |
| 400    | 10    | Bad request (truncated bodies) |
| 401    | 6     | Auth required (MCP proxy)      |
| 202    | 4     | Accepted (async telemetry)     |

Redaction categories detected: `email-address` (11), `phone-international` (6), `credit-card` (1).

---

## 1. Anthropic Messages API

`POST https://api.anthropic.com/v1/messages?beta=true`

The core inference endpoint. 7 requests observed.

### Request variants

Three distinct request shapes observed:

**Quota check (lightweight):**
```json
{
  "model": "claude-haiku-4-5-20251001",
  "max_tokens": 1,
  "messages": [{"role": "user", "content": "quota"}],
  "metadata": {
    "user_id": "{\"device_id\":\"<sha256>\",\"account_uuid\":\"<uuid>\",\"session_id\":\"<uuid>\"}"
  }
}
```

**Standard inference (with tools + structured output):**
```json
{
  "model": "claude-haiku-4-5-20251001",
  "max_tokens": 32000,
  "stream": true,
  "system": [
    {"type": "text", "text": "x-anthropic-billing-header: cc_version=2.1.81..."},
    {"type": "text", "text": "You are Claude Code, Anthropic's official CLI..."}
  ],
  "messages": [{"role": "user", "content": "..."}],
  "tools": [ /* tool definitions */ ],
  "output_config": {
    "format": {
      "type": "json_schema",
      "schema": {
        "type": "object",
        "properties": {"title": {"type": "string"}},
        "required": ["title"],
        "additionalProperties": false
      }
    }
  },
  "temperature": 1.0,
  "metadata": {"user_id": "..."}
}
```

**Extended thinking inference:**
```json
{
  "model": "claude-haiku-4-5-20251001",
  "max_tokens": 32000,
  "stream": true,
  "system": [ /* same as above */ ],
  "messages": [{"role": "user", "content": "..."}],
  "tools": [ /* tool definitions */ ],
  "thinking": {
    "budget_tokens": 31999,
    "type": "enabled"
  },
  "context_management": {
    "edits": [
      {"type": "clear_thinking_20251015", "keep": "all"}
    ]
  },
  "metadata": {"user_id": "..."}
}
```

### System prompt structure

Array of `{type, text}` objects. First block is always a billing header:
```
x-anthropic-billing-header: cc_version=2.1.81.000; cc_entrypoint=cli; cch=<hash>;
```
Second block contains the full Claude Code system prompt.

### Tool definitions (observed)

190+ tools registered per request. Categories:

| Prefix              | Count | Provider     |
|---------------------|-------|--------------|
| (none)              | ~25   | Built-in     |
| `mcp__Azure_MCP_server__` | ~60 | Azure MCP  |
| `mcp__gemini__`     | ~35   | Gemini MCP   |
| `mcp__github__`     | ~30   | GitHub MCP   |
| `mcp__playwright__` | ~20   | Playwright   |
| `mcp__cloudflare__` | ~20   | Cloudflare   |

Built-in tools: `Agent`, `Bash`, `Edit`, `Glob`, `Grep`, `Read`, `Write`, `Skill`, `WebFetch`, `WebSearch`, `SendMessage`, `TaskCreate`, `TaskGet`, `TaskList`, `TaskOutput`, `TaskStop`, `TaskUpdate`, `TeamCreate`, `TeamDelete`, `AskUserQuestion`, `CronCreate`, `CronDelete`, `CronList`, `EnterPlanMode`, `EnterWorktree`, `ExitPlanMode`, `ExitWorktree`, `LSP`, `ListMcpResourcesTool`, `NotebookEdit`, `ReadMcpResourceTool`.

### Response structure

```json
{
  "id": "msg_<id>",
  "type": "message",
  "role": "assistant",
  "model": "claude-haiku-4-5-20251001",
  "content": [{"type": "text", "text": "..."}],
  "stop_reason": "max_tokens",
  "stop_sequence": null,
  "usage": {
    "input_tokens": 8,
    "cache_creation_input_tokens": 0,
    "cache_read_input_tokens": 0,
    "cache_creation": {
      "ephemeral_5m_input_tokens": 0,
      "ephemeral_1h_input_tokens": 0
    },
    "output_tokens": 1,
    "service_tier": "standard",
    "inference_geo": "not_available"
  },
  "context_management": null
}
```

Key `usage` fields:
- `cache_creation_input_tokens` / `cache_read_input_tokens`: prompt caching stats
- `cache_creation.ephemeral_5m_input_tokens` / `ephemeral_1h_input_tokens`: ephemeral cache tiers
- `service_tier`: "standard"
- `inference_geo`: geographic routing info

**Responses are gzip-compressed.** Must decompress before parsing.

---

## 2. Anthropic Account & Config APIs

### Account settings
`GET https://api.anthropic.com/api/oauth/account/settings`

Massive settings blob with 60+ keys. Notable fields:

```json
{
  "grove_enabled": true,
  "domain_excluded": false,
  "enabled_mcp_tools": ...,
  "enabled_web_search": ...,
  "enabled_artifacts_attachments": ...,
  "enabled_saffron": ...,
  "enabled_saffron_search": ...,
  "paprika_mode": ...,
  "orbit_enabled": ...,
  "orbit_timezone": ...,
  "wiggle_egress_allowed_hosts": ...,
  "wiggle_egress_hosts_template": ...,
  "tool_search_mode": ...,
  "ccr_persistent_memory": ...,
  "ccr_autofix_on_pr_create": ...,
  "ccr_auto_archive_on_pr_close": ...,
  "internal_tier_rate_limit_tier": ...,
  "internal_tier_seat_tier": ...
}
```

Feature flag groups:
- **Grove**: `grove_enabled`, `grove_notice_viewed_at`, `grove_updated_at`
- **CCR (Claude Code Review)**: `ccr_autofix_on_pr_create`, `ccr_auto_archive_on_pr_close`, `ccr_persistent_memory`, `ccr_sharing_*`
- **Orbit**: `orbit_enabled`, `orbit_timezone`
- **Wiggle egress**: `wiggle_egress_allowed_hosts`, `wiggle_egress_hosts_template`
- **Product features**: `enabled_web_search`, `enabled_mcp_tools`, `enabled_artifacts_attachments`, `enabled_geolocation`, `enabled_gdrive`, `enabled_gdrive_indexing`
- **Internal tiers**: `internal_tier_rate_limit_tier`, `internal_tier_seat_tier`, `internal_tier_org_type`

### Grove status
`GET https://api.anthropic.com/api/claude_code_grove`

```json
{
  "grove_enabled": true,
  "domain_excluded": false,
  "notice_is_grace_period": false,
  "notice_reminder_frequency": 0
}
```

### Penguin mode
`GET https://api.anthropic.com/api/claude_code_penguin_mode`

```json
{
  "enabled": false,
  "disabled_reason": "extra_usage_disabled"
}
```

### CLI client data
`GET https://api.anthropic.com/api/oauth/claude_cli/client_data`

```json
{"client_data": {}}
```

### MCP servers registry
`GET https://api.anthropic.com/v1/mcp_servers?limit=1000`

```json
{
  "data": [ /* array of MCP server objects */ ],
  "next_page": null
}
```

---

## 3. Anthropic Event Telemetry

`POST https://api.anthropic.com/api/event_logging/v2/batch`

Batched events, ~124 events per batch. 6 requests observed.

### Event structure

```json
{
  "events": [
    {
      "event_type": "ClaudeCodeInternalEvent",
      "event_data": {
        "event_name": "<tengu_event_name>",
        "client_timestamp": "2026-03-22T23:28:52.867Z",
        "model": "claude-haiku-4-5-20251001",
        "session_id": "<uuid>",
        "user_type": "external",
        "betas": "oauth-2025-04-20,interleaved-thinking-2025-05-14,...",
        "entrypoint": "cli",
        "is_interactive": true,
        "client_type": "cli",
        "env": { /* environment block */ },
        "auth": {
          "organization_uuid": "<uuid>",
          "account_uuid": "<uuid>"
        },
        "process": "<base64>",
        "additional_metadata": "<base64>"
      }
    }
  ]
}
```

### Environment block

```json
{
  "platform": "darwin",
  "node_version": "v24.3.0",
  "terminal": "iTerm.app",
  "package_managers": "npm,pnpm",
  "runtimes": "bun,deno,node",
  "is_running_with_bun": true,
  "is_ci": false,
  "is_claude_ai_auth": true,
  "version": "2.1.81",
  "arch": "arm64",
  "deployment_environment": "unknown-darwin",
  "build_time": "2026-03-20T21:26:18Z",
  "vcs": "git",
  "platform_raw": "darwin"
}
```

### All observed event names (tengu_ prefix)

**Lifecycle:** `tengu_started`, `tengu_init`, `tengu_exit`, `tengu_timer`

**API:** `tengu_api_query`, `tengu_api_success`, `tengu_api_error`, `tengu_api_before_normalize`, `tengu_api_after_normalize`, `tengu_api_cache_breakpoints`

**MCP:** `tengu_mcp_servers`, `tengu_mcp_tools_commands_loaded`, `tengu_mcp_list_changed`, `tengu_mcp_instructions_pool_change`, `tengu_mcp_server_connection_succeeded`, `tengu_mcp_server_connection_failed`, `tengu_mcp_server_needs_auth`, `tengu_mcp_claudeai_proxy_401`, `tengu_claudeai_mcp_eligibility`

**System prompt:** `tengu_sysprompt_block`, `tengu_sysprompt_boundary_found`, `tengu_sysprompt_missing_boundary_marker`, `tengu_sysprompt_using_tool_based_cache`

**Features:** `tengu_plugins_loaded`, `tengu_skill_loaded`, `tengu_memdir_loaded`, `tengu_claudemd__initial_load`, `tengu_tool_search_mode_decision`, `tengu_prompt_suggestion_init`, `tengu_attachments`

**UI/UX:** `tengu_input_prompt`, `tengu_paste_text`, `tengu_tip_shown`, `tengu_status_line_mount`, `tengu_session_title_generated`

**Updates:** `tengu_version_check_success`, `tengu_version_lock_failed`, `tengu_native_auto_updater_start`, `tengu_native_auto_updater_success`, `tengu_native_update_complete`, `tengu_native_version_cleanup`

**Infra:** `tengu_concurrent_sessions`, `tengu_context_size`, `tengu_dir_search`, `tengu_file_history_snapshot_success`, `tengu_ripgrep_availability`, `tengu_shell_set_cwd`, `tengu_startup_telemetry`, `tengu_startup_manual_model_config`, `tengu_run_hook`, `tengu_repl_hook_finished`, `tengu_claudeai_limits_status_changed`

---

## 4. MCP Protocol (JSON-RPC 2.0)

Two MCP transports observed:

| Transport | Endpoint | Server |
|-----------|----------|--------|
| Cloudflare Workers Bindings | `POST https://bindings.mcp.cloudflare.com/mcp` | `workers-bindings v0.4.5` |
| Anthropic MCP Proxy | `POST https://mcp-proxy.anthropic.com/v1/mcp/<server_id>` | Varies (requires OAuth) |

### Protocol flow

```
1. CONNECT (TLS tunnel)
2. POST initialize         -> server capabilities
3. POST notifications/initialized  (no response expected)
4. POST tools/list         -> tool definitions
5. POST prompts/list       -> prompt definitions
6. POST tools/call         -> tool execution (not observed in this capture)
```

### Initialize

**Request:**
```json
{
  "method": "initialize",
  "params": {
    "protocolVersion": "2025-11-25",
    "capabilities": {
      "roots": {},
      "elicitation": {"form": {}, "url": {}}
    },
    "clientInfo": {"name": "claude-code", "version": "2.1.81"}
  },
  "jsonrpc": "2.0",
  "id": 0
}
```

**Response (SSE):**
```
event: message
data: {"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{"listChanged":true},"prompts":{"listChanged":true},"completions":{}},"serverInfo":{"name":"workers-bindings","version":"0.4.5"}},"jsonrpc":"2.0","id":0}
```

Note: MCP responses arrive as **Server-Sent Events** (`event: message\ndata: <json>`), not plain JSON.

### Cloudflare Workers Bindings tools (from SSE capture)

Full tool list from the `workers-bindings` MCP server:

**KV:** `kv_namespaces_list`, `kv_namespace_create`, `kv_namespace_delete`, `kv_namespace_get`, `kv_namespace_update`
**R2:** `r2_buckets_list`, `r2_bucket_create`, `r2_bucket_delete`, `r2_bucket_get`
**D1:** `d1_databases_list`, `d1_database_create`, `d1_database_delete`, `d1_database_get`, `d1_database_query`
**Workers:** `workers_list`, `workers_get_worker`, `workers_get_worker_code`
**Hyperdrive:** `hyperdrive_configs_list`, `hyperdrive_config_get`, `hyperdrive_config_edit`, `hyperdrive_config_delete`
**Other:** `accounts_list`, `search_cloudflare_documentation`, `migrate_pages_to_workers_guide`

### Cloudflare prompts

```json
{
  "prompts": [{
    "name": "workers-prompt-full",
    "description": "Detailed prompt for generating Cloudflare Workers code..."
  }]
}
```

### MCP Proxy auth error

When OAuth isn't configured:
```json
{
  "type": "error",
  "error": {
    "type": "authentication_error",
    "message": "MCP server requires authentication but no OAuth token is configured."
  },
  "request_id": "req_<id>"
}
```
Status: 401

---

## 5. OpenTelemetry

`POST https://<your-otel-collector>/v1/metrics`
`POST https://<your-otel-collector>/v1/logs`

**Format:** Binary protobuf (not JSON). Gzip-compressed.

Decoded resource attributes from protobuf (example):

```
project     = "example_project"
team        = "homelab"
environment = "personal"
device      = "macos"
machine     = "workstation"
host.arch   = "arm64"
os.type     = "darwin"
os.version  = "24.6.0"
service.name    = "claude-code"
service.version = "2.1.81"
terminal.type   = "iTerm.app"
```

Metrics observed:
- `com.anthropic.claude_code` (version gauge)
- `claude_code.session.count` (session counter)

---

## 6. Datadog

`POST https://http-intake.logs.us5.datadoghq.com/api/v2/logs`

Single request observed. Region: US5. Log forwarding endpoint.

---

## 7. Version Check

`GET https://storage.googleapis.com/claude-code-dist-<bucket-id>/claude-code-releases/latest`

Returns latest version string. Response is gzip-compressed.

---

## 8. Azure IMDS Probe

`GET https://169.254.169.254/metadata/instance/compute?api-version=2017-08-01&format=json`

Azure Instance Metadata Service (IMDS) probe. Not AWS -- this uses the Azure API version. Likely probing to detect if running in Azure. 2 requests observed, no successful responses captured.

---

## Error Patterns

### Content-Length mismatch after redaction (fixed)

Previously caused 400s when `do_match` redaction changed body size but the original
`Content-Length` header was forwarded unchanged. The proxy now updates the header
after redaction. Error looked like:
```json
{
  "type": "error",
  "error": {
    "type": "invalid_request_error",
    "message": "The request body is not valid JSON: unexpected end of data: line 1 column 252631 (char 252630)"
  }
}
```

### MCP auth failures (401s)

6 responses, all from `mcp-proxy.anthropic.com`. OAuth token not configured for remote MCP servers.

---

## Encoding Notes

The proxy handles these transparently in the log files:

- **Gzip:** Anthropic API and GCS responses are gzip-encoded. Auto-decompressed before logging.
- **JSON bodies:** Parsed and embedded as structured objects (no escaped quotes or newlines).
- **Protobuf:** OTEL metrics/logs are binary protobuf. Logged as `"<binary N bytes>"`.
- **SSE:** Streaming responses (`event: message\ndata: {...}`) logged as plain text strings.
- **Base64:** Event telemetry encodes `process` and `additional_metadata` fields as base64.
- **Nested JSON strings:** `metadata.user_id` in Messages API is a JSON string containing another JSON object.
