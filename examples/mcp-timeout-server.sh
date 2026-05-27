#!/bin/sh
set -eu

log_if_configured() {
  if [ "${AGENTK_FAKE_MCP_EXEC_LOG:-}" ]; then
    printf '%s\n' "$1" >> "$AGENTK_FAKE_MCP_EXEC_LOG"
  fi
}

while IFS= read -r line; do
  case "$line" in
    *agentk*) log_if_configured "metadata leaked" ;;
  esac

  case "$line" in
    *'"method":"initialize"'*)
      printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"agentk-public-timeout-demo","version":"test"}}}'
      ;;
    *'"method":"notifications/initialized"'*)
      ;;
    *'"method":"tools/list"'*)
      printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"demo.hang","description":"Accepts a public request and then never returns a tool response.","inputSchema":{"type":"object","properties":{"input_ref":{"type":"string"}}}}]}}'
      ;;
    *'"id":3'*'"method":"tools/call"'*)
      log_if_configured "timeout tool called"
      while IFS= read -r _; do :; done
      ;;
    *)
      printf '%s\n' '{"jsonrpc":"2.0","id":999,"error":{"code":-32601,"message":"unknown fake request"}}'
      ;;
  esac
done
