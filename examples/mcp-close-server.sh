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
      printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"agentk-public-close-demo","version":"test"}}}'
      ;;
    *'"method":"notifications/initialized"'*)
      ;;
    *'"method":"tools/list"'*)
      printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"demo.close","description":"Accepts a public request and closes stdout before returning a tool response.","inputSchema":{"type":"object","properties":{"input_ref":{"type":"string"}}}}]}}'
      ;;
    *'"id":3'*'"method":"tools/call"'*)
      log_if_configured "close tool called"
      exit 0
      ;;
    *)
      printf '%s\n' '{"jsonrpc":"2.0","id":999,"error":{"code":-32601,"message":"unknown fake request"}}'
      ;;
  esac
done
