#!/usr/bin/env python3
# A minimal MCP server on stdio for end-to-end runs.
#
# It offers one tool, do_thing, and one resource, so an agent's MCP tool names
# and resource tools can be seen reaching the hook. Nothing is executed.
#
# Usage: mcp-server.py (the agent starts it)

import json
import sys


def send(msg):
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    try:
        req = json.loads(line)
    except ValueError:
        continue
    rid, method = req.get("id"), req.get("method")
    if rid is None:
        continue
    result = None
    if method == "initialize":
        result = {"protocolVersion": req.get("params", {}).get("protocolVersion", "2024-11-05"),
                  "capabilities": {"tools": {}, "resources": {}}, "serverInfo": {"name": "e2e", "version": "1"}}
    elif method == "tools/list":
        result = {"tools": [{"name": "do_thing", "description": "Does a thing.",
                             "inputSchema": {"type": "object", "properties": {"a": {"type": "string"}}}}]}
    elif method == "tools/call":
        result = {"content": [{"type": "text", "text": "did it"}]}
    elif method == "resources/list":
        result = {"resources": [{"uri": "e2e://x", "name": "x"}]}
    elif method == "resources/templates/list":
        result = {"resourceTemplates": []}
    elif method == "resources/read":
        result = {"contents": [{"uri": "e2e://x", "text": "resource"}]}
    elif method == "prompts/list":
        result = {"prompts": []}
    if result is None:
        send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "method not found"}})
    else:
        send({"jsonrpc": "2.0", "id": rid, "result": result})
