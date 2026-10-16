#!/usr/bin/env python3
# A scripted OpenAI-compatible endpoint for end-to-end runs, serving both chat
# completions (/v1/chat/completions) and the Responses API (/v1/responses).
#
# Each request that offers tools is answered with the next tool call from the
# script (a JSON list of [tool, arguments]; a tool named "custom:NAME" is sent as
# a freeform custom tool call with the arguments as its text, and in the
# Responses API "ns:NAMESPACE:NAME" is a function call in a namespace), then
# with "done".
# Every request is appended to the log, so a run can check what the agent sent
# the model (the briefing, tool results). No real model is involved.
#
# Usage: scripted-model.py PORT SCRIPT LOG

import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

port, script_path, log_path = int(sys.argv[1]), sys.argv[2], sys.argv[3]
script = json.load(open(script_path))
lock = threading.Lock()
step = [0]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, ctype, body):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.reply(200, "application/json", b'{"object":"list","data":[]}')

    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        with lock:
            with open(log_path, "a") as f:
                f.write(json.dumps(req) + "\n")
            i = step[0]
            if req.get("tools") and i < len(script):
                step[0] += 1
        if self.path.rstrip("/").endswith("/responses"):
            return self.responses_api(req, i)
        if req.get("tools") and i < len(script):
            tool, args = script[i]
            if tool.startswith("custom:"):
                call = {"id": "call_%d" % i, "type": "custom", "custom": {"name": tool[7:], "input": args}}
            else:
                call = {"id": "call_%d" % i, "type": "function", "function": {"name": tool, "arguments": json.dumps(args)}}
            msg, finish = {"role": "assistant", "content": None, "tool_calls": [call]}, "tool_calls"
        else:
            msg, finish = {"role": "assistant", "content": "done"}, "stop"
        base = {"id": "chatcmpl-%d" % i, "created": int(time.time()), "model": req.get("model")}
        usage = {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
        if not req.get("stream"):
            body = dict(base, object="chat.completion", usage=usage,
                        choices=[{"index": 0, "message": msg, "finish_reason": finish}])
            return self.reply(200, "application/json", json.dumps(body).encode())
        delta = dict(msg)
        if "tool_calls" in delta:
            delta["tool_calls"] = [dict(delta["tool_calls"][0], index=0)]
        chunks = [dict(base, object="chat.completion.chunk", choices=[{"index": 0, "delta": delta, "finish_reason": None}]),
                  dict(base, object="chat.completion.chunk", usage=usage, choices=[{"index": 0, "delta": {}, "finish_reason": finish}])]
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        for c in chunks:
            self.wfile.write(b"data: " + json.dumps(c).encode() + b"\n\n")
        self.wfile.write(b"data: [DONE]\n\n")


    def responses_api(self, req, i):
        # The Responses API streams output items and ends with response.completed
        rid = "resp_%d" % i
        if req.get("tools") and i < len(script):
            tool, args = script[i]
            if tool.startswith("custom:"):
                item = {"type": "custom_tool_call", "id": "ctc_%d" % i, "call_id": "call_%d" % i,
                        "name": tool[7:], "input": args, "status": "completed"}
            else:
                item = {"type": "function_call", "id": "fc_%d" % i, "call_id": "call_%d" % i,
                        "name": tool, "arguments": json.dumps(args), "status": "completed"}
                if tool.startswith("ns:"):  # ns:NAMESPACE:NAME, a function in a namespace (Codex's MCP tools)
                    _, item["namespace"], item["name"] = tool.split(":", 2)
        else:
            item = {"type": "message", "id": "msg_%d" % i, "role": "assistant", "status": "completed",
                    "content": [{"type": "output_text", "text": "done", "annotations": []}]}
        usage = {"input_tokens": 1, "input_tokens_details": {"cached_tokens": 0},
                 "output_tokens": 1, "output_tokens_details": {"reasoning_tokens": 0}, "total_tokens": 2}
        response = {"id": rid, "object": "response", "created_at": int(time.time()), "model": req.get("model"),
                    "status": "completed", "output": [item], "usage": usage}
        events = [
            {"type": "response.created", "response": dict(response, status="in_progress", output=[])},
            {"type": "response.output_item.added", "output_index": 0, "item": item},
            {"type": "response.output_item.done", "output_index": 0, "item": item},
            {"type": "response.completed", "response": response},
        ]
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        for e in events:
            self.wfile.write(b"event: " + e["type"].encode() + b"\ndata: " + json.dumps(e).encode() + b"\n\n")


ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
