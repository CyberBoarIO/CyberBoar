// CyberBoar plugin for opencode, written by `cyberboar apply --agent opencode`
// Do not edit: run apply again instead
//
// Every tool call is checked by the cyberboar hook before it runs. The call is
// blocked (this plugin throws) unless the hook answers exactly
// {"decision":"none"} with exit status 0: a missing binary, a crash, a
// timeout, any other exit status and any other output block it too
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const name = "cyberboar";
const command = "/usr/local/bin/cyberboar";
const hookArgs = ["hook","--agent","opencode","--policy","/etc/cyberboar/policy.yaml","--audit","/var/log/cyberboar/audit.jsonl","--pubkey","/etc/cyberboar/policy.pub","--deadline","5s"];
const briefArgs = ["brief","--agent","opencode","--policy","/etc/cyberboar/policy.yaml","--pubkey","/etc/cyberboar/policy.pub"];
const timeoutMs = 15000;
// Project scope: the hook runs in the project root (two levels above this
// file), which a relative policy path is relative to
const cwd = false ? fileURLToPath(new URL("../../", import.meta.url)) : undefined;
const maxOutput = 1 << 20;

function run(args, input) {
  return new Promise((resolve, reject) => {
    let done = false;
    let timer;
    const finish = (fn, value) => {
      if (!done) {
        done = true;
        clearTimeout(timer);
        fn(value);
      }
    };
    let child;
    try {
      child = spawn(command, args, { cwd, shell: false, windowsHide: true, stdio: ["pipe", "pipe", "pipe"] });
    } catch (err) {
      finish(reject, err);
      return;
    }
    const kill = () => {
      try {
        child.kill("SIGKILL");
      } catch {}
    };
    timer = setTimeout(() => {
      kill();
      finish(reject, new Error(`no answer within ${timeoutMs} ms`));
    }, timeoutMs);
    const stdout = [];
    const stderr = [];
    let size = 0;
    const collect = (chunks) => (chunk) => {
      size += chunk.length;
      if (size > maxOutput) {
        kill();
        finish(reject, new Error("more output than a hook answer"));
        return;
      }
      chunks.push(chunk);
    };
    child.stdout.on("data", collect(stdout));
    child.stderr.on("data", collect(stderr));
    child.on("error", (err) => finish(reject, err));
    child.on("close", (code, signal) =>
      finish(resolve, {
        code,
        signal,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      }),
    );
    // A hook that exits without reading its input still answers by its exit status and output
    child.stdin.on("error", () => {});
    child.stdin.end(input);
  });
}

function noObjection(r) {
  if (r.code !== 0) return false;
  let v;
  try {
    v = JSON.parse(r.stdout);
  } catch {
    return false;
  }
  return v !== null && typeof v === "object" && !Array.isArray(v) && Object.keys(v).length === 1 && v.decision === "none";
}

function reasonOf(r) {
  try {
    const v = JSON.parse(r.stdout);
    const s = v?.reason ?? v?.hookSpecificOutput?.permissionDecisionReason;
    if (typeof s === "string" && s !== "") return s;
  } catch {}
  const e = r.stderr.trim();
  if (e !== "") return e.slice(0, 4000);
  return `${name}: the policy check answered with ${r.code === null ? "signal " + r.signal : "exit status " + r.code} and no reason, so the tool call is blocked`;
}

async function check(call) {
  let r;
  try {
    r = await run(hookArgs, JSON.stringify(call));
  } catch (err) {
    throw new Error(`${name}: the policy check could not run (${err?.message ?? err}), so the tool call is blocked`);
  }
  if (!noObjection(r)) throw new Error(reasonOf(r));
}

let briefing;
function brief() {
  briefing ??= run(briefArgs, "")
    .then((r) => {
      if (r.code === 0 && r.stdout.trim() === "") return "";
      const text = JSON.parse(r.stdout).additionalContext;
      if (r.code !== 0 || typeof text !== "string") throw new Error("no briefing text");
      return text;
    })
    .catch(() => `${name}: the policy briefing could not be loaded. Every tool call is still checked against the policy.`);
  return briefing;
}

export const plugin = async (ctx) => {
  const directory = ctx?.directory;
  const worktree = ctx?.worktree;
  // Unknown until the config hook runs, which opencode does before any tool
  // call; the hook refuses calls while they are unknown
  let shell = null;
  let mcpServers = null;
  const hooks = {
    config: async (config) => {
      shell = typeof config?.shell === "string" ? config.shell : "";
      mcpServers = config?.mcp !== null && typeof config?.mcp === "object" ? Object.keys(config.mcp).sort() : [];
    },
    "tool.execute.before": async (input, output) => {
      await check({
        tool: input?.tool,
        sessionID: input?.sessionID,
        callID: input?.callID,
        args: output?.args,
        directory,
        worktree,
        shell,
        mcpServers,
      });
    },
  };
  if (briefArgs !== null) {
    hooks["experimental.chat.system.transform"] = async (input, output) => {
      const text = await brief();
      if (text !== "" && Array.isArray(output?.system)) output.system.push(text);
    };
  }
  return hooks;
};
