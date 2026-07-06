/**
 * sasana-openclaw — forwards real OpenClaw Gateway lifecycle hooks to the
 * Sasana Python ledger over a local Unix domain socket.
 *
 * Hooked events (OpenClaw Plugin SDK, api.on(...), confirmed against a live
 * v2026.6.6 gateway): session_start, session_end, before_tool_call,
 * after_tool_call, model_call_started, model_call_ended, llm_input,
 * llm_output.
 *
 * This plugin never persists anything itself and never blocks a decision —
 * every hook here is observation-only. If the Python bridge (`sasana
 * bridge`) isn't running, events are dropped (bounded queue) rather than
 * raised, so a missing/crashed bridge can never affect a live agent turn.
 */

import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import net from "node:net";
import os from "node:os";
import path from "node:path";

const DEFAULT_SOCKET_PATH = path.join(os.homedir(), ".openclaw", "sasana", "bridge.sock");
const MAX_QUEUE = 200;

type Logger = {
  debug?: (msg: string) => void;
  warn?: (msg: string) => void;
  info?: (msg: string) => void;
};

class SasanaBridgeClient {
  private socket: net.Socket | null = null;
  private connecting = false;
  private queue: string[] = [];
  private closed = false;
  private readonly socketPath: string;
  private readonly logger: Logger;

  constructor(socketPath: string, logger: Logger) {
    this.socketPath = socketPath;
    this.logger = logger;
  }

  connect(): void {
    if (this.closed || this.socket || this.connecting) return;
    this.connecting = true;
    const sock = net.createConnection(this.socketPath);
    sock.on("connect", () => {
      this.connecting = false;
      this.socket = sock;
      const pending = this.queue.splice(0);
      for (const line of pending) sock.write(line);
    });
    sock.on("error", (err) => {
      this.connecting = false;
      this.socket = null;
      this.logger.debug?.(`sasana-openclaw: bridge unavailable (${String(err)})`);
    });
    sock.on("close", () => {
      this.socket = null;
    });
  }

  send(event: Record<string, unknown>): void {
    if (this.closed) return;
    const line = JSON.stringify(event) + "\n";
    if (this.socket && !this.socket.destroyed) {
      this.socket.write(line);
      return;
    }
    if (this.queue.length < MAX_QUEUE) this.queue.push(line);
    this.connect();
  }

  close(): void {
    this.closed = true;
    this.socket?.end();
    this.socket = null;
  }
}

function nowIso(): string {
  return new Date().toISOString();
}

export default definePluginEntry({
  id: "sasana-openclaw",
  name: "Sasana",
  description: "Forwards OpenClaw lifecycle events to the Sasana tamper-evident audit ledger.",
  register(api) {
    const socketPath = process.env.SASANA_BRIDGE_SOCKET || DEFAULT_SOCKET_PATH;
    const bridge = new SasanaBridgeClient(socketPath, api.logger ?? {});

    const forward = (hook: string, event: any, ctx: any) => {
      try {
        bridge.send({
          hook,
          ts: nowIso(),
          sessionKey: ctx?.sessionKey ?? event?.sessionKey,
          sessionId: ctx?.sessionId,
          agentId: ctx?.agentId,
          runId: ctx?.runId ?? event?.runId,
          reason: event?.reason,
          toolName: event?.toolName,
          params: event?.params,
          result: event?.result ?? event?.output,
          error: event?.error ?? event?.errorMessage,
          durationMs: event?.durationMs,
          provider: event?.provider,
          model: event?.model,
          outcome: event?.outcome,
          prompt: event?.prompt,
          systemPrompt: event?.systemPrompt,
          messages: event?.messages,
          content: event?.content,
          usage: event?.usage,
        });
      } catch (err) {
        api.logger?.debug?.(`sasana-openclaw: forward error: ${String(err)}`);
      }
    };

    api.on("gateway_start", async () => {
      bridge.connect();
    });
    api.on("gateway_stop", async () => {
      bridge.close();
    });

    api.on("session_start", async (event: any, ctx: any) => {
      forward("session_start", event, ctx);
    });
    api.on("session_end", async (event: any, ctx: any) => {
      forward("session_end", event, ctx);
    });
    api.on("before_tool_call", async (event: any, ctx: any) => {
      forward("before_tool_call", event, ctx);
      return undefined;
    });
    api.on("after_tool_call", async (event: any, ctx: any) => {
      forward("after_tool_call", event, ctx);
    });
    api.on("model_call_started", async (event: any, ctx: any) => {
      forward("model_call_started", event, ctx);
    });
    api.on("model_call_ended", async (event: any, ctx: any) => {
      forward("model_call_ended", event, ctx);
    });
    api.on("llm_input", async (event: any, ctx: any) => {
      forward("llm_input", event, ctx);
    });
    api.on("llm_output", async (event: any, ctx: any) => {
      forward("llm_output", event, ctx);
    });
  },
});
