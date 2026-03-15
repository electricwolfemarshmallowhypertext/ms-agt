/**
 * Lightweight HTTP server for the GitHub Copilot governance extension.
 *
 * Exposes a single POST endpoint at `/agent` that accepts Copilot agent
 * requests and streams responses using Server-Sent Events (SSE).
 *
 * Usage:
 * ```ts
 * import { createServer } from '@agentmesh/copilot-governance/server';
 * const server = createServer({ port: 3000 });
 * server.listen();
 * ```
 *
 * Deploy this server as a GitHub App with the agent endpoint pointing to
 * `https://your-host/agent`.
 */

import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from "http";
import { handleAgentRequest } from "./agent";
import type { AgentRequest } from "./types";

export interface ServerOptions {
  /** TCP port to listen on (default: 3000). */
  port?: number;
  /** Host to bind (default: "0.0.0.0"). */
  host?: string;
}

/**
 * Create the Copilot governance extension HTTP server.
 *
 * The server handles:
 * - `GET /health` — Liveness probe
 * - `POST /agent` — Copilot Extension agent endpoint (SSE stream)
 */
export function createServer(options: ServerOptions = {}) {
  const port = options.port ?? 3000;
  const host = options.host ?? "0.0.0.0";

  const server = createHttpServer(async (req: IncomingMessage, res: ServerResponse) => {
    // ── Health check ────────────────────────────────────────────────────────
    if (req.method === "GET" && req.url === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "ok", service: "copilot-governance" }));
      return;
    }

    // ── Agent endpoint ───────────────────────────────────────────────────────
    if (req.method === "POST" && req.url === "/agent") {
      let body = "";
      req.on("data", (chunk: Buffer) => {
        body += chunk.toString();
      });

      req.on("end", async () => {
        let parsed: AgentRequest;
        try {
          parsed = JSON.parse(body) as AgentRequest;
        } catch {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Invalid JSON body" }));
          return;
        }

        if (!Array.isArray(parsed?.messages)) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Request must include a `messages` array" }));
          return;
        }

        // Stream SSE response
        res.writeHead(200, {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          Connection: "keep-alive",
          "X-Accel-Buffering": "no",
        });

        try {
          for await (const token of handleAgentRequest(parsed)) {
            const data = JSON.stringify({ choices: [{ delta: { content: token.content } }] });
            res.write(`data: ${data}\n\n`);
          }
          res.write("data: [DONE]\n\n");
        } catch (err) {
          const msg = err instanceof Error ? err.message : "Unknown error";
          const data = JSON.stringify({ error: msg });
          res.write(`data: ${data}\n\n`);
        } finally {
          res.end();
        }
      });

      return;
    }

    // ── 404 fallback ─────────────────────────────────────────────────────────
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not found" }));
  });

  return {
    /** Start listening on the configured port. */
    listen() {
      server.listen(port, host, () => {
        console.log(`[copilot-governance] Server listening on http://${host}:${port}`);
      });
      return server;
    },
    /** Underlying Node.js http.Server instance. */
    server,
  };
}
