/**
 * Static code reviewer for agent governance gaps.
 *
 * Analyses source code (Python or TypeScript/JavaScript) for:
 * - Missing governance middleware wrapping
 * - Unguarded tool calls (direct .execute() without policy check)
 * - Missing audit logging
 * - Absence of PII redaction
 * - Unconstrained tool allow-lists
 *
 * Each finding is mapped to relevant OWASP Agentic Top-10 risk IDs.
 */

import type { ReviewFinding, ReviewResult, Severity } from "./types";

/** A review rule with its detector logic. */
interface Rule {
  ruleId: string;
  title: string;
  severity: Severity;
  owaspRisks: string[];
  /** Returns a finding (with optional line) if the rule fires, or null. */
  detect(source: string): Omit<ReviewFinding, "ruleId" | "title" | "severity" | "owaspRisks"> | null;
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

const RULES: Rule[] = [
  // ── 1. Governance middleware missing ──────────────────────────────────────
  {
    ruleId: "missing-governance-middleware",
    title: "No governance middleware detected",
    severity: "high",
    owaspRisks: ["AT07", "AT08"],
    detect(source) {
      const hasGovernance =
        /governanceMiddleware|governance_middleware|GovernancePolicy|apply_governance/i.test(source);
      if (hasGovernance) return null;
      // Only flag if there are tool definitions — not every file needs governance
      const hasTools =
        /createTool|BaseTool|Tool\b|@tool|def\s+\w+.*tool/i.test(source) ||
        /execute\s*[:(]|\.execute\(/i.test(source);
      if (!hasTools) return null;
      return {
        description:
          "This file defines or executes agent tools but does not apply governance middleware. " +
          "Without policy enforcement, tools can be invoked without rate-limiting, " +
          "content filtering, or allow/deny-list checks.",
        suggestion:
          "Wrap your tool with `governanceMiddleware` (TS) or `apply_governance` (Python):\n\n" +
          "```ts\nimport { createGovernedTool } from '@agentmesh/mastra';\n" +
          "const safe = createGovernedTool(myTool, {\n" +
          "  governance: { rateLimitPerMinute: 60, blockedPatterns: ['(?i)ignore previous'] },\n" +
          "});\n```",
      };
    },
  },

  // ── 2. Unguarded direct tool execution ────────────────────────────────────
  {
    ruleId: "unguarded-tool-execution",
    title: "Direct tool execution without policy check",
    severity: "high",
    owaspRisks: ["AT07", "AT08"],
    detect(source) {
      // Look for .execute( calls not preceded by a governance/policy check
      const hasDirectExecute = /\.execute\s*\(/.test(source);
      if (!hasDirectExecute) return null;
      const hasGovernanceCheck =
        /\.check\s*\(|governanceMiddleware|createGovernedTool|governance_check|policy\.check/i.test(
          source
        );
      if (hasGovernanceCheck) return null;
      return {
        description:
          "Tool `.execute()` is called directly without a preceding governance policy check. " +
          "This bypasses content filtering, rate limiting, and tool allow-list enforcement.",
        suggestion:
          "Use `createGovernedTool` to wrap the tool, or call `gov.check()` before executing:\n\n" +
          "```ts\nconst result = await gov.check(input, toolId, agentId);\nif (!result.allowed) throw new Error(result.reason);\n```",
      };
    },
  },

  // ── 3. Missing audit logging ───────────────────────────────────────────────
  {
    ruleId: "missing-audit-logging",
    title: "No audit logging detected",
    severity: "high",
    owaspRisks: ["AT09"],
    detect(source) {
      const hasAudit =
        /auditMiddleware|audit_middleware|audit\.record|AuditLog|audit_log|hash_chain/i.test(
          source
        );
      if (hasAudit) return null;
      const hasAgentOrTool =
        /Agent|createTool|BaseTool|\.execute\(/i.test(source);
      if (!hasAgentOrTool) return null;
      return {
        description:
          "No audit logging was found. Without a tamper-evident audit trail, " +
          "tool invocations cannot be reviewed after the fact, which undermines " +
          "accountability and incident response.",
        suggestion:
          "Add audit logging with a hash-chain to detect tampering:\n\n" +
          "```ts\nimport { auditMiddleware } from '@agentmesh/mastra';\n" +
          "const audit = auditMiddleware({ captureData: true });\n" +
          "await audit.record({ toolId, agentId, action: 'invoke', input });\n```",
      };
    },
  },

  // ── 4. No PII redaction ────────────────────────────────────────────────────
  {
    ruleId: "missing-pii-redaction",
    title: "No PII redaction configured",
    severity: "medium",
    owaspRisks: ["AT06"],
    detect(source) {
      const hasPii =
        /piiFields|pii_fields|redact_pii|REDACTED|pii_redact/i.test(source);
      if (hasPii) return null;
      // Only flag if agent handles user input
      const handlesInput =
        /user_input|userInput|input\s*[:=]|message\s*[:=]/i.test(source);
      if (!handlesInput) return null;
      return {
        description:
          "The agent handles user input but no PII redaction is configured. " +
          "Sensitive fields (SSN, email, credit-card numbers) may be logged or " +
          "forwarded to downstream services in plaintext.",
        suggestion:
          "Configure `piiFields` in your governance policy:\n\n" +
          "```ts\ngovernanceMiddleware({\n  piiFields: ['ssn', 'email', 'credit_card', 'password'],\n});\n```",
      };
    },
  },

  // ── 5. No trust verification ───────────────────────────────────────────────
  {
    ruleId: "missing-trust-verification",
    title: "No trust score verification for agent-to-agent calls",
    severity: "medium",
    owaspRisks: ["AT07", "AT08"],
    detect(source) {
      const hasTrust =
        /trustGate|trust_gate|TrustConfig|minTrustScore|min_trust_score|getTrustScore/i.test(
          source
        );
      if (hasTrust) return null;
      // Only flag if multi-agent patterns exist
      const hasMultiAgent =
        /handoff|delegate|sub.?agent|agent.?call|invoke.*agent/i.test(source);
      if (!hasMultiAgent) return null;
      return {
        description:
          "Agent handoffs or sub-agent invocations were found but no trust score " +
          "verification is applied. A compromised sub-agent could perform actions " +
          "beyond its intended scope.",
        suggestion:
          "Add a trust gate before delegating to sub-agents:\n\n" +
          "```ts\nimport { trustGate } from '@agentmesh/mastra';\n" +
          "const gate = trustGate({ minTrustScore: 500, getTrustScore: fetchScore });\n" +
          "const result = await gate.verify(subAgentId);\n" +
          "if (!result.verified) throw new Error('Untrusted agent');\n```",
      };
    },
  },

  // ── 6. Unconstrained tool allow-list ──────────────────────────────────────
  {
    ruleId: "no-tool-allowlist",
    title: "No tool allow-list or deny-list configured",
    severity: "medium",
    owaspRisks: ["AT08"],
    detect(source) {
      const hasAllowlist =
        /allowedTools|allowed_tools|blockedTools|blocked_tools|tool_allowlist|tool_denylist/i.test(
          source
        );
      if (hasAllowlist) return null;
      const hasGovernance =
        /governanceMiddleware|createGovernedTool|governance_middleware/i.test(source);
      if (!hasGovernance) return null; // already caught by rule 1
      return {
        description:
          "Governance middleware is present but no tool allow-list or deny-list is defined. " +
          "Without explicit tool constraints, any tool ID is accepted, which enables " +
          "excessive-agency attacks if the LLM generates an unexpected tool name.",
        suggestion:
          "Define an explicit tool allow-list:\n\n" +
          "```ts\ngovernanceMiddleware({\n" +
          "  allowedTools: ['web-search', 'read-file'],  // only these\n" +
          "  blockedTools: ['shell-exec', 'file-delete'], // never these\n" +
          "});\n```",
      };
    },
  },

  // ── 7. Prompt-injection patterns ──────────────────────────────────────────
  {
    ruleId: "no-prompt-injection-guards",
    title: "No prompt-injection input filters configured",
    severity: "medium",
    owaspRisks: ["AT01"],
    detect(source) {
      const hasPatterns =
        /blockedPatterns|blocked_patterns|prompt.?injection|content.?filter/i.test(source);
      if (hasPatterns) return null;
      const hasGovernance =
        /governanceMiddleware|createGovernedTool|governance_middleware/i.test(source);
      if (!hasGovernance) return null;
      return {
        description:
          "Governance middleware is present but `blockedPatterns` is not set. " +
          "Without content filtering, prompt-injection strings such as " +
          '"ignore previous instructions" can reach the agent.',
        suggestion:
          "Add prompt-injection guards to your policy:\n\n" +
          "```ts\ngovernanceMiddleware({\n" +
          "  blockedPatterns: [\n" +
          "    'ignore (all )?previous instructions',  // i flag applied automatically\n" +
          "    'system prompt',\n" +
          "    'act as (if you are|a)',\n" +
          "  ],\n" +
          "});\n```",
      };
    },
  },
];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Review agent source code for governance gaps.
 *
 * @param source - Raw source code string (Python or TypeScript/JavaScript).
 * @returns A ReviewResult with all findings and a summary.
 *
 * @example
 * ```ts
 * import { reviewCode } from '@agentmesh/copilot-governance';
 *
 * const result = reviewCode(myAgentSource);
 * if (!result.passed) {
 *   console.log(result.summary);
 * }
 * ```
 */
export function reviewCode(source: string): ReviewResult {
  const findings: ReviewFinding[] = [];

  for (const rule of RULES) {
    const match = rule.detect(source);
    if (match) {
      findings.push({
        ruleId: rule.ruleId,
        title: rule.title,
        severity: rule.severity,
        owaspRisks: rule.owaspRisks,
        ...match,
      });
    }
  }

  const critical = findings.filter((f) => f.severity === "critical").length;
  const high = findings.filter((f) => f.severity === "high").length;
  const medium = findings.filter((f) => f.severity === "medium").length;
  const passed = critical === 0 && high === 0;

  let summary: string;
  if (findings.length === 0) {
    summary = "✅ **Governance review passed.** No issues found.";
  } else {
    const parts: string[] = [];
    if (critical) parts.push(`${critical} critical`);
    if (high) parts.push(`${high} high`);
    if (medium) parts.push(`${medium} medium`);
    summary =
      `${passed ? "⚠️" : "❌"} **Governance review found ${findings.length} issue(s)**: ` +
      parts.join(", ") +
      ".";
  }

  return { findings, passed, summary };
}

/**
 * Format a ReviewResult as a Markdown string suitable for a Copilot chat reply.
 */
export function formatReviewResult(result: ReviewResult): string {
  const lines: string[] = [result.summary, ""];

  if (result.findings.length === 0) {
    lines.push(
      "Your agent code follows the governance baseline. " +
        "Consider also running `policy-validate` on your YAML policy files."
    );
    return lines.join("\n");
  }

  for (const finding of result.findings) {
    const badge = severityBadge(finding.severity);
    lines.push(`### ${badge} ${finding.title}`);
    lines.push(`**Rule:** \`${finding.ruleId}\``);
    lines.push("");
    lines.push(finding.description);
    if (finding.suggestion) {
      lines.push("");
      lines.push("**Suggested fix:**");
      lines.push(finding.suggestion);
    }
    if (finding.owaspRisks.length > 0) {
      lines.push("");
      lines.push(
        `**OWASP Agentic Top-10:** ${finding.owaspRisks.map((id) => `\`${id}\``).join(", ")}`
      );
    }
    lines.push("");
    lines.push("---");
    lines.push("");
  }

  lines.push(
    "> 📦 Add governance to your agent in minutes: " +
      "`npm install @agentmesh/mastra` (TypeScript) or " +
      "`pip install agent-os` (Python)."
  );

  return lines.join("\n");
}

function severityBadge(severity: Severity): string {
  switch (severity) {
    case "critical":
      return "🔴";
    case "high":
      return "🟠";
    case "medium":
      return "🟡";
    case "low":
      return "🔵";
    default:
      return "⚪";
  }
}
