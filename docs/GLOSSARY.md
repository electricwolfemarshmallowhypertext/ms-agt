# Glossary of Agent Governance Toolkit

This document provides simple explanations for the technical terms used in this toolkit.

### Security & Policy
* **Deterministic Policy Enforcement**: A system that ensures rules are applied exactly as written, with no ambiguity. If a rule says "No Shell Access", the system blocks it every single time.
* **Execution Sandboxing**: A security mechanism for separating running programs. It creates a "safe box" where an AI agent can work without being able to damage the rest of your computer.
* **Middleware**: A software layer that sits between the AI agent and the tools it uses. It acts as a filter to check if an action is allowed before it happens.

### Trust & Identity
* **Trust Score**: A dynamic rating (0-1000) assigned to an agent. Higher scores mean the agent is more "trusted" and has more permissions.
* **Zero-Trust Identity**: A security model where no agent is trusted by default. Every agent must prove its identity using cryptographic keys (like Ed25519) for every action.
* **Audit Logs with Hash Chains**: A tamper-proof record of everything the agent did. Each log entry is mathematically linked to the previous one, so no one can delete or change history without being caught.

### Agentic Issues (ASI)
* **Goal Hijacking (ASI-01)**: When an attacker tricks an AI agent into ignoring its original instructions to follow new, malicious ones.
* **Exfiltration (ASI-06)**: The unauthorized transfer of sensitive data from within the system to an external location controlled by an attacker.
