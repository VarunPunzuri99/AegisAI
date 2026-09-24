# AegisAI Security Principles

These principles guide design and implementation. AegisAI reduces prompt-injection risk with **multiple layers**. It does **not** claim that prompt injection can be completely eliminated.

---

## 1. Treat external content as untrusted

Any content that did not originate from a trusted control plane (user messages, retrieved documents, emails, web pages, tool outputs, third-party APIs) is untrusted. Untrusted content must not be allowed to redefine system instructions without inspection and policy.

## 2. Separate instructions from data

System and developer instructions must remain structurally separate from untrusted data. Prefer clear delimiters, typed roles, and templates that never concatenate attacker-controlled text into privileged instruction channels.

## 3. Never trust LLM output directly for authorization

Model outputs (including tool-call suggestions, “safe to proceed” claims, or rewritten prompts) are advisory signals only. Authorization and allow/deny decisions must come from explicit policy or deterministic enforcement code.

## 4. Use defense in depth

Combine deterministic rules, specialized classifiers (e.g. Prompt Guard), semantic LLM analysis, risk scoring, policy, and a tool firewall. No single detector is sufficient.

## 5. Tool calls require independent policy checks

Every tool invocation must pass an independent policy gate (allowed tools, arguments, rate limits, destination constraints). Simulated demo tools such as `send_test_email()`, `read_demo_secret()`, and `delete_demo_record()` illustrate this pattern without enabling real abuse.

## 6. Sensitive actions require explicit policy enforcement

High-impact actions (secret access, outbound messaging, destructive operations) require explicit allow rules. Absence of a rule means deny (fail closed for sensitive paths).

## 7. Security decisions must be auditable

Allow, sanitize, quarantine, and block decisions — plus detection categories and risk scores — should be recorded for review and evaluation. Audit data must be useful for red-team and compliance review.

## 8. Detection and authorization are separate concerns

Detection answers: *What suspicious signals are present?*  
Authorization/policy answers: *What action is permitted given risk and context?*  
Do not collapse these into a single opaque LLM call.

## 9. Avoid exposing secrets to models

API keys, credentials, private keys, and similar secrets must not be placed in prompts, logs sent to providers, or frontend code. Configuration loads secrets from the environment on the backend only.

## 10. Fail safely

On detector timeout, provider failure, or ambiguous high-risk signals, prefer quarantine or block for sensitive workflows rather than silently allowing untrusted content into agent context.

## 11. Avoid logging API keys or sensitive credentials

Logs and telemetry must redact secrets, tokens, and credential-like strings. Never log `GROQ_API_KEY` or similar values.

## 12. Never claim that prompt injection can be completely eliminated

Prompt injection is an active research and engineering problem. AegisAI aims to **reduce residual risk**, improve visibility, and enforce policy — not to guarantee absolute prevention.

---

## Design consequence

The pipeline is intentionally layered (ingest → normalize → detect → risk → policy → decide → agent → tool firewall → audit). Each layer has a distinct responsibility so that a failure or bypass in one detector does not automatically grant tool access or privileged actions.
