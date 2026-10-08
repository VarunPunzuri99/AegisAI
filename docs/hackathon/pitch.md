# AegisAI — 3-Minute Pitch

**Submission deck (upload one of these):**

- [AegisAI-Pitch-Deck.pdf](./AegisAI-Pitch-Deck.pdf)
- [AegisAI-Pitch-Deck.pptx](./AegisAI-Pitch-Deck.pptx)

Regenerate: `python docs/hackathon/build_pitch_deck.py` (needs `python-pptx`, `reportlab`, Pillow).

## 0:00–0:20 — Problem

AI agents don't only read chat text. They read documents, websites, emails, and tool outputs. Any of these can contain instructions that attempt to hijack the agent — override intent, call tools, or steal secrets.

## 0:20–0:45 — Solution

**AegisAI is a runtime security layer between untrusted content and agent actions.**

**Detect → Understand → Decide → Protect → Audit**

## 0:45–1:20 — Architecture

Rules + Prompt Guard + Semantic classifier → Fusion → Risk → Policy → Agent workflow → Authentication → Authorization → Tool Firewall → Approval/Replay → Mock MCP Gateway → Mock tools → Audit.

The key idea: detecting prompt injection is only the first layer. AegisAI also prevents a compromised agent from turning untrusted instructions into unauthorized tool actions.

## 1:20–2:20 — Live demo

1. Benign request → ALLOW/REVIEW, safe path  
2. Direct prompt injection → BLOCK/REVIEW, tools not executed  
3. Indirect document injection → untrusted content contained  
4. Intent hijack → Tool Firewall DENY  
5. High-risk delete → REQUIRES_APPROVAL (bound approval)  
6. MCP tampering / shadowing → DENY  

## 2:20–2:45 — Evidence

From the repository evaluation artifacts (dataset measurements, not production guarantees):

- Live detection F1 **0.9706** (P 0.9925 / R 0.9496)
- Security invariants **45/45**
- Authorization eval **11/11**
- MCP eval **15/15**
- Backend tests **356+** (plus Phase 18 E2E)
- Audit trail with content hash only

Conservative REVIEW volume (e.g. 144 REVIEW on live policy mix) is intentional — uncertainty is not silently treated as safe.

## 2:45–3:00 — Closing

AegisAI demonstrates defense-in-depth for agentic systems: detect untrusted instructions, decide with explainable risk/policy, and **protect the tool boundary** even when the model is confused.

This is a **hackathon prototype**, not a production security product. Mock MCP and mock tools keep the demo safe while proving the architecture.
