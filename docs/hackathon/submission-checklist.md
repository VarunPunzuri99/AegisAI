# Hackathon Submission Checklist

## Product

- [x] Product name: AegisAI
- [x] One-line description: Agentic Prompt Injection Firewall
- [x] Problem statement (README + pitch)
- [x] Solution statement (Detect → Understand → Decide → Protect → Audit)
- [x] Architecture docs
- [x] Demo flow (demo-script.md)

## Code

- [ ] Backend tests pass _(run before submit)_
- [ ] Frontend tests pass
- [ ] Lint passes
- [ ] Typecheck passes
- [ ] Production build passes
- [ ] Migration works (`alembic upgrade head` with Postgres)
- [x] README complete
- [x] No secrets committed (`.env` / `.env.local` gitignored)

## Security

- [x] Fail-closed behavior
- [x] Provider failure handling (not silent BENIGN)
- [x] Authorization
- [x] Tenant isolation
- [x] Tool firewall
- [x] Approval binding
- [x] Replay protection
- [x] MCP fingerprinting
- [x] MCP shadowing protection
- [x] Input validation
- [x] Output validation
- [x] Audit persistence
- [x] Security invariants (45/45)

## Demo

- [x] Benign scenario
- [x] Direct injection
- [x] Indirect injection
- [x] Intent hijack
- [x] Tool denial
- [x] Approval path
- [x] MCP tampering
- [x] Audit event
- [x] Evaluation screen

## Submission

- [x] README
- [x] Architecture diagram
- [ ] Demo video _(record separately)_
- [x] Pitch _(PDF + PPTX in docs/hackathon/)_
- [ ] Screenshots _(capture separately)_
- [x] Repository link _(https://github.com/VarunPunzuri99/AegisAI)_
- [x] Environment setup
- [x] Known limitations
- [x] License if required _(MIT)_
- [ ] Team information
- [ ] Hackathon submission form
