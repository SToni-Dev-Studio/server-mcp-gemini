# Status: docs-release
Updated: 2026-09-11T20:20:00Z
Branch: agent/docs-release
State: IN_PROGRESS
Last broadcast read: 0003

## Summary
Cloned into own checkout (~/docs-release-work), merged origin/main
(picked up BROADCAST.md + task corrections), read coordination/README.md
and my task brief. pc-agent and hub-cicd branches have zero commits
beyond main so far — nothing to cross-check yet; will re-pull before
finalizing docs.

Read in full: server.py, organiser-agent.py, organiser-agent.cpp,
README.md, BUILD_AND_SETUP.md, SKILL.md, fly.toml, Dockerfile, start.sh,
pc-tunnel@.service, requirements.txt, .gitignore, .secrets.example,
.github/workflows/build-organiser-agent.yml, tests/test_admin_cookie_auth.py.

## Findings so far (cross-checked against actual code)
- README.md is badly stale: describes a 4-tool, per-request-header-auth,
  pre-PC/pre-admin-dashboard version of the server. Needs a full rewrite.
- BUILD_AND_SETUP.md and SKILL.md are already largely accurate against
  current server.py (PCS registry, admin dashboard, diagnostics, multi-PC
  tunnel setup all match). Mainly need polish + an ARCHITECTURE.md split
  + a "known limitations" section, not a rewrite.
- organiser-agent.py (legacy Flask reference, v1.0.0) has NO
  path-traversal/protected-path checks and its own docstring describes
  an obsolete ngrok+ORGANISER_URL deployment model. organiser-agent.cpp
  (v2.0.0-cpp, the one actually referenced as "the" agent everywhere else)
  already has a protected-path guard for Windows system dirs on every
  file-touching endpoint except /run_command (documented as deliberate:
  can't safely string-parse arbitrary shell text). Docs will state the
  C++ build is the supported agent and flag the Python file as a stale
  reference implementation, not touch either file's code.
- No PC identity/name concept in either agent build yet (matches
  pc-agent.md's brief — that's their branch's job, not landing yet).
  Per-PC secret separation already works operationally today (each PCS
  entry's `secret` must match that PC's own ORGANISER_SECRET) but nothing
  enforces the pairing — will note as a docs/installer point.
- fly.toml + Dockerfile exist but Render is what's actually documented/
  wired up everywhere else (RENDER_API_KEY, hardcoded RENDER_SERVICE_ID
  default, /admin dashboard is Render-API-specific). Fly looks vestigial
  but I'm not marking it dead in docs until agent/hub-cicd confirms —
  will re-check their status file before finalizing.
- Only CI today: build-organiser-agent.yml (plain build + rolling
  "latest" release of the .exe). No tagged/versioned release workflow,
  no packaging of server.py/docs, no test/lint step (that gap is
  hub-cicd's, not mine — noting only for release-workflow design).
- .secrets.example only documents GITHUB_TOKEN/MCP_ALLOWED_HOST/PORT —
  well short of the real config surface (SECONDARY/TERTIARY tokens,
  MCP_SERVER_PASSWORD, ADMIN_PASSWORD, PCS, PLEX_*, SERVER_*,
  TAILSCALE_AUTH_KEY, SSH_PRIVATE_KEY). Planning to bring it in line —
  it's a docs/onboarding file, not server code.
- Tooling note (not mine to fix, server.py out of scope): the
  `write_codespace_file` MCP tool always reports "Successfully wrote..."
  even when the underlying write fails, because it doesn't `mkdir -p`
  the parent directory and doesn't check the exec result before
  returning. Hit this firsthand writing this very file. Flagging here
  in case it's useful to whoever owns server.py — not fixing it myself.

## Plan
1. Bring .secrets.example up to date with real config surface.
2. Write ARCHITECTURE.md (split out of BUILD_AND_SETUP's diagram + tool
   inventory).
3. Rewrite README.md to match reality, linking out to ARCHITECTURE.md /
   BUILD_AND_SETUP.md.
4. Light-touch BUILD_AND_SETUP.md: cross-links, "Known limitations",
   the .py-vs-.cpp agent note, Fly/Render flag.
5. Tag-triggered release workflow (build + test + package + publish to
   GitHub Releases with version info).
6. Windows installer script: detect arch, fetch matching release asset,
   verify checksum, install, preserve existing config on upgrade, verify
   it runs post-install. Hold off on a Linux hub installer until
   agent/hub-cicd's tunnel design lands (brief says only build one "if
   needed").
7. Re-pull agent/pc-agent + agent/hub-cicd branches and their status
   files before calling docs "final" — cross-check every claim once
   their real changes exist.

## Files changed
(none committed yet as of this update — first commit landing next)

## Tests run (command -> result)
(none yet)

## Findings / security notes
See "Findings so far" above. No code in server.py / organiser-agent.* /
hub-tunnel files touched or will be touched — out of scope per brief.

## Blockers / questions for lead
- agent/pc-agent and agent/hub-cicd have no commits yet — proceeding
  with docs for the current baseline; will revise once their work lands
  rather than block on it.
- Fly vs Render: treating Render as primary/documented and Fly as
  present-but-unconfirmed in the docs I write, pending hub-cicd's
  findings. Flag if that's wrong.
