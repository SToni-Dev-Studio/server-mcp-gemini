# Task Brief: Documentation, Installer, Release Pipeline
Branch: agent/docs-release
Status file: coordination/status/docs-release.md

## Scope
README.md, BUILD_AND_SETUP.md, SKILL.md, new ARCHITECTURE.md if useful,
a release GitHub Actions workflow (triggered on tags like v1.0.0), and an
installer (script or documented steps) for supported platforms.

## Context
Docs must describe reality, not aspiration. Before writing anything, read
the actual current server.py, organiser-agent.py/.cpp, and whatever
agent/pc-agent and agent/hub-cicd have pushed to their branches (check
coordination/status/pc-agent.md and coordination/status/hub-cicd.md —
pull their branches to see real changes, don't just read the task
briefs). Cross-check every doc claim against actual code/config.

## Known baseline gaps
- BUILD_AND_SETUP.md / SKILL.md likely describe the pre-multi-PC,
  pre-hub architecture — will need updates once pc-agent/hub-cicd land.
- No release workflow exists (only .github/workflows/build-organiser-agent.yml,
  a plain build, not a tagged-release/packaging flow).
- No installer — Windows PC agent presumably has to be built/placed
  manually. Design something better (detect arch, fetch the right
  release asset, verify integrity e.g. checksum, install, preserve
  existing config on upgrade, verify it actually runs after install).
- Fly.io (fly.toml, Dockerfile) vs Render — confirm with agent/hub-cicd's
  findings which is actually current, and stop docs claiming both are
  equally supported if they aren't.

## Deliverables
1. README.md and BUILD_AND_SETUP.md rewritten to match the real,
   current system (link to ARCHITECTURE.md if you split it out).
2. A tag-triggered release workflow: build, test, package, publish to
   GitHub Releases with version info.
3. An installer for the Windows PC agent (and Linux hub setup, if
   agent/hub-cicd's tunnel design needs one) with integrity verification
   and useful error messages on failure.
4. "Known limitations" section that's honest, not marketing copy.
5. coordination/status/docs-release.md.

## Out of scope
Don't rewrite server.py, organiser-agent.*, or hub/tunnel code. If docs
reveal a functional gap, note it in your status file instead of
patching the code yourself.
