# Coordination Protocol — server-mcp-gemini

Shared workspace for Claude-side agents on this project. One "lead"
session (talks to the user, owns integration) and subagent sessions,
each on their own branch, reporting back through this directory.

## Roles
- Lead: owns `main`, writes task briefs, reviews/merges subagent
  branches, writes the final COMPETITION_REPORT.md.
- Subagent: reads its brief in `coordination/tasks/<agent>.md`, works
  ONLY on branch `agent/<agent>`, updates
  `coordination/status/<agent>.md` whenever it pauses or finishes,
  never pushes to `main`, never edits another agent's branch or status
  file.

## Access
- Repo: mienkek13-netizen/server-mcp-gemini (private), account slot
  `tertiary`.
- Inside a codespace shell you'll need a GH token to push (provided to
  you out-of-band by the user for this session). Never commit it,
  print it in full, or paste it into a status file/log.

## Status file format (overwrite in full each update, it's current
## state, not a running log)

    # Status: <agent-name>
    Updated: <UTC timestamp>
    Branch: agent/<agent>
    State: IN_PROGRESS | BLOCKED | DONE

    ## Summary
    ## Files changed
    ## Tests run (command -> result)
    ## Findings / security notes
    ## Blockers / questions for lead

## Rules
- Never touch mienkek13-netizen/server-mcp-gpt or
  mienkek13-netizen/server-mcp-gemini — other competitors' private repos.
- Never commit real secrets; .env/.secrets* stay gitignored.
- Small reviewable commits, not one giant commit.
- Report honestly, including unfinished/unverified work. Do not claim a
  test passed unless you actually ran it and saw it pass.
