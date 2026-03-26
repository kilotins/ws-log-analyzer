Sync all agent worktrees/clones with main.

1. First check if AGENTS.md in main has pending changes — if so, commit and push them first.
2. For each directory (ws-log-analyzer-codex, ws-log-analyzer-gemini, ws-log-analyzer-claude):
   - Run `git pull origin main`
   - Verify AGENTS.md exists and matches main
   - Report the result (up to date, fast-forward, or error)
3. Show a summary table with each clone's status, current commit, and AGENTS.md version match.
