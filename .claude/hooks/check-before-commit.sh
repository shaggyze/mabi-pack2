#!/usr/bin/env bash
# Claude Code PreToolUse hook: runs the pre-commit gate before any `git commit`
# an agent issues, and blocks the call (exit 2) when it fails.
input="$(cat)"
if command -v jq >/dev/null 2>&1; then
    cmd="$(printf '%s' "$input" | jq -r '.tool_input.command // empty' 2>/dev/null)"
else
    cmd="$input" # no jq (e.g. Git for Windows): match on the raw JSON
fi
case "$cmd" in
    *"git commit"*) ;;
    *) exit 0 ;;
esac
out="$("$CLAUDE_PROJECT_DIR/scripts/precommit-check.sh" 2>&1)" && exit 0
echo "$out" | tail -40 >&2
echo "Fix these errors before committing (never bypass with --no-verify)." >&2
exit 2
