#!/usr/bin/env bash
# webapp-audit installer — clones the skill into place, links the CLI, and wires it into
# every coding agent found on this machine (Claude Code, Hermes, Codex, Cursor).
#
#   curl -sL https://audit.jrispace.com/install.sh | bash
#   ./install.sh --dir ~/.config/ai-agents/skills/webapp-audit --no-agents
#
# Idempotent: safe to re-run, never overwrites a dirty install (it pulls instead).
# JRiSpace | Sylvenson Richard
set -euo pipefail

REPO="${AUDIT_REPO:-https://github.com/jrispace/webapp-audit.git}"
DEST="${AUDIT_DIR:-$HOME/.config/ai-agents/skills/webapp-audit}"
BIN="${AUDIT_BIN:-$HOME/scripts}"
WITH_AGENTS=1

while [ $# -gt 0 ]; do
  case "$1" in
    --dir) DEST="$2"; shift 2 ;;
    --bin) BIN="$2"; shift 2 ;;
    --no-agents) WITH_AGENTS=0; shift ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "unknown option: $1"; exit 2 ;;
  esac
done

say() { printf '\033[1;36m→\033[0m %s\n' "$*"; }
ok()  { printf '\033[1;32m✓\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m✗\033[0m %s\n' "$*" >&2; exit 1; }

command -v python3 >/dev/null || die "python3 is required"
command -v git >/dev/null || die "git is required"
command -v node >/dev/null || say "node not found — the browser pass will be skipped (HTTP-only audits)"

# ---------------------------------------------------------------- 1. install
if [ -d "$DEST/.git" ]; then
  say "updating $DEST"
  git -C "$DEST" pull --ff-only --quiet || say "pull failed — keeping the local copy"
elif [ -d "$DEST" ] && [ -f "$DEST/SKILL.md" ]; then
  say "$DEST already present (not a git checkout) — leaving it"
else
  say "cloning into $DEST"
  mkdir -p "$(dirname "$DEST")"
  git clone --depth 1 --quiet "$REPO" "$DEST"
fi

chmod +x "$DEST/audit.sh" "$DEST/scripts/audit.py" 2>/dev/null || true
ok "skill installed at $DEST"

# ---------------------------------------------------------------- 2. CLI
mkdir -p "$BIN"
ln -sfn "$DEST/audit.sh" "$BIN/audit"
ok "CLI linked: $BIN/audit"
case ":$PATH:" in
  *":$BIN:"*) : ;;
  *) say "add this to your shell profile:  export PATH=\"$BIN:\$PATH\"" ;;
esac

# ---------------------------------------------------------------- 3. agents
if [ "$WITH_AGENTS" -eq 1 ]; then
  if [ -d "$HOME/.claude" ]; then
    mkdir -p "$HOME/.claude/skills"
    ln -sfn "$DEST" "$HOME/.claude/skills/webapp-audit"
    ok "linked for Claude Code"
  fi
  if [ -d "$HOME/.hermes" ]; then
    mkdir -p "$HOME/.hermes/skills/quality"
    ln -sfn "$DEST" "$HOME/.hermes/skills/quality/webapp-audit"
    ok "linked for Hermes Agent"
  fi
  if [ -d "$HOME/.codex" ]; then
    mkdir -p "$HOME/.codex/prompts"
    cat > "$HOME/.codex/prompts/audit.md" <<EOF
---
description: Audit a site, app or codebase — security, a11y, performance, SEO, code health
---
Run the JRiSpace audit on: \$ARGUMENTS

Execute exactly:

  python3 $DEST/scripts/audit.py "\$ARGUMENTS" --deep

Then read the audit-report.md it writes, report the grade table, and list the critical/high
findings with their evidence lines and fixes.
EOF
    ok "added /audit prompt for Codex"
  fi
  if [ -d "$HOME/.cursor" ]; then
    mkdir -p "$HOME/.cursor/rules"
    cat > "$HOME/.cursor/rules/audit.mdc" <<EOF
---
description: Audit websites/apps/code with the JRiSpace webapp-audit skill
alwaysApply: false
---
When asked to audit, review, grade or pre-launch check a site, app or codebase:
1. Run \`python3 $DEST/scripts/audit.py <url|path> --deep\`
2. Read the generated audit-report.md.
3. Report the grade table first, then critical/high findings with their evidence.
4. Never claim a finding is fixed without re-running the audit.
EOF
    ok "added audit rule for Cursor"
  fi
fi

# ---------------------------------------------------------------- 4. self-test
if python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)"; then
  ok "python $((python3 -c 'import sys;print(sys.version_info[0])')).$((python3 -c 'import sys;print(sys.version_info[1])')) detected"
else
  die "python 3.9+ required"
fi

cat <<EOF

$(printf '\033[1;32mReady.\033[0m')

  audit https://your-site.com
  audit ~/Projects/your-app --deep
  audit https://your-site.com --no-browser --json

Reports land in ./audit-report.md. Exit code 3 means the grade is below C.
EOF
