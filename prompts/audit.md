---
description: Audit a site, app or codebase — security, a11y, performance, SEO, code health
---
Run the JRiSpace audit on: $ARGUMENTS

Execute exactly:

  python3 ~/.config/ai-agents/skills/webapp-audit/scripts/audit.py "$ARGUMENTS" --deep

Then read the generated audit-report.md and report: the grade table per area, the critical/high
findings with their evidence lines and fixes, and the two fastest fixes that raise the grade.
