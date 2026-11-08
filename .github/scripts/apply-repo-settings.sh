#!/usr/bin/env bash
# Apply this repository's security settings with the GitHub CLI, as its owner.
#
#   gh auth login            # once, as an account that administers the repository
#   bash .github/scripts/apply-repo-settings.sh [owner/repo]
#
# Every step is idempotent: run it again after a change and the settings
# converge. Each step reports ok or FAIL and the script carries on, so one
# endpoint a plan lacks does not stop the rest. Nothing here reads, prints or
# stores a token; gh supplies the credential. The settings themselves are the
# ones docs/REPOSITORY_SETTINGS.md describes.
set -uo pipefail

REPO="${1:-depalmar/ics-dfir-toolkit}"
HERE="$(cd "$(dirname "$0")" && pwd)"
RULESET="$HERE/../rulesets/main.json"
ok=0; failed=0

step() {  # step <name> <gh api arguments...>
  local name="$1"; shift
  local out
  if out=$(gh api "$@" 2>&1); then
    printf 'ok    %s\n' "$name"; ok=$((ok + 1))
  else
    printf 'FAIL  %s\n      %s\n' "$name" "$(printf '%s' "$out" | tr '\n' ' ' | head -c 300)"; failed=$((failed + 1))
  fi
}

gh auth status >/dev/null 2>&1 || { echo "gh is not logged in: run 'gh auth login' first" >&2; exit 2; }
[ -f "$RULESET" ] || { echo "ruleset file not found: $RULESET" >&2; exit 2; }
echo "Applying the security baseline to $REPO"

# 1. Code security: Dependabot alerts and security updates, secret scanning with
#    push protection, private vulnerability reporting (SECURITY.md points here).
step "Dependabot alerts"                 -X PUT "repos/$REPO/vulnerability-alerts"
step "Dependabot security updates"       -X PUT "repos/$REPO/automated-security-fixes"
step "Secret scanning + push protection" -X PATCH "repos/$REPO" \
  -f 'security_and_analysis[secret_scanning][status]=enabled' \
  -f 'security_and_analysis[secret_scanning_push_protection][status]=enabled'
step "Private vulnerability reporting"   -X PUT "repos/$REPO/private-vulnerability-reporting"

# 2. Actions: a read-only default token, workflows cannot approve pull requests,
#    pull requests from outside forks wait for approval before any workflow runs.
step "Workflow token read-only"          -X PUT "repos/$REPO/actions/permissions/workflow" \
  -f default_workflow_permissions=read -F can_approve_pull_request_reviews=false
step "Outside fork PRs need approval"    -X PUT "repos/$REPO/actions/permissions/fork-pr-contributor-approval" \
  -f approval_policy=all_external_contributors

# 3. Repository: merged branches are deleted; no wiki or projects (fewer content
#    surfaces that bypass pull-request review).
step "Repository options"                -X PATCH "repos/$REPO" \
  -F delete_branch_on_merge=true -F has_wiki=false -F has_projects=false

# 4. Pages: HTTPS only. A github.io site already enforces it (the API then answers
#    "The certificate does not exist yet" to the update), so read before writing.
if [ "$(gh api "repos/$REPO/pages" --jq '.https_enforced' 2>/dev/null)" = "true" ]; then
  printf 'ok    %s\n' "Pages HTTPS enforced (already)"; ok=$((ok + 1))
else
  step "Pages HTTPS enforced"            -X PUT "repos/$REPO/pages" -F https_enforced=true
fi

# 5. The ruleset on the default branch, created or updated from .github/rulesets/main.json:
#    no deletion, no force push, changes arrive by pull request, the validate and
#    CodeQL checks must pass on an up-to-date branch.
id="$(gh api "repos/$REPO/rulesets" --jq '.[] | select(.name=="main") | .id' 2>/dev/null | head -n 1)"
if [ -n "$id" ]; then
  step "Ruleset 'main' (update #$id)"    -X PUT "repos/$REPO/rulesets/$id" --input "$RULESET"
else
  step "Ruleset 'main' (create)"         -X POST "repos/$REPO/rulesets" --input "$RULESET"
fi

printf '\n%d applied, %d failed.\nReview: https://github.com/%s/settings/security_analysis and https://github.com/%s/settings/rules\n' \
  "$ok" "$failed" "$REPO" "$REPO"
[ "$failed" -eq 0 ]
