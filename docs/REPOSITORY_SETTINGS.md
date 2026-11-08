# Repository settings baseline

The security of this repository has two halves. The half that lives in files is
committed: least-privilege workflow tokens, every action pinned to a commit,
Dependabot (`.github/dependabot.yml`), CodeQL and OpenSSF Scorecard workflows,
`SECURITY.md` and `CODEOWNERS`. The other half is repository *settings*, which
only an administrator can change and which no file can enforce. This page is
that half, with three ways to apply it.

## The baseline

| Area | Setting | Why |
| --- | --- | --- |
| Rules | Ruleset `main` on the default branch: no deletion, no force push, changes arrive by pull request, required checks **Schemas and cross-references**, **Sigma, YARA and Suricata rules parse**, **CodeQL (python)** and **CodeQL** on an up-to-date branch; no bypass actors | The validator is this repository's gate; a ruleset is what makes it mandatory rather than advisory |
| Code security | Dependabot alerts and security updates; secret scanning with push protection; private vulnerability reporting | Push protection stops a credential before it is in history; private reporting is where `SECURITY.md` sends code vulnerabilities |
| Actions | Default `GITHUB_TOKEN` read-only; workflows cannot approve pull requests; pull requests from outside forks need approval before workflows run | A compromised action or dependency gets a read-only token and no path to a merge |
| Repository | Delete merged branches; wiki and projects off | Fewer content surfaces that are not reviewed through a pull request |
| Pages | HTTPS enforced | The published site is served only over TLS |
| Code scanning | CodeQL **default setup off** | `.github/workflows/codeql.yml` is the advanced setup; GitHub rejects its results when default setup is also on |

Not in the baseline, on purpose: **required signed commits** would reject
commits pushed from Claude Code sessions, which are unsigned; **required linear
history** would forbid the merge commits this repository's history uses.

## Apply it

**With the GitHub CLI, as the owner (one command).** `gh auth login` once, then:

```bash
bash .github/scripts/apply-repo-settings.sh            # defaults to depalmar/ics-dfir-toolkit
```

Every step is idempotent and reports `ok` or `FAIL`; a failing step does not
stop the others. The ruleset is created or updated from
`.github/rulesets/main.json`.

**Importing the ruleset alone.** Settings > Rules > Rulesets > *New ruleset* >
**Import a ruleset**, and choose `.github/rulesets/main.json`. The file is the
format GitHub's own export produces.

**By hand.** Settings > Rules > Rulesets for the ruleset; Settings > Advanced
Security (under *Security and quality*) for Dependabot, secret scanning, push
protection and private vulnerability reporting; Settings > Actions > General
for workflow permissions and fork approval; Settings > General for branch
deletion, wiki and projects; Settings > Pages for HTTPS.

## Check it

The Scorecard workflow measures most of this weekly (`Branch-Protection`,
`Token-Permissions`, `Pinned-Dependencies`, `Dependency-Update-Tool`,
`Security-Policy`, `SAST`) and reports under Security > Code scanning. A
check that still fails after the script has run names the setting to revisit.

Why a Claude Code session cannot apply these: the GitHub App it runs under
has contents, pull-request and issue permissions, not repository
administration. That is the right scope for an agent that writes code; the
settings that constrain the agent should not be settable by it.
