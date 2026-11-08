# Security policy

## What to report here

- **Vulnerabilities in this repository's code**: the validator and maintenance
  scripts under `artifacts/scripts/`, the `icstriage` logic-comparison engine,
  the site generator and the GitHub Actions workflows. `icstriage` parses files
  that may come from a compromised engineering workstation, so a parser that
  can be made to crash, hang, read outside its input or execute anything is in
  scope.
- **Safety errors in the knowledge base**: a collection method whose `impact`
  is rated lower than it is (for example a method marked `read-only` that can
  change a controller's mode), a response step that could reinstall an
  attacker's logic, or a hardening control whose syntax would take a process
  down. These are safety issues first; please report them as soon as you see
  them.

Vulnerabilities in the vendor products this knowledge base describes are out
of scope. Report those to the vendor's PSIRT or through CISA's ICS
vulnerability coordination.

## How to report

- **Code vulnerabilities**: use GitHub's private vulnerability reporting -
  the **Report a vulnerability** button under this repository's **Security**
  tab. Please do not open a public issue for a vulnerability before it is
  fixed.
- **Knowledge-base safety errors**: open a public issue labelled `safety`.
  The records are built from public vendor and government documentation, so
  there is nothing to keep private, and a visible issue reaches other users
  of the record fastest.

Include the file path and record id (`ICS-...`), what the record or code
does, what it should do, and the primary source that shows it. A report
without a source is still welcome; the fix will cite one.

The maintainer aims to acknowledge a report within seven days.

## Supported versions

Only the `main` branch is supported. There are no release branches; fixes
land on `main` and the published site is rebuilt from it.

## What this repository does not do

Nothing in this repository connects to a controller, scans a network or
changes a system. `icstriage` reads files an engineer has already exported
and refuses XML that declares a DOCTYPE or an entity. The maintenance
workflows only read public pages and open issues; they never commit. A
change that would make any script talk to a live control system is a
security issue regardless of intent and should be reported as one.
