# Contributing

1. Create a focused branch.
2. Add a minimized JSON or TOML fixture for the behavior being checked.
3. Run `python -m unittest discover -s tests -v`.
4. Keep rules deterministic and document likely false positives.
5. Open a pull request describing the security impact and remediation.

## Rule proposals

Open a rule-request issue before implementing a broad heuristic. Include:

- the client or manifest shape that exposes the signal;
- one minimized unsafe fixture and one safe fixture;
- the expected severity and remediation;
- likely false positives;
- a primary specification or security reference where one exists.

Maintainers keep rule IDs stable after release. A rule that changes meaning receives a new ID.
