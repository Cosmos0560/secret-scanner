# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | yes |
| older (0.x, never released) | no |

Fixes are made on the newest 1.0.x release.

## Reporting a vulnerability

Use **GitHub private vulnerability reporting**: on the repository page open the **Security** tab
and choose **Report a vulnerability**. The report stays private between you and the maintainer
until a fix is released.

- Do not open a public issue or pull request for a vulnerability.
- **Never put a real secret in a report**, an issue, a pull request or a test. To show a detection
  problem, describe the format, or use a value you invented that is not valid anywhere.
- There is no other reporting channel; in particular no address is published for this project.

Please include: the version (`secret-scanner --version`), the operating system, the Python and git
versions, the exact command, what happened and what you expected. A small directory or repository
that reproduces the problem helps most, as long as it holds no real credential.

This is a personal project maintained in spare time. There is no guaranteed response time and no
bug bounty. Reports are read, answered and credited in the changelog if you want that.

## What counts as a vulnerability here

The threat model is `docs/threat-model.md`. A report is in scope when the tool breaks one of its
own promises, for example:

- a full secret, or more of one than the documented redacted form, appears in any output, error
  message or written file;
- scanning a directory or repository runs a program, reaches the network, or creates, changes or
  deletes something in the scanned content or outside the tool's own output files;
- a link, junction or special file is followed or opened, or the scan reads outside the given
  tree;
- a file name, path, commit or file content injects text into the table, JSON, JSONL or SARIF
  output (forged lines, terminal escape sequences, broken structure);
- a crafted input makes the tool hang or use unbounded memory instead of stopping at a limit with
  exit code 4;
- an incomplete scan is reported as clean (exit code 0);
- a configuration, rules or baseline file is picked up without being named on the command line.

Not vulnerabilities (they are documented limitations, see the README): a secret the patterns do
not detect, a false positive, a format that changed at the vendor, and the fact that a baseline
taken from an untrusted branch can suppress that branch's findings.

## If the tool found a secret of yours

The tool does not check whether a secret is valid and cannot revoke it. Treat every reported
credential as exposed: revoke or rotate it at the service that issued it. Removing it from the
files does not remove it from the git history or from existing clones.
