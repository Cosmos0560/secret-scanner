# Rules and detectors

What `secret-scanner` looks for in version 1: 13 token-format rules from
`src/secret_scanner/rules/builtin.yaml`, the private key detector and the two entropy detectors.
The table is generated from the rules file and the detectors' descriptions (the data
`secret-scanner rules` prints), and `tests/test_rules_doc.py` fails the gate when it differs from
the code. No example secret is listed here or printed by the tool.

Rules file SHA-256 (the "rules version" in JSON, JSONL and SARIF output):
`52928a72916a6e9a2b4691ad56b7b0ca9b6333d0657928348959259ea1568ba1`

<!-- rules-table:start (generated, see tests/doc_samples.py) -->
| Id | Name | Detector | Severity | Confidence | Keywords | What it matches |
|---|---|---|---|---|---|---|
| `aws-access-key-id` | AWS access key id | `rule` | high | high | `akia`, `asia`, `abia`, `acca` | An AWS access key id (AKIA, ASIA, ABIA or ACCA followed by 16 base32 characters). |
| `aws-secret-access-key` | AWS secret access key | `rule` | critical | medium | `aws` | A 40-character base64 value on a line that names both aws and secret. |
| `github-token` | GitHub token | `rule` | critical | high | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` | A GitHub personal access, OAuth, user, server or refresh token (ghp_, gho_, ghu_, ghs_, ghr_). |
| `github-fine-grained-pat` | GitHub fine-grained personal access token | `rule` | critical | high | `github_pat_` | A GitHub fine-grained personal access token (github_pat_ followed by 22, an underscore and 59 characters). |
| `gitlab-pat` | GitLab personal access token | `rule` | critical | high | `glpat-` | A GitLab personal access token (glpat- followed by 20 to 64 characters). |
| `slack-token` | Slack token | `rule` | high | high | `xoxb-`, `xoxp-`, `xoxa-`, `xoxr-`, `xoxs-` | A Slack bot, user, app, refresh or legacy token (xoxb-, xoxp-, xoxa-, xoxr-, xoxs-). |
| `slack-webhook-url` | Slack incoming webhook URL | `rule` | medium | high | `hooks.slack.com` | A Slack incoming webhook URL (hooks.slack.com/services/ followed by T..., B... and 24 characters). |
| `stripe-secret-key` | Stripe live secret key | `rule` | critical | high | `sk_live_`, `rk_live_` | A Stripe live secret or restricted key (sk_live_ or rk_live_ followed by 24 to 99 characters). |
| `google-api-key` | Google API key | `rule` | high | high | `aiza` | A Google API key (AIza followed by 35 characters). |
| `npm-token` | npm access token | `rule` | high | high | `npm_` | An npm access token (npm_ followed by 36 alphanumeric characters). |
| `pypi-token` | PyPI API token | `rule` | critical | high | `pypi-` | A PyPI API token (pypi- and the fixed macaroon header for pypi.org, then at least 50 characters). |
| `sendgrid-api-key` | SendGrid API key | `rule` | high | high | `sg.` | A SendGrid API key (SG. followed by 22, a dot and 43 characters). |
| `azure-storage-account-key` | Azure storage account key | `rule` | critical | high | `accountkey=` | An Azure storage account key in a connection string (AccountKey= and 86 base64 characters ending in ==). |
| `private-key` | Private key block | `private_key` | critical | high | `private key` | A PEM or PGP private key block with at least 64 base64 characters of body. Severity is critical, and medium for an encrypted key; confidence is high for a complete block and medium for a truncated one. |
| `entropy-base64` | High-entropy base64 string | `entropy` | medium | low | (every line) | A run of base64 or base64url characters with a Shannon entropy of at least 4.5 bits per character. Confidence is medium when the line assigns it to a name such as secret, token, password or api_key, and low otherwise (reported only with --min-confidence low). |
| `entropy-hex` | High-entropy hex string | `entropy` | medium | medium | (every line) | A run of at least 32 hex digits with a Shannon entropy of at least 3.0 bits per character, reported only on a line that assigns it to a name such as secret, token, password or api_key (hashes and digests are everywhere). |
<!-- rules-table:end -->

## How to read the table

- **Severity** says how bad a leak of this kind is; **confidence** says how sure the detection is.
  They are separate fields in every output. The table shows the defaults; a finding can differ:
  - `github-token` carries a CRC32 checksum that is checked offline: a valid one gives confidence
    `high`, an invalid one `low`;
  - `private-key` is `critical`, and `medium` for an encrypted key; a complete block has
    confidence `high`, a truncated one (or one that reaches the line limit) `medium`;
  - `entropy-base64` is `medium` when the same line assigns the value to a name such as `secret`,
    `token`, `password` or `api_key`, and `low` otherwise; `entropy-hex` is reported only with
    such a name.
- `--min-confidence` (default `medium`) decides what is reported, so a bare high-entropy string is
  listed only with `--min-confidence low`. `--fail-on` (default `low`) decides which reported
  severities make the exit code 1.
- **Keywords** are lower-case literals. A rule's pattern runs only on a line that contains one of
  them (case-insensitive); this is the main reason a scan is fast. `aws-secret-access-key` also
  needs both `aws` and `secret` on the line.
- Every pattern is compiled only through the regex guard (`core/regex_guard.py`): a restricted
  grammar with bounded quantifiers and a static cost budget, so no rule can backtrack
  catastrophically. The same guard checks rules added through a configuration file.
- A finding shows only the rule's fixed public prefix, the length and an 8-hex-digit hash of the
  secret (README, "How findings are shown").

## The entropy detector

Candidates are runs of the base64 or base64url alphabet of 20 to 256 characters and runs of 32 to
256 hex digits. The score is the Shannon entropy of the token's own characters; the thresholds are
4.5 bits per character for base64 and 3.0 for hex. Not reported: a span a rule already matched,
UUIDs, SRI integrity values (`sha256-`, `sha384-`, `sha512-`), tokens with fewer than two
character classes, path-like tokens, and everything in lockfiles, `*.min.js`, `*.min.css`, `*.map`
and `*.svg` (for this detector only). A configuration file can change the thresholds (base64 3.5
to 6.0, hex 2.5 to 4.0), the minimum length (16 to 64) or switch the detector off. How many
findings it produces on real files is measured in `docs/performance.md`.

A fixed threshold means both kinds of error exist: a random-looking identifier with a suggestive
name is reported, and a real secret whose characters happen to repeat can score below the
threshold and is not.

## The private key detector

A line-based state machine, not a pattern over the file: a `BEGIN ... PRIVATE KEY` header (plain,
RSA, DSA, EC, OPENSSH, ENCRYPTED) or a PGP private key block header, at most 200 body lines, and
the matching end line. A finding needs at least 64 base64 characters of body, so text that only
mentions a header is not reported. The escaped one-line form used in JSON service-account files is
recognised too. The redacted form shows only the key type, the body length and the display hash.

## Where the formats come from, and what is missing

- The formats are the publicly documented ones as known on 2026-10-12. Nothing was checked
  against a live service, and a vendor can change a format at any time.
- Deliberately not in version 1: generic `password = ...` rules (a low-entropy value could be
  guessed back from the display hash), JSON Web Tokens (often not secret), and vendor formats that
  could not be stated precisely without looking them up.
- A configuration file (`--config FILE`) can switch rules off (`disable_rules`) and add its own
  (`extra_rules`, ids starting with `custom-`, the same schema, the same guard and limits).
