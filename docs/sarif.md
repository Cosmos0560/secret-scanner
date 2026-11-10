# SARIF 2.1.0 output

`secret-scanner scan PATH --format sarif` and `secret-scanner scan-git REPO --format sarif` write
one SARIF 2.1.0 document (OASIS errata 01). It is meant for tools that read SARIF, for example
GitHub code scanning. Everything below is checked against the code by `tests/test_sarif_doc.py`: a
field, a table value or an example that changes in the code and not here fails the gate.

Recommended use: `scan` of the checked-out tree in CI. For `scan-git` the results point at paths
that may no longer exist at the tip of the branch (a secret that was committed and later removed);
that is allowed, and each such result names its commit in `properties.commit`.

## Promises

- One run, one `tool.driver`, ASCII only (every non-ASCII character is a `\uXXXX` escape), two-space
  indent, a newline at the end, keys in the order listed below.
- No field holds a secret. A result carries the redacted form of PLAN.md D7 (a fixed public
  prefix, the length and an 8-hex-digit display hash) and a fingerprint (D8). There is no
  `snippet`, no `contextRegion` and no `message.markdown`: a source line can hold a second,
  undetected secret, and a viewer shows the line from the repository itself.
- A file name cannot inject URI syntax: the artifact URI is built from the exact path, one segment
  at a time, and every byte outside the RFC 3986 unreserved set is a `%XX` escape.
- `invocations[0].executionSuccessful` is `false` when the run was incomplete (a limit, the time
  budget, an unreadable file, missing objects, a shallow history), and every cause is a
  `toolExecutionNotifications` entry. An incomplete run is never a clean result.

## Document

| Property | Value |
|---|---|
| `$schema` | `https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json` |
| `version` | `2.1.0` |
| `runs` | exactly one run |

### `runs[0]`

| Property | Meaning |
|---|---|
| `tool` | `driver` with `name` (`secret-scanner`), `version` and `semanticVersion` (both the tool version), `informationUri` (the repository page) and `rules` (below). |
| `columnKind` | `unicodeCodePoints`: columns count Unicode code points (PLAN.md D15). |
| `invocations` | One entry: `executionSuccessful` and `toolExecutionNotifications`, one notification per scan issue (`level` `warning`, the issue text, `descriptor.id` the issue kind). |
| `results` | One result per reported finding, in report order (path, line, column, rule). |
| `properties` | `target`, `complete`, `truncated`, `historyComplete`, `rulesSha256` (the rules version), `suppressedByFingerprint`, `suppressedByPath`, `stale`, `generatedAt`. |

### Rule descriptors, `tool.driver.rules[]`

One descriptor for every rule that can produce a result in the run: the built-in regex rules (or
those left after `disable_rules`), the rules added by `extra_rules` of a configuration file, and
the private key and entropy detectors. A result's `ruleIndex` is the position in this list.

| Property | Meaning |
|---|---|
| `id` | The rule id. |
| `name` | The rule's short name. |
| `shortDescription` | `text`: the name. |
| `fullDescription` | `text`: what the rule matches. |
| `help` | `text`: what to do about an exposed credential (the same text for every rule). |
| `defaultConfiguration` | `level`: from the rule's default severity, table below. |
| `properties` | `tags` (`security`, `secret`), `precision` (from the default confidence), `security-severity` (from the default severity). |

### Results, `runs[0].results[]`

| Property | Meaning |
|---|---|
| `ruleId` | The rule id. |
| `ruleIndex` | Position of the rule in `tool.driver.rules`. |
| `level` | From the finding's severity, table below. |
| `message` | `text`: the rule name and the redacted value, and `in commit <12 hex>` for a history scan. |
| `locations` | One location: `physicalLocation` with `artifactLocation` (`uri`, `uriBaseId` `%SRCROOT%`) and `region` (`startLine`, `startColumn`, `endColumn`, 1-based; `endColumn` is the column after the last character). |
| `partialFingerprints` | `secretScanner/v1`: the fingerprint (32 hex digits), stable across line moves. |
| `properties` | `confidence`, `severity`, `redacted`, and `commit` (the full commit id) for a history scan. |
| `suppressions` | Only on a suppressed finding that the report lists (`--show-suppressed`): one entry, `kind` `external` and a `justification` that says whether the baseline matched by fingerprint or by path. |

## Severity mapping

| Severity | `level` | `security-severity` |
|---|---|---|
| `critical` | `error` | `9.5` |
| `high` | `error` | `8.0` |
| `medium` | `warning` | `5.5` |
| `low` | `note` | `2.0` |
| `info` | `note` | (none) |

`security-severity` is the number GitHub code scanning turns into its severity buckets. A rule's
`precision` is its default confidence: `high`, `medium` or `low`. A result's `level` follows the
finding's own severity, which can differ from the rule's default (an encrypted private key is
`medium`).

## Artifact URIs

`artifactLocation.uri` is the file's path relative to the scan root (for `scan-git`, the path
inside the repository), `/`-separated, with each segment percent-encoded from its UTF-8 bytes (an
invalid byte of a POSIX name stays that byte). Only `A-Z a-z 0-9 - . _ ~` are written as they are.
`uriBaseId` is `%SRCROOT%`; the absolute scan root is never written.

| File name | `uri` |
|---|---|
| `src/app.py` | `src/app.py` |
| `my notes/a#b.txt` | `my%20notes/a%23b.txt` |
| `100%.txt` | `100%25.txt` |
| `key[1]&x.txt` | `key%5B1%5D%26x.txt` |
| `caf` followed by U+00E9 | `caf%C3%A9` |

A name that holds a control character, a bidirectional override or an invalid byte is encoded the
same way, so it stays inert in every viewer and still names the real file.

## Example

Produced by `secret-scanner scan . --format sarif` over a generated project (the secrets were
built at run time and exist nowhere in this repository). Shortened: the `rules` array is cut to
its first entry of 16 (the second result's `ruleIndex` points at a rule that is not shown), and
nothing else is changed.

```json
{
  "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "secret-scanner",
          "version": "1.0.0",
          "semanticVersion": "1.0.0",
          "informationUri": "https://github.com/Cosmos0560/secret-scanner",
          "rules": [
            {
              "id": "aws-access-key-id",
              "name": "AWS access key id",
              "shortDescription": {
                "text": "AWS access key id"
              },
              "fullDescription": {
                "text": "An AWS access key id (AKIA, ASIA, ABIA or ACCA followed by 16 base32 characters)."
              },
              "help": {
                "text": "Treat this credential as exposed. Revoke or rotate it at the service that issued it, remove it from the code and keep it in a secret manager or an environment the repository does not contain. A secret that was committed stays in the git history until the history is rewritten, and in every clone. This tool does not check whether a secret is still valid."
              },
              "defaultConfiguration": {
                "level": "error"
              },
              "properties": {
                "tags": [
                  "security",
                  "secret"
                ],
                "precision": "high",
                "security-severity": "8.0"
              }
            }
          ]
        }
      },
      "columnKind": "unicodeCodePoints",
      "invocations": [
        {
          "executionSuccessful": true,
          "toolExecutionNotifications": []
        }
      ],
      "results": [
        {
          "ruleId": "aws-access-key-id",
          "ruleIndex": 0,
          "level": "error",
          "message": {
            "text": "AWS access key id: AKIA... [20 chars, sha256:11c64dd5]"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "config/.env",
                  "uriBaseId": "%SRCROOT%"
                },
                "region": {
                  "startLine": 2,
                  "startColumn": 19,
                  "endColumn": 39
                }
              }
            }
          ],
          "partialFingerprints": {
            "secretScanner/v1": "357a01ffc066d4e7216b0b78e42104c4"
          },
          "properties": {
            "confidence": "high",
            "severity": "high",
            "redacted": "AKIA... [20 chars, sha256:11c64dd5]"
          }
        },
        {
          "ruleId": "npm-token",
          "ruleIndex": 9,
          "level": "error",
          "message": {
            "text": "npm access token: npm_... [40 chars, sha256:473b5357]"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "src/app.py",
                  "uriBaseId": "%SRCROOT%"
                },
                "region": {
                  "startLine": 3,
                  "startColumn": 10,
                  "endColumn": 50
                }
              }
            }
          ],
          "partialFingerprints": {
            "secretScanner/v1": "68b5a7e585c6721cace03b4ff3cbc0f4"
          },
          "properties": {
            "confidence": "high",
            "severity": "high",
            "redacted": "npm_... [40 chars, sha256:473b5357]"
          }
        }
      ],
      "properties": {
        "target": "fs",
        "complete": true,
        "truncated": false,
        "historyComplete": null,
        "rulesSha256": "52928a72916a6e9a2b4691ad56b7b0ca9b6333d0657928348959259ea1568ba1",
        "suppressedByFingerprint": 0,
        "suppressedByPath": 0,
        "stale": 0,
        "generatedAt": "<time>"
      }
    }
  ]
}
```

`generatedAt` shows `<time>` here; the tool writes the UTC time of the run.

## Known gaps

- **Not validated against the official schema.** The SARIF 2.1.0 JSON schema is not available
  here: no PyPI package ships it (checked on 2026-11-09: `pysarif` 0.1.0, `sarif-om` 1.0.4,
  `sarif-tools` 3.0.5, `sarif-pydantic` 0.6.2 and `check-jsonschema` 0.39.0 hold none), and the
  tool and its tests make no network access. The tests check the structure field by field against
  the SARIF 2.1.0 specification for the subset used (`tests/sarif_check.py`). Before relying on
  the output, validate it once with a SARIF validator of your choice.
- **No upload to GitHub code scanning was done.** There is no network access here. Uploading a
  file written by `--format sarif --output` with `github/codeql-action/upload-sarif` is a step for
  the release and stays a known gap until it has been done.
- The `$schema` URI and the property names come from the specification as known when this was
  written; they were not checked against a live copy.
- `security-severity` is the tool's own mapping (above), not a CVSS score.
