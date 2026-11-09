# Report schema `secret-report/1`

This file documents what `secret-scanner scan` writes with `--format json`, how the table format is
laid out, and what the exit code means. It is checked against the code by
`tests/test_report_schema_doc.py`: a field, an enum value or an exit code that changes in the code
and not here fails the gate.

JSON and table are the two formats of Phase 3. The JSONL format for mini-siem is documented in
`siem-mapping.md` and SARIF in `sarif.md`; the `rules` command has its own section below.

## Promises

- One JSON document per run, UTF-8, **ASCII only** (every non-ASCII character is a `\uXXXX`
  escape), two-space indent, a newline at the end, keys in the order listed below.
- Within `secret-report/1`, fields are only ever added at the end of their object. A consumer must
  ignore unknown keys; the tool itself refuses unknown keys in the files it reads.
- No field holds a secret. A finding carries a redacted form (a fixed public prefix, the length and
  an 8-hex-digit display hash), a fingerprint and a location. There is no line snippet.
- `complete: false` means part of the input was not scanned: the run is **not** a clean result,
  whatever `findings` holds. The exit code is 4 (below).

## Top-level fields

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | Always `secret-report/1`. |
| `tool` | object | `name` (`secret-scanner`) and `version`. |
| `generated_at` | string | UTC time of the run, `YYYY-MM-DDTHH:MM:SSZ`. |
| `host` | string | `--host-label`, or the machine's node name; escaped, at most 255 characters. |
| `rules_sha256` | string | SHA-256 (hex) of the built-in rules file the run used. |
| `target` | object | `kind` (`fs` or `git`) and `path` (the path as given, escaped). |
| `complete` | boolean | `true` only when every file was read and no limit was hit. |
| `truncated` | boolean | `true` when the report limit cut the list of findings. |
| `history_complete` | boolean or null | Git target only; `null` for a directory scan. `true` only when the repository is not shallow and the run was complete; `false` for a shallow repository, even with `--allow-shallow`. |
| `counts` | object | Totals, below. |
| `stats` | object | What was seen, scanned and skipped, below. |
| `findings` | array | Reported findings, plus suppressed ones when `--show-suppressed` is given. |
| `issues` | array | Everything that made the run incomplete, below. |

### `counts`

| Field | Type | Meaning |
|---|---|---|
| `findings` | integer | Reported findings (suppressed ones are not counted here). |
| `by_severity` | object | The same count per severity: `info`, `low`, `medium`, `high`, `critical`. |
| `suppressed_by_fingerprint` | integer | Findings the baseline suppressed by fingerprint. |
| `suppressed_by_path` | integer | Findings the baseline suppressed by a path glob. |
| `stale` | integer or null | Baseline entries that matched nothing; `null` when the run was incomplete (an unread file could hold the finding). |
| `issues` | integer | Length of `issues`. |

### `stats`

| Field | Type | Meaning |
|---|---|---|
| `files_seen` | integer | Regular files read, whether or not they could be scanned. For a history scan: distinct blobs examined. |
| `files_scanned` | integer | Files whose content was scanned. For a history scan: distinct blobs scanned (the same as `blobs_scanned`). |
| `bytes_scanned` | integer | Bytes of the scanned files. |
| `skipped_binary` | integer | Files with a NUL byte in the first 8 000 bytes (not an issue). |
| `skipped_symlink` | integer | Symbolic links and Windows reparse points; never followed. For a history scan: symlink entries of commits (their content is a path, not read). |
| `skipped_offline` | integer | Cloud placeholders; reading them would download them. |
| `skipped_special` | integer | FIFOs, sockets and devices; never opened. |
| `skipped_excluded` | integer | Entries excluded by default excludes or configuration. |
| `skipped_gitignored` | integer | Entries `--gitignore` filtered out: files that git does not list, and directories that hold none (counted once, not entered). |
| `skipped_submodule` | integer | Submodule (gitlink) entries of commits in a history scan; their contents are another repository. |
| `commits` | integer | Commits walked (git target). A commit is walked against its first parent only; blobs new to the walk are scanned, so a secret introduced in a merge resolution is found. |
| `blobs_scanned` | integer | Distinct blobs scanned (git target). |
| `blobs_from_cache` | integer | Entries (a path in a commit) whose blob had been scanned already (git target). |

### `findings[]`

| Field | Type | Meaning |
|---|---|---|
| `rule_id` | string | The rule, or the detector name for the entropy and private key detectors. |
| `detector` | string | `rule`, `entropy` or `private_key`. |
| `severity` | string | How bad a leak of this kind is, from the rule. |
| `confidence` | string | How sure the detection is. |
| `file` | string | Path relative to the scan root, `/` separated, escaped. |
| `line` | integer | 1-based. |
| `column` | integer | 1-based, in Unicode code points. |
| `end_column` | integer | Column after the last character of the match. |
| `commit` | string or null | Commit that first introduced it (git target). |
| `commit_time` | integer or null | Committer time, Unix seconds (git target). |
| `redacted` | object | `shown`, `length`, `hash8` and `text`: all that may be shown of the secret. |
| `fingerprint` | string | 32 hex digits; stable across line moves and used by baselines. |
| `suppressed_by` | string or null | `fingerprint`, `path`, or `null` for a reported finding. |

### `issues[]`

| Field | Type | Meaning |
|---|---|---|
| `kind` | string | Why this part was not fully scanned; see the vocabulary below. |
| `path` | string or null | The file, escaped; `null` for a whole-run limit. |
| `detail` | string | A fixed sentence, never file content. |

## Vocabularies

- Severity: `info`, `low`, `medium`, `high`, `critical`.
- Confidence: `low`, `medium`, `high`.
- Detector: `rule`, `entropy`, `private_key`.
- Target: `fs`, `git`.
- Suppressed by: `fingerprint`, `path`.
- Issue kind: `unreadable`, `vanished`, `unstable`, `too_large`, `line_too_long`, `undecodable`,
  `limit_reached`, `time_budget`, `missing_object`, `shallow_history`, `findings_cap`.

## Escaping

File names, paths and every other string taken from the scanned input are hostile and are escaped
before they reach any output. Control characters (so ANSI sequences are inert), DEL, C1 controls,
bidirectional and zero-width characters, line and paragraph separators, byte-order marks and lone
surrogates (an invalid byte in a POSIX name) become `\xNN`, `\uNNNN` or `\UNNNNNNNN`; a tab, line
feed and carriage return become `\t`, `\n`, `\r`; and a backslash inside a name becomes `\\`, so an
escape sequence in the output always came from the tool.

Paths are shown as components joined by `/`, each component escaped on its own (PLAN.md v0.9).
Finding and issue paths are relative to the scan root and already use `/`. A path the user gave
(the scan root in the table header and in `target.path`, the `--output` and `--write-baseline`
paths in notices and error messages) is shown with `/` on Windows, where `\` is a separator, so a
Windows path never appears with doubled backslashes. On POSIX a backslash is an ordinary character
of a name and stays escaped as `\\`. In JSON the displayed text is encoded as a standard JSON
string, so a `\\` that is part of a POSIX name appears as `\\\\` in the document.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Clean and complete. |
| 1 | Findings at or above `--fail-on` (default `low`) that the baseline does not suppress. |
| 2 | Usage, configuration, rules, baseline or input/output error. |
| 3 | git is unavailable or failed (`scan-git`, Phase 4). |
| 4 | Incomplete run: a limit, the time budget, an unreadable or changed file, missing objects or shallow history. |

Precedence when more than one applies: 2, then 3, then 4, then 1, then 0. An incomplete run still
prints its findings and `complete: false`. `--write-baseline` does not change the exit code: a run
that finds something still exits 1, and the file it wrote is the way to accept those findings.
`--min-confidence` (default `medium`) decides what is reported at all.

## The table

The table lists one row per finding, then a summary. An incomplete run says so in the first lines,
above the findings, and in the summary.

```
secret-scanner 0.1.0 - scan of .
generated 2026-10-13T06:50:48Z

SEVERITY  CONFIDENCE  RULE               LOCATION         REDACTED
high      high        aws-access-key-id  config/.env:2:9  AKIA... [20 chars, sha256:44d2e6b2]
high      high        npm-token          src/app.py:3:10  npm_... [40 chars, sha256:681a73de]

Summary
  files:     3 scanned of 3 seen (112 bytes)
  skipped:   none
  findings:  2 reported, 0 suppressed (0 by fingerprint, 0 by path)
  stale:     0
  issues:    0
  complete:  yes
```

A suppressed finding listed with `--show-suppressed` carries a `[suppressed: fingerprint]` or
`[suppressed: path]` marker after its redacted value. At most 50 issues are listed in the table;
the JSON document lists all of them.

## Example

Produced by `secret-scanner scan . --format json --host-label example-host` over a generated
directory (the secrets were built at run time and exist nowhere in this repository):

```json
{
  "schema": "secret-report/1",
  "tool": {
    "name": "secret-scanner",
    "version": "0.1.0"
  },
  "generated_at": "2026-10-13T06:50:48Z",
  "host": "example-host",
  "rules_sha256": "52928a72916a6e9a2b4691ad56b7b0ca9b6333d0657928348959259ea1568ba1",
  "target": {
    "kind": "fs",
    "path": "."
  },
  "complete": true,
  "truncated": false,
  "history_complete": null,
  "counts": {
    "findings": 2,
    "by_severity": {
      "info": 0,
      "low": 0,
      "medium": 0,
      "high": 2,
      "critical": 0
    },
    "suppressed_by_fingerprint": 0,
    "suppressed_by_path": 0,
    "stale": 0,
    "issues": 0
  },
  "stats": {
    "files_seen": 3,
    "files_scanned": 3,
    "bytes_scanned": 112,
    "skipped_binary": 0,
    "skipped_symlink": 0,
    "skipped_offline": 0,
    "skipped_special": 0,
    "skipped_excluded": 0,
    "skipped_gitignored": 0,
    "skipped_submodule": 0,
    "commits": 0,
    "blobs_scanned": 0,
    "blobs_from_cache": 0
  },
  "findings": [
    {
      "rule_id": "aws-access-key-id",
      "detector": "rule",
      "severity": "high",
      "confidence": "high",
      "file": "config/.env",
      "line": 2,
      "column": 9,
      "end_column": 29,
      "commit": null,
      "commit_time": null,
      "redacted": {
        "shown": "AKIA",
        "length": 20,
        "hash8": "44d2e6b2",
        "text": "AKIA... [20 chars, sha256:44d2e6b2]"
      },
      "fingerprint": "2e46a4068a6546c92e0156a9d7322ae7",
      "suppressed_by": null
    },
    {
      "rule_id": "npm-token",
      "detector": "rule",
      "severity": "high",
      "confidence": "high",
      "file": "src/app.py",
      "line": 3,
      "column": 10,
      "end_column": 50,
      "commit": null,
      "commit_time": null,
      "redacted": {
        "shown": "npm_",
        "length": 40,
        "hash8": "681a73de",
        "text": "npm_... [40 chars, sha256:681a73de]"
      },
      "fingerprint": "00d362eed12650a37a4c812d755ed299",
      "suppressed_by": null
    }
  ],
  "issues": []
}
```

## The rules listing `secret-rules/1`

`secret-scanner rules` lists every built-in rule and detector; `--format json` writes one JSON
document (ASCII only, two-space indent) and the default is a table. The listing is built from the
packaged rules file and from the descriptions of the private key and entropy detectors. It holds no
pattern, no fake specification and no example: nothing in it can be used to build a secret-shaped
value. The command takes no path and writes only to standard output.

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | Always `secret-rules/1`. |
| `tool` | object | `name` and `version`. |
| `rules_sha256` | string | SHA-256 (hex) of the built-in rules file. |
| `rules` | array | One object per rule, below: the rules file's rules in file order, then the detectors. |

### `rules[]`

| Field | Type | Meaning |
|---|---|---|
| `id` | string | The rule id, or `private-key`, `entropy-base64`, `entropy-hex`. |
| `name` | string | A short name. |
| `detector` | string | `rule`, `private_key` or `entropy`. |
| `severity` | string | The default severity; the private key detector lowers an encrypted key to `medium`. |
| `confidence` | string | The default confidence; checksum, context and block completeness adjust it per finding. |
| `description` | string | What the rule matches, in words. |
| `keywords` | array | Lower-case literals; a rule's pattern runs only on a line that holds one. Empty for the entropy detectors, which run on every line. |

A shortened table, produced by `secret-scanner rules`:

```
secret-scanner 0.1.0 - 16 built-in rules
rules file sha256 52928a72916a6e9a2b4691ad56b7b0ca9b6333d0657928348959259ea1568ba1

ID                         SEVERITY  CONFIDENCE  DETECTOR     KEYWORDS
aws-access-key-id          high      high        rule         akia, asia, abia, acca
  An AWS access key id (AKIA, ASIA, ABIA or ACCA followed by 16 base32 characters).
aws-secret-access-key      critical  medium      rule         aws
  A 40-character base64 value on a line that names both aws and secret.
```

## What `scan` reads and writes

- Reads: the files under the given directory (regular files only, never through a link), and the
  files named by `--config` and `--baseline`. Configuration and baseline are never discovered.
- Writes: only `--output` and `--write-baseline`, atomically, never over an existing file without
  `--force`, never through a link, and never inside the scanned tree.
- A baseline written by `--write-baseline` lists the reported findings and the ones the given
  baseline already suppressed by fingerprint, keeps the reasons already written for them, and
  carries the path globs over. Findings suppressed only by a path glob are not duplicated.
