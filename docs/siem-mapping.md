# JSONL output and mini-siem (`secret-event/1`)

`secret-scanner scan PATH --format jsonl` and `secret-scanner scan-git REPO --format jsonl` write
one JSON object per line, shaped for the generic JSON parser of mini-siem (the sibling project in
this portfolio) so that its `ingest` takes the file **without any change to mini-siem**. This file
records how a line is built, how mini-siem reads it, the limits it must stay inside, and a real
ingest. It is checked against the code by `tests/test_siem_mapping_doc.py`: a field name, a limit
or an example that changes in the code and not here fails the gate.

Produce a file and ingest it, from the directory that holds `project`:

```
secret-scanner scan project --format jsonl --host-label build-01 --output events.jsonl
mini-siem ingest events.jsonl --format json
```

The report must be written outside the scanned directory: an `--output` inside it is refused, and
so is any path that contains `..`. Scan the directory by name from its parent, as here, or give
`--output` an absolute path.

(`--format auto` also works: mini-siem guesses JSON from the first character of the first line.)

## Promises

- One finding per line, then one final summary line. Compact JSON, **ASCII only** (every non-ASCII
  character is a `\uXXXX` escape), a newline after every line, fixed key order.
- No field holds a secret. A finding line carries the redacted form (a fixed public prefix, the
  length and an 8-hex-digit display hash), a fingerprint and a location. There is no source line.
- The summary line states whether the run was complete, so a SIEM can see an incomplete run (a
  limit, a time budget, a shallow history) and does not take an empty file for a clean result.
- Within `secret-event/1` fields are only ever added at the end of their object. A consumer must
  ignore unknown keys.
- There is never a top-level `path`, `url`, `user`, `ip`, `status` or `method`: mini-siem would
  reinterpret them (see below). Everything else lives in the object `secret`.

## Top-level fields

| Field | Type | Meaning |
|---|---|---|
| `timestamp` | string | UTC time of the run, `YYYY-MM-DDTHH:MM:SSZ`, the same on every line of a run. For a history scan the time of a commit is `secret.commit_time`. |
| `host` | string | `--host-label`, or the machine's node name; escaped, at most 255 characters. |
| `message` | string | One line of text: the rule, the redacted value and the place (`rule: AKIA... [20 chars, sha256:11c64dd5] at config/.env:2:19`), and `in commit <12 hex>` for a history scan; at most 1 024 characters. |
| `event_type` | string | `secret.finding` or `secret.scan_summary`. |
| `secret` | object | The fields below. |

### The finding line, `secret`

| Field | Type | Meaning |
|---|---|---|
| `rule_id` | string | The rule, or `private-key`, `entropy-base64`, `entropy-hex`. |
| `detector` | string | `rule`, `entropy` or `private_key`. |
| `severity` | string | `info`, `low`, `medium`, `high` or `critical`. |
| `confidence` | string | `low`, `medium` or `high`. |
| `file` | string | Path relative to the scan root, `/` separated, escaped; cut at 1 000 characters (never inside an escape). |
| `file_sha256` | string | SHA-256 (hex) of the full escaped path, so a cut path can still be told apart. |
| `file_truncated` | boolean | `true` when `file` was cut. |
| `line` | integer | 1-based. |
| `column` | integer | 1-based, in Unicode code points. |
| `commit` | string or null | Commit that first introduced the secret (history scan). |
| `commit_time` | integer or null | Committer time of that commit, Unix seconds. |
| `redacted` | string | The redacted value. |
| `secret_length` | integer | Length of the secret in characters. |
| `secret_hash8` | string | First 8 hex digits of the display hash. |
| `fingerprint` | string | 32 hex digits; the same value a baseline lists. |
| `target` | string | `fs` or `git`. |
| `tool_version` | string | The version of secret-scanner. |
| `schema` | string | Always `secret-event/1`. |
| `suppressed_by` | string or null | `fingerprint` or `path` for a suppressed finding listed with `--show-suppressed`, else `null`. |

### The summary line, `secret`

| Field | Type | Meaning |
|---|---|---|
| `target` | string | `fs` or `git`. |
| `target_path` | string | The path as given, escaped; cut at 1 000 characters. |
| `target_path_truncated` | boolean | `true` when `target_path` was cut. |
| `findings` | integer | Reported findings (suppressed ones are not counted). |
| `findings_critical` | integer | The same count for `critical`. |
| `findings_high` | integer | ... for `high`. |
| `findings_medium` | integer | ... for `medium`. |
| `findings_low` | integer | ... for `low`. |
| `findings_info` | integer | ... for `info`. |
| `suppressed_by_fingerprint` | integer | Findings the baseline suppressed by fingerprint. |
| `suppressed_by_path` | integer | Findings the baseline suppressed by a path glob. |
| `stale` | integer or null | Baseline entries that matched nothing; `null` when the run was incomplete. |
| `issues` | integer | Number of scan issues (what made the run incomplete); the details are in `--format json`. |
| `complete` | boolean | `true` only when every file was read and no limit was hit. |
| `truncated` | boolean | `true` when the report limit cut the list of findings. |
| `history_complete` | boolean or null | History scan only. |
| `files_seen` | integer | Files seen (distinct blobs for a history scan). |
| `files_scanned` | integer | Files scanned. |
| `commits` | integer | Commits walked (history scan). |
| `rules_sha256` | string | SHA-256 (hex) of the built-in rules file the run used. |
| `tool_version` | string | The version of secret-scanner. |
| `schema` | string | Always `secret-event/1`. |

## How mini-siem reads a line

Recorded from `src/mini_siem/parsers/jsonlog.py`, `src/mini_siem/core/events.py` and
`src/mini_siem/collectors/jsonl_ingest.py` of mini-siem 1.0.0 (commit `6adc008`), read on
2026-11-09, and confirmed by the ingest below. This is mini-siem's behaviour, not a promise of
this tool: if mini-siem changes, this file must be read again.

- `timestamp` becomes the event time. `host` and `message` become the event's `host` and `message`.
- `event_type` is looked up in mini-siem's closed list of types. `secret.finding` and
  `secret.scan_summary` are not in it, so the event type is `json_event` and the declared value is
  kept as the attribute `declared_event_type`.
- Every other value is flattened into an attribute of text: an object into dotted names
  (`secret.rule_id`), a boolean into `true` or `false`, a number into its digits, `null` is
  dropped (so `commit` and `suppressed_by` are absent on a directory finding).
- Top-level keys that mini-siem reinterprets (and this tool therefore never writes): `@timestamp`,
  `time`, `ts`, `datetime`, `source_ip`, `src_ip`, `client_ip`, `remote_addr`, `remote_ip`, `ip`,
  `user_name`, `username`, `user`, `account`, `msg`, `log`, `event`, `hostname`, `user_agent`,
  `useragent`, `ua`, `http_user_agent`, `url_path`, `url`, `path`, `uri`, `request_uri`,
  `http_method`, `method`, `http_status`, `status`, `status_code`, `process_name`, `process`,
  `program`, `app`.

### Limits recorded

| Limit | Value | Where it applies |
|---|---|---|
| Attributes per event | 64 | A finding line makes at most 19 attributes plus `declared_event_type`; a summary line 22 plus it. |
| Attribute name | 64 characters | The longest name is `secret.suppressed_by_fingerprint`. |
| Attribute value | 1 024 characters | The longest value is `file` or `target_path`, cut at 1 000. |
| `message` | 4 096 characters | This tool keeps it under 1 024. |
| `host` | 255 characters | The host label is cut at 255. |
| Line | 65 536 bytes | A line is far below it: the longest values add up to about 3 000 bytes. |
| Nesting depth | 3 | `secret` is one level deep. |

A value over a limit is cut by mini-siem and flagged with the attribute `truncated_fields`; the
limits above are kept so that never happens to a line of this tool.

## Examples

Produced by `secret-scanner scan . --format jsonl --host-label example-host` over a generated
project (the secrets were built at run time and exist nowhere in this repository). The timestamp
shows `<time>`; the tool writes the UTC time of the run.

```
{"timestamp":"<time>","host":"example-host","message":"aws-access-key-id: AKIA... [20 chars, sha256:11c64dd5] at config/.env:2:19","event_type":"secret.finding","secret":{"rule_id":"aws-access-key-id","detector":"rule","severity":"high","confidence":"high","file":"config/.env","file_sha256":"ea0aa93d44adeb5297069e9601c04b5e9b1aff3576f2e912fcc15f48045c3160","file_truncated":false,"line":2,"column":19,"commit":null,"commit_time":null,"redacted":"AKIA... [20 chars, sha256:11c64dd5]","secret_length":20,"secret_hash8":"11c64dd5","fingerprint":"357a01ffc066d4e7216b0b78e42104c4","target":"fs","tool_version":"1.0.0","schema":"secret-event/1","suppressed_by":null}}
{"timestamp":"<time>","host":"example-host","message":"npm-token: npm_... [40 chars, sha256:473b5357] at src/app.py:3:10","event_type":"secret.finding","secret":{"rule_id":"npm-token","detector":"rule","severity":"high","confidence":"high","file":"src/app.py","file_sha256":"04791d82dd15fdd480f084d7ef65a10789fa5012cb7935f76080763444d48a00","file_truncated":false,"line":3,"column":10,"commit":null,"commit_time":null,"redacted":"npm_... [40 chars, sha256:473b5357]","secret_length":40,"secret_hash8":"473b5357","fingerprint":"68b5a7e585c6721cace03b4ff3cbc0f4","target":"fs","tool_version":"1.0.0","schema":"secret-event/1","suppressed_by":null}}
{"timestamp":"<time>","host":"example-host","message":"secret-scanner directory scan complete: 2 finding(s), 0 issue(s)","event_type":"secret.scan_summary","secret":{"target":"fs","target_path":".","target_path_truncated":false,"findings":2,"findings_critical":0,"findings_high":2,"findings_medium":0,"findings_low":0,"findings_info":0,"suppressed_by_fingerprint":0,"suppressed_by_path":0,"stale":0,"issues":0,"complete":true,"truncated":false,"history_complete":null,"files_seen":3,"files_scanned":3,"commits":0,"rules_sha256":"52928a72916a6e9a2b4691ad56b7b0ca9b6333d0657928348959259ea1568ba1","tool_version":"1.0.0","schema":"secret-event/1"}}
```

A finding of a history scan (`secret-scanner scan-git REPO --format jsonl`) also names its commit.
This line was recorded on 2026-11-09, before the release, when the tool still reported version
`0.1.0`; it is kept as recorded, because it is one of the five lines of the real ingest below:

```
{"timestamp":"<time>","host":"example-host","message":"stripe-secret-key: sk_live_... [38 chars, sha256:7a73ab3b] at service/settings.txt:2:14 in commit a1a75720af86","event_type":"secret.finding","secret":{"rule_id":"stripe-secret-key","detector":"rule","severity":"critical","confidence":"high","file":"service/settings.txt","file_sha256":"26fefb9d3146ecd042f89fdff89ce812f4f6682ecbcbe6f626c527ef0bdbb4b4","file_truncated":false,"line":2,"column":14,"commit":"a1a75720af86cb161343828317659aa6c37a77db","commit_time":1767225660,"redacted":"sk_live_... [38 chars, sha256:7a73ab3b]","secret_length":38,"secret_hash8":"7a73ab3b","fingerprint":"65e1e0f0ffdb2f8dee915e86813d0f38","target":"git","tool_version":"0.1.0","schema":"secret-event/1","suppressed_by":null}}
```

## A real ingest

Done on 2026-11-09 with mini-siem 1.0.0 (commit `6adc008`) from its own virtual environment, over a
file of five lines: the three lines above, the history finding and its summary line. The ingest
was not repeated for the release: on that day every line carried `tool_version` `0.1.0`, which is
the only value that differs from what version 1.0.0 writes, and the stored event below shows it as
it was stored. mini-siem was
used read-only: the program was started with byte-code writing off, from a working directory and
with a data directory inside a temporary folder outside both repositories, and a fingerprint of
the whole mini-siem folder (15 332 entries: path, mode, size and modification time of each) was
the same before and after (`a6b78a42eb0f...`). `<temp>` stands for that folder.

```
$ mini-siem --data-dir <temp>/data ingest <temp>/secret-events.jsonl --format json
<temp>/secret-events.jsonl: format json, 5 line(s), 5 record(s), 0 blank, 0 over-long
events: 5 parsed, 5 newly stored, 0 already stored
parse failures: 0 (dead-letter file: <temp>/data/deadletter.jsonl), over-long lines: 0
alerts: 0 stored (0 allowlisted), 0 duplicate(s) suppressed by cooldown
```

Ingesting the same file again stores nothing twice (`events: 5 parsed, 0 newly stored, 5 already
stored`). A search shows the events, newest first, with the host and the message:

```
$ mini-siem --data-dir <temp>/data search
TIME (UTC)                   TYPE        SOURCE_IP  USER  HOST          DETAIL
2026-11-09T09:54:01.000000Z  json_event                   example-host  secret-scanner history scan complete: 1 finding(s), 0 issue(s)
2026-11-09T09:54:01.000000Z  json_event                   example-host  stripe-secret-key: sk_live_... [38 chars, sha256:7a73ab3b] at service/settings.txt:2:14 in commit a1a75720af86
2026-11-09T09:54:00.000000Z  json_event                   example-host  secret-scanner directory scan complete: 2 finding(s), 0 issue(s)
2026-11-09T09:54:00.000000Z  json_event                   example-host  npm-token: npm_... [40 chars, sha256:473b5357] at src/app.py:3:10
2026-11-09T09:54:00.000000Z  json_event                   example-host  aws-access-key-id: AKIA... [20 chars, sha256:11c64dd5] at config/.env:2:19
5 event(s), newest first
```

and `search --json` shows how one finding is stored (`aws-access-key-id: ...`; the fields that are
empty for this event are left out here, and the two long hex values are cut to their first 12 digits,
because a long hex value next to a key named `secret.*` is exactly what this tool's own scan of this
repository reports as a possible secret):

```
{
  "event_type": "json_event",
  "source": "json",
  "host": "example-host",
  "message": "aws-access-key-id: AKIA... [20 chars, sha256:11c64dd5] at config/.env:2:19",
  "attrs": {
    "declared_event_type": "secret.finding",
    "secret.column": "19",
    "secret.confidence": "high",
    "secret.detector": "rule",
    "secret.file": "config/.env",
    "secret.file_sha256": "ea0aa93d44ad...",
    "secret.file_truncated": "false",
    "secret.fingerprint": "357a01ffc066...",
    "secret.line": "2",
    "secret.redacted": "AKIA... [20 chars, sha256:11c64dd5]",
    "secret.rule_id": "aws-access-key-id",
    "secret.schema": "secret-event/1",
    "secret.secret_hash8": "11c64dd5",
    "secret.secret_length": "20",
    "secret.severity": "high",
    "secret.target": "fs",
    "secret.tool_version": "0.1.0"
  }
}
```

## Known gaps

- **No mini-siem detection rule is written or tested here.** The events are stored and
  searchable; whether and how a mini-siem rule can match on `secret.severity` or the other
  attributes was not examined.
- **A search by attribute does not work in mini-siem 1.0.0.** Its query language has fixed fields
  (`source_ip`, `event_type`, `source`, `host`, `user_name`, `http_status`, `url_path`,
  `user_agent`), so `secret.rule_id:...` is not a query. Free text finds the message (for example
  `mini-siem search stripe-secret-key`), and `host:` finds a host. The attribute
  `declared_event_type` is not found by a search for its name.
- One summary line per run, and issues are only counted there: the list of what was not scanned is
  in `--format json` and `--format sarif`.
- The timestamp is the time of the run on every line, not the time of the commit (`commit_time`).
- The file named by `--output` is written once, whole: the tool does not append to a growing log.
  A scheduled run writes a new file; mini-siem's `ingest` keys events by file path, line and
  content, so re-ingesting a changed file at the same path stores the new lines.
