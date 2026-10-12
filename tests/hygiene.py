"""Repository hygiene checks (CLAUDE.md section 7), shared by the tests of the real repository and
by their positive controls in temporary repositories.

Findings never contain the offending text: only a rule name, a path and a line number, plus (for
secret-shaped strings) the redacted form.

The secret-shaped checks are the minimal hard-coded set of PLAN.md D16 point 4 (AWS key id,
GitHub token, private key block, Slack token, Stripe key). Phase 2 replaces them with the engine
and checks that the engine covers every case of this set.
"""

from __future__ import annotations

import fnmatch
import hashlib
import re
import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from secret_scanner.core.redact import redact_secret
from tests.gitrepo import run_git

SECRET_FILE_PATTERNS = (
    "*.key",
    "*.pem",
    "*.p12",
    "*.pfx",
    "id_rsa*",
    "id_ed25519*",
    ".env*",
    "*.keystore",
    "*.jks",
)
ALLOWED_CONTROL_CHARACTERS = frozenset("\n\r\t")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")

FORMAT_CHECKS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "aws-access-key-id",
        re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}(?![A-Za-z0-9])"),
    ),
    ("github-token", re.compile(r"(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]{36}(?![A-Za-z0-9])")),
    (
        "slack-token",
        re.compile(r"(?<![A-Za-z0-9])xox[abeoprs]-(?:[0-9A-Za-z]{6,}-){1,3}[0-9A-Za-z]{10,}"),
    ),
    ("stripe-secret-key", re.compile(r"(?<![A-Za-z0-9_])[rs]k_live_[0-9A-Za-z]{24,99}")),
)
PRIVATE_KEY_HEADER = re.compile(
    r"-----BEGIN (?:(?:RSA|DSA|EC|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----"
    r"|-----BEGIN PGP PRIVATE KEY BLOCK-----"
)
_BASE64_LINE = re.compile(r"^[A-Za-z0-9+/=]+$")
_HEADER_FIELD = re.compile(r"^[A-Za-z-]+: ")
MIN_KEY_BODY_CHARS = 64
MAX_KEY_LINES = 200
BINARY_PROBE_BYTES = 8_000


@dataclass(frozen=True, slots=True)
class Hit:
    """One hygiene finding. `detail` is redacted or purely descriptive, never file content."""

    check: str
    path: str
    line: int
    detail: str

    def format(self) -> str:
        return f"{self.path}:{self.line}: {self.check} ({self.detail})"


# -- listing --------------------------------------------------------------------------------


def repository_files(root: Path, home: Path) -> list[str]:
    """Tracked, staged and untracked-not-ignored paths, relative to `root`, `/`-separated."""
    result = run_git(
        root,
        home,
        "-c",
        f"safe.directory={root.as_posix()}",
        "ls-files",
        "-z",
        "--cached",
        "--others",
        "--exclude-standard",
    )
    names = [name for name in result.stdout.split("\0") if name]
    return sorted(set(names))


def read_text_files(root: Path, names: list[str]) -> Iterator[tuple[str, str | None]]:
    """Yield `(path, text)`; `text` is None for a binary file or one that is not valid UTF-8.
    Files listed by git but missing on disk (deleted, not yet staged) are skipped."""
    for name in names:
        path = root / name
        if not path.is_file():
            continue
        data = path.read_bytes()
        if b"\0" in data[:BINARY_PROBE_BYTES]:
            yield name, None
            continue
        try:
            yield name, data.decode("utf-8")
        except UnicodeDecodeError:
            yield name, None


# -- checks ---------------------------------------------------------------------------------


def forbidden_characters(path: str, text: str) -> list[Hit]:
    hits: list[Hit] = []
    for number, line in enumerate(text.split("\n"), start=1):
        for char in line:
            category = unicodedata.category(char)
            bad_control = category == "Cc" and char not in ALLOWED_CONTROL_CHARACTERS
            if bad_control or category in {"Cf", "Zl", "Zp"}:
                hits.append(Hit("forbidden-character", path, number, f"U+{ord(char):04X}"))
    return hits


def secret_file_names(names: list[str]) -> list[Hit]:
    hits: list[Hit] = []
    for name in names:
        base = name.rsplit("/", 1)[-1].lower()
        if any(fnmatch.fnmatchcase(base, pattern) for pattern in SECRET_FILE_PATTERNS):
            hits.append(Hit("secret-file", name, 0, "file name matches a key or env pattern"))
    return hits


def email_addresses(path: str, text: str) -> list[Hit]:
    return [
        Hit("email-address", path, number, "address-like text")
        for number, line in enumerate(text.split("\n"), start=1)
        if EMAIL.search(line)
    ]


def _key_body_chars(lines: list[str], index: int, tail: str) -> int:
    """Count base64 body characters after a private key header (line `index`, rest `tail`)."""
    escaped = tail.split("-----END", 1)[0].replace("\\n", "").replace("\\r", "").strip()
    if _BASE64_LINE.match(escaped):
        return len(escaped)
    total = 0
    for line in lines[index + 1 : index + 1 + MAX_KEY_LINES]:
        stripped = line.strip()
        if stripped.startswith("-----END"):
            break
        if _BASE64_LINE.match(stripped):
            total += len(stripped)
        elif stripped and not _HEADER_FIELD.match(stripped):
            break
    return total


def secret_shaped_strings(path: str, text: str) -> list[Hit]:
    hits: list[Hit] = []
    lines = text.split("\n")
    for number, line in enumerate(lines, start=1):
        for name, pattern in FORMAT_CHECKS:
            for match in pattern.finditer(line):
                redacted = redact_secret(match.group(0).encode("ascii"), 0).text
                hits.append(Hit(name, path, number, redacted))
        header = PRIVATE_KEY_HEADER.search(line)
        if header is not None:
            body = _key_body_chars(lines, number - 1, line[header.end() :])
            if body >= MIN_KEY_BODY_CHARS:
                redacted = redact_secret(b"x" * body, 0).text
                hits.append(Hit("private-key", path, number, redacted))
    return hits


def check_repository(root: Path, home: Path) -> list[Hit]:
    """Run every hygiene check over the repository's tracked and untracked-not-ignored files."""
    names = repository_files(root, home)
    hits = secret_file_names(names)
    for name, text in read_text_files(root, names):
        if text is None:
            continue
        hits += forbidden_characters(name, text)
        hits += email_addresses(name, text)
        hits += secret_shaped_strings(name, text)
    return hits


# -- fakes for positive controls (runtime only, built from fragments) -----------------------

BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
BASE62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
DIGITS = "0123456789"


def _body(seed: str, alphabet: str, length: int) -> str:
    out: list[str] = []
    counter = 0
    while len(out) < length:
        digest = hashlib.sha256(f"{seed}:{counter}".encode()).digest()
        counter += 1
        out.extend(alphabet[byte % len(alphabet)] for byte in digest)
    return "".join(out[:length])


def fake_secret(kind: str, seed: str = "control") -> str:
    """A format-valid fake for the minimal set. It must never be written to a tracked file."""
    if kind == "aws-access-key-id":
        return "AK" + "IA" + _body(seed, BASE32, 16)
    if kind == "github-token":
        return "gh" + "p" + "_" + _body(seed, BASE62, 36)
    if kind == "slack-token":
        parts = [_body(seed + "a", DIGITS, 11), _body(seed + "b", DIGITS, 12)]
        return "xo" + "xb" + "-" + "-".join(parts) + "-" + _body(seed, BASE62, 24)
    if kind == "stripe-secret-key":
        return "s" + "k_" + "li" + "ve_" + _body(seed, BASE62, 30)
    if kind == "private-key":
        header = "-----BEGIN " + "RSA PRIVATE" + " KEY-----"
        footer = "-----END " + "RSA PRIVATE" + " KEY-----"
        body = [_body(f"{seed}{n}", BASE62 + "+/", 64) for n in range(3)]
        return "\n".join([header, *body, footer, ""])
    raise ValueError(f"unknown fake kind: {kind}")


FAKE_KINDS = (
    "aws-access-key-id",
    "github-token",
    "slack-token",
    "stripe-secret-key",
    "private-key",
)
