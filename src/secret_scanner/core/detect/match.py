"""`Match`: the only type that holds a secret (PLAN.md section 2).

It lives inside the detection layer. `core/findings.py` turns it into a `Finding` (a redacted value
and a fingerprint) and it is then dropped. The architecture check keeps it away from `render/`,
`app/` and `cli/`. Its repr never shows the secret, so a traceback or a failed assertion cannot
leak it through this type.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from secret_scanner.core.models import Confidence, Detector, Severity


@dataclass(frozen=True, slots=True)
class Match:
    rule_id: str
    detector: Detector
    severity: Severity
    confidence: Confidence
    line: int  # 1-based
    col_start: int  # 1-based, code points
    col_end: int  # exclusive
    secret: bytes = field(repr=False)
    shown_chars: int  # leading characters that are a rule's public prefix (PLAN.md D7)
    kind_label: str = ""  # private key type: "", RSA, DSA, EC, OPENSSH, ENCRYPTED or PGP
