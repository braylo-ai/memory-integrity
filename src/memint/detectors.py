"""Poisoning and contradiction detectors run on every memory write.

A non-empty flag list sends the write to quarantine: stored for audit, not served.
"""

from __future__ import annotations

import re

from .store import MemoryStore, Provenance

PROTECTED = {
    "email",
    "phone",
    "bank_account",
    "address",
    "employer",
    "allowed_recipients",
    "auto_approve_payments",
    "admin",
    "password_hint",
    "emergency_contact",
}

INSTRUCTION_RE = re.compile(
    r"\b(ignore (?:all |any )?(?:previous|prior)|disregard|from now on|always|never tell|"
    r"you must|assistant[,:]|system prompt|do not (?:tell|mention|ask)|whenever|"
    r"(?:send|forward|cc|bcc|wire|transfer) (?:\w+ )*?to)\b|https?://|<\|",
    re.I,
)

MUTEX = {  # (predicate, value) pairs that cannot both hold for one subject
    ("diet", "vegetarian"): {
        ("favorite_food", "steak"),
        ("favorite_food", "bacon"),
        ("favorite_food", "chicken wings"),
    },
    ("diet", "vegan"): {
        ("favorite_food", "steak"),
        ("favorite_food", "cheese"),
        ("favorite_food", "bacon"),
    },
    ("allergy", "peanuts"): {("favorite_food", "peanut butter")},
}
CITY_COUNTRY = {
    "chicago": "usa",
    "new york": "usa",
    "paris": "france",
    "lyon": "france",
    "berlin": "germany",
    "toronto": "canada",
    "london": "uk",
}
FLIP_WINDOW = 7 * 86400
FLIP_LIMIT = 3


def _mutex_conflicts(store: MemoryStore, s: str, p: str, v) -> bool:
    facts = store.facts_about(s)
    pair = (p, str(v).lower())
    for (a, b), bad in MUTEX.items():
        if pair == (a, b) and any(
            (q, str(facts.get(q, "")).lower()) in bad for q, _ in bad
        ):
            return True
        if pair in bad and str(facts.get(a, "")).lower() == b:
            return True
    return False


def detect(store: MemoryStore, s: str, p: str, v, prov: Provenance) -> list[str]:
    flags: list[str] = []
    trust = prov.trust
    # 1. untrusted-source writes
    if p in PROTECTED and trust < 0.9:
        flags.append("untrusted_write_protected_key")
    elif trust <= 0.1:
        flags.append("unknown_source")
    # 2. instruction-like content (only below user/system trust: users may set rules)
    if trust < 0.9 and isinstance(v, str) and INSTRUCTION_RE.search(v):
        flags.append("instruction_like")
    # 3. belief flips
    cur = store.current_version(s, p)
    if cur is not None and cur.value != v and trust < cur.prov.trust:
        flags.append("flip_from_more_trusted")
    recent = [x for x in store.history(s, p) if prov.t - x.prov.t <= FLIP_WINDOW]
    if (
        cur is not None
        and cur.value != v
        and len({str(x.value) for x in recent}) >= FLIP_LIMIT
        and trust < 0.9
    ):
        flags.append("flip_rate")
    # 4. contradictions with other facts
    if _mutex_conflicts(store, s, p, v) and trust < 0.9:
        flags.append("contradiction_mutex")
    if (
        p == "age"
        and cur is not None
        and isinstance(v, (int, float))
        and isinstance(cur.value, (int, float))
    ):
        years = (prov.t - cur.prov.t) / (365 * 86400)
        if v < cur.value or v - cur.value > years + 1:
            flags.append("contradiction_numeric")
    facts = store.facts_about(s)
    if p == "city" and "country" in facts:
        exp = CITY_COUNTRY.get(str(v).lower())
        if exp and exp != str(facts["country"]).lower() and trust < 0.9:
            flags.append("contradiction_geo")
    if p == "country" and "city" in facts:
        exp = CITY_COUNTRY.get(str(facts["city"]).lower())
        if exp and exp != str(v).lower() and trust < 0.9:
            flags.append("contradiction_geo")
    return flags
