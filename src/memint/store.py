"""Versioned long-term memory with per-fact provenance.

Every write is appended to an immutable log as a new version. The served value
for a key is the latest version with status "active". Rollback never deletes:
it marks versions "rolled_back" and the previous active version becomes current.
"""

from __future__ import annotations

from dataclasses import dataclass, field

SOURCE_TRUST = {
    "user": 1.0,
    "system": 0.95,
    "tool": 0.7,
    "agent_inference": 0.5,
    "web": 0.3,
    "email": 0.3,
    "unknown": 0.1,
}


@dataclass(frozen=True)
class Provenance:
    source_id: str  # "user", "tool:crm-sync", "web:blog.example", "email:msg42"
    source_type: str  # key of SOURCE_TRUST
    t: float

    @property
    def trust(self) -> float:
        return SOURCE_TRUST.get(self.source_type, 0.1)


@dataclass
class Version:
    idx: int
    subject: str
    predicate: str
    value: object
    prov: Provenance
    status: str = "active"  # active | quarantined | rolled_back
    flags: tuple = ()

    @property
    def key(self):
        return (self.subject, self.predicate)


@dataclass
class WriteResult:
    idx: int
    decision: str  # accept | quarantine
    flags: tuple


@dataclass
class MemoryStore:
    quarantine: bool = (
        True  # False = flag-only mode: flags recorded, write still served
    )
    detectors: object = (
        None  # callable(store, subject, predicate, value, prov) -> list[str]
    )
    log: list = field(default_factory=list)
    events: list = field(default_factory=list)  # rollback events (also append-only)

    def current(self, subject: str, predicate: str):
        v = self.current_version(subject, predicate)
        return v.value if v else None

    def current_version(self, subject: str, predicate: str) -> Version | None:
        for v in reversed(self.log):
            if v.key == (subject, predicate) and v.status == "active":
                return v
        return None

    def history(self, subject: str, predicate: str) -> list[Version]:
        return [v for v in self.log if v.key == (subject, predicate)]

    def state(self) -> dict:
        out = {}
        for v in self.log:
            if v.status == "active":
                out[v.key] = v.value
        return out

    def facts_about(self, subject: str) -> dict:
        return {p: val for (s, p), val in self.state().items() if s == subject}

    def write(
        self, subject: str, predicate: str, value, prov: Provenance
    ) -> WriteResult:
        flags = (
            tuple(self.detectors(self, subject, predicate, value, prov))
            if self.detectors
            else ()
        )
        status = "quarantined" if flags and self.quarantine else "active"
        v = Version(len(self.log), subject, predicate, value, prov, status, flags)
        self.log.append(v)
        return WriteResult(v.idx, "quarantine" if flags else "accept", flags)

    def snapshot(self) -> int:
        return len(self.log)

    def rollback_to(self, snap: int) -> int:
        """Undo every write made after snapshot `snap`. Returns versions affected."""
        n = 0
        for v in self.log[snap:]:
            if v.status == "active":
                v.status, n = "rolled_back", n + 1
        self.events.append(("rollback_to", snap, n))
        return n

    def rollback_source(self, source_id: str) -> int:
        """Undo every write from one source (e.g. after it is found to be compromised)."""
        n = 0
        for v in self.log:
            if v.prov.source_id == source_id and v.status == "active":
                v.status, n = "rolled_back", n + 1
        self.events.append(("rollback_source", source_id, n))
        return n

    def rollback_writes(self, idxs) -> int:
        """Undo specific writes (e.g. the ones a detector flagged after the fact)."""
        n = 0
        for i in idxs:
            if self.log[i].status == "active":
                self.log[i].status, n = "rolled_back", n + 1
        self.events.append(("rollback_writes", tuple(idxs), n))
        return n

    def release(self, idx: int) -> None:
        """Human reviewer approves a quarantined write."""
        if self.log[idx].status == "quarantined":
            self.log[idx].status = "active"
            self.events.append(("release", idx))
