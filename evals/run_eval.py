"""Detection precision/recall and rollback correctness; writes results/results.json.

    python evals/run_eval.py
"""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from memint.dataset import seeded_store, stream  # noqa: E402
from memint.detectors import detect  # noqa: E402
from memint.store import Provenance  # noqa: E402


def detection() -> dict:
    st = seeded_store(detect)
    tp = fp = fn = tn = 0
    fam = defaultdict(lambda: [0, 0])
    by_flag = Counter()
    by_flag_tp = Counter()
    fps, fns = [], []
    for r in stream():
        res = st.write(
            r["subject"],
            r["predicate"],
            r["value"],
            Provenance(r["source_id"], r["source_type"], r["t"]),
        )
        flagged = res.decision == "quarantine"
        for f in res.flags:
            by_flag[f] += 1
            by_flag_tp[f] += r["poisoned"]
        if r["poisoned"]:
            fam[r["family"]][0] += flagged
            fam[r["family"]][1] += 1
            tp += flagged
            fn += not flagged
            if not flagged:
                fns.append(
                    f'{r["family"]}: {r["subject"]}.{r["predicate"]}={r["value"]!r} ({r["source_id"]})'
                )
        else:
            fp += flagged
            tn += not flagged
            if flagged:
                fps.append(
                    f'{r["subject"]}.{r["predicate"]}={r["value"]!r} ({r["source_id"]}) flags={list(res.flags)}'
                )
    p = tp / (tp + fp) if tp + fp else 0.0
    rc = tp / (tp + fn)
    return {
        "n_poisoned": tp + fn,
        "n_legit": fp + tn,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": round(p, 3),
        "recall": round(rc, 3),
        "f1": round(2 * p * rc / (p + rc), 3),
        "recall_by_family": {k: f"{v[0]}/{v[1]}" for k, v in sorted(fam.items())},
        "flag_counts": {
            k: {"fired": by_flag[k], "on_poison": by_flag_tp[k]}
            for k in sorted(by_flag)
        },
        "false_positives": fps,
        "false_negatives": fns,
    }


def _replay(rows, only_legit=False):
    st = seeded_store(None)  # detectors OFF: simulate poisoning that got through
    snap = st.snapshot()
    for r in rows:
        if only_legit and r["poisoned"]:
            continue
        st.write(
            r["subject"],
            r["predicate"],
            r["value"],
            Provenance(r["source_id"], r["source_type"], r["t"]),
        )
    return st, snap


def _score(state, truth):
    keys = set(state) | set(truth)
    correct = sum(state.get(k) == truth.get(k) for k in keys)
    return correct, len(keys)


def rollback() -> dict:
    rows = stream()
    truth = _replay(rows, only_legit=True)[0].state()
    poisoned_sources = sorted({r["source_id"] for r in rows if r["poisoned"]})
    mixed = sorted(
        s
        for s in poisoned_sources
        if any(r["source_id"] == s and not r["poisoned"] for r in rows)
    )
    out = {
        "poisoned_sources": len(poisoned_sources),
        "mixed_sources_with_legit_writes": mixed,
    }

    st, _ = _replay(rows)
    c, n = _score(st.state(), truth)
    out["no_rollback"] = {
        "keys_correct": c,
        "keys_total": n,
        "accuracy": round(c / n, 3),
    }

    st, snap = _replay(rows)
    st.rollback_to(snap)
    c, n = _score(st.state(), truth)
    lost = sum(1 for r in rows if not r["poisoned"])
    out["snapshot_rollback"] = {
        "keys_correct": c,
        "keys_total": n,
        "accuracy": round(c / n, 3),
        "legit_writes_lost": lost,
    }

    st, _ = _replay(rows)
    for s in poisoned_sources:
        st.rollback_source(s)
    c, n = _score(st.state(), truth)
    lost = sum(
        1 for r in rows if not r["poisoned"] and r["source_id"] in poisoned_sources
    )
    wrong = sorted(
        f"{k[0]}.{k[1]}"
        for k in set(st.state()) | set(truth)
        if st.state().get(k) != truth.get(k)
    )
    out["source_rollback"] = {
        "keys_correct": c,
        "keys_total": n,
        "accuracy": round(c / n, 3),
        "legit_writes_lost": lost,
        "wrong_keys": wrong,
    }

    # detectors in flag-only mode during ingest, then roll back exactly the flagged writes
    st = seeded_store(detect)
    st.quarantine = False
    flagged = []
    for r in rows:
        res = st.write(r["subject"], r["predicate"], r["value"], Provenance(r["source_id"], r["source_type"], r["t"]))
        if res.flags:
            flagged.append(res.idx)
    st.rollback_writes(flagged)
    c, n = _score(st.state(), truth)
    wrong = sorted(f"{k[0]}.{k[1]}" for k in set(st.state()) | set(truth) if st.state().get(k) != truth.get(k))
    legit_idx = {i + len(seeded_store().log) for i, r in enumerate(rows) if not r["poisoned"]}
    out["flagged_write_rollback"] = {"keys_correct": c, "keys_total": n, "accuracy": round(c / n, 3),
                                     "writes_rolled_back": len(flagged),
                                     "legit_writes_lost": len(legit_idx & set(flagged)), "wrong_keys": wrong}

    # snapshot exactness: state after rollback_to(k) equals the state at k
    st, _ = _replay(rows)
    exact = 0
    probes = list(range(20, len(st.log), 9))
    for k in probes:
        ref = seeded_store(None)
        for v in st.log[len(ref.log) : k]:
            ref.write(v.subject, v.predicate, v.value, v.prov)
        s2, _ = _replay(rows)
        s2.rollback_to(k)
        exact += s2.state() == ref.state()
    out["snapshot_exactness"] = f"{exact}/{len(probes)}"
    return out


def main() -> None:
    res = {"detection": detection(), "rollback": rollback()}
    (ROOT / "results" / "results.json").write_text(json.dumps(res, indent=2))
    d = res["detection"]
    print(
        {
            k: d[k]
            for k in [
                "n_poisoned",
                "n_legit",
                "tp",
                "fp",
                "fn",
                "precision",
                "recall",
                "f1",
            ]
        }
    )
    print("by family:", d["recall_by_family"])
    print("flags:", d["flag_counts"])
    print("FP:", *d["false_positives"], sep="\n  ")
    print("FN:", *d["false_negatives"], sep="\n  ")
    print(json.dumps(res["rollback"], indent=1))


if __name__ == "__main__":
    main()
