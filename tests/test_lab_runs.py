from __future__ import annotations

from sysspectogram.lab_runs import RUNS, get_run


def test_ids_are_unique_and_titles_bilingual():
    ids = [r.id for r in RUNS]
    assert len(ids) == len(set(ids))
    for run in RUNS:
        assert run.title["en"] and run.title["ru"]
        assert run.description["en"] and run.description["ru"]


def test_egress_run_never_targets_a_remote_address():
    run = get_run("lab-egress-beacon")
    assert "--local-sink" in run.argv
    assert "--lab" in run.argv


def test_intrusion_runs_require_lab_flag():
    for run in RUNS:
        if any("simulations" in part for part in run.argv):
            assert run.lab_flag, run.id


def test_unknown_run_raises():
    try:
        get_run("nope")
    except KeyError:
        return
    raise AssertionError("unknown run must raise KeyError")
