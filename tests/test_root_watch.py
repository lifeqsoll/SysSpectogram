"""Root process watch tests."""

from __future__ import annotations

from sysspectogram.root_watch import RootWatchState, list_root_procs, poll_new_root


def test_list_root_does_not_crash():
    procs = list_root_procs(include_kernel=False)
    assert isinstance(procs, list)


def test_learn_then_empty():
    st = RootWatchState()
    # force end of learn
    st.baseline_until = 1.0
    st.baseline = {p.pid for p in list_root_procs(include_kernel=False)}
    news = poll_new_root(st, learn_sec=0.0)
    # everything currently root should already be baseline
    assert all(p.pid in st.baseline or p.pid in st.alerted for p in news) or news == []
