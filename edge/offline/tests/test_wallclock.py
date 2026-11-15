"""Clock independence (swarm 2026-11-14 item 3): the faked wall clock really shifts what the code sees, and a
full runtime round trip (decide offline -> come online -> sync -> decide online) does not depend on the host
time of day. The whole suite can also be run under the fake clock: see edge/policy/tests/wallclock.py."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import pytest

from edge.offline import connectivity, sync
from edge.offline.tests.conftest import attempt, bring_online
from edge.policy import engine, runtime
from edge.policy.tests import wallclock

IST = ZoneInfo("Asia/Kolkata")
LATE = datetime(2026, 11, 14, 23, 30, tzinfo=IST)
EARLY = datetime(2026, 11, 15, 5, 0, tzinfo=IST)


@pytest.mark.parametrize("target", [LATE, EARLY], ids=["23:30_IST", "05:00_IST"])
def test_fake_wall_clock_shifts_every_wall_source(monkeypatch, target):
    wallclock.install(monkeypatch, target)
    for mod in (runtime, engine, connectivity, sync):
        seen = mod.datetime.now(UTC).astimezone(IST)
        assert abs((seen - target).total_seconds()) < 60, mod.__name__
    assert abs(time.time() - target.timestamp()) < 60
    assert isinstance(datetime.now(UTC), runtime.datetime)  # real datetimes still pass isinstance checks
    assert connectivity._utcnow().astimezone(IST).hour == target.hour
    assert sync.utcnow().astimezone(IST).hour == target.hour


@pytest.mark.parametrize("target", [LATE, EARLY], ids=["23:30_IST", "05:00_IST"])
def test_runtime_round_trip_is_independent_of_the_host_time_of_day(monkeypatch, make_rt, cloud, target):
    wallclock.install(monkeypatch, target)
    rt = make_rt(cloud)
    off = rt.decide(attempt("att_wc_off"))
    assert off["decision"] == "ALLOW" and off["mode"] == "OFFLINE"
    bring_online(rt)  # signed request timestamps (time.time) + bundle stamps all on the shifted clock
    assert cloud.stored.keys() == {"att_wc_off"} and rt.log.queue_depth() == 0
    on = rt.decide(attempt("att_wc_on"))
    assert on["decision"] == "ALLOW" and on["mode"] == "ONLINE"


def test_target_without_offset_is_refused():
    with pytest.raises(ValueError):
        wallclock.parse_target("2026-11-14T23:30:00")
