import ipaddress

from aimaligator import network

from conftest import make_config


def test_ignore_addresses_filters_local_traffic():
    assert network._ignore_address("127.0.0.1")
    assert network._ignore_address("::1")
    assert network._ignore_address("169.254.1.2")
    assert network._ignore_address("224.0.0.22")
    assert network._ignore_address("not-an-ip")
    assert not network._ignore_address("8.8.8.8")
    assert not network._ignore_address("93.184.216.34")


def test_matches_markers():
    assert network._matches_markers(r"C:\Ollama\ollama.exe", "ollama", ("ollama",))
    assert network._matches_markers("ollama", "ollama", ("ollama",))
    assert not network._matches_markers("chrome", "chrome.exe", ("ollama",))


def test_first_run_creates_store_silently(tmp_path):
    cfg = make_config([], tmp_path / "state")
    records = [
        network.EgressRecord(1, r"F:\Ollama\ollama.exe", "104.18.32.7:443"),
    ]

    first = network.check(cfg, records=records)
    second = network.check(cfg, records=records)

    assert first == []            # baseline for egress, no alerts
    assert second == []           # same endpoints, already known


def test_new_endpoint_alerts_once(tmp_path):
    cfg = make_config([], tmp_path / "state")
    known = [network.EgressRecord(1, r"F:\Ollama\ollama.exe", "104.18.32.7:443")]
    network.check(cfg, records=known)

    stranger = [
        network.EgressRecord(1, r"F:\Ollama\ollama.exe", "203.0.113.9:443"),
    ]
    alerts = network.check(cfg, records=stranger)
    again = network.check(cfg, records=stranger)

    assert [a.kind for a in alerts] == ["new-egress"]
    assert "203.0.113.9:443" in alerts[0].detail
    assert again == []            # reported once, then remembered


def test_store_survives_restart(tmp_path):
    cfg = make_config([], tmp_path / "state")
    records = [network.EgressRecord(1, "ollama", "1.2.3.4:443")]
    network.check(cfg, records=records)

    cfg2 = make_config([], tmp_path / "state")
    assert network.check(cfg2, records=records) == []
