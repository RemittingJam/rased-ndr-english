from app.detections.dns_spike import DnsSpikeRule


def test_dns_spike_detection():
    events = [
        (index / 10, "192.168.1.50", f"test{index}.example.com")
        for index in range(25)
    ]

    alerts = DnsSpikeRule().detect({
        "dns_events": events
    })

    assert len(alerts) == 1
    assert alerts[0]["type"] == "Unusual DNS Activity"
    assert alerts[0]["source"] == "192.168.1.50"
    assert alerts[0]["destination"] == "DNS"