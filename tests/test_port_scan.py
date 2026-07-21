from app.detections.port_scan import PortScanRule


def test_port_scan_detection():
    events = [
        (index / 10, "192.168.1.20", "192.168.1.10", 20 + index)
        for index in range(15)
    ]

    alerts = PortScanRule().detect({
        "tcp_port_events": events
    })

    assert len(alerts) == 1
    assert alerts[0]["type"] == "Possible Port Scan"
    assert alerts[0]["source"] == "192.168.1.20"
    assert alerts[0]["destination"] == "192.168.1.10"