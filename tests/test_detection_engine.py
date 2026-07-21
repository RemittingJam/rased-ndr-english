from app.detections.engine import DetectionEngine


def test_detection_engine_runs_all_rules():
    context = {
        "tcp_port_events": [
            (
                index / 10,
                "192.168.1.20",
                "192.168.1.10",
                20 + index,
            )
            for index in range(15)
        ],
        "dns_events": [
            (
                index / 10,
                "192.168.1.50",
                f"test{index}.example.com",
            )
            for index in range(25)
        ],
    }

    alerts = DetectionEngine().run(context)

    alert_types = {
        alert["type"]
        for alert in alerts
    }

    assert len(alerts) == 2
    assert "Possible Port Scan" in alert_types
    assert "Unusual DNS Activity" in alert_types