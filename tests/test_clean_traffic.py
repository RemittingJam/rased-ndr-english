from app.detections.engine import DetectionEngine


def test_clean_traffic_generates_no_alerts():
    context = {
        "tcp_port_events": [
            (
                index,
                "192.168.1.20",
                "192.168.1.10",
                80,
            )
            for index in range(5)
        ],
        "dns_events": [
            (
                index,
                "192.168.1.50",
                f"normal{index}.example.com",
            )
            for index in range(5)
        ],
    }

    alerts = DetectionEngine().run(context)

    assert alerts == []