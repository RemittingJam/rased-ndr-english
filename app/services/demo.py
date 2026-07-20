from datetime import datetime, timedelta, timezone


def build_demo_result() -> dict:
    start = datetime.now(timezone.utc).replace(microsecond=0)
    timeline = [
        {
            "timestamp": (start + timedelta(seconds=index)).isoformat(),
            "packets": value,
        }
        for index, value in enumerate([8, 14, 18, 26, 39, 44, 32, 21, 15, 10])
    ]

    return {
        "meta": {
            "project": "Rased NDR",
            "version": "0.1.1",
            "filename": "demo-capture.pcap",
            "analyzed_packets": 1842,
            "packet_limit_reached": False,
            "first_seen": start.isoformat(),
            "last_seen": (start + timedelta(seconds=9)).isoformat(),
            "duration_seconds": 9,
        },
        "summary": {
            "packets": 1842,
            "devices": 7,
            "protocols": 4,
            "alerts": 2,
        },
        "protocols": [
            {"name": "TCP", "count": 978},
            {"name": "DNS", "count": 432},
            {"name": "UDP", "count": 286},
            {"name": "IPv4", "count": 146},
        ],
        "top_hosts": [
            {"host": "192.168.1.20", "packets": 834},
            {"host": "192.168.1.10", "packets": 601},
            {"host": "8.8.8.8", "packets": 240},
            {"host": "192.168.1.1", "packets": 167},
        ],
        "top_conversations": [
            {
                "source": "192.168.1.20",
                "destination": "192.168.1.10",
                "packets": 554,
            },
            {
                "source": "192.168.1.20",
                "destination": "8.8.8.8",
                "packets": 231,
            },
            {
                "source": "192.168.1.10",
                "destination": "192.168.1.1",
                "packets": 144,
            },
        ],
        "timeline": timeline,
        "alerts": [
            {
                "id": "RASED-NET-001-1",
                "type": "Possible Port Scan",
                "severity": "medium",
                "source": "192.168.1.20",
                "destination": "192.168.1.10",
                "confidence": 91,
                "reason": (
                    "192.168.1.20 contacted 26 unique ports on "
                    "192.168.1.10 within 10 seconds."
                ),
                "evidence": {
                    "unique_ports": 26,
                    "sample_ports": [21, 22, 23, 25, 53, 80, 110, 135, 139, 443],
                    "window_seconds": 10,
                    "first_seen": start.isoformat(),
                    "last_seen": (start + timedelta(seconds=8)).isoformat(),
                },
            },
            {
                "id": "RASED-NET-002-1",
                "type": "Unusual DNS Activity",
                "severity": "low",
                "source": "192.168.1.20",
                "destination": "DNS",
                "confidence": 84,
                "reason": "192.168.1.20 generated 28 DNS queries within 10 seconds.",
                "evidence": {
                    "query_count": 28,
                    "sample_queries": [
                        "example.com",
                        "api.example.com",
                        "cdn.example.net",
                    ],
                    "window_seconds": 10,
                    "first_seen": start.isoformat(),
                    "last_seen": (start + timedelta(seconds=9)).isoformat(),
                },
            },
        ],
    }
