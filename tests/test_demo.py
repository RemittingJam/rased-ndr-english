from app.services.demo import build_demo_result


def test_demo_result_has_expected_sections():
    result = build_demo_result()

    assert result["meta"]["project"] == "Rased NDR"
    assert result["summary"]["packets"] > 0
    assert len(result["protocols"]) > 0
    assert len(result["alerts"]) == 2
