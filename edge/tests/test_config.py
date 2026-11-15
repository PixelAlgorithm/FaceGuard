from edge.config import Thresholds, parse_env_value


def test_env_inline_comments_are_stripped():
    assert parse_env_value("        # must exist in config") == ""
    assert parse_env_value("KIOSK_MAIN_01         # must exist in config") == "KIOSK_MAIN_01"
    assert parse_env_value("abc=def=") == "abc=def="
    assert parse_env_value('"value # not a comment"  # comment') == "value # not a comment"
    assert parse_env_value("false            # demo switch") == "false"


def test_thresholds_dotted_get(thresholds):
    assert thresholds.get("liveness.pad.real_class_index") == 1
    assert thresholds.get("liveness.pad.input_scale", 1.0) == 1.0
    assert isinstance(thresholds, Thresholds)
    try:
        thresholds.get("liveness.nope.missing")
    except KeyError:
        pass
    else:
        raise AssertionError("missing key must raise")
