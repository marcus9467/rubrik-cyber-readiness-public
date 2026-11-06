"""A "Not entitled" answer on recovery plans is named as a permission gap on the assessment account."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from collectors import recovery  # noqa: E402


class Denied:
    def __init__(self, msg):
        self.msg = msg

    def paginate(self, *a, **k):
        raise RuntimeError(self.msg)


def test_not_entitled_is_tagged_as_a_permission_gap():
    try:
        recovery.collect(Denied("Not entitled to access this resource"))
    except RuntimeError as e:
        assert str(e).startswith(recovery.NOT_ENTITLED) and "role" in str(e)
    else:
        raise AssertionError("expected RuntimeError")


def test_other_errors_pass_through_unchanged():
    try:
        recovery.collect(Denied("HTTP 500"))
    except RuntimeError as e:
        assert str(e) == "HTTP 500"
    else:
        raise AssertionError("expected RuntimeError")
