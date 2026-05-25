from textwrap import dedent
import pytest

def test_import() -> None:
    import amzn_idle_resource_remediator  # type: ignore # noqa: F401
