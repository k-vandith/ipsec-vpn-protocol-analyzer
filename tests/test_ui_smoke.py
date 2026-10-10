"""Streamlit AppTest smoke coverage for every TunnelScope page."""
from __future__ import annotations

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

APP_FILE = Path(__file__).resolve().parents[1] / "src" / "app.py"
PAGES = [
    "Overview",
    "Upload & Configure",
    "Negotiation Timeline",
    "Configuration Review",
    "Packet Explorer",
    "Reports",
    "Glossary",
]


def test_ui_entrypoint() -> None:
    import src.app as app

    assert callable(app.main)


@pytest.mark.parametrize("page", PAGES)
def test_ui_page_smoke(page: str) -> None:
    app = AppTest.from_file(str(APP_FILE), default_timeout=30)
    app.session_state["current_page"] = page
    app.run()
    assert not app.exception, "\n".join(str(item.message) for item in app.exception)
