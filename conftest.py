import os
import sys
from pathlib import Path
from unittest.mock import patch
import pytest

# Ensure project root is in sys.path
root_dir = Path(__file__).resolve().parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from app.core.config import settings

@pytest.fixture(autouse=True)
def disable_live_network_in_tests():
    settings.enable_startup_ingestion = False
    with patch("app.main.init_db"):
        yield
