"""Make the src layout importable in a checkout without an editable install."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
