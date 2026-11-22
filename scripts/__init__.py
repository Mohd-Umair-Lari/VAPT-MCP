"""Runtime modules for the VAPT agent.

The modules retain simple top-level imports so they can also be launched as
standalone scripts. Add this directory to the import path when loaded as a
package entry point.
"""
from pathlib import Path
import sys

_SCRIPT_DIR = str(Path(__file__).resolve().parent)
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)
