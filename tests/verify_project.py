"""Project verification moved to tests/verify_project.py
   Adjusted to be usable from tests/ and not require archived docs.
"""

import sys
from pathlib import Path
import importlib.util

# Ensure project root is on path (parent of tests/)
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

# Load the top-level verify_project.py by file path to avoid importing the
# test file itself (which would cause a name collision).
verify_path = project_root / "verify_project.py"
spec = importlib.util.spec_from_file_location("verify_project_main", str(verify_path))
verify_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify_mod)
verify_main = getattr(verify_mod, "main")

def main():
    print("Running project verification (tests/verify_project.py)")
    ok = verify_main()
    return 0 if ok else 1

if __name__ == "__main__":
    raise SystemExit(main())
