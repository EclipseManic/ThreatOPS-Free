"""Simple pytest wrapper to check a project verification entrypoint exists in the project root.

This project was consolidated to a single entrypoint. Historically the project contained
`verify_project.py`; newer layout uses `run.py`. The test accepts either file being present.
"""

from pathlib import Path


def test_verification_entrypoint_exists():
    project_root = Path(__file__).parent.parent
    candidates = [project_root / 'verify_project.py', project_root / 'run.py']
    found = [p for p in candidates if p.exists()]
    assert found, (
        "No verification entrypoint found. Expected one of: "
        f"{', '.join(str(p.name) for p in candidates)}"
    )
