"""Local launcher: ``python run.py``.

Equivalent to ``uvicorn trace_api.main:app --reload`` but with no shell
quoting needed on Windows.
"""

from __future__ import annotations

import os

import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "trace_api.main:app",
        host=os.environ.get("TRACE_HOST", "127.0.0.1"),
        port=int(os.environ.get("TRACE_PORT", "8000")),
        reload=os.environ.get("TRACE_RELOAD", "0") == "1",
    )
