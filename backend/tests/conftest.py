"""
Pytest configuration and test client fixtures.
"""

import sys
from pathlib import Path
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# Ensure root workspace directory is in sys.path
root_dir = Path(__file__).resolve().parent.parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from backend.app.main import app


@pytest_asyncio.fixture
async def client():
    """Async test client using ASGI transport."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
