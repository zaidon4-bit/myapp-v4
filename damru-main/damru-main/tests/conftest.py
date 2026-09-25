"""Pytest collection helpers for Damru's mixed test suite.

The repository contains both fast unit tests and environment-heavy probes that
need ADB, Docker/Redroid, GPU access, or live sites. Filename-based markers keep
the existing tests runnable while making selective runs predictable.
"""
from __future__ import annotations

from pathlib import Path

import pytest


_MARKER_KEYWORDS = {
    "adb": ("adb", "mumu", "device", "identity", "hardware"),
    "docker": ("pool", "damru_e2e", "redroid", "image"),
    "network": (
        "benchmark",
        "browserscan",
        "creepjs",
        "fingerprint",
        "ip_leak",
        "parallel_sites",
        "screen_sites",
        "todetect",
        "tls",
        "vpn",
    ),
    "e2e": ("e2e", "phase", "smoke", "stealth"),
    "gpu": ("gpu", "vulkan"),
}



def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--run-damru-probes",
        action="store_true",
        default=False,
        help="run environment-heavy ADB/Docker/network/GPU probe tests",
    )

def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    run_probes = config.getoption("--run-damru-probes")
    skip_probe = pytest.mark.skip(reason="environment-heavy probe; pass --run-damru-probes to run")

    for item in items:
        name = Path(str(item.fspath)).name.lower()
        applied = False

        if "unit" in name:
            item.add_marker(pytest.mark.unit)
            continue

        for marker, keywords in _MARKER_KEYWORDS.items():
            if any(keyword in name for keyword in keywords):
                item.add_marker(getattr(pytest.mark, marker))
                applied = True

        if not applied:
            item.add_marker(pytest.mark.unit)

        if not run_probes and not item.get_closest_marker("unit"):
            item.add_marker(skip_probe)
