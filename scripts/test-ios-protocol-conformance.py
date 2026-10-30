#!/usr/bin/env python3
"""Run shared vectors against the same Swift sources compiled by the D3 harness."""
from pathlib import Path
import runpy

root = Path(__file__).resolve().parent
runner = runpy.run_path(str(root / "test-ios-protocol-boundaries.py"))
runner["run"]((root / "fixtures/ios-protocol-conformance.swift").read_text())
