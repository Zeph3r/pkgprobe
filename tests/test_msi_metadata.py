"""
Tests for MSI metadata and notes: _msi unavailable vs available, ProductCode missing.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from pkgprobe.analyzers.msi import analyze_msi


def test_msi_module_unavailable_notes_and_metadata(tmp_path: Path) -> None:
    """When _msi is unavailable: metadata has FileName + SizeBytes; notes do not say 'ProductCode not found'."""
    msi_file = tmp_path / "dummy.msi"
    msi_file.write_bytes(b"MZ placeholder")
    msi_path = str(msi_file)

    with patch("pkgprobe.analyzers.msi._msi_module_available", return_value=False):
        plan = analyze_msi(msi_path)

    assert plan.metadata.get("FileName") == "dummy.msi"
    assert plan.metadata.get("SizeBytes") is not None
    assert plan.metadata.get("ProductCode") is None
    assert plan.metadata.get("ProductName") is None

    notes_text = " ".join(plan.notes)
    assert "MSI properties unavailable" in notes_text or "not loaded" in notes_text
    assert "CPython on Windows" in notes_text or "not WSL" in notes_text
    assert "ProductCode not found" not in notes_text


def test_msi_module_available_product_code_missing_note(tmp_path: Path) -> None:
    """When _msi is available but ProductCode is missing: note says ProductCode not found in Property table."""
    msi_file = tmp_path / "no_product_code.msi"
    msi_file.write_bytes(b"MZ")
    msi_path = str(msi_file)

    props = {
        "ProductName": None,
        "ProductCode": None,
        "UpgradeCode": None,
        "ProductVersion": None,
        "Manufacturer": None,
    }

    with (
        patch("pkgprobe.analyzers.msi._msi_module_available", return_value=True),
        patch("pkgprobe.analyzers.msi._read_msi_properties", return_value=(props, False)),
    ):
        plan = analyze_msi(msi_path)

    notes_text = " ".join(plan.notes)
    assert "ProductCode not found" in notes_text
    assert "Property table" in notes_text
    assert "MSI properties unavailable" not in notes_text
    assert "not loaded" not in notes_text


def test_msi_module_available_read_failed_note(tmp_path: Path) -> None:
    """When _msi is available but read fails: note says MSI property read failed."""
    msi_file = tmp_path / "bad.msi"
    msi_file.write_bytes(b"MZ")
    msi_path = str(msi_file)

    props = {
        "ProductName": None,
        "ProductCode": None,
        "UpgradeCode": None,
        "ProductVersion": None,
        "Manufacturer": None,
    }

    with (
        patch("pkgprobe.analyzers.msi._msi_module_available", return_value=True),
        patch("pkgprobe.analyzers.msi._read_msi_properties", return_value=(props, True)),
    ):
        plan = analyze_msi(msi_path)

    notes_text = " ".join(plan.notes)
    assert "MSI property read failed" in notes_text
    assert "ProductCode not found" not in notes_text
