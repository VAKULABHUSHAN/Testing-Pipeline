"""Unit tests for APK validation and metadata extraction."""

import io
import zipfile
import pytest
from pathlib import Path
from sentinel.analyzers.apk.extractor import APKExtractor
from sentinel.core.exceptions import APKValidationError


def test_validate_apk_file_not_found(tmp_path: Path) -> None:
    extractor = APKExtractor()
    with pytest.raises(APKValidationError, match="does not exist"):
        extractor.validate_apk_file(tmp_path / "non_existent.apk")


def test_validate_apk_wrong_extension(tmp_path: Path) -> None:
    txt_file = tmp_path / "app.txt"
    txt_file.write_text("dummy")
    extractor = APKExtractor()
    with pytest.raises(APKValidationError, match="expected .apk extension"):
        extractor.validate_apk_file(txt_file)


def test_validate_apk_empty_file(tmp_path: Path) -> None:
    apk_file = tmp_path / "empty.apk"
    apk_file.touch()
    extractor = APKExtractor()
    with pytest.raises(APKValidationError, match="empty"):
        extractor.validate_apk_file(apk_file)


def test_validate_apk_corrupted_zip(tmp_path: Path) -> None:
    apk_file = tmp_path / "corrupt.apk"
    apk_file.write_text("NOT A REAL ZIP")
    extractor = APKExtractor()
    with pytest.raises(APKValidationError, match="not a valid ZIP archive"):
        extractor.validate_apk_file(apk_file)


def test_validate_apk_valid_zip(tmp_path: Path) -> None:
    apk_file = tmp_path / "valid.apk"
    with zipfile.ZipFile(apk_file, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"fake binary xml")
    extractor = APKExtractor()
    res = extractor.validate_apk_file(apk_file)
    assert res == apk_file.resolve()

    sha = extractor.calculate_sha256(apk_file)
    assert len(sha) == 64


def test_parse_badging() -> None:
    extractor = APKExtractor()
    badging = (
        "package: name='com.test.app' versionCode='42' versionName='2.1.0'\n"
        "sdkVersion:'26'\n"
        "targetSdkVersion:'34'\n"
        "application-label:'Test App'\n"
        "launchable-activity: name='com.test.app.MainActivity'\n"
        "uses-permission: name='android.permission.INTERNET'\n"
        "uses-permission: name='android.permission.CAMERA'\n"
    )
    pkg, code, name = extractor._parse_badging_package(badging)
    assert pkg == "com.test.app"
    assert code == 42
    assert name == "2.1.0"

    min_sdk, target_sdk = extractor._parse_badging_sdk(badging)
    assert min_sdk == 26
    assert target_sdk == 34

    label = extractor._parse_badging_label(badging)
    assert label == "Test App"

    launcher = extractor._parse_badging_launcher(badging)
    assert launcher == "com.test.app.MainActivity"

    perms = extractor._parse_badging_permissions(badging)
    assert perms == ["android.permission.INTERNET", "android.permission.CAMERA"]
