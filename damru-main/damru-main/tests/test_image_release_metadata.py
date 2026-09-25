from pathlib import Path

import damru.cli as cli
import damru.docker as docker


def test_image_checksum_constant_matches_release_file():
    sha_file = Path(__file__).resolve().parents[1] / "damru-redroid-latest.tar.sha256"
    digest = sha_file.read_text(encoding="utf-8").split()[0]

    assert cli._DAMRU_IMAGE_SHA256 == digest


def test_chrome_auto_selection_does_not_skip_known_good_versions():
    assert cli._CHROME_APK_AUTO_SKIP_VERSIONS == set()
    assert docker._CHROME_APK_AUTO_SKIP_VERSIONS == set()
