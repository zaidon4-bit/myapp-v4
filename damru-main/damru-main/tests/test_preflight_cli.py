import argparse
import json
import subprocess

import pytest

import damru.cli as cli


def _cp(code=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(["test"], code, stdout, stderr)


def _stub_common(monkeypatch, *, image_exists=True, physical_adb=False):
    monkeypatch.setattr(cli, "_is_windows", lambda: False)
    monkeypatch.setattr(cli.platform, "system", lambda: "Linux")
    monkeypatch.setattr(cli.platform, "release", lambda: "6.8-test")
    monkeypatch.setattr(cli, "_verify_bundled_wsl_kernel", lambda: (True, "kernel"))
    monkeypatch.setattr(cli, "_preflight_playwright_patch_status", lambda: (True, "/pw/crPage.js"))
    monkeypatch.setattr(cli.importlib.util, "find_spec", lambda name: object() if name == "playwright" else object())
    monkeypatch.setattr(cli, "_preflight_apk_status", lambda: (True, "/home/damru/chrome-apks"))
    monkeypatch.setattr(cli, "_preflight_linux_disk_free_gb", lambda timeout: 200.0)
    monkeypatch.setattr(cli, "_preflight_linux_mem_total_gb", lambda timeout: 64.0)
    monkeypatch.setattr(cli.os, "cpu_count", lambda: 16)
    monkeypatch.setattr(cli, "_preflight_port_open", lambda port: False)
    monkeypatch.setattr(cli, "_kernel_config_text", lambda: "CONFIG_ANDROID_BINDER_IPC=y\nCONFIG_ANDROID_BINDERFS=y\n")
    monkeypatch.setattr(cli, "_binderfs_mount_populated", lambda: True)
    monkeypatch.setattr(cli, "_preflight_config", lambda: {"mode": "auto", "num_devices": 2, "image": "damru-redroid:latest", "base_port": 5600, "chrome_apk": None})

    def fake_linux(script, timeout):
        if "docker image inspect" in script:
            return _cp(0 if image_exists else 1)
        return _cp(0, "/usr/bin/tool\n")

    monkeypatch.setattr(cli, "_preflight_linux_readonly", fake_linux)
    adb = "List of devices attached\n"
    adb += "USB123 device product:phone\n" if physical_adb else "127.0.0.1:5600 device product:redroid14\n"
    monkeypatch.setattr(cli, "_adb_devices_text", lambda: adb)


def test_parser_accepts_check_preflight_json():
    parser = cli.build_parser()
    args = parser.parse_args(["check", "preflight", "--json", "--timeout", "1"])
    assert args.func is cli._check_preflight
    assert args.json is True
    assert args.timeout == 1


def test_preflight_json_success_shape(monkeypatch, capsys):
    _stub_common(monkeypatch)
    code = cli._check_preflight(argparse.Namespace(json=True, strict=False, no_adb=False, timeout=1))
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["ok"] is True
    assert payload["summary"]["fail"] == 0
    assert any(check["id"] == "redroid_image" for check in payload["checks"])


def test_missing_redroid_image_is_fail(monkeypatch, capsys):
    _stub_common(monkeypatch, image_exists=False)
    code = cli._check_preflight(argparse.Namespace(json=True, strict=False, no_adb=False, timeout=1))
    payload = json.loads(capsys.readouterr().out)
    image = next(check for check in payload["checks"] if check["id"] == "redroid_image")
    assert code == 1
    assert image["status"] == "fail"
    assert "install-image" in image["fix"]


def test_physical_adb_warn_becomes_fail_in_strict(monkeypatch, capsys):
    _stub_common(monkeypatch, physical_adb=True)
    code = cli._check_preflight(argparse.Namespace(json=True, strict=True, no_adb=False, timeout=1))
    payload = json.loads(capsys.readouterr().out)
    adb = next(check for check in payload["checks"] if check["id"] == "adb_devices")
    assert code == 1
    assert adb["status"] == "fail"


def test_preflight_does_not_call_mutating_helpers(monkeypatch):
    _stub_common(monkeypatch)
    monkeypatch.setattr(cli, "_ensure_binderfs_mounted", lambda: pytest.fail("mutated binderfs"))
    monkeypatch.setattr(cli, "_repair_wsl_main_route_rule", lambda: pytest.fail("mutated WSL route"))
    monkeypatch.setattr(cli, "_docker_bridge_internet_ok", lambda *a, **k: pytest.fail("started Docker container"))
    assert cli._check_preflight(argparse.Namespace(json=True, strict=False, no_adb=True, timeout=1)) == 0

def test_wsl_linux_kernel_status_reads_binderfs_config(monkeypatch):
    monkeypatch.setattr(cli, "_is_wsl_linux", lambda: True)
    monkeypatch.setattr(cli.platform, "uname", lambda: argparse.Namespace(release="6.6.114.1-microsoft-standard-WSL2+"))
    monkeypatch.setattr(cli, "_kernel_config_text", lambda: "CONFIG_ANDROID_BINDER_IPC=y\nCONFIG_ANDROID_BINDERFS=y\n")

    status, detail, fix = cli._preflight_wsl_kernel_status(timeout=1)

    assert status == "pass"
    assert "binderfs support" in detail
    assert fix == ""

def test_wsl_unmounted_binderfs_is_warning_by_default(monkeypatch, capsys):
    _stub_common(monkeypatch)
    monkeypatch.setattr(cli, "_is_wsl_linux", lambda: True)
    monkeypatch.setattr(cli.platform, "uname", lambda: argparse.Namespace(release="6.6.114.1-microsoft-standard-WSL2+"))
    monkeypatch.setattr(cli, "_binderfs_mount_populated", lambda: False)

    def fake_linux(script, timeout):
        if "test -e /dev/binder && test -e /dev/hwbinder" in script:
            return _cp(1)
        if "test -d /dev/binderfs && mount" in script:
            return _cp(1)
        if "docker image inspect" in script:
            return _cp(0)
        return _cp(0, "/usr/bin/tool\n")

    monkeypatch.setattr(cli, "_preflight_linux_readonly", fake_linux)

    code = cli._check_preflight(argparse.Namespace(json=True, strict=False, no_adb=True, timeout=1))
    payload = json.loads(capsys.readouterr().out)
    binderfs = next(check for check in payload["checks"] if check["id"] == "binderfs")

    assert code == 0
    assert binderfs["status"] == "warn"
    assert "fix-wsl" in binderfs["fix"]

def test_windows_wsl_kernel_status_checks_kernel_config(monkeypatch):
    monkeypatch.setattr(cli, "_is_wsl_linux", lambda: False)
    monkeypatch.setattr(cli, "_is_windows", lambda: True)
    monkeypatch.setattr(cli.shutil, "which", lambda name: "wsl.exe" if name == "wsl" else None)
    monkeypatch.setattr(cli, "_configured_wsl_distro", lambda: "Ubuntu")

    def fake_run(cmd, timeout=30):
        joined = " ".join(cmd)
        if "CONFIG_ANDROID_BINDERFS" in joined or "/proc/config.gz" in joined:
            return _cp(0, "CONFIG_ANDROID_BINDER_IPC=y\nCONFIG_ANDROID_BINDERFS=y\n")
        if "uname -r" in joined:
            return _cp(0, "6.6.114.1-microsoft-standard-WSL2+\n")
        return _cp(1, stderr="unexpected command")

    monkeypatch.setattr(cli, "_run", fake_run)
    monkeypatch.setattr(cli, "_verify_bundled_wsl_kernel", lambda: pytest.fail("should use kernel config first"))

    status, detail, fix = cli._preflight_wsl_kernel_status(timeout=1)

    assert status == "pass"
    assert "binderfs support" in detail
    assert fix == ""
