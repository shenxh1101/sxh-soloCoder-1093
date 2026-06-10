import json
import os
import sqlite3
import sys
import tarfile
import tempfile
from io import BytesIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner.utils import version_compare, version_lt, version_gt, version_ge, version_le
from scanner.image_parser import InstalledPackage
from scanner.package_extractor import PackageExtractor
from scanner.vuln_db import VersionRange, VulnerabilityEntry, CPEMatchDetail, VulnerabilityDatabase, FixVersionDatabase
from scanner.matcher import VulnerabilityMatcher, MatchResult
from scanner.report_generator import ReportGenerator
from scanner.config import ScannerConfig


def create_realistic_rpmdb_sqlite():
    conn = sqlite3.connect(":memory:")
    
    conn.execute("""
        CREATE TABLE "Packages" (
            hnum INTEGER,
            blob BLOB,
            name TEXT,
            version TEXT,
            release TEXT,
            epoch INTEGER,
            arch TEXT,
            installtime INTEGER,
            sigmd5 TEXT
        )
    """)
    
    packages = [
        ("openssl", "1.1.1k", "5.el8", 1, "x86_64"),
        ("openssl-libs", "1.1.1k", "5.el8", 1, "x86_64"),
        ("openssl-devel", "1.1.1k", "5.el8", 1, "x86_64"),
        ("curl", "7.61.1", "22.el8", 0, "x86_64"),
        ("libcurl", "7.61.1", "22.el8", 0, "x86_64"),
        ("curl-minimal", "7.61.1", "22.el8", 0, "x86_64"),
        ("systemd", "239", "58.el8", 0, "x86_64"),
        ("glibc", "2.28", "164.el8", 0, "x86_64"),
        ("bash", "4.4.20", "4.el8", 0, "x86_64"),
        ("vim-minimal", "8.0.1763", "19.el8_6.4", 2, "x86_64"),
        ("python3", "3.6.8", "47.el8", 0, "x86_64"),
        ("zlib", "1.2.11", "20.el8", 0, "x86_64"),
        ("rpm", "4.14.3", "23.el8", 0, "x86_64"),
        ("rpm-libs", "4.14.3", "23.el8", 0, "x86_64"),
        ("rpm-build-libs", "4.14.3", "23.el8", 0, "x86_64"),
        ("dnf", "4.7.0", "11.el8", 0, "noarch"),
        ("dnf-data", "4.7.0", "11.el8", 0, "noarch"),
        ("yum", "4.7.0", "11.el8", 0, "noarch"),
        ("sqlite-libs", "3.26.0", "17.el8_7", 0, "x86_64"),
        ("ca-certificates", "2022.2.54", "80.2.el8_6", 0, "noarch"),
    ]
    
    for pkg in packages:
        conn.execute(
            "INSERT INTO Packages (name, version, release, epoch, arch, installtime) VALUES (?, ?, ?, ?, ?, 1609459200)",
            pkg
        )
    
    conn.commit()
    
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".sqlite")
    os.close(tmp_fd)
    conn2 = sqlite3.connect(tmp_path)
    conn.backup(conn2)
    conn2.commit()
    conn2.close()
    conn.close()
    
    db_content = Path(tmp_path).read_bytes()
    os.unlink(tmp_path)
    
    return db_content


def create_fake_docker_tar_with_rpmdb():
    temp_dir = tempfile.mkdtemp(prefix="test_rpm_")
    
    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {
            "Labels": {
                "org.opencontainers.image.ref.name": "centos-test",
            },
            "Env": [
                "ID=centos",
                "VERSION_ID=8",
            ],
        },
        "rootfs": {
            "diff_ids": [
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ],
        },
    }
    config_json = json.dumps(config)
    
    manifest = [{
        "Config": "config.json",
        "RepoTags": ["centos:8"],
        "Layers": ["layer0/layer.tar"],
    }]
    manifest_json = json.dumps(manifest)
    
    rpmdb_content = create_realistic_rpmdb_sqlite()
    
    layer_tar_buf = BytesIO()
    with tarfile.open(fileobj=layer_tar_buf, mode="w") as layer_tar:
        pkg_dir = tarfile.TarInfo(name="var/lib/rpm/")
        pkg_dir.type = tarfile.DIRTYPE
        layer_tar.addfile(pkg_dir)
        
        rpmdb_info = tarfile.TarInfo(name="var/lib/rpm/rpmdb.sqlite")
        rpmdb_info.size = len(rpmdb_content)
        layer_tar.addfile(rpmdb_info, BytesIO(rpmdb_content))
        
        os_dir = tarfile.TarInfo(name="etc/")
        os_dir.type = tarfile.DIRTYPE
        layer_tar.addfile(os_dir)
        
        os_release = b'ID="centos"\nVERSION_ID="8"\nNAME="CentOS Linux"\n'
        os_info = tarfile.TarInfo(name="etc/os-release")
        os_info.size = len(os_release)
        layer_tar.addfile(os_info, BytesIO(os_release))
        
        centos_release = b"CentOS Linux release 8.5.2111\n"
        cr_info = tarfile.TarInfo(name="etc/centos-release")
        cr_info.size = len(centos_release)
        layer_tar.addfile(cr_info, BytesIO(centos_release))
    
    layer_tar_content = layer_tar_buf.getvalue()
    
    full_tar_buf = BytesIO()
    with tarfile.open(fileobj=full_tar_buf, mode="w") as full_tar:
        mf_info = tarfile.TarInfo(name="manifest.json")
        mf_info.size = len(manifest_json)
        full_tar.addfile(mf_info, BytesIO(manifest_json.encode()))
        
        cfg_info = tarfile.TarInfo(name="config.json")
        cfg_info.size = len(config_json)
        full_tar.addfile(cfg_info, BytesIO(config_json.encode()))
        
        layer_info = tarfile.TarInfo(name="layer0/layer.tar")
        layer_info.size = len(layer_tar_content)
        full_tar.addfile(layer_info, BytesIO(layer_tar_content))
    
    tar_path = Path(temp_dir) / "centos8.tar"
    tar_path.write_bytes(full_tar_buf.getvalue())
    
    return tar_path, temp_dir


def create_fake_debian_docker_tar():
    temp_dir = tempfile.mkdtemp(prefix="test_deb_")
    
    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {
            "Labels": {
                "org.opencontainers.image.ref.name": "debian-test",
            },
            "Env": [
                "ID=debian",
                "VERSION_ID=11",
            ],
        },
        "rootfs": {
            "diff_ids": [
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ],
        },
    }
    config_json = json.dumps(config)
    
    manifest = [{
        "Config": "config.json",
        "RepoTags": ["debian:11"],
        "Layers": ["layer0/layer.tar"],
    }]
    manifest_json = json.dumps(manifest)
    
    dpkg_status = (
        "Package: libpcre3\n"
        "Status: install ok installed\n"
        "Version: 2:8.39-13+deb11u1\n"
        "Architecture: amd64\n"
        "Source: pcre3\n"
        "\n"
        "Package: libpcre2-8-0\n"
        "Status: install ok installed\n"
        "Version: 10.36-2+deb11u1\n"
        "Architecture: amd64\n"
        "Source: pcre2\n"
        "\n"
        "Package: zlib1g\n"
        "Status: install ok installed\n"
        "Version: 1:1.2.11.dfsg-2+deb11u2\n"
        "Architecture: amd64\n"
        "Source: zlib\n"
        "\n"
        "Package: libssl1.1\n"
        "Status: install ok installed\n"
        "Version: 1.1.1n-0+deb11u3\n"
        "Architecture: amd64\n"
        "Source: openssl\n"
        "\n"
        "Package: openssl\n"
        "Status: install ok installed\n"
        "Version: 1.1.1n-0+deb11u3\n"
        "Architecture: amd64\n"
        "Source: openssl\n"
        "\n"
        "Package: curl\n"
        "Status: install ok installed\n"
        "Version: 7.74.0-1.3+deb11u7\n"
        "Architecture: amd64\n"
        "Source: curl\n"
        "\n"
        "Package: libc-bin\n"
        "Status: install ok installed\n"
        "Version: 2.31-13+deb11u6\n"
        "Architecture: amd64\n"
        "Source: glibc\n"
        "\n"
    )
    
    layer_tar_buf = BytesIO()
    with tarfile.open(fileobj=layer_tar_buf, mode="w") as layer_tar:
        var_dir = tarfile.TarInfo(name="var/lib/dpkg/")
        var_dir.type = tarfile.DIRTYPE
        layer_tar.addfile(var_dir)
        
        status_info = tarfile.TarInfo(name="var/lib/dpkg/status")
        status_info.size = len(dpkg_status)
        layer_tar.addfile(status_info, BytesIO(dpkg_status.encode()))
        
        os_dir = tarfile.TarInfo(name="etc/")
        os_dir.type = tarfile.DIRTYPE
        layer_tar.addfile(os_dir)
        
        os_release = b'ID="debian"\nVERSION_ID="11"\n'
        os_info = tarfile.TarInfo(name="etc/os-release")
        os_info.size = len(os_release)
        layer_tar.addfile(os_info, BytesIO(os_release))
    
    layer_tar_content = layer_tar_buf.getvalue()
    
    full_tar_buf = BytesIO()
    with tarfile.open(fileobj=full_tar_buf, mode="w") as full_tar:
        mf_info = tarfile.TarInfo(name="manifest.json")
        mf_info.size = len(manifest_json)
        full_tar.addfile(mf_info, BytesIO(manifest_json.encode()))
        
        cfg_info = tarfile.TarInfo(name="config.json")
        cfg_info.size = len(config_json)
        full_tar.addfile(cfg_info, BytesIO(config_json.encode()))
        
        layer_info = tarfile.TarInfo(name="layer0/layer.tar")
        layer_info.size = len(layer_tar_content)
        full_tar.addfile(layer_info, BytesIO(layer_tar_content))
    
    tar_path = Path(temp_dir) / "debian11.tar"
    tar_path.write_bytes(full_tar_buf.getvalue())
    
    return tar_path, temp_dir


def setup_test_vuln_db():
    tmp_dir = Path(tempfile.mkdtemp(prefix="test_db_"))
    config = ScannerConfig()
    config.db_dir = tmp_dir
    config.offline_mode = True
    
    db = VulnerabilityDatabase(config)
    
    entries = [
        VulnerabilityEntry(
            cve_id="CVE-2022-3602",
            description="A buffer overrun in OpenSSL 3.0.x before 3.0.7 and OpenSSL 1.1.1 before 1.1.1s could be triggered.",
            cvss_v3_score=7.5,
            cvss_v2_score=0.0,
            severity="HIGH",
            published_date="2022-11-01T08:15:00",
            last_modified_date="2022-11-02T12:00:00",
            affected_vendors={"openssl"},
            affected_products={"openssl"},
            cpe_match_details=[
                CPEMatchDetail(
                    criteria="cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*",
                    vendor="openssl",
                    product="openssl",
                    cpe_version_fragment="1.1.1k",
                    version_range=VersionRange(
                        start_including="1.1.1",
                        end_excluding="1.1.1s",
                    ),
                ),
            ],
            fixed_versions={"openssl": "1.1.1s-6.el8"},
        ),
        VulnerabilityEntry(
            cve_id="CVE-2022-42916",
            description="A vulnerability in curl before version 7.86.0 allows information disclosure.",
            cvss_v3_score=7.5,
            cvss_v2_score=0.0,
            severity="HIGH",
            published_date="2022-10-26T08:15:00",
            last_modified_date="2022-10-27T12:00:00",
            affected_vendors={"haxx"},
            affected_products={"curl"},
            cpe_match_details=[
                CPEMatchDetail(
                    criteria="cpe:2.3:a:haxx:curl:7.61.1:*:*:*:*:*:*:*",
                    vendor="haxx",
                    product="curl",
                    cpe_version_fragment="7.61.1",
                    version_range=VersionRange(
                        end_excluding="7.86.0",
                    ),
                ),
            ],
            fixed_versions={"curl": "7.86.0-2.el8"},
        ),
        VulnerabilityEntry(
            cve_id="CVE-2023-0464",
            description="A security vulnerability in openssl. Fixed in version 1.1.1k-7.el8 of openssl.",
            cvss_v3_score=7.5,
            cvss_v2_score=0.0,
            severity="HIGH",
            published_date="2023-03-22T06:15:00",
            last_modified_date="2023-03-23T12:00:00",
            affected_vendors={"openssl"},
            affected_products={"openssl"},
            cpe_match_details=[
                CPEMatchDetail(
                    criteria="cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*",
                    vendor="openssl",
                    product="openssl",
                    cpe_version_fragment="1.1.1k",
                    version_range=VersionRange(
                        end_excluding="1.1.1k-7",
                    ),
                ),
            ],
            fixed_versions={"openssl": "1.1.1k-7.el8"},
        ),
        VulnerabilityEntry(
            cve_id="CVE-2024-TEST-DEBIAN-TILDE",
            description="A test CVE for Debian tilde version handling. Fixed in version 2:8.39-14 of pcre3.",
            cvss_v3_score=7.5,
            cvss_v2_score=0.0,
            severity="HIGH",
            published_date="2024-01-15T00:00:00",
            last_modified_date="2024-01-16T00:00:00",
            affected_vendors={"pcre"},
            affected_products={"pcre3"},
            cpe_match_details=[
                CPEMatchDetail(
                    criteria="cpe:2.3:a:pcre:pcre3:8.39:*:*:*:*:*:*:*",
                    vendor="pcre",
                    product="pcre3",
                    version_range=VersionRange(
                        end_excluding="8.39-14",
                    ),
                ),
            ],
            fixed_versions={"pcre3": "2:8.39-14+deb11u1"},
        ),
        VulnerabilityEntry(
            cve_id="CVE-2024-TEST-DEBIAN-PLUS",
            description="A test CVE for Debian +deb version handling. Fixed in version 10.36-2+deb11u2 of pcre2.",
            cvss_v3_score=5.5,
            cvss_v2_score=0.0,
            severity="MEDIUM",
            published_date="2024-02-20T00:00:00",
            last_modified_date="2024-02-21T00:00:00",
            affected_vendors={"pcre"},
            affected_products={"pcre2"},
            cpe_match_details=[
                CPEMatchDetail(
                    criteria="cpe:2.3:a:pcre:pcre2:10.36:*:*:*:*:*:*:*",
                    vendor="pcre",
                    product="pcre2",
                    version_range=VersionRange(
                        end_excluding="10.36-3",
                    ),
                ),
            ],
            fixed_versions={"pcre2": "10.36-3+deb11u2"},
        ),
    ]
    
    for entry in entries:
        db._entries[entry.cve_id] = entry
        db._index_entry(entry)
    
    db._save_index()
    db._save_metadata()
    
    return db, tmp_dir


def test_version_compare_debian_tilde():
    print("\n=== Test: Debian Version Comparison (~ tilde) ===")
    
    test_cases = [
        ("2.32-0ubuntu1~20.04.1", "2.32-0ubuntu1", -1),
        ("2.32-0ubuntu1", "2.32-0ubuntu1~20.04.1", 1),
        ("1.2.3~rc1", "1.2.3", -1),
        ("1.2.3", "1.2.3~rc1", 1),
        ("1.2.3~rc1", "1.2.3~rc2", -1),
        ("1.2.3~rc2", "1.2.3~rc1", 1),
        ("1.2.3~alpha", "1.2.3~beta", -1),
        ("1.2.3~a", "1.2.3", -1),
        ("1.2.3~10", "1.2.3~2", 1),
        ("1.2.3", "1.2.3", 0),
        ("1:1.2.3~rc1", "1.2.3", 1),
        ("1.2.3~rc1", "1:1.2.3~rc1", -1),
    ]
    
    passed = 0
    for a, b, expected in test_cases:
        result = version_compare(a, b)
        status = "PASS" if result == expected else "FAIL"
        if status == "PASS":
            passed += 1
        print(f"  {status}: version_compare('{a}', '{b}') = {result} (expected {expected})")
    
    print(f"  {passed}/{len(test_cases)} passed")
    return passed == len(test_cases)


def test_version_compare_debian_plus():
    print("\n=== Test: Debian Version Comparison (+deb suffix) ===")
    
    test_cases = [
        ("2:8.39-13+deb11u1", "2:8.39-13", 1),
        ("2:8.39-13", "2:8.39-13+deb11u1", -1),
        ("1.1.1n-0+deb11u3", "1.1.1n-0+deb11u1", 1),
        ("1.1.1n-0+deb11u1", "1.1.1n-0+deb11u3", -1),
        ("1.1.1n-0+deb11u1", "1.1.1n-0", 1),
        ("7.74.0-1.3+deb11u7", "7.74.0-1.3+deb11u5", 1),
    ]
    
    passed = 0
    for a, b, expected in test_cases:
        result = version_compare(a, b)
        status = "PASS" if result == expected else "FAIL"
        if status == "PASS":
            passed += 1
        print(f"  {status}: version_compare('{a}', '{b}') = {result} (expected {expected})")
    
    print(f"  {passed}/{len(test_cases)} passed")
    return passed == len(test_cases)


def test_version_compare_el8():
    print("\n=== Test: RPM EL8 Version Comparison ===")
    
    test_cases = [
        ("1.1.1k-5.el8", "1.1.1k-7.el8", -1),
        ("1.1.1k-7.el8", "1.1.1k-5.el8", 1),
        ("7.61.1-22.el8", "7.86.0-2.el8", -1),
        ("1.1.1k-7.el8", "1.1.1k-5.el8_6", 1),
        ("1.1.1k-5.el8_6.4", "1.1.1k-5.el8_6.5", -1),
    ]
    
    passed = 0
    for a, b, expected in test_cases:
        result = version_compare(a, b)
        status = "PASS" if result == expected else "FAIL"
        if status == "PASS":
            passed += 1
        print(f"  {status}: version_compare('{a}', '{b}') = {result} (expected {expected})")
    
    print(f"  {passed}/{len(test_cases)} passed")
    return passed == len(test_cases)


def test_version_compare_alpine():
    print("\n=== Test: Alpine r0 Version Comparison ===")
    
    test_cases = [
        ("3.18.4-r0", "3.18.4-r1", -1),
        ("3.18.4-r1", "3.18.4-r0", 1),
        ("3.18.4-r0", "3.18.5-r0", -1),
        ("3.18.4-r0", "3.18.4-r0", 0),
    ]
    
    passed = 0
    for a, b, expected in test_cases:
        result = version_compare(a, b)
        status = "PASS" if result == expected else "FAIL"
        if status == "PASS":
            passed += 1
        print(f"  {status}: version_compare('{a}', '{b}') = {result} (expected {expected})")
    
    print(f"  {passed}/{len(test_cases)} passed")
    return passed == len(test_cases)


def test_rpmdb_extraction():
    print("\n=== Test: RPMDB.SQLITE Package Extraction ===")
    
    tar_path, tmp_dir = create_fake_docker_tar_with_rpmdb()
    
    try:
        from scanner.image_parser import ImageParser
        parser = ImageParser(str(tar_path))
        image_info = parser.parse()
        
        print(f"  Image: {image_info.full_name}")
        print(f"  Distro: {image_info.distro} {image_info.distro_version}")
        print(f"  Layers: {len(image_info.layers)}")
        
        extractor = PackageExtractor()
        layer_paths = {layer.order: layer.tar_path for layer in image_info.layers}
        packages = extractor.extract_from_image(layer_paths)
        
        print(f"  Total packages extracted: {len(packages)}")
        
        assert len(packages) > 0, "No packages extracted!"
        
        pkg_names = {p.name for p in packages}
        required = {"openssl", "openssl-libs", "curl", "libcurl", "glibc", "bash", "systemd", "zlib"}
        found = required & pkg_names
        
        print(f"  Required packages found: {sorted(found)}")
        
        missing = required - pkg_names
        if missing:
            print(f"  MISSING packages: {sorted(missing)}")
        
        assert len(found) >= 5, f"Only found {len(found)}/{len(required)} required RPM packages"
        
        for p in packages:
            if p.name in ("openssl", "curl"):
                assert p.package_manager == "rpm", f"{p.name} should be rpm, got {p.package_manager}"
                assert p.version, f"{p.name} should have version"
                assert "-" in p.version or p.release, f"{p.name} should have release in version, got {p.version}"
                print(f"  {p.name}: version={p.version}, release={p.release}, manager={p.package_manager}, layer={p.layer_order}")
        
        parser.cleanup()
        return True
    finally:
        import shutil
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_debian_version_matching():
    print("\n=== Test: Debian Version Range Matching ===")

    db, tmp_dir = setup_test_vuln_db()

    try:
        matcher = VulnerabilityMatcher(db)

        pcre3 = InstalledPackage(
            name="libpcre3",
            version="8.39-13+deb11u1",
            architecture="amd64",
            package_manager="apt",
            layer_order=0,
            source_name="pcre3",
            distro="",
        )

        results = matcher.match_package(pcre3, "")
        cve_ids = [r.cve_id for r in results]
        print(f"  libpcre3 8.39-13+deb11u1 matched CVEs: {cve_ids}")

        pcre2 = InstalledPackage(
            name="libpcre2-8-0",
            version="10.36-2+deb11u1",
            architecture="amd64",
            package_manager="apt",
            layer_order=0,
            source_name="pcre2",
            distro="",
        )

        results_vuln = matcher.match_package(pcre2, "")
        cve_ids_vuln = [r.cve_id for r in results_vuln]
        print(f"  libpcre2-8-0 10.36-2+deb11u1 (VULNERABLE) matched CVEs: {cve_ids_vuln}")

        pcre2_safe = InstalledPackage(
            name="libpcre2-8-0",
            version="10.36-3+deb11u2",
            architecture="amd64",
            package_manager="apt",
            layer_order=0,
            source_name="pcre2",
            distro="",
        )

        results_safe = matcher.match_package(pcre2_safe, "")
        cve_ids_safe = [r.cve_id for r in results_safe]
        print(f"  libpcre2-8-0 10.36-3+deb11u2 (SAFE) matched CVEs: {cve_ids_safe}")

        assert "CVE-2024-TEST-DEBIAN-PLUS" not in cve_ids_safe, \
            "Safe version 10.36-3+deb11u2 should NOT match CVE-2024-TEST-DEBIAN-PLUS"

        return True
    finally:
        import shutil
        shutil.rmtree(str(tmp_dir), ignore_errors=True)


def test_fix_versions_with_distro_suffixes():
    print("\n=== Test: Fix Versions with Distro Suffixes ===")

    db, tmp_dir = setup_test_vuln_db()

    try:
        matcher = VulnerabilityMatcher(db)

        openssl_vuln = InstalledPackage(
            name="openssl",
            version="1.1.1k-5.el8",
            architecture="x86_64",
            package_manager="rpm",
            layer_order=0,
            source_name="openssl",
            distro="",
        )

        results = matcher.match_package(openssl_vuln, "")

        assert len(results) > 0, f"Expected at least 1 matched CVE, got {len(results)}"

        for r in results:
            print(f"  {r.cve_id}: installed={r.package_version}, fixed={r.fixed_version}")

            if r.cve_id == "CVE-2022-3602":
                assert r.fixed_version, f"{r.cve_id} should have a fix version"
                assert "el8" in r.fixed_version or "s-6" in r.fixed_version, \
                    f"Fix version should contain el8 suffix, got: {r.fixed_version}"
                print(f"    -> Fix version OK: {r.fixed_version}")

            if r.cve_id == "CVE-2023-0464":
                assert r.fixed_version, f"{r.cve_id} should have a fix version"
                assert "el8" in r.fixed_version, \
                    f"Fix version should contain el8 suffix, got: {r.fixed_version}"
                print(f"    -> Fix version OK: {r.fixed_version}")

        for r in results:
            d = r.to_dict()
            assert "fixed_version" in d, "MatchResult.to_dict should include fixed_version"
            assert d["fixed_version"] == r.fixed_version, "fixed_version in dict should match"

        print("  All fix versions correctly include distro suffixes")
        return True
    finally:
        import shutil
        shutil.rmtree(str(tmp_dir), ignore_errors=True)


def test_report_formats_show_fix_versions():
    print("\n=== Test: Report Formats Show Fix Versions ===")
    
    from scanner.image_parser import ImageInfo, Layer
    import tempfile as tmpf
    
    image_info = ImageInfo(
        name="test-image",
        tag="latest",
        architecture="amd64",
        os_type="linux",
        distro="rhel",
        distro_version="8",
        layers=[Layer(layer_id="abc", diff_id="sha:abc", tar_path=Path("."), order=0, size=0)],
    )
    
    results = [
        MatchResult(
            cve_id="CVE-2022-3602",
            description="OpenSSL vulnerability",
            cvss_v3_score=7.5,
            cvss_v2_score=0.0,
            severity="HIGH",
            package_name="openssl",
            package_version="1.1.1k-5.el8",
            layer_order=0,
            package_manager="rpm",
            distro="rhel",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2022-3602"],
            fixed_version="1.1.1s-6.el8",
        ),
        MatchResult(
            cve_id="CVE-2022-42916",
            description="Curl vulnerability",
            cvss_v3_score=7.5,
            cvss_v2_score=0.0,
            severity="HIGH",
            package_name="curl",
            package_version="7.61.1-22.el8",
            layer_order=0,
            package_manager="rpm",
            distro="rhel",
            references=[],
            fixed_version="7.86.0-2.el8",
        ),
        MatchResult(
            cve_id="CVE-2024-TEST-DEBIAN-PLUS",
            description="pcre2 vulnerability",
            cvss_v3_score=5.5,
            cvss_v2_score=0.0,
            severity="MEDIUM",
            package_name="libpcre2-8-0",
            package_version="10.36-2+deb11u1",
            layer_order=1,
            package_manager="apt",
            distro="debian",
            references=[],
            fixed_version="10.36-3+deb11u2",
        ),
    ]
    
    summary = {
        "total_vulnerabilities": 3,
        "critical": 0,
        "high": 2,
        "medium": 1,
        "low": 0,
        "unknown": 0,
        "unique_cves": 3,
        "unique_affected_packages": 2,
        "fix_available": 3,
        "layer_distribution": {0: 2, 1: 1},
    }
    
    report_gen = ReportGenerator(image_info, results, summary)
    
    console = report_gen.generate_console_report()
    assert "1.1.1s-6.el8" in console, "Console report should show fix version 1.1.1s-6.el8"
    assert "7.86.0-2.el8" in console, "Console report should show fix version 7.86.0-2.el8"
    assert "10.36-3+deb11u2" in console, "Console report should show fix version 10.36-3+deb11u2"
    print("  Console report: OK")
    
    with tmpf.TemporaryDirectory() as tmpdir:
        csv_path = Path(tmpdir) / "test.csv"
        report_gen.generate_csv_report(str(csv_path))
        csv_content = csv_path.read_text()
        assert "1.1.1s-6.el8" in csv_content, "CSV should contain fix version 1.1.1s-6.el8"
        assert "7.86.0-2.el8" in csv_content, "CSV should contain fix version 7.86.0-2.el8"
        assert "10.36-3+deb11u2" in csv_content, "CSV should contain fix version 10.36-3+deb11u2"
        print("  CSV report: OK")
    
    with tmpf.TemporaryDirectory() as tmpdir:
        json_path = Path(tmpdir) / "test.json"
        report_gen.generate_json_report(str(json_path))
        json_content = json_path.read_text()
        json_data = json.loads(json_content)
        vulns = json_data["vulnerabilities"]
        fix_versions = {v["cve_id"]: v["fixed_version"] for v in vulns}
        assert fix_versions.get("CVE-2022-3602") == "1.1.1s-6.el8", \
            f"JSON fix version: {fix_versions.get('CVE-2022-3602')}"
        assert fix_versions.get("CVE-2022-42916") == "7.86.0-2.el8", \
            f"JSON fix version: {fix_versions.get('CVE-2022-42916')}"
        assert fix_versions.get("CVE-2024-TEST-DEBIAN-PLUS") == "10.36-3+deb11u2", \
            f"JSON fix version: {fix_versions.get('CVE-2024-TEST-DEBIAN-PLUS')}"
        print("  JSON report: OK")
    
    with tmpf.TemporaryDirectory() as tmpdir:
        html_path = Path(tmpdir) / "test.html"
        report_gen.generate_html_report(str(html_path))
        html_content = html_path.read_text()
        assert "1.1.1s-6.el8" in html_content, "HTML should contain fix version 1.1.1s-6.el8"
        assert "7.86.0-2.el8" in html_content, "HTML should contain fix version 7.86.0-2.el8"
        assert "10.36-3+deb11u2" in html_content, "HTML should contain fix version 10.36-3+deb11u2"
        print("  HTML report: OK")
    
    return True


def test_debian_package_extraction():
    print("\n=== Test: Debian Package Extraction ===")
    
    tar_path, tmp_dir = create_fake_debian_docker_tar()
    
    try:
        from scanner.image_parser import ImageParser
        parser = ImageParser(str(tar_path))
        image_info = parser.parse()
        
        print(f"  Image: {image_info.full_name}")
        print(f"  Distro: {image_info.distro} {image_info.distro_version}")
        
        extractor = PackageExtractor()
        layer_paths = {layer.order: layer.tar_path for layer in image_info.layers}
        packages = extractor.extract_from_image(layer_paths)
        
        print(f"  Total packages: {len(packages)}")
        
        pkg_map = {p.name: p for p in packages}
        
        for name in ["openssl", "curl", "libpcre3", "libpcre2-8-0", "zlib1g", "libssl1.1"]:
            if name in pkg_map:
                p = pkg_map[name]
                print(f"  {name}: {p.version} (manager={p.package_manager}, layer={p.layer_order})")
                assert "+deb" in p.version, f"{name} version should contain +deb: {p.version}"
        
        parser.cleanup()
        return True
    finally:
        import shutil
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_version_range_debian_tilde_matching():
    print("\n=== Test: VersionRange with Debian ~ (Safe vs Vulnerable) ===")

    db, tmp_dir = setup_test_vuln_db()

    try:
        matcher = VulnerabilityMatcher(db)

        debian_tilde_vuln = InstalledPackage(
            name="libpcre3",
            version="8.39-13",
            architecture="amd64",
            package_manager="apt",
            layer_order=0,
            source_name="pcre3",
            distro="",
        )

        results_vuln = matcher.match_package(debian_tilde_vuln, "")
        cve_vuln = [r.cve_id for r in results_vuln]
        print(f"  libpcre3 8.39-13 matched: {cve_vuln}")

        debian_tilde_safe = InstalledPackage(
            name="libpcre3",
            version="8.39-14+deb11u1",
            architecture="amd64",
            package_manager="apt",
            layer_order=0,
            source_name="pcre3",
            distro="",
        )

        results_safe = matcher.match_package(debian_tilde_safe, "")
        cve_safe = [r.cve_id for r in results_safe]
        print(f"  libpcre3 8.39-14+deb11u1 matched: {cve_safe}")

        assert "CVE-2024-TEST-DEBIAN-TILDE" not in cve_safe, \
            "Safe version 8.39-14+deb11u1 should NOT report CVE-2024-TEST-DEBIAN-TILDE"
        print("  Debian tilde version range: safe version correctly excluded")

        return True
    finally:
        import shutil
        shutil.rmtree(str(tmp_dir), ignore_errors=True)


def test_version_compare_cve_range():
    print("\n=== Test: CVE Version Range with Debian Suffixes ===")

    vr = VersionRange(end_excluding="10.36-3")
    assert vr.contains_version("10.36-2+deb11u1"), "10.36-2+deb11u1 should be in range <10.36-3"
    assert not vr.contains_version("10.36-3+deb11u2"), "10.36-3+deb11u2 should NOT be in range <10.36-3"
    print("  VersionRange with +deb suffixes: PASS")

    vr2 = VersionRange(end_excluding="1.1.1k-7")
    assert vr2.contains_version("1.1.1k-5.el8"), "1.1.1k-5.el8 should be in range <1.1.1k-7"
    assert not vr2.contains_version("1.1.1k-7.el8"), "1.1.1k-7.el8 should NOT be in range <1.1.1k-7"
    print("  VersionRange with el8 suffixes: PASS")

    return True


def test_fix_version_extraction_from_description():
    print("\n=== Test: Fix Version Extraction from CVE Description ===")
    
    fix_db = FixVersionDatabase(Path(tempfile.mkdtemp()) / "fix.json")
    
    test_descriptions = [
        (
            "CVE-TEST-1",
            "A vulnerability in openssl. Fixed in version 1.1.1k-7.el8 of openssl.",
            {"openssl": "1.1.1k-7.el8"},
        ),
        (
            "CVE-TEST-2",
            "libcurl was fixed in version 7.86.0-2.el8 to address this issue.",
            {"libcurl": "7.86.0-2.el8"},
        ),
        (
            "CVE-TEST-3",
            "DSA-1234-1 openssl 1.1.1n-0+deb11u5",
            {"openssl": "1.1.1n-0+deb11u5"},
        ),
        (
            "CVE-TEST-4",
            "DLA-5678-1 pcre2 10.36-3+deb11u2",
            {"pcre2": "10.36-3+deb11u2"},
        ),
        (
            "CVE-TEST-5",
            "RHSA-2022:1001",
            {"*": "RHSA-2022:1001"},
        ),
        (
            "CVE-TEST-6",
            "Update openssl package to version 1.1.1k-7.el8 to fix CVE.",
            {"openssl": "1.1.1k-7.el8"},
        ),
    ]
    
    for cve_id, desc, expected in test_descriptions:
        result = fix_db.extract_from_cve_description(cve_id, desc)
        print(f"  {cve_id}: {result}")
        for key, val in expected.items():
            assert key in result, f"Expected key '{key}' in {cve_id} results"
            if key != "*":
                assert expected[key] in result[key] or result[key] == expected[key], \
                    f"Expected {expected[key]} for {cve_id}[{key}], got {result[key]}"
    
    print("  All fix version extraction tests passed")
    return True


if __name__ == "__main__":
    all_passed = True
    
    all_passed &= test_version_compare_debian_tilde()
    all_passed &= test_version_compare_debian_plus()
    all_passed &= test_version_compare_el8()
    all_passed &= test_version_compare_alpine()
    all_passed &= test_rpmdb_extraction()
    all_passed &= test_debian_package_extraction()
    all_passed &= test_debian_version_matching()
    all_passed &= test_version_range_debian_tilde_matching()
    all_passed &= test_fix_versions_with_distro_suffixes()
    all_passed &= test_report_formats_show_fix_versions()
    all_passed &= test_version_compare_cve_range()
    all_passed &= test_fix_version_extraction_from_description()
    
    print("\n" + "=" * 60)
    if all_passed:
        print("  ALL TESTS PASSED")
    else:
        print("  SOME TESTS FAILED")
    print("=" * 60)
    
    sys.exit(0 if all_passed else 1)