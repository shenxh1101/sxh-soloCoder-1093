import json
import os
import re
import shutil
import subprocess
import tempfile
import sys
from pathlib import Path
from typing import Optional

import click

from .config import ScannerConfig
from .filter import VulnerabilityFilter
from .image_parser import ImageParser
from .matcher import VulnerabilityMatcher
from .package_extractor import PackageExtractor
from .report_generator import ReportGenerator
from .vuln_db import VulnerabilityDatabase


def _is_docker_available() -> bool:
    return shutil.which("docker") is not None


def _is_image_reference(target: str) -> bool:
    target_path = Path(target)
    if target_path.exists() and target_path.is_file():
        if tarfile.is_tarfile(target):
            return False
    if ":" in target and not target_path.exists():
        return True
    if "/" in target and not target_path.exists():
        return True
    if not target_path.exists():
        return True
    return False


def _resolve_image_to_tar(target: str) -> tuple:
    import tarfile as tf

    target_path = Path(target)

    if target_path.exists() and target_path.is_file() and tf.is_tarfile(target):
        return str(target_path.absolute()), None

    if not _is_docker_available():
        raise click.ClickException(
            f"'{target}' 不是有效的tar文件，且未找到docker命令。\n"
            f"请提供 docker save 导出的tar包路径，或安装docker后重试。"
        )

    image_ref = target
    click.echo(f"  Resolving image: {image_ref}")

    click.echo(f"  Pulling image...")
    pull_result = subprocess.run(
        ["docker", "pull", image_ref],
        capture_output=False,
        text=True,
    )
    if pull_result.returncode != 0:
        raise click.ClickException(f"Failed to pull image: {image_ref}")

    tmp_dir = tempfile.mkdtemp(prefix="scanner_docker_")
    tar_path = os.path.join(tmp_dir, f"{image_ref.replace('/', '_').replace(':', '_')}.tar")

    safe_name = re.sub(r'[^\w\-.]', '_', image_ref)
    tar_path = os.path.join(tmp_dir, f"{safe_name}.tar")

    click.echo(f"  Exporting image to temporary file...")
    save_result = subprocess.run(
        ["docker", "save", "-o", tar_path, image_ref],
        capture_output=True,
        text=True,
    )
    if save_result.returncode != 0:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise click.ClickException(f"Failed to save image: {image_ref}\n{save_result.stderr}")

    click.echo(f"  Image exported to: {tar_path}")
    return tar_path, tmp_dir


def _cleanup_temp_dir(tmp_dir: Optional[str]) -> None:
    if tmp_dir and os.path.isdir(tmp_dir):
        try:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass


@click.group()
@click.option("--offline", is_flag=True, help="运行在离线模式，仅使用已缓存的漏洞数据库")
@click.option("--db-dir", type=click.Path(), default=None, help="漏洞数据库缓存目录")
@click.option("--ignore-file", type=click.Path(), default=None, help="忽略列表文件路径")
@click.pass_context
def cli(ctx, offline, db_dir, ignore_file):
    """容器镜像漏洞扫描分析工具

    扫描 Docker 镜像中的已知漏洞，支持多种包管理器，生成详细报告。
    """
    config = ScannerConfig()
    config.offline_mode = offline

    if db_dir:
        config.db_dir = Path(db_dir)
    if ignore_file:
        config.ignore_file = Path(ignore_file)

    config.load_ignore_list()

    ctx.obj = config


@cli.command()
@click.argument("target", type=str)
@click.option("--output", "-o", type=click.Path(), default=None, help="输出报告文件路径")
@click.option("--format", "-f", "output_format", type=click.Choice(["console", "html", "csv", "json"]), default="console", help="输出报告格式")
@click.option("--min-severity", "-s", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]), default=None, help="最低严重等级过滤")
@click.option("--min-cvss", type=float, default=None, help="最低CVSS评分过滤")
@click.option("--max-cvss", type=float, default=None, help="最高CVSS评分过滤")
@click.option("--package", "-p", type=str, default=None, help="按包名过滤")
@click.option("--layer", "-l", type=int, default=None, help="按layer序号过滤")
@click.option("--cve", type=str, default=None, help="按CVE编号过滤")
@click.option("--sort", "sort_by", type=click.Choice(["severity", "cvss", "package", "layer"]), default="severity", help="排序方式")
@click.option("--no-update", is_flag=True, help="跳过漏洞数据库更新")
@click.option("--force-update", is_flag=True, help="强制更新漏洞数据库")
@click.pass_context
def scan(ctx, target, output, output_format, min_severity, min_cvss, max_cvss, package,
         layer, cve, sort_by, no_update, force_update):
    """扫描容器镜像中的已知漏洞

    TARGET 可以是 docker save 导出的 tar 包路径，也可以是镜像名（如 nginx:latest）。
    输入镜像名时会自动 docker pull 并导出到临时文件后扫描。
    """
    config: ScannerConfig = ctx.obj
    tmp_dir = None

    try:
        click.echo("=" * 60)
        click.echo("  Container Image Vulnerability Scanner")
        click.echo("=" * 60)
        click.echo()

        tar_path, tmp_dir = _resolve_image_to_tar(target)

        click.echo()
        click.echo("[1/5] Loading vulnerability database...")
        vuln_db = VulnerabilityDatabase(config)
        vuln_db.load()

        if not no_update and not config.offline_mode:
            click.echo("  Checking for database updates...")
            try:
                vuln_db.update(force=force_update)
                click.echo("  Database update complete.")
            except Exception as e:
                click.echo(f"  Warning: Could not update database: {e}", err=True)

        stats = vuln_db.get_statistics()
        click.echo(f"  Loaded {stats['total_entries']} CVE entries (last updated: {stats['last_updated']})")

        click.echo()
        click.echo("[2/5] Parsing Docker image...")
        parser = ImageParser(tar_path)
        try:
            image_info = parser.parse()
            click.echo(f"  Image: {image_info.full_name}")
            click.echo(f"  Architecture: {image_info.architecture}")
            click.echo(f"  Distro: {image_info.distro} {image_info.distro_version}")
            click.echo(f"  Layers: {len(image_info.layers)}")
        except Exception as e:
            click.echo(f"  Error parsing image: {e}", err=True)
            sys.exit(1)

        click.echo()
        click.echo("[3/5] Extracting installed packages...")
        extractor = PackageExtractor()

        layer_paths = {layer.order: layer.tar_path for layer in image_info.layers}
        packages = extractor.extract_from_image(layer_paths)

        pkg_summary = extractor.get_package_summary(packages)
        click.echo(f"  Found {pkg_summary['total_packages']} packages across {len(image_info.layers)} layers")
        for pm, count in pkg_summary.get("package_managers", {}).items():
            click.echo(f"    {pm}: {count} packages")

        distro = pkg_summary.get("distro", image_info.distro)
        if not distro:
            distro = image_info.distro

        for pkg in packages:
            if not pkg.distro:
                pkg.distro = distro

        manager_types = set(p.package_manager for p in packages)
        if manager_types:
            click.echo(f"  Package managers detected: {', '.join(sorted(manager_types))}")

        click.echo()
        click.echo("[4/5] Matching vulnerabilities against database...")
        matcher = VulnerabilityMatcher(vuln_db)
        matcher.set_ignored_cves(config.get_ignored_cves())
        results = matcher.match_packages(packages, distro)

        click.echo(f"  Found {len(results)} potential vulnerabilities")

        click.echo()
        click.echo("[5/5] Applying filters and generating report...")

        vuln_filter = VulnerabilityFilter(results)
        filtered_results = vuln_filter.apply(
            min_severity=min_severity,
            min_cvss=min_cvss,
            max_cvss=max_cvss,
            package_filter=package,
            layer_filter=layer,
            cve_filter=cve,
        )

        if sort_by == "severity":
            filtered_results = vuln_filter.sort_by_severity(filtered_results)
        elif sort_by == "cvss":
            filtered_results = vuln_filter.sort_by_cvss(filtered_results)
        elif sort_by == "package":
            filtered_results = vuln_filter.sort_by_package(filtered_results)
        elif sort_by == "layer":
            filtered_results = vuln_filter.sort_by_layer(filtered_results)

        summary = matcher.get_summary(filtered_results)

        click.echo(f"  Displaying {len(filtered_results)} vulnerabilities (filtered from {len(results)})")
        if summary.get("fix_available", 0) > 0:
            click.echo(f"  Fix versions available for: {summary['fix_available']} vulnerabilities")

        report_gen = ReportGenerator(image_info, filtered_results, summary)

        if output_format == "console":
            report = report_gen.generate_console_report()
            click.echo(report)
        elif output_format == "html":
            out_path = output or f"vuln_report_{image_info.name}_{image_info.tag}.html"
            result_path = report_gen.generate_html_report(out_path)
            click.echo(f"  HTML report saved to: {result_path}")
        elif output_format == "csv":
            out_path = output or f"vuln_report_{image_info.name}_{image_info.tag}.csv"
            result_path = report_gen.generate_csv_report(out_path)
            click.echo(f"  CSV report saved to: {result_path}")
        elif output_format == "json":
            out_path = output or f"vuln_report_{image_info.name}_{image_info.tag}.json"
            result_path = report_gen.generate_json_report(out_path)
            click.echo(f"  JSON report saved to: {result_path}")

        if output and output_format == "console":
            with open(output, "w", encoding="utf-8") as f:
                f.write(report_gen.generate_console_report())
            click.echo(f"  Console report saved to: {output}")

        parser.cleanup()
    finally:
        _cleanup_temp_dir(tmp_dir)


@cli.command()
@click.option("--force", "-f", is_flag=True, help="强制重新下载所有年份的漏洞数据")
@click.option("--years", "-y", type=str, default=None, help="指定要下载的年份，用逗号分隔 (例: 2022,2023,2024)")
@click.pass_context
def update_db(ctx, force, years):
    """更新本地漏洞数据库"""
    config: ScannerConfig = ctx.obj

    if config.offline_mode:
        click.echo("Error: Cannot update database in offline mode.", err=True)
        sys.exit(1)

    year_list = None
    if years:
        try:
            year_list = [int(y.strip()) for y in years.split(",")]
        except ValueError:
            click.echo("Error: Invalid year format. Use comma-separated integers.", err=True)
            sys.exit(1)

    click.echo("Updating vulnerability database...")
    vuln_db = VulnerabilityDatabase(config)

    try:
        updated = vuln_db.update(force=force, years=year_list)
        if updated:
            click.echo("Database updated successfully.")
        else:
            click.echo("Database is up to date.")
    except Exception as e:
        click.echo(f"Error updating database: {e}", err=True)
        sys.exit(1)

    stats = vuln_db.get_statistics()
    click.echo(f"  Total entries: {stats['total_entries']}")
    click.echo(f"  Indexed products: {stats['indexed_products']}")


@cli.command()
@click.pass_context
def db_status(ctx):
    """显示漏洞数据库状态"""
    config: ScannerConfig = ctx.obj
    vuln_db = VulnerabilityDatabase(config)
    vuln_db.load()

    stats = vuln_db.get_statistics()
    click.echo("Vulnerability Database Status")
    click.echo("-" * 40)
    click.echo(f"  Total CVE entries:    {stats['total_entries']}")
    click.echo(f"  Indexed products:     {stats['indexed_products']}")
    click.echo(f"  Last updated:         {stats['last_updated']}")
    click.echo(f"  Database directory:   {config.db_dir}")
    click.echo(f"  Offline mode:         {'Yes' if config.offline_mode else 'No'}")


@cli.command()
@click.option("--list", "list_ignored", is_flag=True, help="列出所有已忽略的CVE")
@click.option("--add", type=str, default=None, help="添加CVE到忽略列表")
@click.option("--remove", type=str, default=None, help="从忽略列表中移除CVE")
@click.pass_context
def ignore(ctx, list_ignored, add, remove):
    """管理漏洞忽略列表"""
    config: ScannerConfig = ctx.obj
    config.load_ignore_list()

    if list_ignored:
        ignored = config.get_ignored_cves()
        if ignored:
            click.echo("Ignored CVEs:")
            for cve_id in ignored:
                info = config._ignore_list.get(cve_id, {})
                reason = info.get("reason", "")
                reason_str = f" - {reason}" if reason else ""
                click.echo(f"  {cve_id}{reason_str}")
        else:
            click.echo("No CVEs in ignore list.")
        return

    if add:
        config.ignore_cve(add.upper(), reason="User-defined ignore")
        click.echo(f"Added {add.upper()} to ignore list.")
        return

    if remove:
        config.unignore_cve(remove.upper())
        click.echo(f"Removed {remove.upper()} from ignore list.")
        return

    click.echo("Usage: ignore --list | --add <CVE-ID> | --remove <CVE-ID>")


@cli.command()
@click.argument("keyword", type=str)
@click.pass_context
def search(ctx, keyword):
    """搜索CVE漏洞信息"""
    config: ScannerConfig = ctx.obj
    vuln_db = VulnerabilityDatabase(config)
    vuln_db.load()

    results = vuln_db.search_cve(keyword)
    click.echo(f"Found {len(results)} CVEs matching '{keyword}':")
    click.echo("-" * 60)

    for entry in results[:20]:
        click.echo(f"  [{entry.cve_id}] [{entry.severity}] CVSS v3: {entry.cvss_v3_score}")
        desc = entry.description[:150] + "..." if len(entry.description) > 150 else entry.description
        click.echo(f"    {desc}")
        if entry.fixed_versions:
            click.echo(f"    Fix versions: {entry.fixed_versions}")
        click.echo()