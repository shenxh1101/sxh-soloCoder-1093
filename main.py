#!/usr/bin/env python3
"""容器镜像漏洞扫描分析工具

用法:
    python main.py scan <镜像路径> [选项]
    python main.py update-db [选项]
    python main.py db-status
    python main.py ignore --list|--add <CVE>|--remove <CVE>
    python main.py search <关键词>
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from scanner.cli import cli

if __name__ == "__main__":
    cli()