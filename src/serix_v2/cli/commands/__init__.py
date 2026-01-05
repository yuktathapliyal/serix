"""
Serix v2 - CLI Commands

Command implementations for:
- serix init
- serix status
- serix test
- serix demo (stub - Phase 11C)
- serix run (deprecated compatibility stub)
"""

from serix_v2.cli.commands.demo_cmd import demo
from serix_v2.cli.commands.init_cmd import init
from serix_v2.cli.commands.run_cmd import run
from serix_v2.cli.commands.status_cmd import status
from serix_v2.cli.commands.test_cmd import test

__all__ = ["demo", "init", "run", "status", "test"]
