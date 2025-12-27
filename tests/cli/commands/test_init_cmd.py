"""Tests for init command."""

from __future__ import annotations

import tempfile
from pathlib import Path

from typer.testing import CliRunner

from serix.cli import app
from serix.core.constants import CONFIG_FILENAME

runner = CliRunner()


class TestInitCommand:
    """Tests for serix init command."""

    def test_init_creates_config(self) -> None:
        """Test init creates serix.toml."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with runner.isolated_filesystem(temp_dir=tmpdir):
                result = runner.invoke(app, ["init"])

                assert result.exit_code == 0
                assert "Created serix.toml" in result.stdout

                config_path = Path(CONFIG_FILENAME)
                assert config_path.exists()

                content = config_path.read_text()
                assert "[target]" in content
                assert "[attack]" in content
                # These are commented out in the template (sensible defaults)
                assert "# [models]" in content or "[models]" in content
                assert "# [output]" in content or "[output]" in content

    def test_init_custom_path(self) -> None:
        """Test init with custom path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with runner.isolated_filesystem(temp_dir=tmpdir):
                custom_path = ".serix.toml"
                result = runner.invoke(app, ["init", "--path", custom_path])

                assert result.exit_code == 0
                assert f"Created {custom_path}" in result.stdout
                assert Path(custom_path).exists()

    def test_init_fails_if_exists(self) -> None:
        """Test init fails if config exists without --force."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with runner.isolated_filesystem(temp_dir=tmpdir):
                # Create existing config
                config_path = Path(CONFIG_FILENAME)
                config_path.write_text("existing content")

                result = runner.invoke(app, ["init"])

                assert result.exit_code == 1
                assert "already exists" in result.stdout
                assert "--force" in result.stdout

                # Content should not be overwritten
                assert config_path.read_text() == "existing content"

    def test_init_force_overwrites(self) -> None:
        """Test init --force overwrites existing config."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with runner.isolated_filesystem(temp_dir=tmpdir):
                # Create existing config
                config_path = Path(CONFIG_FILENAME)
                config_path.write_text("existing content")

                result = runner.invoke(app, ["init", "--force"])

                assert result.exit_code == 0
                assert f"Created {CONFIG_FILENAME}" in result.stdout

                # Content should be overwritten
                content = config_path.read_text()
                assert "[attack]" in content
                assert "existing content" not in content

    def test_init_template_has_all_sections(self) -> None:
        """Test init template contains all expected sections per spec 1.8."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with runner.isolated_filesystem(temp_dir=tmpdir):
                result = runner.invoke(app, ["init"])

                assert result.exit_code == 0

                content = Path(CONFIG_FILENAME).read_text()

                # Check required sections per spec 1.8
                assert "[target]" in content
                assert 'path = "agent.py:my_agent"' in content

                assert "[attack]" in content
                assert "depth = 5" in content
                assert 'mode = "adaptive"' in content
                assert 'scenarios = "all"' in content
                assert "goal =" in content  # Has default goal

                # Check commented sections (sensible defaults)
                assert "# [regression]" in content
                assert "# [output]" in content
                assert "# [models]" in content
                assert "# [fuzz]" in content

                # Check behavior section
                assert "# BEHAVIOR" in content
                assert "# verbose = false" in content
