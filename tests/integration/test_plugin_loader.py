"""Integration tests for the plugin loader."""
import pytest
from webvulnscanner.plugins import ALL_PLUGINS, load_plugins
from webvulnscanner.plugins.base import BaseCheck


class TestPluginLoader:

    def test_all_plugins_not_empty(self):
        """Ensure at least one plugin gets loaded."""
        assert len(ALL_PLUGINS) > 0

    def test_no_duplicate_plugins(self):
        """BUG-10 regression: ALL_PLUGINS must not contain duplicate class entries."""
        ids = [id(p) for p in ALL_PLUGINS]
        assert len(ids) == len(set(ids)), "Duplicate plugin classes detected"
        names = [p().name for p in ALL_PLUGINS]
        assert len(names) == len(set(names)), "Duplicate plugin names detected"

    def test_all_plugins_subclass_basecheck(self):
        for plugin_cls in ALL_PLUGINS:
            assert issubclass(plugin_cls, BaseCheck), \
                f"{plugin_cls.__name__} does not subclass BaseCheck"

    def test_all_plugins_have_name_property(self):
        """BUG-1 regression: every plugin must expose name via @property."""
        for plugin_cls in ALL_PLUGINS:
            assert isinstance(
                type(plugin_cls()).name, property
            ) or isinstance(plugin_cls.name, property), \
                f"{plugin_cls.__name__}.name must be a @property"

    def test_plugin_names_are_non_empty_strings(self):
        for plugin_cls in ALL_PLUGINS:
            instance = plugin_cls()
            assert isinstance(instance.name, str)
            assert len(instance.name.strip()) > 0, \
                f"{plugin_cls.__name__}.name must not be empty"

    def test_reload_does_not_duplicate(self):
        """Calling load_plugins() multiple times must not grow ALL_PLUGINS."""
        load_plugins()
        count_after_one = len(ALL_PLUGINS)
        load_plugins()
        count_after_two = len(ALL_PLUGINS)
        assert count_after_one == count_after_two

    def test_expected_plugin_names_present(self):
        """Sanity check that all expected plugin names are registered."""
        expected = {
            "Reflected XSS",
            "Error-Based SQLi",
            "Secrets & Tokens",
            "Security Headers",
            "CSRF Heuristic",
            "SSRF Candidate",
        }
        loaded_names = {p().name for p in ALL_PLUGINS}
        for name in expected:
            assert name in loaded_names, f"Plugin '{name}' not found in ALL_PLUGINS"
