import importlib
import pkgutil
import inspect
from typing import List, Type
from .base import BaseCheck

# Populated by load_plugins() on module import
ALL_PLUGINS: List[Type[BaseCheck]] = []


def load_plugins() -> None:
    """
    Dynamically loads all BaseCheck subclasses from this package.
    Deduplicates by class identity to avoid double-registration when a
    plugin module re-imports classes from sibling modules.
    """
    global ALL_PLUGINS
    ALL_PLUGINS.clear()

    seen_ids: set[int] = set()
    package_name = __name__

    for _, module_name, _ in pkgutil.iter_modules(__path__):
        if module_name == 'base':
            continue

        full_module_name = f"{package_name}.{module_name}"
        module = importlib.import_module(full_module_name)

        for _, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, BaseCheck) and obj is not BaseCheck:
                # BUG-10 FIX: use id() to avoid duplicate entries
                if id(obj) not in seen_ids:
                    seen_ids.add(id(obj))
                    ALL_PLUGINS.append(obj)


# Load plugins when the package is first imported
load_plugins()
