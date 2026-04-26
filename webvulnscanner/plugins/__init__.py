import importlib
import pkgutil
import inspect
from typing import List, Type
from .base import BaseCheck, BaseNetworkPlugin

# Populated by load_plugins() on module import
ALL_PLUGINS: List[Type[BaseCheck]] = []
NETWORK_PLUGINS: List[Type[BaseNetworkPlugin]] = []


def load_plugins() -> None:
    """
    Dynamically loads all BaseCheck and BaseNetworkPlugin subclasses from this package.
    """
    ALL_PLUGINS.clear()
    NETWORK_PLUGINS.clear()

    seen_ids: set[int] = set()
    package_name = __name__

    for _, module_name, _ in pkgutil.walk_packages(__path__, package_name + "."):
        if module_name.endswith('.base'):
            continue

        module = importlib.import_module(module_name)

        for _, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, BaseCheck) and obj is not BaseCheck:
                if id(obj) not in seen_ids:
                    seen_ids.add(id(obj))
                    ALL_PLUGINS.append(obj)
            elif issubclass(obj, BaseNetworkPlugin) and obj is not BaseNetworkPlugin:
                if id(obj) not in seen_ids:
                    seen_ids.add(id(obj))
                    NETWORK_PLUGINS.append(obj)


# Load plugins when the package is first imported
load_plugins()
