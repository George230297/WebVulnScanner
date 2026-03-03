import importlib
import pkgutil
import inspect
from typing import List, Type
from .base import BaseCheck

# We will load plugins dynamically
ALL_PLUGINS: List[Type[BaseCheck]] = []

def load_plugins():
    global ALL_PLUGINS
    ALL_PLUGINS.clear()
    
    # Iterate over all modules in the current package
    package_name = __name__
    for _, module_name, _ in pkgutil.iter_modules(__path__):
        if module_name == 'base':
            continue
            
        full_module_name = f"{package_name}.{module_name}"
        module = importlib.import_module(full_module_name)
        
        # Find all classes that inherit from BaseCheck
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, BaseCheck) and obj is not BaseCheck:
                ALL_PLUGINS.append(obj)

# Load plugins when the module is imported
load_plugins()
