#!/usr/bin/env python3
"""
WebVulnScanner v2 - Entry Point
"""
import sys
import os

# Add the current directory to sys.path to ensure the package is resolvable
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

try:
    from webvulnscanner.ui.cli import main
except ImportError as e:
    print(f"Error importing webvulnscanner package: {e}")
    sys.exit(1)

if __name__ == "__main__":
    main()
