from setuptools import setup, find_packages

setup(
    name='webvulnscanner',
    version='0.2.1',
    packages=find_packages(),
    install_requires=[
        'requests', 
        'beautifulsoup4',
        'aiohttp',
        'aiodns',
        'cchardet'
    ],
    entry_points={
        'console_scripts': [
            'webvulnscanner = webvulnscanner.ui.cli:main',
            'webvulnscanner-tui = webvulnscanner.ui.tui:main'
        ]
    },
    description='WebVulnScanner v2 - Escáner Web Asíncrono Modular',
    author='Tu nombre',
)