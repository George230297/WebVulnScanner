import json
from datetime import datetime, timezone
from collections import defaultdict
from typing import Dict, List, Any
from webvulnscanner.core.engine import AsyncScanner


class ReportGenerator:
    @staticmethod
    def prepare_results(target: str, scanner: AsyncScanner) -> Dict[str, Any]:
        """Converts scanner results into a structured dictionary.
        
        Now includes severity and a scan timestamp in the metadata.
        """
        checks_data: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for v in scanner.vulnerabilities:
            key = v.category.lower() if hasattr(v, 'category') and v.category else 'general'

            checks_data[key].append({
                'type': v.type,
                'url': v.url,
                'param': getattr(v, 'param', None) or 'N/A',
                'evidence': v.evidence,
                'severity': v.severity,  # BUG-13 FIX: include severity in JSON output
            })

        return {
            'meta': {
                'target': target,
                'scanner': 'WebVulnScanner v2_modular',
                'timestamp': datetime.now(timezone.utc).isoformat(),  # BUG-13 FIX: add timestamp
            },
            'crawl': {
                'pages_count': len(scanner.visited),
                'js_files_scanned': list(scanner.js_files_scanned),
            },
            'checks': dict(checks_data),
        }

    @staticmethod
    def generate_json(data: Dict[str, Any]) -> str:
        return json.dumps(data, indent=2, ensure_ascii=False)

    @staticmethod
    def generate_markdown(data: Dict[str, Any]) -> str:
        lines: List[str] = []
        meta = data.get('meta', {})
        lines.append(f"# Reporte de Vulnerabilidades: {meta.get('target', 'N/A')}")
        lines.append(f"**Scanner**: {meta.get('scanner', 'WebVulnScanner v2')}")
        lines.append(f"**Fecha**: {meta.get('timestamp', datetime.now(timezone.utc).isoformat())}\n")

        # Recon Summary
        crawl = data.get('crawl', {})
        lines.append("## Resumen de Reconocimiento")
        lines.append(f"- **Páginas Escaneadas**: {crawl.get('pages_count', 0)}")
        lines.append(f"- **Archivos JS Analizados**: {len(crawl.get('js_files_scanned', []))}")

        # Vulnerability Findings
        lines.append("\n## Hallazgos de Seguridad")
        checks = data.get('checks', {})
        total_vulns = 0

        for category, items in checks.items():
            if not items:
                continue
            lines.append(f"\n### {category.upper()}")
            total_vulns += len(items)

            for idx, item in enumerate(items, 1):
                severity = item.get('severity', 'Unknown')
                lines.append(f"**{idx}. {item.get('type')}** — Severity: `{severity}`")
                lines.append(f"- **URL**: `{item.get('url')}`")
                if item.get('param') and item.get('param') != 'N/A':
                    lines.append(f"- **Parámetro**: `{item.get('param')}`")
                lines.append(f"- **Evidencia**: `{item.get('evidence')}`")
                lines.append("")

        if total_vulns == 0:
            lines.append("\n> [!NOTE]\n> No se encontraron vulnerabilidades obvias.")

        return "\n".join(lines)
