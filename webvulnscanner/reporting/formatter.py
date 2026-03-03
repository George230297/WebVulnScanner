import json
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Any
from webvulnscanner.core.engine import AsyncScanner

class ReportGenerator:
    @staticmethod
    def prepare_results(target: str, scanner: AsyncScanner) -> Dict[str, Any]:
        """Converts scanner results into a structured dictionary."""
        checks_data: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for v in scanner.vulnerabilities:
            # Use centralized category from model
            key = v.category.lower() if hasattr(v, 'category') and v.category else 'general'
            
            checks_data[key].append({
                'type': v.type,
                'url': v.url,
                'param': getattr(v, 'param', 'N/A'),
                'evidence': v.evidence
            })
            
        return {
            'meta': {'target': target, 'scanner': 'v2_modular'},
            'crawl': {
                'pages_count': len(scanner.visited),
                'js_files_scanned': list(scanner.js_files_scanned)
            },
            'checks': dict(checks_data)
        }

    @staticmethod
    def generate_json(data: Dict[str, Any]) -> str:
        return json.dumps(data, indent=2)

    @staticmethod
    def generate_markdown(data: Dict[str, Any]) -> str:
        lines = []
        meta = data.get('meta', {})
        lines.append(f"# Reporte de Vulnerabilidades: {meta.get('target', 'N/A')}")
        lines.append(f"**Scanner**: {meta.get('scanner', 'WebVulnScanner v2')}")
        lines.append(f"**Date**: {datetime.now().isoformat()}\n")
        
        # Recon Summary
        crawl = data.get('crawl', {})
        lines.append("## Resumen de Reconocimiento")
        lines.append(f"- **Páginas Escaneadas**: {crawl.get('pages_count', 0)}")
        lines.append(f"- **Archivos JS Analizados**: {len(crawl.get('js_files_scanned', []))}")
        
        # Vulns
        lines.append("\n## Hallazgos de Seguridad")
        checks = data.get('checks', {})
        total_vulns = 0
        
        for category, items in checks.items():
            if not items: continue
            lines.append(f"\n### {category.upper()}")
            total_vulns += len(items)
            
            for idx, item in enumerate(items, 1):
                lines.append(f"**{idx}. {item.get('type')}**")
                lines.append(f"- **URL**: `{item.get('url')}`")
                if item.get('param') and item.get('param') != 'N/A':
                    lines.append(f"- **Parámetro**: `{item.get('param')}`")
                lines.append(f"- **Evidencia**: `{item.get('evidence')}`")
                lines.append("")
                
        if total_vulns == 0:
             lines.append("\n> [!NOTE]\n> No se encontraron vulnerabilidades obvias.")
             
        return "\n".join(lines)
