import json
from datetime import datetime
from typing import Dict, List, Any

class ReportGenerator:
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
                if item.get('param'):
                    lines.append(f"- **Parámetro**: `{item.get('param')}`")
                lines.append(f"- **Evidencia**: `{item.get('evidence')}`")
                lines.append("")
                
        if total_vulns == 0:
             lines.append("\n> [!NOTE]\n> No se encontraron vulnerabilidades obvias.")
             
        return "\n".join(lines)
