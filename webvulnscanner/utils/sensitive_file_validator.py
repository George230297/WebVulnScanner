import os
import logging

logger = logging.getLogger(__name__)

def is_real_sensitive_file(status_code: int, response_text: str, file_path: str) -> bool:
    """
    Validación rigurosa de archivos sensibles requerida para prevenir los
    falsos positivos inyectados por SPAs, Firewalls y páginas 404 dinámicas.
    Supera la precaria validación inicial de estado HTTP 200 OK mediante heurística.
    
    Implementa en la arquitectura oficial la lógica solicitada 
    manteniendo principios de seguridad y robustez.
    """
    # 1. Descartar de plano si no es un Success (HTTP 200 OK)
    if status_code != 200:
        return False
        
    cuerpo = response_text.lower()
    
    # Extraer la extensión del endpoint auditado (ej. /db_backup.sql -> .sql)
    _, file_extension = os.path.splitext(file_path.split('?')[0])
    file_extension = file_extension.lower()
    
    # 2. Heurística Anti-Falsos Positivos de Renderizado Inicial Front-End
    # Archivos como un .zip, .sql o .env JAMÁS deberían contener skeletons HTML nativos
    firmas_falso_positivo = [
        "<html", 
        "<!doctype html", 
        '<div id="root">', 
        '<div id="app">',
        '<script type="module"'
    ]
    
    for firma in firmas_falso_positivo:
        if firma in cuerpo:
            return False # Se trata de una inyección del frontend o servidor proxy tramposo
            
    # 3. Validación de Capa 7 Específica por Extensión (Filtro Anti-Basura)
    if file_extension == ".sql":
        # Un volcado de DB real invariablemente contendrá instrucciones DDL o DML masivas
        if "insert into" not in cuerpo and "create table" not in cuerpo and "drop table" not in cuerpo:
            return False
            
    elif file_extension == ".env":
        # Evitar dar por bueno un archivo .env si en realidad devolvió texto plano inútil
        # Todo config de entorno debe mapearse con operadores de asignación estáticos
        if "=" not in cuerpo:
            return False
            
    elif file_extension == ".json":
        if "{" not in cuerpo or "}" not in cuerpo:
             return False

    # Sobrevive a cribas heurísticas y de tipado de extensión: Es Vulnerabilidad Confirmada
    return True
