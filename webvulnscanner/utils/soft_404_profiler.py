import hashlib
import random
import string
import logging
from typing import Dict, Any, Optional, Union
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="requests")
warnings.filterwarnings("ignore", message=".*urllib3.*chardet.*")
try:
    from requests.exceptions import RequestsDependencyWarning
    warnings.simplefilter('ignore', RequestsDependencyWarning)
except ImportError:
    pass

import requests
from requests.exceptions import Timeout, ConnectionError, RequestException

logger = logging.getLogger(__name__)

class Soft404Profile:
    """Clase que representa el perfil base de un Soft 404."""
    
    def __init__(self, status_code: int, content_length: int, body_hash: str, text_sample: str):
        self.status_code = status_code
        self.content_length = content_length
        self.body_hash = body_hash
        self.text_sample = text_sample

    def to_dict(self) -> Dict[str, Union[int, str]]:
        return {
            "status_code": self.status_code,
            "content_length": self.content_length,
            "body_hash": self.body_hash,
            "text_sample": self.text_sample
        }

def _generate_random_path(length: int = 12) -> str:
    """Genera una cadena alfanumérica aleatoria para simular un archivo inexistente."""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def _extract_text_sample(text: str) -> str:
    """
    Extrae una muestra clave del texto para identificar SPAs (ej. React, Vue, Angular)
    o páginas de error por defecto. Busca patrones comunes.
    """
    indicators = [
        '<div id="root">',
        '<div id="app">',
        '<script type="module"',
        '<noscript>'
    ]
    for indicator in indicators:
        if indicator in text:
            return indicator
    return ""

def calibrate_target(base_url: str, timeout: int = 10) -> Optional[Soft404Profile]:
    """
    Fase de Calibración: Realiza una petición a una ruta inexistente
    para generar un perfil de "Soft 404".
    
    Retorna un objeto Soft404Profile si tiene éxito, o None si falla.
    """
    random_path = _generate_random_path() + ".txt"
    # Asegurar que base_url no termine en barra extra
    target_url = f"{base_url.rstrip('/')}/{random_path}"

    try:
        response = requests.get(target_url, timeout=timeout, allow_redirects=True)
        
        status_code = response.status_code
        body_text = response.text
        content_length = len(body_text)
        
        # Calcular hash MD5 del cuerpo
        body_hash = hashlib.md5(body_text.encode('utf-8', errors='ignore')).hexdigest()
        
        # Extraer muestra de texto clave (ej. estructura base de una SPA)
        text_sample = _extract_text_sample(body_text)

        profile = Soft404Profile(
            status_code=status_code,
            content_length=content_length,
            body_hash=body_hash,
            text_sample=text_sample
        )
        
        logger.info(f"[+] Perfil Soft 404 calibrado para {base_url} - Status: {status_code}, Longitud: {content_length}")
        return profile

    except Timeout:
        logger.error(f"[-] Timeout al intentar calibrar {base_url}")
    except ConnectionError:
        logger.error(f"[-] Error de conexión al intentar calibrar {base_url}")
    except RequestException as e:
        logger.error(f"[-] Error en la petición (calibración) en {base_url}: {e}")
    
    return None

def is_soft_404(response: requests.Response, baseline_profile: Soft404Profile, length_tolerance: float = 0.05) -> bool:
    """
    Fase de Verificación: Compara una respuesta sospechosa con el perfil base para determinar 
    si, aunque sea un 200 OK, la página en realidad actúa como un Soft 404.
    
    - Tolerancia en la longitud (~5%) para tolerar contenido dinámico (CSRF tokens, IDs, etc).
    - Verificación secundaria con hash exacto o base estructural HTML.
    """
    if not isinstance(baseline_profile, Soft404Profile):
        raise ValueError("baseline_profile debe ser una instancia válida de Soft404Profile")

    # Generalmente un 404 real directo del servidor (HTTP 404) no es un Soft 404.
    # Pero si el perfil de calibración indica algún estado, un Soft 404 coincidirá con ese patrón HTTP.
    # Principalmente buscamos falsos 200 OK.
    if response.status_code != baseline_profile.status_code and baseline_profile.status_code == 200:
        if response.status_code == 404:
            # Un verdadero 404 legítimo significa que la página realmente no existe a ojos del backend
            return False

    body_text = response.text
    current_length = len(body_text)
    current_hash = hashlib.md5(body_text.encode('utf-8', errors='ignore')).hexdigest()

    # 1. Verificación Fuerte: El hash exacto del body es idéntico.
    if current_hash == baseline_profile.body_hash:
        return True

    # 2. Verificación Flexible: Diferencia de longitud dentro de la tolerancia calculada.
    if baseline_profile.content_length > 0:
        length_diff_ratio = abs(current_length - baseline_profile.content_length) / baseline_profile.content_length
    else:
        length_diff_ratio = 0.0 if current_length == 0 else 1.0

    if length_diff_ratio <= length_tolerance:
        # Si la longitud es parecida, buscamos si se mantiene la estructura típica (ej. divs root de SPA).
        if baseline_profile.text_sample and baseline_profile.text_sample in body_text:
            return True
        # Si el perfil no guardó ninguna estructura clave, la coincidencia de longitud es la métrica decisiva.
        elif baseline_profile.text_sample == "":
            return True

    # Si la longitud varía bastante o no concuerda en estructura, es menos probable que sea el template 404/SPA original
    return False
