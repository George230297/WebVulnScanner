import urllib.parse
import re
import random

class WafEncoder:
    """
    Motor de mutación y ofuscación de payloads (Polymorphism Engine) 
    para evadir detecciones basadas en firmas y expresiones regulares (Regex) de WAFs.
    """
    def __init__(self):
        self.level = 0

    @staticmethod
    def double_url_encode(payload: str) -> str:
        """
        Doble URL-Encoding para bypassear decodificadores simples de capa 7.
        Ej: '<script>' se transforma en '%253Cscript%253E'
        """
        first_pass = urllib.parse.quote(payload)
        return urllib.parse.quote(first_pass)

    @staticmethod
    def sqli_tamper(payload: str) -> str:
        """
        Reemplaza espacios en blanco estáticos con comentarios SQL 
        dinámicos o saltos de línea permitidos por el motor de base de datos.
        Ej: 'UNION SELECT' -> 'UNION/**/SELECT' o 'UNION%0aSELECT'
        """
        evasion_chars = ['/**/', '%0a', '%0b', '%0c', '%0d', '%09']
        
        # Split tokens effectively bypassing basic string matching (UNION SELECT -> UNION/**/SELECT)
        # Using a regex to replace actual spaces outside of strings if necessary, but a simple replace works for basic payloads
        def replace_space(match):
            return random.choice(evasion_chars)
            
        return re.sub(r'\s+', replace_space, payload)

    @staticmethod
    def hex_encode(payload: str) -> str:
        """
        Codifica una cadena a formato Hexadecimal de URL puro.
        Útil en inyecciones directas o XSS en contextos permisivos.
        Ej: 'admin' => '%61%64%6d%69%6e'
        """
        return ''.join(f'%{ord(c):02x}' for c in payload)

    @staticmethod
    def unicode_encode(payload: str) -> str:
        """
        Codifica con escapes Unicode para payloads JSON o contextos JS.
        Ej: '<' -> '\\u003c'
        """
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
        
    def apply_random_mutation(self, payload: str, context: str = "general") -> str:
        """
        Aplica una mutación estocástica basándose en el nivel configurado.
        Si la evasión es 0, no contamina el payload original.
        """
        if self.level == 0:
            return payload

        import random
        if context == "sqli":
            mutations = [WafEncoder.sqli_tamper, lambda x: x]
        elif context == "xss":
            # Mutaciones semánticas que sobreviven al transporte estructural JSON
            mutations = [
                lambda x: x.replace("alert(1)", "prompt(1)"),
                lambda x: x.replace("<script", "<sCrIpT"), 
                lambda x: x
            ]
        else:
            mutations = [lambda x: x]
            
        chosen_mutation = random.choice(mutations)
        return chosen_mutation(payload)

# Global instance
encoder = WafEncoder()
