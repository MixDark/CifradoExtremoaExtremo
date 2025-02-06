from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import base64

class CifradorExtremoAExtremo:
    def __init__(self):
        # Generar par de claves inicial
        self.generar_nuevas_claves()

    def generar_nuevas_claves(self):
        """Genera un nuevo par de claves RSA"""
        self.clave_privada = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.clave_publica = self.clave_privada.public_key()

    def obtener_clave_publica(self):
        """Retorna la clave pública"""
        return self.clave_publica

    def cifrar_mensaje(self, mensaje, clave_publica_destino):
        """Cifra el mensaje usando la clave pública del destinatario"""
        try:
            mensaje_cifrado = clave_publica_destino.encrypt(
                mensaje.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return base64.b64encode(mensaje_cifrado).decode('utf-8')
        except Exception as e:
            raise ValueError(f"Error al cifrar el mensaje: {str(e)}")

    def descifrar_mensaje(self, mensaje_cifrado):
        """Descifra el mensaje usando la clave privada propia"""
        try:
            mensaje_bytes = base64.b64decode(mensaje_cifrado)
            mensaje_descifrado = self.clave_privada.decrypt(
                mensaje_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return mensaje_descifrado.decode()
        except Exception as e:
            raise ValueError(f"Error al descifrar el mensaje: {str(e)}")
