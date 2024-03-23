from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

class CifradorExtremoAExtremo:

    def __init__(self):
        # Generar un par de claves
        self.clave_publica, self.clave_privada = self.generar_claves()

    def generar_claves(self):

        #Genera un par de claves (pública y privada) RSA
        clave_privada = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        clave_publica = clave_privada.public_key()
        return clave_publica, clave_privada

    def cifrar_mensaje(self, mensaje):
    
        #Cifra el mensaje ingresado utilizando la clave pública proporcionada
        try:
            mensaje_cifrado = self.clave_publica.encrypt(
                mensaje.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return mensaje_cifrado.hex()
        
        except Exception as e:
            raise ValueError(f"Error al cifrar el mensaje: {e}")

    def descifrar_mensaje(self, mensaje_cifrado):

        #Descifra el mensaje cifrado utilizando la clave privada proporcionada
        try:
            mensaje_descifrado = self.clave_privada.decrypt(
                bytes.fromhex(mensaje_cifrado),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode()
            return mensaje_descifrado
        
        except Exception as e:
            raise ValueError(f"Error al descifrar el mensaje: {e}")