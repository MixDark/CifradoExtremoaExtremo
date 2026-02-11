import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
import secrets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

class CifradorExtremoAExtremo:
    def generar_nuevas_claves(self):
        self.clave_publica, self.clave_privada = self.generar_claves()
    def cifrar_archivo(self, ruta_entrada, ruta_salida):
        # Cifra un archivo de cualquier tamaño usando AES y la clave AES cifrada con RSA
        try:
            with open(ruta_entrada, 'rb') as f:
                datos = f.read()
            # Generar clave AES aleatoria
            clave_aes = secrets.token_bytes(32)  # AES-256
            iv = secrets.token_bytes(16)
            # Cifrar datos con AES
            cipher = Cipher(algorithms.AES(clave_aes), modes.CBC(iv))
            encryptor = cipher.encryptor()
            padder = sym_padding.PKCS7(128).padder()
            datos_padded = padder.update(datos) + padder.finalize()
            datos_cifrados = encryptor.update(datos_padded) + encryptor.finalize()
            # Cifrar clave AES con RSA
            clave_aes_cifrada = self.clave_publica.encrypt(
                clave_aes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            # Guardar: [longitud_clave][clave_aes_cifrada][iv][datos_cifrados]
            with open(ruta_salida, 'wb') as f:
                f.write(len(clave_aes_cifrada).to_bytes(4, 'big'))
                f.write(clave_aes_cifrada)
                f.write(iv)
                f.write(datos_cifrados)
        except Exception as e:
            raise ValueError(f"Error al cifrar archivo: {e}")

    def descifrar_archivo(self, ruta_entrada, ruta_salida):
        # Descifra un archivo cifrado con AES y la clave AES cifrada con RSA
        try:
            with open(ruta_entrada, 'rb') as f:
                datos = f.read()
            # Extraer longitud de clave cifrada
            len_clave = int.from_bytes(datos[:4], 'big')
            clave_aes_cifrada = datos[4:4+len_clave]
            iv = datos[4+len_clave:4+len_clave+16]
            datos_cifrados = datos[4+len_clave+16:]
            # Descifrar clave AES
            clave_aes = self.clave_privada.decrypt(
                clave_aes_cifrada,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            # Descifrar datos con AES
            cipher = Cipher(algorithms.AES(clave_aes), modes.CBC(iv))
            decryptor = cipher.decryptor()
            datos_padded = decryptor.update(datos_cifrados) + decryptor.finalize()
            unpadder = sym_padding.PKCS7(128).unpadder()
            datos = unpadder.update(datos_padded) + unpadder.finalize()
            with open(ruta_salida, 'wb') as f:
                f.write(datos)
        except Exception as e:
            raise ValueError(f"Error al descifrar archivo: {e}")

    def __init__(self):
        # Generar un par de claves
        self.clave_publica, self.clave_privada = self.generar_claves()

    def exportar_clave_privada(self, ruta, password=None):
        # Exporta la clave privada a un archivo en formato PEM
        try:
            if password:
                cifrado = serialization.BestAvailableEncryption(password.encode())
            else:
                cifrado = serialization.NoEncryption()
            with open(ruta, 'wb') as f:
                f.write(self.clave_privada.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=cifrado
                ))
        except Exception as e:
            raise ValueError(f"Error al exportar clave privada: {e}")

    def exportar_clave_publica(self, ruta):
        # Exporta la clave pública a un archivo en formato PEM
        try:
            with open(ruta, 'wb') as f:
                f.write(self.clave_publica.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
        except Exception as e:
            raise ValueError(f"Error al exportar clave pública: {e}")

    def importar_clave_privada(self, ruta, password=None):
        # Importa una clave privada desde un archivo PEM
        try:
            with open(ruta, 'rb') as f:
                self.clave_privada = serialization.load_pem_private_key(
                    f.read(),
                    password=password.encode() if password else None
                )
            self.clave_publica = self.clave_privada.public_key()
        except Exception as e:
            raise ValueError(f"Error al importar clave privada: {e}")

    def importar_clave_publica(self, ruta):
        # Importa una clave pública desde un archivo PEM
        try:
            with open(ruta, 'rb') as f:
                self.clave_publica = serialization.load_pem_public_key(f.read())
        except Exception as e:
            raise ValueError(f"Error al importar clave pública: {e}")

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