# Cifrado de Extremo a Extremo (E2E) - Python GUI

Este proyecto es una aplicación de escritorio moderna desarrollada con **Python** y **PyQt6** que implementa un sistema de cifrado de extremo a extremo (E2E) utilizando algoritmos robustos como **RSA-2048** y **AES-256**.

## 🚀 Características

- **Chat Seguro**: Cifrado de mensajes en tiempo real.
- **Cifrado de Archivos**: Procesa archivos de cualquier tipo con una combinación de RSA y AES (Cifrado Híbrido).
- **Gestión Avanzada de Claves**:
  - Generación, exportación e importación de claves PEM.
  - Panel de información técnica detallada (huella SHA-256, bits, exponente, etc.).
- **Multi-idioma**: Soporte completo para **Español** e **Inglés**.
- **Interfaz Moderna**: Diseño oscuro elegante basado en Fluent Design.

## 🛠️ Tecnologías Utilizadas

- **Python 3.x**
- **PyQt6**: Para la interfaz gráfica de usuario.
- **Cryptography**: Librería estándar para operaciones criptográficas seguras.
- **RSA**: Para intercambio de claves y cifrado de mensajes cortos.
- **AES-256 (CBC)**: Para cifrado eficiente de archivos de gran tamaño.

## 📋 Requisitos

Asegúrate de tener instaladas las dependencias necesarias:

```bash
pip install PyQt6 cryptography
```

## 🖥️ Uso

1. Ejecuta la aplicación:
   ```bash
   python InterfazGrafica.py
   ```
2. **Generar Claves**: Al iniciar se generará un par de claves automáticamente. Puedes rotarlas en la pestaña "Gestión de claves".
3. **Cifrar/Descifrar**: Copia mensajes o selecciona archivos para proteger tu información.

## 🔒 Detalles de Seguridad

- **Asimétrico**: RSA 2048 bits.
- **Simétrico**: AES-256-CBC con relleno PKCS7.
- **Relleno RSA**: OAEP con MGF1 y SHA-256.
- **Integridad**: Huellas digitales SHA-256 para verificación de claves.

## 📄 Licencia

Este proyecto está bajo la Licencia MIT.
