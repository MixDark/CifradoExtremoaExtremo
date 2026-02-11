# Changelog

Todos los cambios notables en este proyecto serán documentados en este archivo.

## [1.1.0] - 2026-02-10

### Añadido
- **Panel de Información de Claves**: Nueva sección detallada en la pestaña de Gestión de Claves.
  - Visualización de huella digital SHA-256.
  - Detalles técnicos: tamaño de clave, exponente público, esquema de relleno (OAEP/MGF1).
  - Estadísticas de sesión: contador de mensajes y archivos procesados, tiempo de sesión.
- **Internacionalización**: Traducción completa de los nuevos detalles técnicos a inglés y español.
- **Persistencia de metadatos**: Registro de fecha de generación/importación de claves.

### Mejoras
- **Refactorización de UI**: Migración de tablas HTML a layouts nativos de PyQt6 para garantizar proporcionalidad perfecta en las columnas (33.3% cada una).
- **Estética**: Mejoras en el diseño oscuro y uso de tipografías monoespaciadas para datos técnicos.
- **Globalización de imports**: Corrección de errores de importación y optimización de carga de módulos.

## [1.0.0] - 2024-02-09

### Inicial
- Implementación base del cifrador lógico `CifradoE2E.py`.
- Interfaz gráfica inicial con `PyQt6`.
- Soporte para chat seguro y cifrado de archivos individuales.
- Sistema básico de importación/exportación de claves.
