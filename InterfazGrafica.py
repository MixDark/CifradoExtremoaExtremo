from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QTextEdit, QGridLayout, QMessageBox, QFileDialog, QComboBox, QGroupBox
)
from PyQt6.QtWidgets import QTabWidget, QVBoxLayout, QHBoxLayout, QStatusBar, QMainWindow
import os
import time
from idiomas import idiomas
from PyQt6.QtCore import Qt, QTime
from PyQt6.QtGui import QIcon
from CifradoE2E import CifradorExtremoAExtremo
import sys

class InterfazCifradorExtremo(QWidget):
    def rotar_claves(self):
        try:
            self.cifrador.generar_nuevas_claves()
            import time
            self.fecha_claves = time.strftime("%Y-%m-%d %H:%M:%S")
            self.estado_claves.setText(f"{self.textos[self.idioma].get('estado_label', 'Estado')}: {self.textos[self.idioma].get('claves_rotadas', 'Claves rotadas correctamente')}")
            QMessageBox.information(self, self.textos[self.idioma].get('exito', 'Éxito'), self.textos[self.idioma].get('claves_rotadas_msg', 'Las claves han sido rotadas.'))
            self.actualizar_info_claves()
        except Exception as e:
            self.estado_claves.setText("Estado: Error al rotar claves")
            QMessageBox.critical(self, "Error", str(e))
    def exportar_clave_privada(self):
        ruta, _ = QFileDialog.getSaveFileName(self, "Exportar clave privada", "clave_privada.pem", "PEM Files (*.pem)")
        if ruta:
            try:
                self.cifrador.exportar_clave_privada(ruta)
                QMessageBox.information(self, "Éxito", "Clave privada exportada correctamente.")
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    def exportar_clave_publica(self):
        ruta, _ = QFileDialog.getSaveFileName(self, "Exportar clave pública", "clave_publica.pem", "PEM Files (*.pem)")
        if ruta:
            try:
                self.cifrador.exportar_clave_publica(ruta)
                QMessageBox.information(self, "Éxito", "Clave pública exportada correctamente.")
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    def importar_clave_privada(self):
        ruta, _ = QFileDialog.getOpenFileName(self, "Importar clave privada", "", "PEM Files (*.pem)")
        if ruta:
            try:
                self.cifrador.importar_clave_privada(ruta)
                import time
                self.fecha_claves = time.strftime("%Y-%m-%d %H:%M:%S") + " (Import)"
                QMessageBox.information(self, "Éxito", "Clave privada importada correctamente.")
                self.actualizar_info_claves()
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    def importar_clave_publica(self):
        ruta, _ = QFileDialog.getOpenFileName(self, "Importar clave pública", "", "PEM Files (*.pem)")
        if ruta:
            try:
                self.cifrador.importar_clave_publica(ruta)
                import time
                self.fecha_claves = time.strftime("%Y-%m-%d %H:%M:%S") + " (Import)"
                QMessageBox.information(self, "Éxito", "Clave pública importada correctamente.")
                self.actualizar_info_claves()
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    def cambiar_idioma(self, nuevo_idioma=None):
        if nuevo_idioma:
            self.idioma = nuevo_idioma
        else:
            self.idioma = self.selector_idioma.currentText()
        self.update_textos()

    def update_textos(self):
        textos = self.textos[self.idioma]
        self.setWindowTitle(textos['titulo'])
        self.label_idioma.setText(textos.get('idioma_label', 'Idioma:' if self.idioma == 'es' else 'Language:'))
        self.entrada_mensaje.setPlaceholderText(textos['mensaje_a_cifrar'])
        self.boton_cifrar.setText(textos['cifrar'])
        self.boton_copiar_cifrado.setText(textos['copiar_cifrado'])
        self.boton_pegar_en_recibido.setText(textos['pegar_en_recibido'])
        self.boton_copiar_descifrado.setText(textos['copiar_descifrado'])
        self.boton_exportar_priv.setText(textos['exportar_priv'])
        self.boton_exportar_pub.setText(textos['exportar_pub'])
        self.boton_importar_priv.setText(textos['importar_priv'])
        self.boton_importar_pub.setText(textos['importar_pub'])
        self.boton_rotar_claves.setText(textos.get('rotar_claves', 'Rotar claves' if self.idioma == 'es' else 'Rotate keys'))
        self.estado_claves.setText(textos.get('estado_claves_cargadas', 'Estado: Claves cargadas' if self.idioma == 'es' else 'Status: Keys loaded'))
        self.boton_cifrar_archivo.setText(textos['cifrar_archivo'])
        self.boton_descifrar_archivo.setText(textos['descifrar_archivo'])
        
        # Actualizar los textos de las pestañas
        tab_names = [
            'chat_seguro',
            'gestion_claves',
            'info_e2e',
            'archivos'
        ]
        for i, key in enumerate(tab_names):
            if i < self.tabs.count():
                self.tabs.setTabText(i, textos.get(key, key.capitalize()))
        
        # Actualizar contenido de la pestaña de información E2E
        if hasattr(self, 'info_label'):
            self.info_label.setText(textos['info_e2e_contenido'])

        # Actualizar los títulos de los grupos
        if hasattr(self, 'tab_archivos'):
            for group in self.tab_archivos.findChildren(QGroupBox):
                if "cifrado" in group.title().lower() or "encrypted" in group.title().lower():
                    group.setTitle(textos['detalles_archivo_cifrado'])
                elif "descifrado" in group.title().lower() or "decrypted" in group.title().lower():
                    group.setTitle(textos['detalles_archivo_descifrado'])

        # Traducción dinámica de detalles de archivos
        labels_info = [
            (self.detalles_cifrado, 'archivo_cifrado_label', 'archivo_cifrado_title'),
            (self.detalles_descifrado, 'archivo_descifrado_label', 'archivo_descifrado_title')
        ]

        for label, label_key, title_key in labels_info:
            if hasattr(self, label_key.replace('_label', '')) or (hasattr(self, 'detalles_cifrado') and label == self.detalles_cifrado) or (hasattr(self, 'detalles_descifrado') and label == self.detalles_descifrado):
                datos = label.text()
                if not datos or datos == "<b>Archivo cifrado:</b>" or datos == "<b>Archivo descifrado:</b>" or "Encrypted file" in datos or "Decrypted file" in datos:
                    # Si no hay datos reales, solo poner el título
                    tag = "cifrado" if label == self.detalles_cifrado else "descifrado"
                    label.setText(f"<b>{textos['archivo_' + tag + '_title']}:</b>")
                    continue

                import re
                # Extraer valores limpieza de etiquetas
                def get_val(patterns, text):
                    for p in patterns:
                        m = re.search(p, text)
                        if m: return m.group(1)
                    return ""

                nombre = get_val([r'Nombre: (.+?)<br>', r'Name: (.+?)<br>'], datos)
                ruta = get_val([r'Ruta: (.+?)<br>', r'Path: (.+?)<br>'], datos)
                tam = get_val([r'Tamaño: (.+?) bytes<br>', r'Size: (.+?) bytes<br>'], datos)
                creado = get_val([r'Creado: (.+?)<br>', r'Created: (.+?)<br>'], datos)
                modificado = get_val([r'Modificado: (.+?)<br>', r'Modified: (.+?)<br>'], datos)
                tipo = get_val([r'Tipo: (.+?)<br>', r'Type: (.+?)<br>'], datos)
                permisos = get_val([r'Permisos: (.+)$', r'Permissions: (.+)$'], datos)

                tag = "cifrado" if label == self.detalles_cifrado else "descifrado"
                nuevo = f"<b>{textos['archivo_' + tag + '_title']}:</b><br>"
                nuevo += f"{textos['lbl_nombre']}: {nombre}<br>"
                nuevo += f"{textos['lbl_ruta']}: {ruta}<br>"
                nuevo += f"{textos['lbl_tamano']}: {tam} bytes<br>"
                nuevo += f"{textos['lbl_creado']}: {creado}<br>"
                nuevo += f"{textos['lbl_modificado']}: {modificado}<br>"
                nuevo += f"{textos['lbl_tipo']}: {tipo}<br>"
                nuevo += f"{textos['lbl_permisos']}: {permisos}"
                label.setText(nuevo)
        
        # Actualizar grupo de información de claves
        if hasattr(self, 'label_info_claves_titulo'):
            self.label_info_claves_titulo.setTitle(textos['info_claves'])
            self.actualizar_info_claves()

    def actualizar_info_claves(self):
        if not hasattr(self, 'cifrador') or not self.cifrador.clave_publica:
            return
        
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import hashlib

        textos = self.textos[self.idioma]
        
        # Obtener bytes de la clave pública para la huella
        pub_bytes = self.cifrador.clave_publica.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        huella = hashlib.sha256(pub_bytes).hexdigest().upper()
        huella_formateada = ":".join(huella[i:i+4] for i in range(0, len(huella), 4))
        
        # Vista previa (primeros y últimos caracteres del PEM)
        pem_bytes = self.cifrador.clave_publica.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        lineas = pem_bytes.split('\n')
        preview = lineas[1][:30] + "..." + lineas[-3][-30:]

        # Detalles adicionales
        exponente = self.cifrador.clave_publica.public_numbers().e
        tamano = self.cifrador.clave_publica.key_size

        # Columna 1: Criptografía
        html_col1 = f"""
        <div style="line-height: 1.4;">
            <p><b>{textos['huella_digital']}:</b><br>
            <code style="color: #00ff00; font-size: 9px; word-wrap: break-word;">{huella_formateada}</code></p>
            <p><b>{textos['tamano_clave']}:</b> {tamano} bits (RSA)</p>
            <p><b>{textos['exponente_publico']}:</b> {exponente}</p>
            <p><b>{textos['algoritmo_hash']}:</b> SHA-256</p>
            <p><b>{textos['esquema_relleno']}:</b> OAEP + MGF1</p>
        </div>
        """
        
        # Columna 2: Sesión y Formato
        html_col2 = f"""
        <div style="line-height: 1.4;">
            <p><b>{textos['fecha_generacion']}:</b><br>{self.fecha_claves}</p>
            <p><b>{textos['tiempo_sesion']}:</b><br>{int((time.time() - self.inicio_sesion)/60)} {textos['minutos']}</p>
            <p><b>{textos['formato_clave']}:</b> SPKI / PKCS#8</p>
        </div>
        """
        
        # Columna 3: Estado y Estadísticas
        html_col3 = f"""
        <div style="line-height: 1.4;">
            <p><b>{textos['seguridad_estado']}:</b> 
            <span style="color: #00ff00;">● {textos['seguridad_alta']}</span></p>
            <p><b>{textos['mensajes_procesados']}:</b> {self.mensajes_cont}</p>
            <p><b>{textos['archivos_procesados']}:</b> {self.archivos_cont}</p>
            <p style="background-color: #333; padding: 8px; border-radius: 4px; font-size: 11px; color: #eee;">
                <i style="color: #f1c40f;">{textos['consejo_seguridad']}:</i><br>
                {textos['tip_rotacion']}
            </p>
        </div>
        """

        self.label_info_col1.setText(html_col1)
        self.label_info_col2.setText(html_col2)
        self.label_info_col3.setText(html_col3)
        
        # Vista previa aparte
        preview_html = f"""
        <div style="line-height: 1.4; border-top: 1px solid #444; margin-top: 10px; padding-top: 10px;">
            <p><b>{textos['clave_publica_vista']}:</b><br>
            <code style="color: #aaa; font-size: 11px;">{preview}</code></p>
        </div>
        """
        self.label_preview_clave.setText(preview_html)

    def generar_detalles_archivo(self, ruta, info, tag):
        import os, time
        textos = self.textos[self.idioma]
        nuevo = f"<b>{textos['archivo_' + tag + '_title']}:</b><br>"
        nuevo += f"{textos['lbl_nombre']}: {os.path.basename(ruta)}<br>"
        nuevo += f"{textos['lbl_ruta']}: {ruta}<br>"
        nuevo += f"{textos['lbl_tamano']}: {info.st_size} bytes<br>"
        nuevo += f"{textos['lbl_creado']}: {time.ctime(info.st_ctime)}<br>"
        nuevo += f"{textos['lbl_modificado']}: {time.ctime(info.st_mtime)}<br>"
        nuevo += f"{textos['lbl_tipo']}: {os.path.splitext(ruta)[1]}<br>"
        nuevo += f"{textos['lbl_permisos']}: {oct(info.st_mode)[-3:]}"
        return nuevo

    def __init__(self):
        super().__init__()
        self.idioma = 'es'
        from idiomas import idiomas
        self.textos = idiomas
        self.historial = []
        self.mensajes_cont = 0
        self.archivos_cont = 0
        import time
        self.inicio_sesion = time.time()
        self.fecha_claves = time.strftime("%Y-%m-%d %H:%M:%S")
        self.setFixedSize(900, 600)
        self.setWindowFlags(Qt.WindowType.Window | Qt.WindowType.WindowMinimizeButtonHint | Qt.WindowType.WindowCloseButtonHint)
        self.setWindowTitle(self.textos[self.idioma]['titulo'])
        self.setWindowIcon(QIcon("favicon.ico"))
        self.cifrador = CifradorExtremoAExtremo()
        self.label_idioma = QLabel("Idioma:")
        self.selector_idioma = QComboBox()
        self.selector_idioma.addItems(["es", "en"])
        self.selector_idioma.setCurrentText(self.idioma)
        self.selector_idioma.currentTextChanged.connect(self.cambiar_idioma)
        self.tabs = QTabWidget()
        self.init_ui()
        if hasattr(self, 'label_idioma'):
            self.update_textos()

    def init_ui(self):
        # Limpiar widgets previos
        layout = self.layout()
        if layout is not None:
            while layout.count():
                item = layout.takeAt(0)
                widget = item.widget()
                if widget is not None:
                    widget.setParent(None)
            layout.deleteLater()
        main_layout = QVBoxLayout()
        # --- Selector de idioma ---
        idioma_layout = QHBoxLayout()
        idioma_layout.addWidget(self.label_idioma)
        idioma_layout.addWidget(self.selector_idioma)
        idioma_layout.addStretch()
        main_layout.addLayout(idioma_layout)
        # --- Pestaña de Chat Seguro ---
        self.tab_chat = QWidget()
        chat_layout = QVBoxLayout()
        self.texto_historial = QTextEdit()
        self.texto_historial.setReadOnly(True)
        chat_layout.addWidget(self.texto_historial)
        input_layout = QHBoxLayout()
        self.entrada_mensaje = QLineEdit()
        input_layout.addWidget(self.entrada_mensaje)
        self.boton_cifrar = QPushButton()
        self.boton_cifrar.clicked.connect(self.cifrar_mensaje)
        input_layout.addWidget(self.boton_cifrar)
        self.boton_copiar_cifrado = QPushButton()
        self.boton_copiar_cifrado.clicked.connect(self.copiar_cifrado)
        self.boton_pegar_en_recibido = QPushButton()
        self.boton_pegar_en_recibido.clicked.connect(self.pegar_en_recibido)
        self.boton_copiar_descifrado = QPushButton()
        self.boton_copiar_descifrado.clicked.connect(self.copiar_descifrado)
        botones_historial_layout = QHBoxLayout()
        botones_historial_layout.addWidget(self.boton_copiar_cifrado)
        botones_historial_layout.addWidget(self.boton_pegar_en_recibido)
        botones_historial_layout.addWidget(self.boton_copiar_descifrado)
        chat_layout.addLayout(botones_historial_layout)
        chat_layout.addLayout(input_layout)
        self.tab_chat.setLayout(chat_layout)
        self.tabs.addTab(self.tab_chat, "Chat seguro")
        # --- Pestaña de Gestión de claves ---
        self.tab_claves = QWidget()
        claves_layout = QVBoxLayout()
        self.boton_exportar_priv = QPushButton()
        self.boton_exportar_priv.setFixedHeight(28)
        self.boton_exportar_priv.setMinimumWidth(160)
        self.boton_exportar_priv.clicked.connect(self.exportar_clave_privada)
        self.boton_exportar_pub = QPushButton()
        self.boton_exportar_pub.setFixedHeight(28)
        self.boton_exportar_pub.setMinimumWidth(160)
        self.boton_exportar_pub.clicked.connect(self.exportar_clave_publica)
        self.boton_importar_priv = QPushButton()
        self.boton_importar_priv.setFixedHeight(28)
        self.boton_importar_priv.setMinimumWidth(160)
        self.boton_importar_priv.clicked.connect(self.importar_clave_privada)
        self.boton_importar_pub = QPushButton()
        self.boton_importar_pub.setFixedHeight(28)
        self.boton_importar_pub.setMinimumWidth(160)
        self.boton_importar_pub.clicked.connect(self.importar_clave_publica)
        self.boton_rotar_claves = QPushButton()
        self.boton_rotar_claves.setFixedHeight(28)
        self.boton_rotar_claves.setMinimumWidth(160)
        self.boton_rotar_claves.clicked.connect(self.rotar_claves)
        self.estado_claves = QLabel()
        self.estado_claves.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.estado_claves.setStyleSheet("color: #aaa; font-size: 13px;")
        
        botones_layout = QHBoxLayout()
        botones_layout.addWidget(self.boton_exportar_priv)
        botones_layout.addWidget(self.boton_exportar_pub)
        botones_layout.addWidget(self.boton_importar_priv)
        botones_layout.addWidget(self.boton_importar_pub)
        botones_layout.addWidget(self.boton_rotar_claves)
        
        claves_layout.addLayout(botones_layout)
        claves_layout.addSpacing(20)
        
        # Grupo de Información Detallada
        self.label_info_claves_titulo = QGroupBox("Información de las claves")
        info_total_layout = QVBoxLayout()
        
        # Contenedor para las 3 columnas
        columnas_widget = QWidget()
        columnas_layout = QHBoxLayout(columnas_widget)
        columnas_layout.setContentsMargins(0, 0, 0, 0)
        columnas_layout.setSpacing(10)
        
        self.label_info_col1 = QLabel()
        self.label_info_col1.setWordWrap(True)
        self.label_info_col1.setAlignment(Qt.AlignmentFlag.AlignTop)
        
        self.label_info_col2 = QLabel()
        self.label_info_col2.setWordWrap(True)
        self.label_info_col2.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.label_info_col2.setStyleSheet("border-left: 1px solid #444; padding-left: 10px;")
        
        self.label_info_col3 = QLabel()
        self.label_info_col3.setWordWrap(True)
        self.label_info_col3.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.label_info_col3.setStyleSheet("border-left: 1px solid #444; padding-left: 10px;")
        
        # Añadir con stretch factor igual para garantizar proporcionalidad
        columnas_layout.addWidget(self.label_info_col1, 1)
        columnas_layout.addWidget(self.label_info_col2, 1)
        columnas_layout.addWidget(self.label_info_col3, 1)
        
        # Etiqueta para la vista previa inferior
        self.label_preview_clave = QLabel()
        self.label_preview_clave.setWordWrap(True)
        
        info_total_layout.addWidget(columnas_widget)
        info_total_layout.addWidget(self.label_preview_clave)
        
        # Aplicar estilo al contenedor general
        container_style = "background-color: #2b2b2b; padding: 15px; border-radius: 8px;"
        self.label_info_claves_titulo.setStyleSheet(container_style)
        self.label_info_claves_titulo.setLayout(info_total_layout)
        
        claves_layout.addWidget(self.label_info_claves_titulo)
        
        claves_layout.addStretch()
        claves_layout.addWidget(self.estado_claves)
        claves_layout.addSpacing(10)
        self.tab_claves.setLayout(claves_layout)
        self.tabs.addTab(self.tab_claves, "Gestión de claves")
        # --- Pestaña de Información E2E ---
        self.tab_info = QWidget()
        info_layout = QVBoxLayout()
        self.info_label = QLabel()
        self.info_label.setWordWrap(True)
        info_layout.addWidget(self.info_label)
        self.tab_info.setLayout(info_layout)
        self.tabs.addTab(self.tab_info, "Información E2E")
        # --- Pestaña de Archivos ---
        self.tab_archivos = QWidget()
        archivos_layout = QVBoxLayout()
        # Inicializar botones antes de usarlos
        self.boton_cifrar_archivo = QPushButton("Cifrar archivo")
        self.boton_cifrar_archivo.setFixedHeight(24)
        self.boton_cifrar_archivo.setMinimumWidth(140)
        self.boton_cifrar_archivo.clicked.connect(self.cifrar_archivo)
        self.boton_descifrar_archivo = QPushButton("Descifrar archivo")
        self.boton_descifrar_archivo.setFixedHeight(24)
        self.boton_descifrar_archivo.setMinimumWidth(140)
        self.boton_descifrar_archivo.clicked.connect(self.descifrar_archivo)
        # Sección de detalles de archivo cifrado
        grupo_cifrado = QGroupBox("Detalles del archivo cifrado")
        grupo_cifrado_layout = QVBoxLayout()
        self.detalles_cifrado = QLabel("<b>Archivo cifrado:</b>")
        self.detalles_cifrado.setStyleSheet("color: #fff; font-size: 13px;")
        self.detalles_cifrado.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        grupo_cifrado_layout.addWidget(self.detalles_cifrado)
        grupo_cifrado_layout.addWidget(self.boton_cifrar_archivo, alignment=Qt.AlignmentFlag.AlignHCenter)
        grupo_cifrado.setLayout(grupo_cifrado_layout)
        archivos_layout.addWidget(grupo_cifrado)
        archivos_layout.addSpacing(32)
        # Sección de detalles de archivo descifrado
        grupo_descifrado = QGroupBox("Detalles del archivo descifrado")
        grupo_descifrado_layout = QVBoxLayout()
        self.detalles_descifrado = QLabel("<b>Archivo descifrado:</b>")
        self.detalles_descifrado.setStyleSheet("color: #fff; font-size: 13px;")
        self.detalles_descifrado.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        grupo_descifrado_layout.addWidget(self.detalles_descifrado)
        grupo_descifrado_layout.addWidget(self.boton_descifrar_archivo, alignment=Qt.AlignmentFlag.AlignHCenter)
        grupo_descifrado.setLayout(grupo_descifrado_layout)
        archivos_layout.addWidget(grupo_descifrado)
        archivos_layout.addStretch()
        self.tab_archivos.setLayout(archivos_layout)
        self.tabs.addTab(self.tab_archivos, "Archivos")
        main_layout.addWidget(self.tabs)
        self.setLayout(main_layout)
        self.update_textos()

    def cifrar_mensaje(self):
        textos = self.textos[self.idioma]
        mensaje = self.entrada_mensaje.text().strip()
        if not mensaje:
            QMessageBox.warning(self, textos.get('advertencia', 'Advertencia'), textos.get('ingrese_mensaje', "Por favor ingrese un mensaje."))
            return
        try:
            mensaje_cifrado = self.cifrador.cifrar_mensaje(mensaje)
            mensaje_descifrado = self.cifrador.descifrar_mensaje(mensaje_cifrado)
            hora = QTime.currentTime().toString("[hh:mm:ss]")
            self.historial.append(f"{hora} {textos.get('msg_original', 'Mensaje original')}: {mensaje}")
            self.historial.append(f"{hora} {textos.get('msg_cifrado', 'Cifrado')}: {mensaje_cifrado}")
            self.historial.append(f"{hora} {textos.get('msg_descifrado', 'Mensaje descifrado')}: {mensaje_descifrado}")
            self.texto_historial.setPlainText("\n".join(self.historial))
            self.entrada_mensaje.clear()
            self.mensajes_cont += 1
            self.actualizar_info_claves()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
        self.historial.append(f"Tú: {mensaje}\nCifrado: {mensaje_cifrado}")
        self.texto_historial.setPlainText("\n".join(self.historial))
        self.entrada_mensaje.clear()

    def copiar_cifrado(self):
        texto = self.texto_historial.toPlainText()
        QApplication.clipboard().setText(texto)
        QMessageBox.information(self, "Copiado", "Texto cifrado copiado al portapapeles.")

    def pegar_en_recibido(self):
        texto = QApplication.clipboard().text()
        self.entrada_mensaje.setText(texto)

    def copiar_descifrado(self):
        if self.historial:
            ultimo = self.historial[-1]
            QApplication.clipboard().setText(ultimo)
            QMessageBox.information(self, "Copiado", "Texto descifrado copiado al portapapeles.")

    def cifrar_archivo(self):
        import os, stat, time
        ruta_entrada, _ = QFileDialog.getOpenFileName(self, "Selecciona archivo a cifrar", "", "Todos los archivos (*)")
        if ruta_entrada:
            ruta_salida, _ = QFileDialog.getSaveFileName(self, "Guardar archivo descifrado", "archivo_descifrado.bin", "Todos los archivos (*)")
            if ruta_salida:
                try:
                    self.cifrador.cifrar_archivo(ruta_entrada, ruta_salida)
                    info = os.stat(ruta_salida)
                    self.detalles_cifrado.setText(self.generar_detalles_archivo(ruta_salida, info, "cifrado"))
                    self.archivos_cont += 1
                    self.actualizar_info_claves()
                except Exception as e:
                    QMessageBox.critical(self, "Error", str(e))

    def descifrar_archivo(self):
        import os, stat, time
        ruta_entrada, _ = QFileDialog.getOpenFileName(self, "Selecciona archivo a descifrar", "", "Todos los archivos (*)")
        if ruta_entrada:
            ruta_salida, _ = QFileDialog.getSaveFileName(self, "Guardar archivo descifrado", "archivo_descifrado.bin", "Todos los archivos (*)")
            if ruta_salida:
                try:
                    self.cifrador.descifrar_archivo(ruta_entrada, ruta_salida)
                    info = os.stat(ruta_salida)
                    self.detalles_descifrado.setText(self.generar_detalles_archivo(ruta_salida, info, "descifrado"))
                    self.archivos_cont += 1
                    self.actualizar_info_claves()
                except Exception as e:
                    QMessageBox.critical(self, "Error", str(e))

if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    ventana = InterfazCifradorExtremo()
    ventana.show()
    sys.exit(app.exec())
