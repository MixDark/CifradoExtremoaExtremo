import sys
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QLabel, 
                            QLineEdit, QPushButton, QTextEdit, QVBoxLayout, 
                            QHBoxLayout, QMessageBox, QTabWidget)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QIcon
from CifradoE2E import CifradorExtremoAExtremo
from cryptography.hazmat.primitives import serialization
import datetime

class InterfazCifradorExtremo(QMainWindow):
    def __init__(self):
        super().__init__()
        # Inicializamos dos cifradores para simular dos dispositivos diferentes
        self.cifrador_emisor = CifradorExtremoAExtremo()
        self.cifrador_receptor = CifradorExtremoAExtremo()
        self.mensajes_chat = []
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Simulador de cifrado extremo a extremo')
        self.setFixedSize(800, 600)
        self.setWindowIcon(QIcon('icono.png'))

        # Widget central
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Crear pestañas
        tabs = QTabWidget()
        tabs.addTab(self.crear_tab_chat(), "Chat seguro")
        tabs.addTab(self.crear_tab_claves(), "Gestión de claves")
        tabs.addTab(self.crear_tab_info(), "Información E2E")
        
        layout.addWidget(tabs)

        self.setStyleSheet("""
                QMainWindow {
                    background-color: #f5f5f5;
                }
                QTabWidget::pane {
                    border: 1px solid #cccccc;
                    background: white;
                    border-radius: 4px;
                }
                QTabBar::tab {
                    background: #e0e0e0;
                    color: black;       
                    padding: 8px 20px;
                    border: 1px solid #cccccc;
                    border-bottom: none;
                    border-top-left-radius: 4px;
                    border-top-right-radius: 4px;
                }
                QTabBar::tab:selected {
                    background: white;
                    color: black;       
                    border-bottom: none;
                }
                QLabel {
                    font-size: 14px;
                    color: #333333;
                }
                QLineEdit, QTextEdit {
                    background-color: white;
                    color: black;
                    border: 1px solid #cccccc;
                    border-radius: 4px;
                    padding: 8px;
                    font-size: 14px;
                }
                QPushButton {
                    background-color: #007bff;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    padding: 8px 15px;
                    font-size: 14px;                    
                }
                QPushButton:hover {
                    background-color: #0056b3;
                }
                #chat_area {
                    background-color: #f8f9fa;
                    border: 1px solid #dee2e6;
                    border-radius: 4px;
                }
                QMessageBox {
                    background-color: white;
                }
                QMessageBox QLabel {
                    color: black;
                }
                QMessageBox QPushButton {
                    background-color: #007bff;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    padding: 6px 12px;
                    min-width: 60px;
                }
                QMessageBox QPushButton:hover {
                    background-color: #0056b3;
                }
            """)

    def crear_tab_chat(self):
        tab = QWidget()
        layout = QVBoxLayout()

        # Área de chat
        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)
        self.chat_area.setObjectName("chat_area")
        layout.addWidget(self.chat_area)

        # Área de entrada y envío
        input_layout = QHBoxLayout()
        self.mensaje_input = QLineEdit()
        self.mensaje_input.setPlaceholderText("Escribe tu mensaje...")
        self.boton_enviar = QPushButton("Enviar")
        self.boton_enviar.clicked.connect(self.enviar_mensaje)
        
        input_layout.addWidget(self.mensaje_input)
        input_layout.addWidget(self.boton_enviar)
        layout.addLayout(input_layout)

        # Panel de información de cifrado
        info_layout = QHBoxLayout()
        self.estado_cifrado = QLabel("Estado: Cifrado activo")
        self.estado_cifrado.setStyleSheet("color: green;")
        info_layout.addWidget(self.estado_cifrado)
        layout.addLayout(info_layout)

        tab.setLayout(layout)
        return tab
    
    def crear_tab_claves(self):
        tab = QWidget()
        layout = QVBoxLayout()

        # Información de claves del emisor
        layout.addWidget(QLabel("Clave pública del emisor:"))
        self.clave_publica_emisor = QTextEdit()
        self.clave_publica_emisor.setReadOnly(True)
        self.clave_publica_emisor.setMaximumHeight(100)
        self.actualizar_info_clave_emisor()
        layout.addWidget(self.clave_publica_emisor)

        # Información de claves del receptor
        layout.addWidget(QLabel("Clave pública del receptor:"))
        self.clave_publica_receptor = QTextEdit()
        self.clave_publica_receptor.setReadOnly(True)
        self.clave_publica_receptor.setMaximumHeight(100)
        self.actualizar_info_clave_receptor()
        layout.addWidget(self.clave_publica_receptor)

        # Botones de gestión de claves
        botones_layout = QHBoxLayout()
        
        self.boton_rotar_emisor = QPushButton("Rotar claves emisor")
        self.boton_rotar_emisor.clicked.connect(self.rotar_claves_emisor)
        botones_layout.addWidget(self.boton_rotar_emisor)
        
        self.boton_rotar_receptor = QPushButton("Rotar claves receptor")
        self.boton_rotar_receptor.clicked.connect(self.rotar_claves_receptor)
        botones_layout.addWidget(self.boton_rotar_receptor)

        layout.addLayout(botones_layout)

        # Información adicional
        info_label = QLabel("""
        <p><b>Información sobre la rotación de claves:</b></p>
        <p>La rotación de claves es una práctica de seguridad que consiste en 
        cambiar periódicamente las claves criptográficas para minimizar el 
        impacto de posibles compromisos de seguridad.</p>
        <p>Al rotar las claves:</p>
        <ul>
            <li>Se generan nuevos pares de claves</li>
            <li>Se invalidan las claves anteriores</li>
            <li>Se aumenta la seguridad del sistema</li>
        </ul>
        """)
        info_label.setWordWrap(True)
        layout.addWidget(info_label)

        tab.setLayout(layout)
        return tab

    def actualizar_info_clave_emisor(self):
        """Actualiza la información mostrada de la clave pública del emisor"""
        clave_publica = self.cifrador_emisor.obtener_clave_publica()
        clave_pem = clave_publica.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.clave_publica_emisor.setText(clave_pem.decode('utf-8'))

    def actualizar_info_clave_receptor(self):
        """Actualiza la información mostrada de la clave pública del receptor"""
        clave_publica = self.cifrador_receptor.obtener_clave_publica()
        clave_pem = clave_publica.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.clave_publica_receptor.setText(clave_pem.decode('utf-8'))

    def rotar_claves_emisor(self):
        """Rota las claves del emisor"""
        try:
            self.cifrador_emisor.generar_nuevas_claves()
            self.actualizar_info_clave_emisor()
            QMessageBox.information(self, "Éxito", 
                                  "Las claves del emisor han sido rotadas exitosamente")
        except Exception as e:
            QMessageBox.critical(self, "Error", 
                               f"Error al rotar las claves del emisor: {str(e)}")

    def rotar_claves_receptor(self):
        """Rota las claves del receptor"""
        try:
            self.cifrador_receptor.generar_nuevas_claves()
            self.actualizar_info_clave_receptor()
            QMessageBox.information(self, "Éxito", 
                                  "Las claves del receptor han sido rotadas exitosamente")
        except Exception as e:
            QMessageBox.critical(self, "Error", 
                               f"Error al rotar las claves del receptor: {str(e)}")

    def crear_tab_info(self):
        tab = QWidget()
        layout = QVBoxLayout()

        info_text = """
        <h2>Cifrado extremo a extremo (E2E)</h2>
        <p>El cifrado extremo a extremo es un sistema de comunicación donde solo 
        los usuarios que se comunican pueden leer los mensajes.</p>
        
        <h3>Características principales:</h3>
        <ul>
            <li>Los mensajes se cifran en el dispositivo del emisor</li>
            <li>Solo pueden ser descifrados en el dispositivo del receptor</li>
            <li>Ni siquiera el servidor puede leer los mensajes</li>
            <li>Utiliza criptografía de clave pública y privada</li>
        </ul>

        <h3>Proceso de cifrado:</h3>
        <ol>
            <li>Generación de par de claves para cada usuario</li>
            <li>Intercambio de claves públicas</li>
            <li>Cifrado del mensaje con la clave pública del receptor</li>
            <li>Descifrado con la clave privada del receptor</li>
        </ol>
        """

        info_label = QLabel(info_text)
        info_label.setWordWrap(True)
        info_label.setOpenExternalLinks(True)
        layout.addWidget(info_label)

        tab.setLayout(layout)
        return tab

    def enviar_mensaje(self):
        mensaje = self.mensaje_input.text()
        if not mensaje:
            return

        try:
            # Cifrar usando la clave pública del receptor
            mensaje_cifrado = self.cifrador_emisor.cifrar_mensaje(
                mensaje, 
                self.cifrador_receptor.obtener_clave_publica()
            )
            
            # Simular transmisión
            self.simular_transmision(mensaje, mensaje_cifrado)
            
            # Limpiar campo de entrada
            self.mensaje_input.clear()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error en el cifrado: {str(e)}")

    def simular_transmision(self, mensaje_original, mensaje_cifrado):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        
        # Mostrar el proceso
        self.chat_area.append(f"\n[{timestamp}] Mensaje original: {mensaje_original}")
        self.chat_area.append(f"[{timestamp}] Cifrado: {mensaje_cifrado[:50]}...")
        
        # Simular delay de red
        QTimer.singleShot(1000, lambda: self.recibir_mensaje(mensaje_cifrado, timestamp))

    def recibir_mensaje(self, mensaje_cifrado, timestamp):
        try:
            # Descifrar usando la clave privada del receptor
            mensaje_descifrado = self.cifrador_receptor.descifrar_mensaje(mensaje_cifrado)
            self.chat_area.append(f"[{timestamp}] Mensaje descifrado: {mensaje_descifrado}\n")
            
        except Exception as e:
            self.chat_area.append(f"[{timestamp}] Error al descifrar el mensaje: {str(e)}\n")

def main():
    app = QApplication(sys.argv)
    ventana = InterfazCifradorExtremo()
    ventana.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()
