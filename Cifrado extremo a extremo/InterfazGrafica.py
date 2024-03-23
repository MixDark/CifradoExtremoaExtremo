import tkinter as tk
from tkinter import messagebox
from CifradoE2E import CifradorExtremoAExtremo

class InterfazCifradorExtremo:

    def __init__(self, ventana):
        self.ventana = ventana
        self.ventana.title("Cifrado de extremo a extremo")
        self.ventana.resizable(0,0)
        self.ancho = 570
        self.alto = 360
        self.ventana_x = ventana.winfo_screenwidth() // 2 - self.ancho // 2
        self.ventana_y = ventana.winfo_screenheight() // 2 - self.alto // 2
        posicion = str(self.ancho) + "x" + str(self.alto) + "+" + str(self.ventana_x) + "+" + str(self.ventana_y)
        self.ventana.geometry(posicion)

        # Inicializar el cifrador
        self.cifrador = CifradorExtremoAExtremo()

        # Crear widgets
        self.etiqueta_mensaje = tk.Label(ventana, text="Mensaje a cifrar:")
        self.etiqueta_mensaje.grid(row=0, column=0, sticky="w", padx=5, pady=5)

        self.entrada_mensaje = tk.Entry(ventana, width=50)
        self.entrada_mensaje.grid(row=0, column=1, columnspan=2, padx=5, pady=5)

        self.boton_cifrar = tk.Button(ventana, text="Cifrar", command=self.cifrar_mensaje)
        self.boton_cifrar.grid(row=0, column=3, padx=5, pady=5)

        self.etiqueta_cifrado = tk.Label(ventana, text="Mensaje cifrado enviado:")
        self.etiqueta_cifrado.grid(row=1, column=0, sticky="w", padx=5, pady=5)

        self.texto_cifrado = tk.Text(ventana, width=50, height=5)
        self.texto_cifrado.grid(row=1, column=1, columnspan=3, padx=5, pady=5)

        self.etiqueta_cifrado = tk.Label(ventana, text="Mensaje cifrado recibido:")
        self.etiqueta_cifrado.grid(row=2, column=0, sticky="w", padx=5, pady=5)

        self.entrada_cifrado = tk.Text(ventana, width=50, height=5)
        self.entrada_cifrado.grid(row=2, column=1, columnspan=3, padx=5, pady=5)

        self.boton_descifrar = tk.Button(ventana, text="Descifrar", command=self.descifrar_mensaje)
        self.boton_descifrar.grid(row=3, column=1, padx=10, pady=5)

        self.etiqueta_descifrado = tk.Label(ventana, text="Mensaje descifrado:")
        self.etiqueta_descifrado.grid(row=4, column=0, sticky="w", padx=5, pady=5)

        self.texto_descifrado = tk.Text(ventana, width=50, height=5)
        self.texto_descifrado.grid(row=4, column=1, columnspan=3, padx=5, pady=5)

    def cifrar_mensaje(self):

        mensaje = self.entrada_mensaje.get()
        if not mensaje:
            messagebox.showwarning("Advertencia", "Por favor ingrese un mensaje.")
            return

        try:
            mensaje_cifrado = self.cifrador.cifrar_mensaje(mensaje)
            self.texto_cifrado.delete(1.0, tk.END)
            self.texto_cifrado.insert(tk.END, mensaje_cifrado)
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def descifrar_mensaje(self):

        mensaje_cifrado = self.entrada_cifrado.get("1.0", tk.END)
        if not mensaje_cifrado:
            messagebox.showwarning("Advertencia", "Por favor ingrese un mensaje cifrado.")
            return

        try:
            mensaje_descifrado = self.cifrador.descifrar_mensaje(mensaje_cifrado)
            self.texto_descifrado.delete(1.0, tk.END)
            self.texto_descifrado.insert(tk.END, mensaje_descifrado)

        except ValueError as e:
            messagebox.showerror("Error", "El mensaje no se pudo descifrar")

ventana_principal = tk.Tk()
app = InterfazCifradorExtremo(ventana_principal)
ventana_principal.mainloop()