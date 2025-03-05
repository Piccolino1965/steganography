#!/usr/bin/env python3
# ------------------------------------------------------------------------
# Steganografia in Immagini - aiutocomputerhelp 2025
# Giovanni Popolizio - anon@m00n
# Con criptazione AES-GCM 256 (migliorata rispetto ad AES-CBC)
# Utilizza PyCryptodome
# ------------------------------------------------------------------------

import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageTk
import logging
import numpy as np
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Random import get_random_bytes

# logging per registrare eventi ed errori
logging.basicConfig(
    filename="steganografia.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

def encrypt_data(data, key):
    """
    Cifra i dati usando AES-GCM con una chiave derivata tramite PBKDF2.

    Parameter:
      data (bytes): I dati da cifrare.
      key (str): La chiave di cifratura (minimo 10 caratteri).

    Return:
      bytes: Il payload cifrato, formato da salt, nonce, tag e ciphertext concatenati.

    Raise:
      ValueError: Se la chiave non soddisfa la lunghezza minima.
    """
    if len(key) < 10:
        raise ValueError("La chiave deve essere almeno di 10 caratteri.")
    # Genera un salt casuale di 16 byte
    salt = get_random_bytes(16)
    # Deriva una chiave di 32 byte (256 bit) usando PBKDF2
    key_bytes = PBKDF2(key, salt, dkLen=32, count=100000)
    # Crea il cifrario AES in modalità GCM
    cipher = AES.new(key_bytes, AES.MODE_GCM)
    # Cifra i dati e genera il tag di autenticazione
    ciphertext, tag = cipher.encrypt_and_digest(data)
    logging.info("Dati cifrati con successo.")
    # Ritorna la concatenazione: salt || nonce || tag || ciphertext
    return salt + cipher.nonce + tag + ciphertext

def decrypt_data(encrypted_data, key):
    """
    Decifra i dati cifrati con AES-GCM utilizzando la stessa chiave e derivazione.

    Parameters:
      encrypted_data (bytes): I dati cifrati, contenenti salt, nonce, tag e ciphertext.
      key (str): La chiave di cifratura utilizzata originariamente.

    Return:
      bytes: I dati decifrati se la verifica ha successo, altrimenti None.
    """
    try:
        # Estrai i primi 16 byte come salt
        salt = encrypted_data[:16]
        # Estrai i 12 byte successivi come nonce
        nonce = encrypted_data[16:16 + 12]
        # Estrai i 16 byte successivi come tag
        tag = encrypted_data[16 + 12:16 + 12 + 16]
        # Il resto è il ciphertext
        ciphertext = encrypted_data[16 + 12 + 16:]
        # Deriva la chiave usando lo stesso salt e PBKDF2
        key_bytes = PBKDF2(key, salt, dkLen=32, count=100000)
        # Crea il cifrario AES in modalità GCM usando il nonce
        cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
        # Decifra e verifica l'autenticità dei dati
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
        logging.info("Decifratura e verifica dei dati avvenute con successo.")
        return decrypted
    except Exception as e:
        logging.error(f"Decifratura fallita: {e}")
        return None

def encode_image(image_path, full_message, output_path):
    """
    Incorpora un messaggio binario all'interno di un'immagine utilizzando la tecnica LSB.

    Parameters:
      image_path (str): Il percorso dell'immagine originale.
      full_message (bytes): Il messaggio completo da nascondere (includendo header e payload cifrato).
      output_path (str): Il percorso dove salvare l'immagine modificata.

    Return:
      bool: True se l'operazione ha successo, False in caso di errore.
    """
    try:
        # Apri l'immagine e convertila in RGB
        image = Image.open(image_path).convert("RGB")
        image_np = np.array(image)
        height, width, channels = image_np.shape
        # Calcola la capacità in bit dell'immagine (numero totale di canali)
        capacity = width * height * channels

        # Converte il messaggio completo in un array di bit
        message_bytes = np.frombuffer(full_message, dtype=np.uint8)
        message_bits = np.unpackbits(message_bytes)
        num_bits = message_bits.size

        # Verifica che l'immagine sia grande abbastanza per il messaggio
        if num_bits > capacity:
            messagebox.showerror("Errore", "I dati da nascondere sono troppo grandi per l'immagine selezionata.")
            logging.error("Capacità dell'immagine insufficiente per incorporare i dati.")
            return False

        # Vai di rullo compressore: appiattisci l'array dell'immagine in un vettore 1D
        flat_pixels = image_np.flatten()
        # Pulisci il bit meno significativo (LSB) e incorpora i bit del messaggio
        flat_pixels[:num_bits] = (flat_pixels[:num_bits] & 254) | message_bits
        # Ripristina la forma originale dell'immagine
        image_np = flat_pixels.reshape((height, width, channels))
        encoded_image = Image.fromarray(image_np.astype(np.uint8))
        encoded_image.save(output_path)
        logging.info(f"Dati incorporati con successo in {output_path}")
        return True
    except Exception as e:
        logging.error(f"Errore durante inserimento messaggio: {e}")
        messagebox.showerror("Errore", f"Errore durante l'incorporamento: {e}")
        return False

def decode_image(image_path, key):
    """
    Estrae e decifra il messaggio nascosto all'interno di un'immagine.

    Parameter:
      image_path (str): Il percorso dell'immagine contenente i dati nascosti.
      key (str): La chiave di cifratura per la decifratura.

    Return:
      tuple: (mode, decrypted) dove 'mode' indica il tipo di dato nascosto (es. testo o file)
             e 'decrypted' contiene i dati decifrati; ritorna (None, None) in caso di errore.
    """
    try:
        # Apri l'immagine e convertila in RGB
        image = Image.open(image_path).convert("RGB")
        image_np = np.array(image)
        height, width, channels = image_np.shape
        capacity = width * height * channels

        # Pialla l'immagine ed estrai i bit LSB
        flat_pixels = image_np.flatten()
        bits = flat_pixels & 1

        # Verifica che l'immagine sia abbastanza grande per contenere l'header (40 bit)
        if capacity < 40:
            messagebox.showerror("Errore", "Immagine troppo piccola per contenere dati validi.")
            logging.error("Capacità dell'immagine insufficiente per estrarre l'header.")
            return None, None

        # Estrai l'header (40 bit: 1 byte per la modalità e 4 byte per la lunghezza del payload)
        header_bits = bits[:40]
        header_bytes = np.packbits(header_bits).tobytes()
        mode = header_bytes[0]
        payload_length = int.from_bytes(header_bytes[1:5], byteorder='big')
        total_required_bits = (payload_length + 5) * 8

        # Verifica che il numero totale di bit richiesti non superi la capacità dell'immagine
        if total_required_bits > capacity:
            messagebox.showerror("Errore", "Header o payload non validi: dimensioni incoerenti.")
            logging.error("L'header indica un payload maggiore della capacità dell'immagine.")
            return None, None

        # Estrai i bit utili corrispondenti al messaggio nascosto
        useful_bits = bits[:total_required_bits]
        full_data = np.packbits(useful_bits).tobytes()
        # Seleziona il payload cifrato (escludendo i primi 5 byte di header)
        encrypted_payload = full_data[5:5 + payload_length]
        decrypted = decrypt_data(encrypted_payload, key)
        if decrypted is None:
            logging.error("Decifratura ha restituito None.")
            return None, None
        logging.info("Immagine decodificata con successo.")
        return mode, decrypted
    except Exception as e:
        logging.error(f"Errore durante la decodifica: {e}")
        messagebox.showerror("Errore", f"Errore durante la decodifica: {e}")
        return None, None

class SteganographyApp:
    """
    Classe principale per l'applicazione GUI di steganografia.

    Gestisce l'interfaccia grafica, l'interazione con l'utente e le operazioni di codifica
    e decodifica dei dati nascosti nelle immagini.
    """
    def __init__(self, root):
        """
        Inizializza l'applicazione.

        Parameter:
          root (tk.Tk): La finestra principale dell'applicazione.
        """
        self.root = root
        self.root.title("Cifratura Payload AES-GCM 256")
        self.root.geometry("850x600")
        self.root.configure(bg="#73B2FF")
        self.build_gui()

    def build_gui(self):
        """
        Come Bob aggiusta tutto...
        """
        self.main_frame = tk.Frame(self.root, bg="#73B2FF")
        self.main_frame.pack(padx=20, pady=20, fill="both", expand=True)

        # Selezione dell'immagine
        tk.Label(self.main_frame, text="Seleziona un'immagine:", bg="#73B2FF").pack(pady=5)
        self.image_path_entry = tk.Entry(self.main_frame, width=50)
        self.image_path_entry.pack(pady=5, padx=10)
        tk.Button(self.main_frame, text="Scegli Immagine", command=self.choose_image).pack(pady=5)
        tk.Button(self.main_frame, text="Preview Immagine", command=self.preview_image).pack(pady=5)

        # Inserimento della chiave
        tk.Label(self.main_frame, text="Chiave di cifratura:", bg="#73B2FF").pack(pady=5)
        self.key_entry = tk.Entry(self.main_frame, width=50, show="*")
        self.key_entry.pack(pady=5, padx=10)

        # Pulsanti per scegliere il tipo di dato da nascondere (Testo o File)
        self.data_type_var = tk.StringVar(value="text")
        frame_radio = tk.Frame(self.main_frame, bg="#73B2FF")
        frame_radio.pack(pady=5)
        tk.Radiobutton(frame_radio, text="Testo", variable=self.data_type_var, value="text",
                       bg="#73B2FF", command=self.toggle_data_input).pack(side="left", padx=10)
        tk.Radiobutton(frame_radio, text="File", variable=self.data_type_var, value="file",
                       bg="#73B2FF", command=self.toggle_data_input).pack(side="left", padx=10)

        # Campo di input per il testo da nascondere
        self.text_label = tk.Label(self.main_frame, text="Inserisci il testo da nascondere:", bg="#73B2FF")
        self.text_label.pack(pady=5)
        self.message_entry = tk.Entry(self.main_frame, width=150)
        self.message_entry.pack(pady=5, padx=10)

        # Campo di input per il file da nascondere
        self.file_label = tk.Label(self.main_frame, text="Seleziona il file da nascondere:", bg="#73B2FF")
        self.file_label.pack(pady=5)
        self.data_path_entry = tk.Entry(self.main_frame, width=50)
        self.data_path_entry.pack(pady=5, padx=10)
        tk.Button(self.main_frame, text="Scegli File", command=self.choose_file).pack(pady=5)

        # Pulsanti per avviare le operazioni di codifica e decodifica
        tk.Button(self.main_frame, text="Codifica Dati", command=self.encode_message).pack(pady=5)
        tk.Button(self.main_frame, text="Decodifica Dati", command=self.decode_message).pack(pady=5)

        # Placeholder per la barra di progresso
        self.progress = None

        self.toggle_data_input()

    def toggle_data_input(self):
        """
        Abilita o disabilita i campi di input in base al tipo di dato selezionato (Testo o File).
        """
        mode = self.data_type_var.get()
        if mode == "text":
            self.text_label.config(state="normal")
            self.message_entry.config(state="normal")
            self.file_label.config(state="disabled")
            self.data_path_entry.config(state="disabled")
        else:
            self.text_label.config(state="disabled")
            self.message_entry.config(state="disabled")
            self.file_label.config(state="normal")
            self.data_path_entry.config(state="normal")

    def choose_image(self):
        """
        Permette all'utente di selezionare un'immagine da utilizzare per la codifica/decodifica.
        """
        file_path = filedialog.askopenfilename(
            filetypes=[("Image Files", ("*.png", "*.jpg", "*.jpeg", "*.bmp"))]
        )

        if file_path:
            self.image_path_entry.delete(0, tk.END)
            self.image_path_entry.insert(0, file_path)

    def preview_image(self):
        """
        Mostra un'anteprima dell'immagine selezionata in una nuova finestra.
        """
        image_path = self.image_path_entry.get()
        if not image_path:
            messagebox.showerror("Errore", "Nessuna immagine selezionata per la preview.")
            return
        try:
            image = Image.open(image_path)
            preview_win = tk.Toplevel(self.root)
            preview_win.title("Preview Immagine")
            preview_win.geometry("600x600")
            # Ridimensiona l'immagine per adattarla alla finestra di anteprima
            img_resized = image.resize((600, 600), Image.ANTIALIAS)
            photo = ImageTk.PhotoImage(img_resized)
            label = tk.Label(preview_win, image=photo)
            label.image = photo  # Mantiene un riferimento all'immagine
            label.pack()
        except Exception as e:
            messagebox.showerror("Errore", f"Impossibile aprire l'immagine: {e}")

    def choose_file(self):
        """
        Permette all'utente di selezionare un file da nascondere nell'immagine.
        """
        file_path = filedialog.askopenfilename()
        if file_path:
            self.data_path_entry.delete(0, tk.END)
            self.data_path_entry.insert(0, file_path)

    def start_progress(self):
        """
        Avvia una barra di progresso indeterminata per indicare che un'operazione è in corso.
        """
        self.progress = ttk.Progressbar(self.main_frame, orient="horizontal", mode="indeterminate")
        self.progress.pack(pady=10)
        self.progress.start()

    def stop_progress(self):
        """
        Ferma e rimuove la barra di progresso.
        """
        if self.progress:
            self.progress.stop()
            self.progress.destroy()
            self.progress = None

    def encode_message(self):
        """
        Gestisce la codifica dei dati nell'immagine. Raccoglie gli input, cifra il payload,
        costruisce l'header e richiama la funzione di incorporamento.
        """
        image_path = self.image_path_entry.get()
        key = self.key_entry.get()
        if not image_path or not key:
            messagebox.showerror("Errore", "Seleziona un'immagine e inserisci la chiave di cifratura.")
            return

        if len(key) < 10:
            messagebox.showerror("Errore", "La chiave deve essere almeno di 10 caratteri.")
            return

        data_type = self.data_type_var.get()
        if data_type == "text":
            text = self.message_entry.get()
            if not text:
                messagebox.showerror("Errore", "Inserisci un testo da nascondere.")
                return
            payload = text.encode('utf-8')
            mode = 0
        else:
            file_path = self.data_path_entry.get()
            if not file_path:
                messagebox.showerror("Errore", "Seleziona un file da nascondere.")
                return
            filename = os.path.basename(file_path)
            try:
                with open(file_path, "rb") as f:
                    file_bytes = f.read()
            except Exception as e:
                messagebox.showerror("Errore", f"Impossibile leggere il file: {e}")
                return
            filename_bytes = filename.encode('utf-8')
            if len(filename_bytes) > 255:
                messagebox.showerror("Errore", "Il nome del file è troppo lungo.")
                return
            # Prepara il payload: lunghezza del nome, nome del file, e contenuto del file
            payload = len(filename_bytes).to_bytes(1, byteorder='big') + filename_bytes + file_bytes
            mode = 1

        try:
            encrypted_payload = encrypt_data(payload, key)
        except Exception as e:
            messagebox.showerror("Errore", f"Errore durante la cifratura: {e}")
            return

        # Costruisce l'header: 1 byte per la modalità + 4 byte per la lunghezza del payload cifrato
        header = mode.to_bytes(1, byteorder='big') + len(encrypted_payload).to_bytes(4, byteorder='big')
        full_message = header + encrypted_payload

        base, ext = os.path.splitext(image_path)
        if ext.lower() not in ['.png', '.bmp']:
            output_path = base + "_encoded.png"
        else:
            output_path = base + "_encoded" + ext

        self.start_progress()
        # Usa after() per eseguire la codifica senza bloccare la GUI
        self.root.after(100, lambda: self._encode_and_notify(image_path, full_message, output_path))

    def _encode_and_notify(self, image_path, full_message, output_path):
        """
        Metodo per eseguire l'incorporamento e notificare l'utente al termine.

        Parameters:
          image_path (str): Percorso dell'immagine originale.
          full_message (bytes): Messaggio completo da incorporare.
          output_path (str): Percorso per salvare l'immagine modificata.
        """
        success = encode_image(image_path, full_message, output_path)
        self.stop_progress()
        if success:
            messagebox.showinfo("Successo", f"Dati cifrati e nascosti in {output_path}")
        else:
            messagebox.showerror("Errore", "Operazione di codifica fallita.")

    def decode_message(self):
        """
        Gestisce la decodifica dei dati nascosti nell'immagine.
        Verifica gli input e avvia il processo di decodifica.
        """
        image_path = self.image_path_entry.get()
        key = self.key_entry.get()
        if not image_path or not key:
            messagebox.showerror("Errore", "Seleziona un'immagine e inserisci la chiave.")
            return

        if len(key) < 10:
            messagebox.showerror("Errore", "La chiave deve essere almeno di 10 caratteri.")
            return

        self.start_progress()
        self.root.after(100, lambda: self._decode_and_notify(image_path, key))

    def _decode_and_notify(self, image_path, key):
        """
        Metodo per eseguire la decodifica e notificare l'utente al termine.

        Paramters:
          image_path (str): Percorso dell'immagine con dati nascosti.
          key (str): Chiave di cifratura per la decodifica.
        """
        mode, decrypted = decode_image(image_path, key)
        self.stop_progress()
        if decrypted is None:
            messagebox.showerror("Errore", "Decifratura fallita. La chiave potrebbe essere errata o i dati alterati.")
            return

        if mode == 0:
            # Visualizza il testo nascosto in una nuova finestra
            decode_window = tk.Toplevel(self.root)
            decode_window.title("Messaggio Nascosto")
            text_area = tk.Text(decode_window, wrap="word", width=60, height=25)
            try:
                decoded_text = decrypted.decode('utf-8')
            except UnicodeDecodeError:
                decoded_text = "<Errore nella decodifica del testo>"
            text_area.insert(tk.END, decoded_text)
            text_area.pack(padx=10, pady=10, expand=True, fill="both")
        elif mode == 1:
            # Estrae e salva il file nascosto
            if len(decrypted) < 1:
                messagebox.showerror("Errore", "Dati decrittati non validi per il file.")
                return
            filename_length = decrypted[0]
            if len(decrypted) < 1 + filename_length:
                messagebox.showerror("Errore", "Dati decrittati incompleti per il file.")
                return
            try:
                filename = decrypted[1:1 + filename_length].decode('utf-8')
            except UnicodeDecodeError:
                messagebox.showerror("Errore", "Errore nella decodifica del nome del file.")
                return
            file_data = decrypted[1 + filename_length:]
            output_file = os.path.join(os.path.dirname(image_path), filename)
            try:
                with open(output_file, "wb") as f:
                    f.write(file_data)
                messagebox.showinfo("Successo", f"File estratto e salvato in {output_file}")
            except Exception as e:
                messagebox.showerror("Errore", f"Impossibile salvare il file: {e}")
        else:
            messagebox.showerror("Errore", "Modalità di dato sconosciuta.")

if __name__ == "__main__":
    # Avvia l'applicazione GUI
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop()
