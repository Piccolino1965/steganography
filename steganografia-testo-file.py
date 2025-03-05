# ------------------------------------------------------------------------
# Steganografia in Immagini - aiutocomputerhelp 2025
# Giovanni Popolizio - anon@m00n
# Con criptazione aes-cbc 256
# Fai in modo che la chiave sia lunga almeno 10 caratteri e dimentica.....
# ------------------------------------------------------------------------


from PIL import Image
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import os

def encrypt_data(data, key):
    key_bytes = hashlib.sha256(key.encode()).digest()
    cipher = AES.new(key_bytes, AES.MODE_CBC)
    encrypted = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + encrypted

def decrypt_data(encrypted_data, key):
    key_bytes = hashlib.sha256(key.encode()).digest()
    iv = encrypted_data[:AES.block_size]
    ciphertext = encrypted_data[AES.block_size:]
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    try:
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    except ValueError:
        return None
    return decrypted

def encode_image(image_path, full_message, output_path):
    image = Image.open(image_path).convert("RGB")
    pixels = image.load()
    
    message_bits = ''.join(format(byte, '08b') for byte in full_message)
    if len(message_bits) > image.size[0] * image.size[1] * 3:
        messagebox.showerror("Errore", "I dati da nascondere sono troppo grandi per l'immagine selezionata.")
        return

    data_index = 0
    width, height = image.size
    for y in range(height):
        for x in range(width):
            pixel = list(pixels[x, y])
            for color in range(3):
                if data_index < len(message_bits):
                    pixel[color] = (pixel[color] & ~1) | int(message_bits[data_index])
                    data_index += 1
            pixels[x, y] = tuple(pixel)
            if data_index >= len(message_bits):
                break
        if data_index >= len(message_bits):
            break

    image.save(output_path)
    messagebox.showinfo("Successo", f"Dati cifrati e nascosti in {output_path}")

def decode_image(image_path, key):
    image = Image.open(image_path).convert("RGB")
    pixels = image.load()
    width, height = image.size

    bits = []
    total_required_bits = None
    payload_length = None
    mode = None

    # Itera sui pixel e accumula i bit fino a raggiungere il numero necessario
    for y in range(height):
        for x in range(width):
            pixel = pixels[x, y]
            for color in range(3):
                bits.append(str(pixel[color] & 1))
                # Se abbiamo almeno i primi 40 bit, possiamo leggere l'header
                if total_required_bits is None and len(bits) >= 40:
                    header_bits = "".join(bits[:40])
                    header_bytes = bytearray(int(header_bits[i:i+8], 2) for i in range(0, 40, 8))
                    mode = header_bytes[0]
                    payload_length = int.from_bytes(header_bytes[1:5], byteorder='big')
                    total_required_bits = (payload_length + 5) * 8
                # Se abbiamo già calcolato il totale e raggiunto la quantità necessaria, interrompiamo
                # altrimenti con un file di grosse dimensioni.... bit per bit.... addioooo!!!
                if total_required_bits is not None and len(bits) >= total_required_bits:
                    break
            if total_required_bits is not None and len(bits) >= total_required_bits:
                break
        if total_required_bits is not None and len(bits) >= total_required_bits:
            break

    if total_required_bits is None:
        messagebox.showerror("Errore", "Impossibile leggere l'header dai dati nascosti.")
        return None, None

    useful_bits = "".join(bits[:total_required_bits])
    full_data = bytearray(int(useful_bits[i:i+8], 2) for i in range(0, len(useful_bits), 8))
    encrypted_payload = full_data[5:5+payload_length]
    decrypted = decrypt_data(encrypted_payload, key)
    if decrypted is None:
        return None, None
    return mode, decrypted

def choose_image():
    file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png; *.jpg; *.jpeg; *.bmp ")])
    if file_path:
        image_path_entry.delete(0, tk.END)
        image_path_entry.insert(0, file_path)

def choose_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        data_path_entry.delete(0, tk.END)
        data_path_entry.insert(0, file_path)

def encode_message():
    image_path = image_path_entry.get()
    key = key_entry.get()
    if not image_path or not key:
        messagebox.showerror("Errore", "Seleziona un'immagine e inserisci la chiave di cifratura.")
        return

    data_type = data_type_var.get()
    if data_type == "text":
        text = message_entry.get()
        if not text:
            messagebox.showerror("Errore", "Inserisci un testo da nascondere.")
            return
        payload = text.encode('utf-8')
        mode = 0
    else:
        file_path = data_path_entry.get()
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
        payload = len(filename_bytes).to_bytes(1, byteorder='big') + filename_bytes + file_bytes
        mode = 1

    encrypted_payload = encrypt_data(payload, key)
    header = mode.to_bytes(1, byteorder='big') + len(encrypted_payload).to_bytes(4, byteorder='big')
    full_message = header + encrypted_payload

    base, ext = os.path.splitext(image_path)
    if ext.lower() not in ['.png', '.bmp']:
        output_path = base + "_encoded.png"
    else:
        output_path = base + "_encoded" + ext

    encode_image(image_path, full_message, output_path)

def decode_message():
    image_path = image_path_entry.get()
    key = key_entry.get()
    if not image_path or not key:
        messagebox.showerror("Errore", "Seleziona un'immagine e inserisci la chiave.")
        return

    mode, decrypted = decode_image(image_path, key)
    if decrypted is None:
        messagebox.showerror("Errore", "Decifratura fallita. La chiave potrebbe essere errata o i dati alterati.")
        return

    if mode == 0:
        decode_window = tk.Toplevel(root)
        decode_window.title("Messaggio Nascosto")
        text_area = tk.Text(decode_window, wrap="word", width=60, height=25)
        try:
            decoded_text = decrypted.decode('utf-8')
        except UnicodeDecodeError:
            decoded_text = "<Errore nella decodifica del testo>"
        text_area.insert(tk.END, decoded_text)
        text_area.pack(padx=10, pady=10, expand=True, fill="both")
    elif mode == 1:
        filename_length = decrypted[0]
        filename = decrypted[1:1+filename_length].decode('utf-8')
        file_data = decrypted[1+filename_length:]
        output_file = os.path.join(os.path.dirname(image_path), filename)
        try:
            with open(output_file, "wb") as f:
                f.write(file_data)
            messagebox.showinfo("Andato a buon fine", f"File estratto e salvato in {output_file}")
        except Exception as e:
            messagebox.showerror("Errore", f"Impossibile salvare il file: {e}")
    else:
        messagebox.showerror("Errore", "Modalità di dato sconosciuta.")

root = tk.Tk()
root.title("Cifratura Payload AES-CBC 256 ")
root.geometry("800x500")  # Imposta dimensioni
root.configure(bg="#73B2FF")  # Colore sfondo

# Creiamo un frame principale con padding per evitare che i widget tocchino i bordi della finestra
main_frame = tk.Frame(root, bg="#73B2FF")
main_frame.pack(padx=20, pady=20, fill="both", expand=True)

tk.Label(main_frame, text="Seleziona un'immagine:", bg="#73B2FF").pack(pady=5)
image_path_entry = tk.Entry(main_frame, width=50)
image_path_entry.pack(pady=5, padx=10)
tk.Button(main_frame, text="Scegli Immagine", command=choose_image).pack(pady=5)

tk.Label(main_frame, text="Chiave di cifratura:", bg="#73B2FF").pack(pady=5)
key_entry = tk.Entry(main_frame, width=50)
key_entry.pack(pady=5, padx=10)

data_type_var = tk.StringVar(value="text")
frame_radio = tk.Frame(main_frame, bg="#73B2FF")
frame_radio.pack(pady=5)
tk.Radiobutton(frame_radio, text="Testo", variable=data_type_var, value="text", bg="#73B2FF").pack(side="left", padx=10)
tk.Radiobutton(frame_radio, text="File", variable=data_type_var, value="file", bg="#73B2FF").pack(side="left", padx=10)

tk.Label(main_frame, text="Inserisci il testo da nascondere:", bg="#73B2FF").pack(pady=5)
message_entry = tk.Entry(main_frame, width=150)
message_entry.pack(pady=5, padx=10)

tk.Label(main_frame, text="Seleziona il file da nascondere:", bg="#73B2FF").pack(pady=5)
data_path_entry = tk.Entry(main_frame, width=50)
data_path_entry.pack(pady=5, padx=10)
tk.Button(main_frame, text="Scegli File", command=choose_file).pack(pady=5)

tk.Button(main_frame, text="Codifica Dati", command=encode_message).pack(pady=5)
tk.Button(main_frame, text="Decodifica Dati", command=decode_message).pack(pady=5)

root.mainloop()
