import os
import config
import dropbox
import tkinter as tk
from tkinter import filedialog

from Crypto import Random
from Crypto.Cipher import AES

dbx = dropbox.Dropbox(config.access_token)
key = b'\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18'

class Application(tk.Frame):
    def __init__(self, master=None):
        tk.Frame.__init__(self, master)
        self.master.title("Cloudbox")
        self.pack()
        self.createWidgets()

    def createWidgets(self):
        self.hi_there = tk.Button(self)
        self.hi_there["text"] = "Print files"
        self.hi_there["command"] = self.say_hi
        self.hi_there.pack(side="top")

        self.txt_box = tk.Label(self, text="This is going to be a rather large label.\nHopefully it takes up\nmore than one line")
        self.txt_box.pack(side="top")

        self.button_frame = tk.Frame(self)
        self.button_frame.pack(side="bottom")

        self.UPLOAD = tk.Button(self.button_frame, text="Upload", fg="blue", command=self.load_file)
        self.UPLOAD.pack(side="left")

        self.DOWNLOAD = tk.Button(self.button_frame, text="Download", fg="blue", command=self.say_hi)
        self.DOWNLOAD.pack(side="left")

        self.QUIT = tk.Button(self.button_frame, text="Quit", fg="red", command=root.destroy)
        self.QUIT.pack(side="right")

    def say_hi(self):
        for entry in dbx.files_list_folder('').entries:
            print(entry.name)

    def load_file(self):
        fname = filedialog.askopenfilename(filetypes=(("Template files", "*.tplate"),
                                           ("HTML files", "*.html;*.htm"),
                                           ("Text files", "*.txt"),
                                           ("All files", "*.*") ))
        if fname:
            # try:
            print(fname)
            #dbx.files_upload('This is a test upload', '/Cloudbox/upload.txt')
            encrypt_file(fname, key)
            print('Done')
            # except:                     # <- naked except is a bad idea
            #     print("Open Source File", "Failed to read file\n'%s'" % fname)

def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

def encrypt(message, key, key_size=256):
    message = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")

def encrypt_file(file_name, key):
    with open(file_name, 'rb') as fo:
        plaintext = fo.read()
    enc = encrypt(plaintext, key)
    with open(file_name + ".enc", 'wb') as fo:
        fo.write(enc)

def decrypt_file(file_name, key):
    with open(file_name, 'rb') as fo:
        ciphertext = fo.read()
    dec = decrypt(ciphertext, key)
    with open(file_name[:-4], 'wb') as fo:
        fo.write(dec)

root = tk.Tk()
app = Application(master=root)
app.mainloop()
