import os.path
from sys import getsizeof
import config
import dropbox
import tkinter as tk
from tkinter import filedialog

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random

dbx = dropbox.Dropbox(config.access_token)

# 'Secret' key used to encrypt all uploaded files
key = b'Sixteen byte key'

# Class for GUI and encryption
class Application(tk.Frame):
    def __init__(self, master=None):
        tk.Frame.__init__(self, master)
        self.master.title("Cloudbox")
        self.pack()
        self.createWidgets()

    def createWidgets(self):

        # Dropdown menu
        self.current_file = ""
        self.current_user = ""
        self.options = ["Alice", "Bob", "Conor"]
        self.files = []
        var = tk.StringVar()
        self.drop = tk.OptionMenu(self, var, *self.options, command=self.user_selected)
        self.drop.config(width=10)
        var.set("Select User")
        self.drop.pack(side="top")

        # Text box
        self.txt_box = tk.Label(self, text="- Generate: generate RSA keys for a user (essentially add them to group)\n- Upload: encrypt file and upload to Dropbox\n- Download: download file from dropbox and decrypt\n- Quit: close program")
        self.txt_box.pack(side="top")

        # Frame to hold buttons
        self.button_frame = tk.Frame(self)
        self.button_frame.pack(side="top")

        # User interaction buttons
        self.GENERATE = tk.Button(self.button_frame, text="Generate keys for user", fg="blue", command=self.generate_keys)
        self.GENERATE.pack(side="left")

        self.UPLOAD = tk.Button(self.button_frame, text="Upload", fg="blue", command=self.upload_file)
        self.UPLOAD.pack(side="left")

        self.DOWNLOAD = tk.Button(self.button_frame, text="Download from DB", fg="blue", command=self.add_drop)
        self.DOWNLOAD.pack(side="left")

        self.QUIT = tk.Button(self.button_frame, text="Quit", fg="red", command=root.destroy)
        self.QUIT.pack(side="right")

    # Dynamically creates a dropdown menu when the download button is clicked
    def add_drop(self):
        if self.current_user == "":
            print("Please select user first")
        elif not os.path.isfile(self.current_user + '_Public.pem'):
            print("Create public key first!")
        else:
            for entry in dbx.files_list_folder('/Cloudbox').entries:
                print(entry.name)
                self.files.append(entry.name)
            self.DL_FILE = tk.Button(self, text="Download selected file", fg="red", command=self.download_file)
            self.DL_FILE.pack(expand=1, side="right", fill=tk.X)


            var = tk.StringVar()
            self.drop2 = tk.OptionMenu(self, var, *self.files, command=self.file_selected)
            self.drop2.config(width=30)
            var.set("Select file to download")
            self.drop2.pack(side="left")

    # Generates RSA public and private key for particular user
    def generate_keys(self):
        if self.current_user == "":
            print("Please select user first")
        else:
            print("Generating keys for {}...".format(self.current_user))
            private = RSA.generate(1024)
            public = private.publickey()

            # User encrypts a copy of secret key which is later decrypted
            # using their private key
            encrypted_AES = public.encrypt(key, 32)

            fname_public = self.current_user + '_Public.pem'
            with open(fname_public, 'wb') as f_out:
                f_out.write(encrypted_AES[0])
                print("> Public key generated")

            fname_private = self.current_user + '_Private.pem'
            with open(fname_private, 'wb') as f_out:
                f_out.write(private.exportKey())
                print("> Private key generated")

    def user_selected(self, user):
        self.current_user = user

    def file_selected(self, file):
        self.current_file = file

    # Encrypts a file and uploads it to dropbox
    def upload_file(self):
        if self.current_user == "":
            print("No user selected")
        elif not os.path.isfile(self.current_user + '_Public.pem'):
            print("Create public key first!")
        else:
            with open(self.current_user + '_Private.pem', mode='rb') as f:
                private_data = f.read()
                private_key = RSA.importKey(private_data)

            with open(self.current_user + '_Public.pem', mode='rb') as f:
                public_data = f.read()
                decrypted_AES = private_key.decrypt(public_data)

            fname = filedialog.askopenfilename()
            if fname:
                try:
                    print("> Encrypting file...")
                    encrypt_file(fname, decrypted_AES)
                    # encrypt_file(fname, key)

                    enc_fname = fname + '.enc'
                    with open(enc_fname, mode='rb') as f:
                        f_data = f.read()
                    base_file = os.path.basename(os.path.normpath(enc_fname))
                    print('> Encryption Complete!')
                    print('> Uploading encrypted file...')
                    dbx.files_upload(f_data, '/Cloudbox/' + base_file)
                    print('> Upload complete!')
                    os.remove(enc_fname)
                except:
                    print("Failed to read file\n'%s'" % fname)

    # Downloads encrypted file from dropbox and decrypts it
    def download_file(self):
        if self.current_file == "":
            print("No file selected")
        elif not os.path.isfile(self.current_user + '_Public.pem'):
            print("Create keys first!")
        else:
            print('> Downloading from Dropbox')
            dl = dbx.files_download_to_file(self.current_file, '/Cloudbox/'+self.current_file)
            print('> File downloaded')
            print()

            print('Grabbing keys')
            fname_public = self.current_user + '_Public.pem'
            fname_private = self.current_user + '_Private.pem'

            with open(self.current_user + '_Private.pem', mode='rb') as f:
                private_data = f.read()
                private_key = RSA.importKey(private_data)

            with open(self.current_user + '_Public.pem', mode='rb') as f:
                public_data = f.read()
                decrypted_AES = private_key.decrypt(public_data)

            print('> DECRYPTING')
            decrypt_file(self.current_file, decrypted_AES)
            print('> DONE')
            os.remove(self.current_file)

# Helper functions to encrypt and decrypt files using the secret key_size
# Pads data with zeros until it is aligned with the block size
def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

# Encrypts file using secret key
def encrypt(message, key, key_size=256):
    message = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

# Decrypts file using secret key
def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")

# Takes an unencrypted file and returns an encrypted version
def encrypt_file(file_name, key):
    with open(file_name, 'rb') as fo:
        plaintext = fo.read()
    enc = encrypt(plaintext, key)
    with open(file_name + ".enc", 'wb') as fo:
        fo.write(enc)

# Takes an encrypted file and returns an unencrypted version
def decrypt_file(file_name, key):
    with open(file_name, 'rb') as fo:
        ciphertext = fo.read()
    dec = decrypt(ciphertext, key)
    new_fname = file_name[:-8] + '_decrypted' + file_name[-8:-4]
    with open(new_fname, 'wb') as fo:
        fo.write(dec)

root = tk.Tk()
app = Application(master=root)
app.mainloop()
