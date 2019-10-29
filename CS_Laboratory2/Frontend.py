import secrets
from tkinter import *

from AES_algorithm import encrypt, decrypt

window = Tk()

window.title("Encryption Algorithms")
window.geometry('800x600')

var = IntVar()
encrypt_key = StringVar()
encrypt_string = StringVar()
decrypt_string = StringVar()
encrypted_text = StringVar()

var.set(16)
keys = {'128': 16, '192': 24, '256': 32}


def get_select():
    encrypt_key.set(secrets.token_hex(var.get()))


option_info = Label(window, text="Choose your key in bits: ", font=("Arial Bold", 13))
option_info.grid(row=0, column=2)

i = 1
for key in keys:
    radiobutton = Radiobutton(window, text=key, variable=var, command=get_select, value=keys[key],
                              foreground='black', font=("Arial Bold", 12))
    radiobutton.grid(row=i, column=2)
    i = i + 1

l1 = Label(window, text="Key:", font=("Arial Bold", 12))
l1.grid(row=1, column=0)

l2 = Label(window, text="Text:", font=("Arial Bold", 12))
l2.grid(row=2, column=0)

l3 = Label(window, text="Ciphered text:", font=("Arial Bold", 12))
l3.grid(row=5, column=0)

l4 = Label(window, text="Deciphered text:", font=("Arial Bold", 12))
l4.grid(row=7, column=0)

# define entries

e1 = Entry(window, textvariable=encrypt_key)
e1.grid(row=1, column=1)
encrypt_key.set(secrets.token_hex(16))
e2 = Entry(window, textvariable=encrypted_text)
e2.grid(row=2, column=1)

l5 = Label(window, textvariable=encrypt_string, font=("Arial Bold", 12))
l5.grid(row=5, column=1)
l6 = Label(window, textvariable=decrypt_string, font=("Arial Bold", 12))
l6.grid(row=7, column=1)


# functionality
def clicked():
    encrypt_value = encrypt(encrypt_key.get().encode(), encrypted_text.get().encode(), 10000)
    encrypt_string.set(encrypt_value)
    decrypt_string.set(decrypt(encrypt_key.get(), encrypt_value, 10000))


b1 = Button(window, text="Cypher", font=("Arial Bold", 12), bg="#02cfff", command=clicked)
b1.grid(row=3, column=1)

window.mainloop()
