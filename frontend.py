import tkinter as tk

import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA512
import base64
random_generator = Random.new().read

# TODO: add environment

# main window
top = tk.Tk()
top.title( 'QuickCrypt Text' )
top.resizable( False, False )

# ------------------------------------------------------------------------------------------
# setup and utility

# block by block
key_size = 12

def block_apply( data, func, inWidth, outWidth=None ):
    result = bytearray()
    gen = ( 
        data[ i * inWidth : ( i + 1 ) * inWidth ] 
        for i in range( ( len( data ) + inWidth - 1 ) // inWidth ) 
    )
    for block in gen:
        temp = func( block )
        if outWidth:
            result += bytearray( outWidth - len( temp ) ) + temp
        else:
            result += temp
    return bytes( result )

# string variables for entry
gen_keysize_var = tk.StringVar( value=str( key_size ) )
private_key_var = tk.StringVar()
public_key_var = tk.StringVar()
peer_key_var = tk.StringVar()
plaintext_var = tk.StringVar()
ciphertext_var = tk.StringVar()

# callbacks
def keygenCallback():
    key = RSA.generate( 2**key_size, random_generator )
    public_key = key.publickey().exportKey( format='PEM' ).decode( 'utf-8' )
    private_key = key.exportKey( format='PEM' ).decode( 'utf-8' )
    private_key_var.set( private_key )
    public_key_var.set( public_key )

reset = None
def keysizeValidate():
    # on leaving entry field
    # check parse to integer
    # if fail or less than 11, reset to 11
    global key_size
    global reset
    try:
        bits = int( gen_keysize_var.get() )
        if bits > 10:
            key_size = bits
            return True
    except:
        pass
    top.after_idle( reset )
    return False

def encryptCallback():
    '''get keys and plaintext, encrypt and sign.'''
    text = plaintext_var.get().encode( 'utf-8' )
    peer_key_str = peer_key_var.get()

    # Empty 'peer' field no encrypt
    if peer_key_str:
        peer_cipher = PKCS1_OAEP.new( 
            RSA.importKey( peer_key_str.encode( 'utf-8' ) ), 
            SHA512 
        )
        text = block_apply( text, peer_cipher.encrypt, ( peer_cipher._key.size() - 1020 ) // 8 - 2, ( peer_cipher._key.size() + 4 ) // 8 )

    ciphertext_var.set( str( base64.encodebytes( text ), 'utf-8' ) )    

def decryptCallback():
    '''get keys and ciphertext, decrypt and unsign.'''
    text = base64.decodebytes( bytes( ciphertext_var.get(), 'ascii' ) )
    private_key_str = private_key_var.get()

    # Empty 'private' field no decrypt
    if private_key_str:
        private_cipher = PKCS1_OAEP.new( 
            RSA.importKey( bytes( private_key_str, 'utf-8' ) ),
            SHA512 
        )
        text = block_apply( text, private_cipher.decrypt, ( private_cipher._key.size() + 4 ) // 8 )

    plaintext_var.set( text.decode( 'utf-8' ) )

# ------------------------------------------------------------------------------------------
# Elements of GUI

# key management
keygen_button = tk.Button( top, text="New Keys", command=keygenCallback )
keysize_label = tk.Label( top, text="Key Bits: 2**" )
keysize_field = tk.Entry( top, textvariable=gen_keysize_var, 
                          validate='focusout', 
                          validatecommand=top.register( keysizeValidate ),
                          invalidcommand=top.register( lambda: gen_keysize_var.set( str( key_size ) ) ) )
reset = lambda: keysize_field.config( validate='focusout' )

private_key_label = tk.Label( top, text="Your Private Key" )
private_key_field = tk.Entry( top, textvariable=private_key_var )

public_key_label = tk.Label( top, text="Your Public Key" )
public_key_field = tk.Entry( top, textvariable=public_key_var )

peer_key_label = tk.Label( top, text="Peer's Public Key" )
peer_key_field = tk.Entry( top, textvariable=peer_key_var )

# text interaction
plaintext_label = tk.Label( text='Plaintext' )
plaintext_field = tk.Entry( top, textvariable=plaintext_var )
encrypt_button = tk.Button( top, text='Encrypt', command=encryptCallback )
decrypt_button = tk.Button( top, text='Decrypt', command=decryptCallback )
ciphertext_label = tk.Label( text='Ciphertext' )
ciphertext_field = tk.Entry( top, textvariable=ciphertext_var )

# ------------------------------------------------------------------------------------------
# assemble layout

padding = dict(
    # ipadx=10,
    # ipady=10,
    padx=4,
    pady=4
)

keygen_button.grid( row=0, column=0, columnspan=2, **padding )
keysize_label.grid( row=1, column=0, **padding )
keysize_field.grid( row=1, column=1, **padding )
private_key_label.grid( row=0, column=2, **padding )
private_key_field.grid( row=0, column=3, columnspan=2, **padding )
public_key_label.grid( row=1, column=2, **padding )
public_key_field.grid( row=1, column=3, columnspan=2, **padding )
peer_key_label.grid( row=2, column=0, **padding )
peer_key_field.grid( row=2, column=1, columnspan=2, **padding )
ciphertext_label.grid( row=3, column=0, **padding )
ciphertext_field.grid( row=3, column=1, columnspan=2, **padding )
decrypt_button.grid( row=3, column=4, **padding )
plaintext_label.grid( row=4, column=0, **padding )
plaintext_field.grid( row=4, column=1, columnspan=2, **padding )
encrypt_button.grid( row=4, column=4, **padding )

# run
top.mainloop()