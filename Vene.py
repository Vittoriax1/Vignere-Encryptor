def vigenere_encrypt(plaintext, key):
    # Create a mapping of the alphabet to the shifted alphabet
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    key_len = len(key)
    key_int = [ord(i) for i in key]
    ciphertext = ""

    for i, c in enumerate(plaintext.upper()):
        if c in alphabet:
            ciphertext += alphabet[(alphabet.index(c) + key_int[i % key_len]) % 26]
        else:
            ciphertext += c

    return ciphertext

def vigenere_decrypt(ciphertext, key):
    # Create a mapping of the alphabet to the shifted alphabet
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    key_len = len(key)
    key_int = [ord(i) for i in key]
    plaintext = ""

    for i, c in enumerate(ciphertext.upper()):
        if c in alphabet:
            plaintext += alphabet[(alphabet.index(c) - key_int[i % key_len]) % 26]
        else:
            plaintext += c

    return plaintext

# Get user input for the plaintext and key
plaintext = input("Enter the plaintext message: ")
key = input("Enter the key: ")

# Encrypt the message
ciphertext = vigenere_encrypt(plaintext, key)
print(f"Ciphertext: {ciphertext}")

# Decrypt the message
decrypted_text = vigenere_decrypt(ciphertext, key)
print(f"Decrypted text: {decrypted_text}")
