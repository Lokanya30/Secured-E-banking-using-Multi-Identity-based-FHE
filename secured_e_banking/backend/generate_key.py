from cryptography.fernet import Fernet

# Generate a key and save it
def generate_and_save_key():
    key = Fernet.generate_key()
    with open('secret.key', 'wb') as key_file:
        key_file.write(key)
    print("Key has been generated and saved to 'secret.key'")

if __name__ == "__main__":
    generate_and_save_key()