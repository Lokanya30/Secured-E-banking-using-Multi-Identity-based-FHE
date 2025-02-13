import tenseal as ts

def create_context():
    """
    Creates a CKKS context with the appropriate parameters.
    
    Returns:
        ts.Context: The CKKS encryption context.
    """
    try:
        context = ts.context(
            ts.SCHEME_TYPE.CKKS,
            poly_modulus_degree=8192,
            coeff_mod_bit_sizes=[60, 40, 40, 60]  # Parameter settings for encryption
        )
        context.global_scale = 2**40  # Set the global scale
        context.generate_galois_keys()  # Generate keys for vector operations
        print("Context created successfully.")  # Debugging log
        return context
    except Exception as e:
        print(f"Error during context creation: {e}")
        return None

# Create a global encryption context for reuse
context = create_context()

def encrypt_data(data):
    """
    Encrypts the given data using CKKS encryption.

    Args:
        data (float): The data to be encrypted.

    Returns:
        ts.CKKSTensor: The encrypted tensor.
    """
    try:
        if context is None:
            raise Exception("Encryption context is not initialized.")
        
        print(f"Encrypting data: {data}")  # Debugging log
        encrypted_tensor = ts.ckks_vector(context, [float(data)])  # Ensure data is a float
        print(f"Encrypted data: {encrypted_tensor}")  # Debugging log
        return encrypted_tensor  # Return the encrypted tensor directly
    except Exception as e:
        print(f"Error during encryption: {e}")
        return None

def decrypt_data(encrypted_tensor):
    """
    Decrypts the given encrypted data.

    Args:
        encrypted_tensor (ts.CKKSTensor): The encrypted tensor.

    Returns:
        float: The decrypted value, or None if decryption fails.
    """
    try:
        if encrypted_tensor is None:
            raise Exception("Encrypted tensor is None.")
        
        print(f"Decrypting data: {encrypted_tensor}")  # Debugging log
        decrypted_tensor = encrypted_tensor.decrypt()
        print(f"Decrypted data: {decrypted_tensor}")  # Debugging log
        return decrypted_tensor[0]  # Return the first element
    except Exception as e:
        print(f"Error during decryption: {e}")
        return None