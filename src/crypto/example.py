from .service import CryptoService
from .rsa_algorithm import RSACryptoAlgorithm
from .pem_encoding import PEMKeyEncoding


def main():
    # Instantiate the implementations
    rsa_algorithm = RSACryptoAlgorithm()
    pem_encoding = PEMKeyEncoding()

    # Create the CryptoService with our chosen implementations
    crypto_service = CryptoService(
        algorithm=rsa_algorithm,
        key_encoding=pem_encoding)

    # Generate a new RSA key pair
    private_key_pem, public_key_pem = crypto_service.generate_key_pair()

    # Sign a message
    message = b"Hello, world!"
    signature = crypto_service.create_signature(private_key_pem, message)

    # Verify the signature
    is_valid = crypto_service.verify_signature(
        public_key_pem, signature, message)
    print(f"Signature valid: {is_valid}")


if __name__ == "__main__":
    main()
