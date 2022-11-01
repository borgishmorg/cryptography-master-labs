from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption


def generate_keys() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def show_keys(name: str, private_key: ec.EllipticCurvePrivateKey, public_key: ec.EllipticCurvePublicKey):
    print(name)
    print('Key size:', private_key.key_size)
    print(private_key.private_bytes(encoding=Encoding.PEM,
          format=PrivateFormat.TraditionalOpenSSL, encryption_algorithm=NoEncryption()).decode())
    print(public_key.public_bytes(encoding=Encoding.PEM,
          format=PublicFormat.SubjectPublicKeyInfo).decode())


def main():
    alice_private_key, alice_public_key = generate_keys()
    bob_private_key, bob_public_key = generate_keys()

    show_keys('Alice', alice_private_key, alice_public_key)
    show_keys('Bob', bob_private_key, bob_public_key)

    alice_shared_key = alice_private_key.exchange(
        algorithm=ec.ECDH(),
        peer_public_key=bob_public_key
    )
    bob_shared_key = bob_private_key.exchange(
        algorithm=ec.ECDH(),
        peer_public_key=alice_public_key
    )

    print(alice_shared_key == bob_shared_key, len(alice_shared_key))


if __name__ == '__main__':
    main()
