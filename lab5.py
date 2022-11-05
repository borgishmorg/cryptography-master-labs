from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme


def generate_keys(length: int = 3072) -> tuple[RSA.RsaKey, RSA.RsaKey]:
    key = RSA.generate(bits=length)
    return key, key.public_key()


def show_keys(private_key: RSA.RsaKey, public_key: RSA.RsaKey):
    print('Key length:', private_key.size_in_bits(), 'bits')
    print(private_key.exportKey().decode())
    print(public_key.exportKey().decode())


def sign(msg: bytes, private_key: RSA.RsaKey) -> bytes:
    signer = PKCS115_SigScheme(private_key)
    hash = SHA512.new(msg)
    signature = signer.sign(hash)
    return signature


def verify(msg: bytes, signature: bytes, public_key: RSA.RsaKey) -> bool:
    signer = PKCS115_SigScheme(public_key)
    hash = SHA512.new(msg)
    try:
        signer.verify(hash, signature)
    except ValueError:
        return False
    else:
        return True


def main():
    msg = b'Document to sign'

    private_key, public_key = generate_keys()
    show_keys(private_key, public_key)

    signature = sign(msg, private_key)

    print()
    print('Message:', msg)
    print('Signature:', signature.hex())
    print()
    print('Verify:', verify(msg, signature, public_key))
    print('Verify (wrong message):', verify(b'wrong message', signature, public_key))  # noqa
    print('Verify (wrong signature):', verify(msg, b'wrong signature', public_key))  # noqa
    print('Verify (wrong key):', verify(msg, signature, generate_keys()[1]))  # noqa


if __name__ == '__main__':
    main()
