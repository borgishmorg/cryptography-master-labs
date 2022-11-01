from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def generate_secret(length: int = 32) -> bytes:
    return get_random_bytes(length)


def encrypt(secret: bytes, message: bytes) -> bytes:
    nonce = get_random_bytes(AES.block_size // 2)
    initial_value = get_random_bytes(AES.block_size // 2)
    cypher = AES.new(
        key=secret,
        mode=AES.MODE_CTR,
        nonce=nonce,
        initial_value=initial_value
    )
    encrypted_message = cypher.encrypt(message)
    return nonce + initial_value + encrypted_message


def decrypt(secret: bytes, encrypted_message: bytes) -> bytes:
    nonce, initial_value, encrypted_message = (
        encrypted_message[:AES.block_size//2],
        encrypted_message[AES.block_size//2:AES.block_size],
        encrypted_message[AES.block_size:],
    )
    cipher = AES.new(
        key=secret,
        mode=AES.MODE_CTR,
        nonce=nonce,
        initial_value=initial_value
    )
    decrypted_message = cipher.decrypt(encrypted_message)
    return decrypted_message


def main():
    secret = generate_secret()
    message = b'My dirty secret.'
    encrypted_message = encrypt(secret=secret, message=message)
    decrypted_message = decrypt(secret=secret, encrypted_message=encrypted_message)  # noqa

    print(f'{secret=}')
    print(f'{message=}')
    print(f'{encrypted_message=}')
    print(f'{decrypted_message=}')


if __name__ == '__main__':
    main()
