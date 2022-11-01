from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256


def generate_secret(length: int = 32) -> bytes:
    return get_random_bytes(length)


def sign(secret: bytes, message: bytes) -> bytes:
    return HMAC.new(key=secret, msg=message, digestmod=SHA256).digest()


def verify(secret: bytes, message: bytes, mac_tag: bytes) -> bool:
    hmac = HMAC.new(key=secret, msg=message, digestmod=SHA256)
    try:
        hmac.verify(mac_tag=mac_tag)
    except ValueError:
        return False
    else:
        return True


def main():
    secret = generate_secret()
    message = b'My dirty secret.'
    mac_tag = sign(secret=secret, message=message)

    print(f'{secret=}')
    print(f'{message=}')
    print(f'{mac_tag=}')
    print()
    print('verify:', verify(secret=secret, message=message, mac_tag=mac_tag))
    print('verify (wrong secret):', verify(secret=generate_secret(), message=message, mac_tag=mac_tag))  # noqa
    print('verify (wrong message):', verify(secret=secret, message=b'Some message', mac_tag=mac_tag))  # noqa
    print('verify (wrong mac):', verify(secret=secret, message=message, mac_tag=get_random_bytes(32)))  # noqa


if __name__ == '__main__':
    main()
