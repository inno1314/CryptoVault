import os
from typing import Tuple

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt, PBKDF2
from Crypto.Hash import HMAC, SHA256

# === Константы ===
from config import (
    SALT_SIZE,
    PBKDF2_ITERATIONS,
    KEY_LENGTH,
)


# Вместо использования пароля напрямую, мы применяем Key Derivation Function (KDF)
# для защиты от Known Plaintext атак (brute-force, rainbow tables).
def derive_key(passphrase: str, salt: bytes) -> bytes:
    """
    Производит ключ из пользовательского пароля с использованием выбранной KDF-функции.

    :param passphrase: Пароль пользователя (в байтах).
    :param salt: Случайная соль (в байтах).
    :return: Производный ключ (в байтах).
    """
    return PBKDF2(
        password=passphrase,
        salt=salt,
        dkLen=KEY_LENGTH,
        count=PBKDF2_ITERATIONS,
        hmac_hash_module=SHA256,
    )


def encrypt(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes, bytes, bytes]:
    """
    Шифрует данные с помощью AES-GCM и добавляет HMAC для целостности.

    :param plaintext: Простой текст.
    :param key: Ключ шифрования.
    :return: Кортеж (nonce, ciphertext, tag, hmac_tag).
    """
    # Случайный nonce для AES-GCM (уникальный для каждой операции)
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    # HMAC для защиты от модификации: считаем по nonce + ciphertext + tag
    hmac_obj = HMAC.new(key, digestmod=SHA256)
    hmac_obj.update(nonce + ciphertext + tag)
    hmac_tag = hmac_obj.digest()

    return nonce, ciphertext, tag, hmac_tag


def decrypt(
    nonce: bytes, ciphertext: bytes, tag: bytes, key: bytes, hmac_tag: bytes
) -> bytes:
    """
    Проверяет HMAC и расшифровывает данные с использованием AES-GCM.

    :param nonce: nonce, использованный при шифровании (в байтах).
    :param ciphertext: Зашифрованные данные.
    :param tag: GCM-тег аутентификации.
    :param key: Ключ шифрования.
    :param hmac_tag: Ожидаемый HMAC.
    :return: Открытые данные.
    :raises ValueError: Если HMAC или GCM-аутентификация не прошли.
    """
    # Проверка HMAC
    hmac_obj = HMAC.new(key, digestmod=SHA256)
    hmac_obj.update(nonce + ciphertext + tag)
    try:
        hmac_obj.verify(hmac_tag)
    except ValueError:
        raise ValueError("Ошибка проверки HMAC.")

    # Расшифровка с проверкой тега
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        raise ValueError(
            "Ошибка проверки AES-GCM. Неверный ключ или поврежденные данные."
        )

    return plaintext


def generate_salt() -> bytes:
    """
    Генерирует случайную соль для использования в KDF.

    :return: Соль (в байтах).
    """
    return os.urandom(SALT_SIZE)
