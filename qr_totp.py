#!/usr/bin/env python3

import argparse
import base64
import binascii
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import cv2


def read_qr(image_path: Path) -> str:
    image_path = image_path.expanduser()
    image = cv2.imread(str(image_path))
    if image is None:
        raise ValueError(f"Не удалось открыть изображение: {image_path}")

    data, _, _ = cv2.QRCodeDetector().detectAndDecode(image)
    if not data:
        raise ValueError("QR-код не найден или не удалось его распознать")
    return data


def extract_totp_secret(qr_text: str) -> str:
    uri = urlparse(qr_text.strip())
    if uri.scheme.lower() != "otpauth":
        raise ValueError("QR-код не содержит otpauth://-ссылку аутентификатора")
    if uri.netloc.lower() != "totp":
        raise ValueError("Поддерживаются только TOTP-коды (otpauth://totp/...)")

    secrets = parse_qs(uri.query).get("secret", [])
    if len(secrets) != 1 or not secrets[0].strip():
        raise ValueError("В QR-коде отсутствует параметр secret")

    secret = secrets[0].replace(" ", "").upper().rstrip("=")
    try:
        base64.b32decode(secret + "=" * (-len(secret) % 8))
    except (binascii.Error, ValueError) as error:
        raise ValueError("Секрет в QR-коде имеет неверный формат Base32") from error
    return secret


def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            raise ValueError("Повреждены данные otpauth-migration")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
    raise ValueError("Неверный varint в данных otpauth-migration")


def protobuf_fields(data: bytes):
    offset = 0
    while offset < len(data):
        tag, offset = read_varint(data, offset)
        field_number, wire_type = tag >> 3, tag & 7
        if wire_type == 0:
            value, offset = read_varint(data, offset)
        elif wire_type == 2:
            length, offset = read_varint(data, offset)
            if offset + length > len(data):
                raise ValueError("Повреждены данные otpauth-migration")
            value = data[offset:offset + length]
            offset += length
        else:
            raise ValueError("Неподдерживаемый формат данных otpauth-migration")
        yield field_number, wire_type, value


def extract_migration_secrets(qr_text: str) -> list[str]:
    uri = urlparse(qr_text.strip())
    payloads = parse_qs(uri.query).get("data", [])
    if len(payloads) != 1 or not payloads[0]:
        raise ValueError("В QR-коде otpauth-migration отсутствует параметр data")

    try:
        payload = base64.b64decode(payloads[0], validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("Неверная Base64-кодировка данных otpauth-migration") from error

    secrets = []
    for field, wire, otp_data in protobuf_fields(payload):
        if field != 1 or wire != 2:
            continue
        secret_bytes = None
        otp_type = 0
        for otp_field, otp_wire, value in protobuf_fields(otp_data):
            if otp_field == 1 and otp_wire == 2:
                secret_bytes = value
            elif otp_field == 6 and otp_wire == 0:
                otp_type = value
        if otp_type == 1:
            raise ValueError("HOTP из otpauth-migration не поддерживается, нужен TOTP")
        if secret_bytes:
            secrets.append(base64.b32encode(secret_bytes).decode("ascii").rstrip("="))

    if not secrets:
        raise ValueError("В QR-коде otpauth-migration не найдены секреты")
    return secrets


def extract_secrets(qr_text: str) -> list[str]:
    scheme = urlparse(qr_text.strip()).scheme.lower()
    if scheme == "otpauth":
        return [extract_totp_secret(qr_text)]
    if scheme == "otpauth-migration":
        return extract_migration_secrets(qr_text)
    raise ValueError("QR-код не содержит ссылку otpauth:// или otpauth-migration://")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Извлекает Base32-секреты TOTP из QR-кодов аутентификатора."
    )
    parser.add_argument("image", type=Path, help="путь к PNG/JPG со скриншотом QR-кода")
    args = parser.parse_args()

    try:
        for secret in extract_secrets(read_qr(args.image)):
            print(secret)
    except ValueError as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
