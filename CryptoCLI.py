import os
import sys
import time
import struct
from typing import List, Tuple, Dict, Union


class CryptoCLI:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.logs = []

    def log(self, message: str):
        """Логирование сообщений"""
        if self.verbose:
            print(message)
        self.logs.append(message)

    @staticmethod
    def _rotate_left(value: int, shift: int, bits: int = 32) -> int:
        """Циклический сдвиг влево"""
        shift %= bits
        return ((value << shift) | (value >> (bits - shift))) & ((1 << bits) - 1)

    @staticmethod
    def _rotate_right(value: int, shift: int, bits: int = 32) -> int:
        """Циклический сдвиг вправо"""
        shift %= bits
        return ((value >> shift) | (value << (bits - shift))) & ((1 << bits) - 1)

    def _pseudo_random_generator(self, seed: int, count: int) -> List[int]:
        """Генератор псевдослучайных чисел на основе линейного конгруэнтного метода"""
        a = 1664525
        c = 1013904223
        m = 2 ** 32
        numbers = []
        for _ in range(count):
            seed = (a * seed + c) % m
            numbers.append(seed)
        return numbers

    def _derive_key(self, passphrase: str) -> bytes:
        """Генерация 256-битного ключа из парольной фразы"""
        self.log("Генерация ключа из парольной фразы...")
        # Хеширование парольной фразы
        hash_value = 5381
        for c in passphrase:
            hash_value = ((hash_value << 5) + hash_value) + ord(c)
            hash_value &= 0xFFFFFFFF

        # Генерация случайных чисел для ключа
        random_numbers = self._pseudo_random_generator(hash_value, 8)  # 8 * 32 бит = 256 бит

        # Преобразование в байты
        key = b''.join(struct.pack('>I', num) for num in random_numbers)
        self.log(f"Сгенерированный ключ: {key.hex()}")
        return key

    def _substitution_step(self, data: bytes, key: bytes, reverse: bool = False) -> bytes:
        """Подстановочный шаг (S-блок)"""
        # Инициализация S-блока
        s_box = list(range(256))
        if not isinstance(s_box, list):
            raise TypeError("S-box must be a list")

        # Подготовка ключа
        key_bytes = key * (256 // len(key) + 1)
        if not isinstance(key_bytes, (bytes, bytearray)):
            raise TypeError("Key must be bytes")

        # Перемешивание S-блока
        j = 0
        for i in range(256):
            j = (j + s_box[i] + key_bytes[i]) % 256
            s_box[i], s_box[j] = s_box[j], s_box[i]  # Обмен значений

        # Применение подстановки
        result = bytearray()
        for byte in data:
            if reverse:
                result.append(s_box.index(byte))  # Обратная подстановка
            else:
                result.append(s_box[byte])  # Прямая подстановка
        return bytes(result)
    def _permutation_step(self, data: bytes, key: bytes, reverse: bool = False) -> bytes:
        """Перестановочный шаг (P-блок)"""
        data_len = len(data)
        if data_len == 0:
            return data

        # Генерация последовательности перестановок на основе ключа
        key_int = int.from_bytes(key, 'big')
        random_numbers = self._pseudo_random_generator(key_int, data_len)

        # Создание таблицы перестановок
        indices = list(range(data_len))
        for i in range(data_len):
            swap_with = random_numbers[i] % data_len
            indices[i], indices[swap_with] = indices[swap_with], indices[i]

        if reverse:
            # Обратная перестановка
            reverse_indices = [0] * data_len
            for i, pos in enumerate(indices):
                reverse_indices[pos] = i
            indices = reverse_indices

        # Применение перестановки
        result = bytearray(data_len)
        for i, pos in enumerate(indices):
            result[i] = data[pos]
        return bytes(result)

    def _xor_with_key(self, data: bytes, key: bytes) -> bytes:
        """XOR данных с ключом"""
        key_bytes = key * (len(data) // len(key) + 1)
        return bytes(b ^ k for b, k in zip(data, key_bytes[:len(data)]))

    def encrypt(self, data: bytes, passphrase: str) -> bytes:
        """Шифрование данных"""
        self.log("Начало шифрования...")
        start_time = time.time()

        if not data:
            return b''

        key = self._derive_key(passphrase)

        # Применение криптографических преобразований
        # 1. Подстановка
        data = self._substitution_step(data, key)
        self.log("Применен первый подстановочный шаг")

        # 2. Перестановка
        data = self._permutation_step(data, key)
        self.log("Применен первый перестановочный шаг")

        # 3. XOR с ключом
        data = self._xor_with_key(data, key)
        self.log("Применен XOR с ключом")

        # 4. Вторая подстановка
        data = self._substitution_step(data, key[::-1])
        self.log("Применен второй подстановочный шаг")

        # 5. Вторая перестановка
        data = self._permutation_step(data, key[::-1])
        self.log("Применен второй перестановочный шаг")

        elapsed = time.time() - start_time
        speed = len(data) * 8 / elapsed / 1e6 if elapsed > 0 else 0
        self.log(f"Шифрование завершено. Скорость: {speed:.2f} Мбит/сек")
        return data

    def decrypt(self, data: bytes, passphrase: str) -> bytes:
        """Расшифрование данных"""
        self.log("Начало расшифрования...")
        start_time = time.time()

        if not data:
            return b''

        key = self._derive_key(passphrase)

        # Обратные преобразования в обратном порядке
        # 1. Обратная вторая перестановка
        data = self._permutation_step(data, key[::-1], reverse=True)
        self.log("Применен обратный второй перестановочный шаг")

        # 2. Обратная вторая подстановка
        data = self._substitution_step(data, key[::-1], reverse=True)
        self.log("Применен обратный второй подстановочный шаг")

        # 3. XOR с ключом (обратное преобразование такое же)
        data = self._xor_with_key(data, key)
        self.log("Применен XOR с ключом")

        # 4. Обратная первая перестановка
        data = self._permutation_step(data, key, reverse=True)
        self.log("Применен обратный первый перестановочный шаг")

        # 5. Обратная первая подстановка
        data = self._substitution_step(data, key, reverse=True)
        self.log("Применен обратный первый подстановочный шаг")

        elapsed = time.time() - start_time
        speed = len(data) * 8 / elapsed / 1e6 if elapsed > 0 else 0
        self.log(f"Расшифрование завершено. Скорость: {speed:.2f} Мбит/сек")
        return data

    def encrypt_file(self, input_path: str, output_path: str, passphrase: str):
        """Шифрование файла"""
        self.log(f"Шифрование файла {input_path} -> {output_path}")
        with open(input_path, 'rb') as f:
            data = f.read()

        encrypted = self.encrypt(data, passphrase)

        with open(output_path, 'wb') as f:
            f.write(encrypted)

    def decrypt_file(self, input_path: str, output_path: str, passphrase: str):
        """Расшифрование файла"""
        self.log(f"Расшифрование файла {input_path} -> {output_path}")
        with open(input_path, 'rb') as f:
            data = f.read()

        decrypted = self.decrypt(data, passphrase)

        with open(output_path, 'wb') as f:
            f.write(decrypted)

    def encrypt_directory(self, dir_path: str, output_file: str, passphrase: str):
        """Шифрование каталога"""
        self.log(f"Шифрование каталога {dir_path} в файл {output_file}")
        import tarfile
        import io

        # Создаем tar-архив в памяти
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode='w:gz') as tar:
            for root, _, files in os.walk(dir_path):
                for file in files:
                    full_path = os.path.join(root, file)
                    arcname = os.path.relpath(full_path, start=dir_path)
                    tar.add(full_path, arcname=arcname)

        # Шифруем архив
        encrypted = self.encrypt(tar_buffer.getvalue(), passphrase)

        # Сохраняем зашифрованный архив
        with open(output_file, 'wb') as f:
            f.write(encrypted)

    def decrypt_directory(self, input_file: str, output_dir: str, passphrase: str):
        """Расшифрование каталога"""
        self.log(f"Расшифрование файла {input_file} в каталог {output_dir}")
        import tarfile
        import io

        # Читаем и расшифровываем архив
        with open(input_file, 'rb') as f:
            encrypted = f.read()

        decrypted = self.decrypt(encrypted, passphrase)

        # Извлекаем tar-архив
        tar_buffer = io.BytesIO(decrypted)
        os.makedirs(output_dir, exist_ok=True)
        with tarfile.open(fileobj=tar_buffer, mode='r:gz') as tar:
            tar.extractall(path=output_dir)


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Утилита для шифрования и расшифрования данных')
    parser.add_argument('action', choices=['encrypt', 'decrypt', 'encrypt-dir', 'decrypt-dir'],
                        help='Действие: encrypt/decrypt для файлов, encrypt-dir/decrypt-dir для каталогов')
    parser.add_argument('input', help='Входной файл или каталог')
    parser.add_argument('output', help='Выходной файл или каталог')
    parser.add_argument('-p', '--passphrase', required=True, help='Парольная фраза для шифрования')
    parser.add_argument('-v', '--verbose', action='store_true', help='Подробный вывод')

    args = parser.parse_args()

    crypto = CryptoCLI(verbose=args.verbose)

    try:
        if args.action == 'encrypt':
            crypto.encrypt_file(args.input, args.output, args.passphrase)
        elif args.action == 'decrypt':
            crypto.decrypt_file(args.input, args.output, args.passphrase)
        elif args.action == 'encrypt-dir':
            crypto.encrypt_directory(args.input, args.output, args.passphrase)
        elif args.action == 'decrypt-dir':
            crypto.decrypt_directory(args.input, args.output, args.passphrase)

        print("Операция успешно завершена!")
        if args.verbose:
            print("\nЛоги выполнения:")
            for log in crypto.logs:
                print(f"- {log}")
    except Exception as e:
        print(f"Ошибка: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()