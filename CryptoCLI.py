import os
import sys
import time
import struct
import multiprocessing
from typing import List, Tuple


class CryptoCLI:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.logs = []

    def log(self, message: str):
        if self.verbose:
            print(message)
        self.logs.append(message)

    @staticmethod
    def _rotate_left(value: int, shift: int, bits: int = 32) -> int:
        shift %= bits
        return ((value << shift) | (value >> (bits - shift))) & ((1 << bits) - 1)

    @staticmethod
    def _rotate_right(value: int, shift: int, bits: int = 32) -> int:
        shift %= bits
        return ((value >> shift) | (value << (bits - shift))) & ((1 << bits) - 1)

    def _pseudo_random_generator(self, seed: int, count: int) -> List[int]:
        """Генератор псевдослучайных чисел на основе Xorshift32"""
        numbers = []
        x = seed & 0xFFFFFFFF  # Маскируем начальное значение seed
        for _ in range(count):
            x ^= (x << 13) & 0xFFFFFFFF
            x ^= (x >> 17) & 0xFFFFFFFF
            x ^= (x << 5) & 0xFFFFFFFF
            x &= 0xFFFFFFFF  # Маскируем результат после всех операций
            numbers.append(x)
        return numbers
    def _derive_key(self, passphrase: str) -> bytes:
        self.log("Генерация ключа из парольной фразы...")
        hash_value = 5381
        for c in passphrase:
            hash_value = ((hash_value << 5) + hash_value) + ord(c)
            hash_value &= 0xFFFFFFFF
        random_numbers = self._pseudo_random_generator(hash_value, 8)
        key = b''.join(struct.pack('>I', num) for num in random_numbers)
        self.log(f"Сгенерированный ключ: {key.hex()}")
        return key

    def _substitution_step(self, data: bytes, key: bytes, reverse: bool = False) -> bytes:
        s_box = list(range(256))
        key_bytes = key * (256 // len(key) + 1)

        j = 0
        for i in range(256):
            j = (j + s_box[i] + key_bytes[i]) % 256
            s_box[i], s_box[j] = s_box[j], s_box[i]

        # Предвычисляем обратный S-блок
        s_box_inverse = [0] * 256
        for idx, val in enumerate(s_box):
            s_box_inverse[val] = idx

        result = bytearray(len(data))
        if reverse:
            for i, b in enumerate(data):
                result[i] = s_box_inverse[b]
        else:
            for i, b in enumerate(data):
                result[i] = s_box[b]
        return bytes(result)
    def _permutation_step(self, data: bytes, key: bytes, reverse: bool = False) -> bytes:
        data_len = len(data)
        if data_len == 0:
            return data

        key_int = int.from_bytes(key[:4], 'big')
        random_numbers = self._pseudo_random_generator(key_int, data_len)

        indices = list(range(data_len))
        for i in range(data_len):
            swap_with = random_numbers[i] % data_len
            indices[i], indices[swap_with] = indices[swap_with], indices[i]

        if reverse:
            reverse_indices = [0] * data_len
            for i, pos in enumerate(indices):
                reverse_indices[pos] = i
            indices = reverse_indices

        result = bytearray(len(data))
        for i, pos in enumerate(indices):
            result[i] = data[pos]
        return bytes(result)

    def _xor_with_key(self, data: bytes, key: bytes) -> bytes:
        key_bytes = key * (len(data) // len(key) + 1)
        result = bytearray(len(data))
        for i in range(len(data)):
            result[i] = data[i] ^ key_bytes[i]
        return bytes(result)

    @staticmethod
    def _process_block(args: Tuple[int, bytes, bytes, bool]) -> Tuple[int, bytes]:
        block_num, block_data, key, is_encrypt = args
        # Создаем временный экземпляр для вызова методов
        crypto = CryptoCLI()
        if is_encrypt:
            processed = crypto._substitution_step(block_data, key)
            processed = crypto._permutation_step(processed, key)
            processed = crypto._xor_with_key(processed, key)
            processed = crypto._substitution_step(processed, key[::-1])
            processed = crypto._permutation_step(processed, key[::-1])
        else:
            processed = crypto._permutation_step(block_data, key[::-1], reverse=True)
            processed = crypto._substitution_step(processed, key[::-1], reverse=True)
            processed = crypto._xor_with_key(processed, key)
            processed = crypto._permutation_step(processed, key, reverse=True)
            processed = crypto._substitution_step(processed, key, reverse=True)
        return (block_num, processed)
    def _parallel_process(self, data: bytes, key: bytes, is_encrypt: bool,
                          block_size: int = 32 * 1024) -> bytes:
        """Параллельная обработка данных по блокам"""
        if not data:
            return b''

        # Разделение данных на блоки
        num_blocks = (len(data) + block_size - 1) // block_size
        blocks = []

        for i in range(num_blocks):
            start = i * block_size
            end = min((i + 1) * block_size, len(data))
            block_data = data[start:end]

            # Генерируем уникальный ключ для каждого блока
            block_seed = int.from_bytes(key, 'big') ^ i
            block_key = self._pseudo_random_generator(block_seed, 16)
            block_key_bytes = b''.join(struct.pack('>I', num) for num in block_key[:8])

            blocks.append((i, block_data, block_key_bytes, is_encrypt))

        # Параллельная обработка блоков
        with multiprocessing.Pool(multiprocessing.cpu_count()) as pool:
            results = pool.map(self._process_block, blocks)

        # Сортировка результатов по номеру блока
        results.sort(key=lambda x: x[0])

        # Сборка финального результата
        return b''.join(data for _, data in results)

    def encrypt(self, data: bytes, passphrase: str) -> bytes:
        self.log("Начало шифрования...")
        start_time = time.time()

        key = self._derive_key(passphrase)
        result = self._parallel_process(data, key, is_encrypt=True)

        elapsed = time.time() - start_time
        speed = len(data) * 8 / elapsed / 1e6 if elapsed > 0 else 0
        self.log(f"Шифрование завершено. Скорость: {speed:.2f} Мбит/сек")
        return result

    def decrypt(self, data: bytes, passphrase: str) -> bytes:
        self.log("Начало расшифрования...")
        start_time = time.time()

        key = self._derive_key(passphrase)
        result = self._parallel_process(data, key, is_encrypt=False)

        elapsed = time.time() - start_time
        speed = len(data) * 8 / elapsed / 1e6 if elapsed > 0 else 0
        self.log(f"Расшифрование завершено. Скорость: {speed:.2f} Мбит/сек")
        return result

    def encrypt_file(self, input_path: str, output_path: str, passphrase: str):
        self.log(f"Шифрование файла {input_path} -> {output_path}")
        with open(input_path, 'rb') as f:
            data = f.read()
        encrypted = self.encrypt(data, passphrase)
        with open(output_path, 'wb') as f:
            f.write(encrypted)

    def decrypt_file(self, input_path: str, output_path: str, passphrase: str):
        self.log(f"Расшифрование файла {input_path} -> {output_path}")
        with open(input_path, 'rb') as f:
            data = f.read()
        decrypted = self.decrypt(data, passphrase)
        with open(output_path, 'wb') as f:
            f.write(decrypted)

    def encrypt_directory(self, dir_path: str, output_file: str, passphrase: str):
        self.log(f"Шифрование каталога {dir_path} в файл {output_file}")
        import tarfile
        import io
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode='w:gz') as tar:
            for root, _, files in os.walk(dir_path):
                for file in files:
                    full_path = os.path.join(root, file)
                    arcname = os.path.relpath(full_path, start=dir_path)
                    tar.add(full_path, arcname=arcname)
        encrypted = self.encrypt(tar_buffer.getvalue(), passphrase)
        with open(output_file, 'wb') as f:
            f.write(encrypted)

    def decrypt_directory(self, input_file: str, output_dir: str, passphrase: str):
        self.log(f"Расшифрование файла {input_file} в каталог {output_dir}")
        import tarfile
        import io
        with open(input_file, 'rb') as f:
            encrypted = f.read()
        decrypted = self.decrypt(encrypted, passphrase)
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
    multiprocessing.freeze_support()
    main()