import os
import time
import hashlib
import tempfile
from CryptoCLI import CryptoCLI  # Убедитесь, что файл с классом называется CryptoCLI.py

# --- Генерация тестового файла ---
def generate_test_file(size_mb: int) -> str:
    """Создаёт временный файл заданного размера и возвращает его путь"""
    fd, path = tempfile.mkstemp(suffix=f"_{size_mb}MB.bin")
    os.close(fd)

    chunk_size = 1024 * 1024  # 1 MB
    with open(path, 'wb') as f:
        for _ in range(size_mb):
            f.write(os.urandom(chunk_size))  # Генерируем случайные данные
    print(f"✅ Сгенерирован файл {path} ({size_mb} МБ)")
    return path

# --- Вычисление хэша для проверки ---
def calculate_sha256(file_path: str) -> str:
    """Вычисляет SHA-256 хэш файла для проверки целостности"""
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

# --- Тестирование одного файла ---
def test_file_performance(size_mb: int, passphrase: str):
    input_path = generate_test_file(size_mb)
    encrypted_path = input_path + ".enc"
    decrypted_path = input_path + ".dec"

    original_hash = calculate_sha256(input_path)
    crypto = CryptoCLI(verbose=False)

    print(f"\n🧪 Тестирование файла {size_mb} МБ...")

    # Шифрование
    start = time.time()
    crypto.encrypt_file(input_path, encrypted_path, passphrase)
    encrypt_time = time.time() - start
    encrypt_speed = (size_mb * 8) / encrypt_time
    print(f"🔒 Зашифровано за {encrypt_time:.2f} сек | {encrypt_speed:.2f} Мбит/сек")

    # Расшифрование
    start = time.time()
    crypto.decrypt_file(encrypted_path, decrypted_path, passphrase)
    decrypt_time = time.time() - start
    decrypt_speed = (size_mb * 8) / decrypt_time
    print(f"🔓 Расшифровано за {decrypt_time:.2f} сек | {decrypt_speed:.2f} Мбит/сек")

    # Проверка
    decrypted_hash = calculate_sha256(decrypted_path)
    if decrypted_hash == original_hash:
        print("🟢 Целостность данных сохранена")
    else:
        print("🔴 Ошибка! Данные повреждены!")

    # Очистка
    os.remove(input_path)
    os.remove(encrypted_path)
    os.remove(decrypted_path)

    return {
        "size": size_mb,
        "encrypt_time": encrypt_time,
        "encrypt_speed": encrypt_speed,
        "decrypt_time": decrypt_time,
        "decrypt_speed": decrypt_speed,
        "integrity_ok": (decrypted_hash == original_hash)
    }

# --- Запуск тестов на разных размерах ---
def run_performance_tests():
    sizes = [1, 5, 10, 50, 100]  # Размеры в МБ
    passphrase = "my_strong_password_123"
    results = []

    print("\n🚀 Начало нагрузочного тестирования...\n")

    for size in sizes:
        result = test_file_performance(size, passphrase)
        results.append(result)

    # --- Вывод сводного отчёта ---
    print("\n📊 Сводная таблица производительности:")
    print("-" * 70)
    print(f"{'Размер':<6} | {'Шифрование (сек)':<15} | {'Скорость':<10} | "
          f"{'Расшифр. (сек)':<15} | {'Скорость':<10} | {'Целостность'}")
    print("-" * 70)

    for r in results:
        enc_speed = f"{r['encrypt_speed']:.2f}"
        dec_speed = f"{r['decrypt_speed']:.2f}"
        integrity = "OK" if r['integrity_ok'] else "Ошибка"
        print(f"{r['size']:<6} | {r['encrypt_time']:.2f}           | {enc_speed:<10} | "
              f"{r['decrypt_time']:.2f}           | {dec_speed:<10} | {integrity}")
    print("-" * 70)

if __name__ == "__main__":
    run_performance_tests()