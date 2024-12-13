import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_file(input_file: str, output_file: str, key: bytes) -> bytes:

    # Генеруємо випадковий вектор ініціалізації (IV)
    iv = os.urandom(12)  # 12 байтів для GCM

    # Читаємо дані з вхідного файлу
    with open(input_file, 'rb') as f:
        plaintext = f.read()

    # Створюємо об'єкт шифрування
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    # Шифруємо дані
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Записуємо шифротекст та IV у вихідний файл
    with open(output_file, 'wb') as f:
        f.write(iv + ciphertext)

    # Повертаємо тег аутентифікації
    return encryptor.tag

if __name__ == "__main__":
    input_path = input("Введіть шлях до текстового файлу: ").strip().strip('"')
    output_path = input("Введіть шлях для збереження шифротексту: ").strip().strip('"')

    # Перевіряємо, чи введено коректний шлях до файлу
    if os.path.isdir(output_path):
        print("Помилка: Ви вказали папку, а не файл для збереження. Додайте ім'я файлу, наприклад, 'ciphertext.bin'.")
        exit(1)

    # Генеруємо випадковий AES-ключ
    aes_key = os.urandom(32)  # 256-бітовий ключ

    # Виконуємо шифрування
    try:
        tag = encrypt_file(input_path, output_path, aes_key)
        print(f"Шифрування завершено! Тег автентифікації: {tag.hex()}")

        # Пропонуємо переглянути шифротекст
        view_choice = input("Бажаєте переглянути шифротекст? (так/ні): ").strip().lower()
        if view_choice in ["так"]:
            with open(output_path, 'rb') as f:
                ciphertext = f.read()
                print(f"Шифротекст (у двійковому вигляді): {ciphertext.hex()}")

    except FileNotFoundError:
        print("Файл не знайдено. Перевірте правильність шляху.")
    except PermissionError:
        print("Помилка доступу: Перевірте права доступу до папки або файлу.")
    except Exception as e:
        print(f"Сталася помилка: {e}")
