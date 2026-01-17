import os
import sys
import json
import time
import threading
import subprocess
import concurrent.futures
import base64
import zipfile
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple, BinaryIO
import secrets
import shutil
def check_and_install_packages():
    required_packages = ['cryptography']
    try:
        import tkinter
        from tkinter import filedialog
    except ImportError:
        print("Предупреждение: Tkinter не установлен. Графический интерфейс будет недоступен.")
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            print(f"Установка недостающего пакета: {package}")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                print(f"Пакет {package} успешно установлен")
            except Exception as e:
                print(f"Ошибка установки {package}: {e}")
                sys.exit(1)
check_and_install_packages()
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
try:
    import tkinter as tk
    from tkinter import filedialog, messagebox
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False
class KeyManager:
    KEYS_DIR = "keys"
    SYM_KEY_FILE = "aes_key.bin"
    RSA_PRIVATE_KEY_FILE = "private_key.pem"
    RSA_PUBLIC_KEY_FILE = "public_key.pem"
    KEY_INFO_FILE = "key_info.json"
    def __init__(self):
        self.symmetric_key = None
        self.rsa_private_key = None
        self.rsa_public_key = None
        self.key_info = {}
        self.ensure_keys_dir()
        self.load_keys()
    def ensure_keys_dir(self):
        os.makedirs(self.KEYS_DIR, exist_ok=True)
    def generate_symmetric_key(self, key_size: int = 32) -> bytes:
        self.symmetric_key = secrets.token_bytes(key_size)
        self.save_symmetric_key()
        return self.symmetric_key
    def generate_rsa_keys(self, key_size: int = 2048):
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        self.rsa_public_key = self.rsa_private_key.public_key()
        self.save_rsa_keys()
    def save_symmetric_key(self):
        if self.symmetric_key:
            key_path = os.path.join(self.KEYS_DIR, self.SYM_KEY_FILE)
            with open(key_path, 'wb') as f:
                f.write(self.symmetric_key)
            self.key_info['symmetric_key'] = {
                'algorithm': 'AES-256',
                'key_size': len(self.symmetric_key),
                'created': datetime.now().isoformat()
            }
            self.save_key_info()
    def save_rsa_keys(self):
        if self.rsa_private_key and self.rsa_public_key:
            private_key_path = os.path.join(self.KEYS_DIR, self.RSA_PRIVATE_KEY_FILE)
            with open(private_key_path, 'wb') as f:
                f.write(self.rsa_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            public_key_path = os.path.join(self.KEYS_DIR, self.RSA_PUBLIC_KEY_FILE)
            with open(public_key_path, 'wb') as f:
                f.write(self.rsa_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            self.key_info['rsa_keys'] = {
                'algorithm': 'RSA',
                'key_size': 2048,
                'created': datetime.now().isoformat(),
                'private_key_file': self.RSA_PRIVATE_KEY_FILE,
                'public_key_file': self.RSA_PUBLIC_KEY_FILE
            }
            self.save_key_info()
    def save_key_info(self):
        info_path = os.path.join(self.KEYS_DIR, self.KEY_INFO_FILE)
        with open(info_path, 'w', encoding='utf-8') as f:
            json.dump(self.key_info, f, indent=2, ensure_ascii=False)
    def load_keys(self):
        sym_key_path = os.path.join(self.KEYS_DIR, self.SYM_KEY_FILE)
        if os.path.exists(sym_key_path):
            try:
                with open(sym_key_path, 'rb') as f:
                    self.symmetric_key = f.read()
                print(f"Загружен симметричный ключ AES-256 ({len(self.symmetric_key)} байт)")
            except Exception as e:
                print(f"Ошибка загрузки симметричного ключа: {e}")
        private_key_path = os.path.join(self.KEYS_DIR, self.RSA_PRIVATE_KEY_FILE)
        public_key_path = os.path.join(self.KEYS_DIR, self.RSA_PUBLIC_KEY_FILE)
        if os.path.exists(private_key_path):
            try:
                with open(private_key_path, 'rb') as f:
                    self.rsa_private_key = serialization.load_pem_private_key(
                        f.read(),
                        password=None,
                        backend=default_backend()
                    )
                print(f"Загружен RSA приватный ключ")
            except Exception as e:
                print(f"Ошибка загрузки RSA приватного ключа: {e}")
        if os.path.exists(public_key_path):
            try:
                with open(public_key_path, 'rb') as f:
                    self.rsa_public_key = serialization.load_pem_public_key(
                        f.read(),
                        backend=default_backend()
                    )
                print(f"Загружен RSA публичный ключ")
            except Exception as e:
                print(f"Ошибка загрузки RSA публичного ключа: {e}")
        info_path = os.path.join(self.KEYS_DIR, self.KEY_INFO_FILE)
        if os.path.exists(info_path):
            try:
                with open(info_path, 'r', encoding='utf-8') as f:
                    self.key_info = json.load(f)
            except Exception as e:
                print(f"Ошибка загрузки информации о ключах: {e}")
    def export_keys(self, export_path: str) -> bool:
        try:
            with zipfile.ZipFile(export_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(self.KEYS_DIR):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, self.KEYS_DIR)
                        zipf.write(file_path, arcname=os.path.join('keys', arcname))
            print(f"Ключи успешно экспортированы в {export_path}")
            return True
        except Exception as e:
            print(f"Ошибка экспорта ключей: {e}")
            return False
    def import_keys(self, import_path: str) -> bool:
        try:
            temp_dir = "temp_import"
            os.makedirs(temp_dir, exist_ok=True)
            with zipfile.ZipFile(import_path, 'r') as zipf:
                zipf.extractall(temp_dir)
            keys_temp_dir = os.path.join(temp_dir, 'keys')
            if not os.path.exists(keys_temp_dir):
                keys_temp_dir = temp_dir
            for item in os.listdir(keys_temp_dir):
                src_path = os.path.join(keys_temp_dir, item)
                dst_path = os.path.join(self.KEYS_DIR, item)
                if os.path.isfile(src_path):
                    shutil.copy2(src_path, dst_path)
                elif os.path.isdir(src_path):
                    if os.path.exists(dst_path):
                        shutil.rmtree(dst_path)
                    shutil.copytree(src_path, dst_path)
            shutil.rmtree(temp_dir)
            self.load_keys()
            print(f"Ключи успешно импортированы из {import_path}")
            return True
        except Exception as e:
            print(f"Ошибка импорта ключей: {e}")
            return False
    def get_key_status(self) -> Dict[str, bool]:
        return {
            'symmetric_key': self.symmetric_key is not None,
            'rsa_private_key': self.rsa_private_key is not None,
            'rsa_public_key': self.rsa_public_key is not None
        }
class ThreadPoolManager:
    def __init__(self, max_workers: int = None):
        self.max_workers = max_workers or min(os.cpu_count() or 4, 8)
        self.executor = None
        self.futures = []
    def __enter__(self):
        self.executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_workers,
            thread_name_prefix='CryptoWorker'
        )
        return self
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.executor:
            self.executor.shutdown(wait=True)
    def submit(self, fn, *args, **kwargs):
        if not self.executor:
            raise RuntimeError("ThreadPoolManager не инициализирован")
        future = self.executor.submit(fn, *args, **kwargs)
        self.futures.append(future)
        return future
    def wait_completion(self, timeout=None):
        results = []
        for future in concurrent.futures.as_completed(self.futures, timeout=timeout):
            try:
                results.append(future.result())
            except Exception as e:
                results.append(e)
        self.futures.clear()
        return results
class ParallelEncryptor:
    BLOCK_SIZE = 1024 * 1024
    def __init__(self, console, max_workers=8):
        self.console = console
        self.max_workers = max_workers
        self.processed_blocks = 0
        self.total_blocks = 0
        self.lock = threading.Lock()
    def encrypt_chunk(self, chunk: bytes, key: bytes, iv: bytes, chunk_num: int) -> Tuple[int, bytes]:
        try:
            block_iv = self.generate_block_iv(iv, chunk_num)
            cipher = Cipher(
                algorithms.AES(key),
                modes.CFB(block_iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(chunk) + encryptor.finalize()
            with self.lock:
                self.processed_blocks += 1
            return chunk_num, (block_iv, encrypted)
        except Exception as e:
            print(f"Ошибка шифрования блока {chunk_num}: {e}")
            return chunk_num, None
    def decrypt_chunk(self, chunk: bytes, key: bytes, iv: bytes, chunk_num: int) -> Tuple[int, bytes]:
        try:
            cipher = Cipher(
                algorithms.AES(key),
                modes.CFB(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(chunk) + decryptor.finalize()
            with self.lock:
                self.processed_blocks += 1
            return chunk_num, decrypted
        except Exception as e:
            print(f"Ошибка дешифрования блока {chunk_num}: {e}")
            return chunk_num, None
    def generate_block_iv(self, base_iv: bytes, chunk_num: int) -> bytes:
        chunk_bytes = chunk_num.to_bytes(16, 'big')
        block_iv = bytearray(base_iv)
        for i in range(min(16, len(chunk_bytes))):
            block_iv[i] ^= chunk_bytes[i]
        return bytes(block_iv)
    def parallel_encrypt(self, file_data: bytes, key: bytes, iv: bytes) -> bytes:
        chunks = [file_data[i:i + self.BLOCK_SIZE]
                 for i in range(0, len(file_data), self.BLOCK_SIZE)]
        self.processed_blocks = 0
        self.total_blocks = len(chunks)
        encrypted_data = bytearray()
        block_ivs = [None] * len(chunks)
        with ThreadPoolManager(max_workers=self.max_workers) as pool:
            futures = []
            for i, chunk in enumerate(chunks):
                future = pool.submit(self.encrypt_chunk, chunk, key, iv, i)
                futures.append(future)
            results = {}
            for future in concurrent.futures.as_completed(futures):
                chunk_num, result = future.result()
                if result is not None:
                    results[chunk_num] = result
            for i in range(len(chunks)):
                if i in results:
                    block_iv, encrypted = results[i]
                    block_ivs[i] = block_iv
                    encrypted_data.extend(encrypted)
        result = bytearray()
        for block_iv in block_ivs:
            result.extend(block_iv)
        result.extend(encrypted_data)
        return bytes(result)
    def parallel_decrypt(self, encrypted_data: bytes, key: bytes, num_blocks: int) -> bytes:
        block_size = 16
        total_iv_size = num_blocks * block_size
        block_ivs_data = encrypted_data[:total_iv_size]
        actual_encrypted_data = encrypted_data[total_iv_size:]
        chunks = [actual_encrypted_data[i:i + self.BLOCK_SIZE]
                 for i in range(0, len(actual_encrypted_data), self.BLOCK_SIZE)]
        self.processed_blocks = 0
        self.total_blocks = len(chunks)
        decrypted_chunks = [None] * len(chunks)
        with ThreadPoolManager(max_workers=self.max_workers) as pool:
            futures = []
            for i, chunk in enumerate(chunks):
                block_iv = block_ivs_data[i * block_size:(i + 1) * block_size]
                future = pool.submit(self.decrypt_chunk, chunk, key, block_iv, i)
                futures.append(future)
            for future in concurrent.futures.as_completed(futures):
                chunk_num, decrypted = future.result()
                if decrypted is not None:
                    decrypted_chunks[chunk_num] = decrypted
        return b''.join(decrypted_chunks)
class ConsoleManager:
    @staticmethod
    def clear_lines(num_lines: int = 1):
        for _ in range(num_lines):
            sys.stdout.write('\033[F')
            sys.stdout.write('\033[K')
    @staticmethod
    def print_header():
        os.system('cls' if os.name == 'nt' else 'clear')
        print("=" * 60)
        print("СИСТЕМА ШИФРОВАНИЯ AES-256 С МНОГОПОТОЧНОСТЬЮ")
        print("=" * 60)
    @staticmethod
    def show_spinner(message="Обработка", delay: float = 0.1):
        spinner = ['|', '/', '-', '\\']
        idx = 0
        while getattr(threading.current_thread(), "do_run", True):
            sys.stdout.write(f"\r[{spinner[idx % len(spinner)]}] {message}...")
            sys.stdout.flush()
            time.sleep(delay)
            idx += 1
        sys.stdout.write('\r' + ' ' * 50 + '\r')
    @staticmethod
    def show_spinner_threaded(message="Обработка", delay: float = 0.1):
        spinner_thread = threading.Thread(
            target=ConsoleManager.show_spinner,
            args=(message, delay)
        )
        spinner_thread.do_run = True
        spinner_thread.start()
        return spinner_thread
    @staticmethod
    def print_progress(current, total, operation="Обработка"):
        percent = (current / total) * 100
        bar_length = 40
        filled_length = int(bar_length * current // total)
        bar = '█' * filled_length + '░' * (bar_length - filled_length)
        sys.stdout.write(f'\r{operation}: |{bar}| {percent:.1f}% ({current}/{total})')
        sys.stdout.flush()
class FileSelector:
    @staticmethod
    def select_file_gui(title="Выберите файл"):
        if not TKINTER_AVAILABLE:
            print("GUI недоступен. Введите путь к файлу:")
            return input().strip()
        root = tk.Tk()
        root.withdraw()
        file_path = filedialog.askopenfilename(title=title)
        root.destroy()
        return file_path
    @staticmethod
    def select_folder_gui(title="Выберите папку"):
        if not TKINTER_AVAILABLE:
            print("GUI недоступен. Введите путь к папке:")
            return input().strip()
        root = tk.Tk()
        root.withdraw()
        folder_path = filedialog.askdirectory(title=title)
        root.destroy()
        return folder_path
    @staticmethod
    def save_file_gui(title="Сохранить файл как"):
        if not TKINTER_AVAILABLE:
            print("GUI недоступен. Введите путь для сохранения:")
            return input().strip()
        root = tk.Tk()
        root.withdraw()
        file_path = filedialog.asksaveasfilename(title=title)
        root.destroy()
        return file_path
class AESCryptoSystem:
    def __init__(self):
        self.console = ConsoleManager()
        self.file_selector = FileSelector()
        self.key_manager = KeyManager()
        self.parallel_encryptor = None
        self.max_workers = min(os.cpu_count() or 4, 8)
        self.use_multithreading = True
        self.use_digital_signature = True
        self.compression_enabled = False
        self.initialize()
    def initialize(self):
        self.console.print_header()
        print("Инициализация системы шифрования...")
        self.parallel_encryptor = ParallelEncryptor(self.console, self.max_workers)
        key_status = self.key_manager.get_key_status()
        if not key_status['symmetric_key']:
            print("\nСимметричный ключ не найден.")
            choice = input("Сгенерировать новый ключ AES-256? (Y/n): ").strip().lower()
            if choice in ['', 'y', 'yes', 'да']:
                self.generate_symmetric_key()
        if self.use_digital_signature and not key_status['rsa_private_key']:
            print("\nRSA ключи для цифровой подписи не найдены.")
            choice = input("Сгенерировать RSA ключи для подписи? (Y/n): ").strip().lower()
            if choice in ['', 'y', 'yes', 'да']:
                self.generate_rsa_keys()
        print("\nСистема готова к работе!")
        time.sleep(1)
    def generate_symmetric_key(self):
        print("Генерация ключа AES-256...")
        spinner_thread = self.console.show_spinner_threaded("Генерация ключа")
        try:
            key = self.key_manager.generate_symmetric_key()
            spinner_thread.do_run = False
            spinner_thread.join()
            print(f"\rКлюч AES-256 успешно сгенерирован и сохранен в папке keys/")
            print(f"Длина ключа: {len(key)} байт ({len(key)*8} бит)")
            return True
        except Exception as e:
            if spinner_thread:
                spinner_thread.do_run = False
                spinner_thread.join()
            print(f"\rОшибка генерации ключа: {e}")
            return False
    def generate_rsa_keys(self):
        print("Генерация RSA ключей для цифровой подписи...")
        spinner_thread = self.console.show_spinner_threaded("Генерация RSA ключей")
        try:
            self.key_manager.generate_rsa_keys()
            spinner_thread.do_run = False
            spinner_thread.join()
            print(f"\rRSA ключи успешно сгенерированы и сохранены в папке keys/")
            print("Приватный ключ: private_key.pem")
            print("Публичный ключ: public_key.pem")
            return True
        except Exception as e:
            if spinner_thread:
                spinner_thread.do_run = False
                spinner_thread.join()
            print(f"\rОшибка генерации RSA ключей: {e}")
            return False
    def calculate_file_hash(self, file_path: str) -> bytes:
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.digest()
    def create_signature(self, data: bytes) -> Optional[bytes]:
        if not self.key_manager.rsa_private_key:
            print("RSA приватный ключ не найден!")
            return None
        try:
            data_hash = hashlib.sha256(data).digest()
            signature = self.key_manager.rsa_private_key.sign(
                data_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return signature
        except Exception as e:
            print(f"Ошибка создания подписи: {e}")
            return None
    def verify_signature(self, data: bytes, signature: bytes) -> bool:
        if not self.key_manager.rsa_public_key:
            print("RSA публичный ключ не найден!")
            return False
        try:
            data_hash = hashlib.sha256(data).digest()
            self.key_manager.rsa_public_key.verify(
                signature,
                data_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            print(f"Ошибка проверки подписи: {e}")
            return False
    def encrypt_file(self, input_path: str, output_path: str = None) -> bool:
        if not self.key_manager.symmetric_key:
            print("Симметричный ключ не найден!")
            return False
        try:
            print(f"Шифрование файла: {input_path}")
            with open(input_path, 'rb') as f:
                file_data = f.read()
            file_size = len(file_data)
            print(f"Размер файла: {file_size / 1024 / 1024:.2f} MB")
            iv = secrets.token_bytes(16)
            signature = None
            if self.use_digital_signature:
                signature = self.create_signature(file_data)
                if signature:
                    print("✓ Создана цифровая подпись")
                else:
                    print("⚠ Не удалось создать цифровую подпись")
            print("Начало шифрования...")
            spinner_thread = self.console.show_spinner_threaded("Шифрование")
            if self.use_multithreading and file_size > self.parallel_encryptor.BLOCK_SIZE:
                print(f"Используется многопоточное шифрование ({self.max_workers} потоков)")
                encrypted_data = self.parallel_encryptor.parallel_encrypt(
                    file_data,
                    self.key_manager.symmetric_key,
                    iv
                )
            else:
                print("Используется однопоточное шифрование")
                cipher = Cipher(
                    algorithms.AES(self.key_manager.symmetric_key),
                    modes.CFB(iv),
                    backend=default_backend()
                )
                encryptor = cipher.encryptor()
                encrypted_data = encryptor.update(file_data) + encryptor.finalize()
            spinner_thread.do_run = False
            spinner_thread.join()
            if not output_path:
                output_path = input_path + ".enc"
            with open(output_path, 'wb') as f:
                f.write(b'\x01')
                f.write(b'\x01' if signature else b'\x00')
                f.write(iv)
                if signature:
                    f.write(len(signature).to_bytes(4, 'big'))
                    f.write(signature)
                else:
                    f.write((0).to_bytes(4, 'big'))
                f.write(encrypted_data)
            print(f"\nФайл успешно зашифрован: {output_path}")
            print(f"Размер зашифрованного файла: {os.path.getsize(output_path) / 1024 / 1024:.2f} MB")
            if signature:
                print("✓ Файл содержит цифровую подпись")
            return True
        except Exception as e:
            if 'spinner_thread' in locals():
                spinner_thread.do_run = False
                spinner_thread.join()
            print(f"Ошибка шифрования: {e}")
            return False
    def decrypt_file(self, input_path: str, output_path: str = None) -> bool:
        if not self.key_manager.symmetric_key:
            print("Симметричный ключ не найден!")
            return False
        try:
            print(f"Дешифрование файла: {input_path}")
            with open(input_path, 'rb') as f:
                version = f.read(1)
                if version != b'\x01':
                    print("Неверная версия формата файла!")
                    return False
                has_signature = f.read(1) == b'\x01'
                iv = f.read(16)
                signature_len = int.from_bytes(f.read(4), 'big')
                signature = f.read(signature_len) if signature_len > 0 else None
                encrypted_data = f.read()
            print("Начало дешифрования...")
            spinner_thread = self.console.show_spinner_threaded("Дешифрование")
            if self.use_multithreading and len(encrypted_data) > self.parallel_encryptor.BLOCK_SIZE:
                print(f"Используется многопоточное дешифрование ({self.max_workers} потоков)")
                block_size = 16
                data_size = len(encrypted_data)
                header_size = 1 + 1 + 16 + 4 + (len(signature) if signature else 0)
                actual_encrypted_size = data_size - header_size
                num_blocks = (actual_encrypted_size + self.parallel_encryptor.BLOCK_SIZE - 1) // self.parallel_encryptor.BLOCK_SIZE
                decrypted_data = self.parallel_encryptor.parallel_decrypt(
                    encrypted_data,
                    self.key_manager.symmetric_key,
                    num_blocks
                )
            else:
                print("Используется однопоточное дешифрование")
                cipher = Cipher(
                    algorithms.AES(self.key_manager.symmetric_key),
                    modes.CFB(iv),
                    backend=default_backend()
                )
                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
            spinner_thread.do_run = False
            spinner_thread.join()
            signature_valid = False
            if has_signature and signature:
                if self.verify_signature(decrypted_data, signature):
                    print("✓ Цифровая подпись подтверждена")
                    signature_valid = True
                else:
                    print("⚠ Цифровая подпись недействительна!")
            elif has_signature and not signature:
                print("⚠ Файл должен содержать подпись, но она отсутствует")
            elif signature and not has_signature:
                print("⚠ Обнаружена подпись, но флаг подписи не установлен")
            if not output_path:
                if input_path.endswith('.enc'):
                    output_path = input_path[:-4]
                else:
                    output_path = input_path + '.decrypted'
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            print(f"\nФайл успешно расшифрован: {output_path}")
            print(f"Размер расшифрованного файла: {os.path.getsize(output_path) / 1024 / 1024:.2f} MB")
            if has_signature and signature_valid:
                print("✓ Целостность и подлинность файла подтверждены")
            return True
        except Exception as e:
            if 'spinner_thread' in locals():
                spinner_thread.do_run = False
                spinner_thread.join()
            print(f"Ошибка дешифрования: {e}")
            return False
    def encrypt_folder(self, folder_path: str, extensions: List[str] = None):
        if not self.key_manager.symmetric_key:
            print("Симметричный ключ не найден!")
            return
        print(f"Пакетное шифрование папки: {folder_path}")
        files_to_process = []
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                if extensions:
                    ext_ok = any(file_path.lower().endswith(ext.lower()) for ext in extensions)
                    if not ext_ok:
                        continue
                files_to_process.append(file_path)
        if not files_to_process:
            print("Файлы для обработки не найдены!")
            return
        print(f"Найдено файлов для обработки: {len(files_to_process)}")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_folder = os.path.join(folder_path, f"encrypted_{timestamp}")
        os.makedirs(output_folder, exist_ok=True)
        successful = 0
        failed = 0
        for i, file_path in enumerate(files_to_process, 1):
            print(f"\n[{i}/{len(files_to_process)}] Обработка: {os.path.basename(file_path)}")
            try:
                rel_path = os.path.relpath(os.path.dirname(file_path), folder_path)
                if rel_path != '.':
                    output_subfolder = os.path.join(output_folder, rel_path)
                    os.makedirs(output_subfolder, exist_ok=True)
                    output_file = os.path.join(output_subfolder, os.path.basename(file_path) + ".enc")
                else:
                    output_file = os.path.join(output_folder, os.path.basename(file_path) + ".enc")
                if self.encrypt_file(file_path, output_file):
                    successful += 1
                else:
                    failed += 1
            except Exception as e:
                print(f"Ошибка при обработке файла: {e}")
                failed += 1
        print(f"\n{'='*60}")
        print("ПАКЕТНОЕ ШИФРОВАНИЕ ЗАВЕРШЕНО")
        print(f"Успешно: {successful}")
        print(f"С ошибками: {failed}")
        print(f"Результаты сохранены в: {output_folder}")
        print(f"{'='*60}")
    def decrypt_folder(self, folder_path: str):
        if not self.key_manager.symmetric_key:
            print("Симметричный ключ не найден!")
            return
        print(f"Пакетное дешифрование папки: {folder_path}")
        encrypted_files = []
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                if file.endswith('.enc'):
                    encrypted_files.append(os.path.join(root, file))
        if not encrypted_files:
            print("Зашифрованных файлов (.enc) не найдено!")
            return
        print(f"Найдено зашифрованных файлов: {len(encrypted_files)}")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_folder = os.path.join(folder_path, f"decrypted_{timestamp}")
        os.makedirs(output_folder, exist_ok=True)
        successful = 0
        failed = 0
        for i, file_path in enumerate(encrypted_files, 1):
            print(f"\n[{i}/{len(encrypted_files)}] Обработка: {os.path.basename(file_path)}")
            try:
                rel_path = os.path.relpath(os.path.dirname(file_path), folder_path)
                if rel_path != '.':
                    output_subfolder = os.path.join(output_folder, rel_path)
                    os.makedirs(output_subfolder, exist_ok=True)
                    output_file = os.path.join(output_subfolder, os.path.basename(file_path)[:-4])
                else:
                    output_file = os.path.join(output_folder, os.path.basename(file_path)[:-4])
                if self.decrypt_file(file_path, output_file):
                    successful += 1
                else:
                    failed += 1
            except Exception as e:
                print(f"Ошибка при обработке файла: {e}")
                failed += 1
        print(f"\n{'='*60}")
        print("ПАКЕТНАЯ РАСШИФРОВКА ЗАВЕРШЕНА")
        print(f"Успешно: {successful}")
        print(f"С ошибками: {failed}")
        print(f"Результаты сохранены в: {output_folder}")
        print(f"{'='*60}")
    def export_all_keys(self):
        print("Экспорт ключей...")
        export_path = self.file_selector.save_file_gui(
            "Выберите место для сохранения ключей"
        )
        if not export_path:
            print("Экспорт отменен")
            return
        if not export_path.endswith('.zip'):
            export_path += '.zip'
        if self.key_manager.export_keys(export_path):
            print(f"Ключи успешно экспортированы в: {export_path}")
        else:
            print("Ошибка экспорта ключей")
    def import_all_keys(self):
        print("Импорт ключей...")
        import_path = self.file_selector.select_file_gui(
            "Выберите файл с ключами (.zip)"
        )
        if not import_path:
            print("Импорт отменен")
            return
        if not os.path.exists(import_path):
            print("Файл не найден!")
            return
        if self.key_manager.import_keys(import_path):
            print("Ключи успешно импортированы")
            print("Текущие ключи загружены")
        else:
            print("Ошибка импорта ключей")
    def show_key_status(self):
        self.console.print_header()
        print("СТАТУС КЛЮЧЕЙ:")
        print("=" * 60)
        key_status = self.key_manager.get_key_status()
        if key_status['symmetric_key']:
            key = self.key_manager.symmetric_key
            print(f"✓ Симметричный ключ AES-256: {len(key)} байт")
            print(f"  Хранится в: keys/{KeyManager.SYM_KEY_FILE}")
        else:
            print("✗ Симметричный ключ AES-256: ОТСУТСТВУЕТ")
        print()
        if key_status['rsa_private_key']:
            print("✓ RSA приватный ключ для подписи: НАЙДЕН")
            print(f"  Хранится в: keys/{KeyManager.RSA_PRIVATE_KEY_FILE}")
        else:
            print("✗ RSA приватный ключ для подписи: ОТСУТСТВУЕТ")
        if key_status['rsa_public_key']:
            print("✓ RSA публичный ключ для подписи: НАЙДЕН")
            print(f"  Хранится в: keys/{KeyManager.RSA_PUBLIC_KEY_FILE}")
        else:
            print("✗ RSA публичный ключ для подписи: ОТСУТСТВУЕТ")
        print()
        print("НАСТРОЙКИ СИСТЕМЫ:")
        print(f"• Многопоточность: {'ВКЛЮЧЕНА' if self.use_multithreading else 'ВЫКЛЮЧЕНА'}")
        print(f"• Количество потоков: {self.max_workers}")
        print(f"• Цифровая подпись: {'ВКЛЮЧЕНА' if self.use_digital_signature else 'ВЫКЛЮЧЕНА'}")
        print(f"• Графический интерфейс: {'Доступен' if TKINTER_AVAILABLE else 'Недоступен'}")
        print("=" * 60)
        input("\nНажмите Enter для продолжения...")
    def main_menu(self):
        while True:
            self.console.print_header()
            key_status = self.key_manager.get_key_status()
            sym_status = "✓" if key_status['symmetric_key'] else "✗"
            rsa_status = "✓" if key_status['rsa_private_key'] else "✗"
            print(f"[{sym_status}] Ключ AES-256")
            print(f"[{rsa_status}] Ключи RSA для подписи")
            print(f"[{'✓' if self.use_multithreading else '✗'}] Многопоточность ({self.max_workers} потоков)")
            print(f"[{'✓' if self.use_digital_signature else '✗'}] Цифровая подпись")
            print("=" * 60)
            print("1. Зашифровать файл")
            print("2. Расшифровать файл")
            print("3. Пакетное шифрование папки")
            print("4. Пакетная расшифровка папки")
            print("5. Сгенерировать ключ AES-256")
            print("6. Сгенерировать RSA ключи для подписи")
            print("7. Экспорт всех ключей")
            print("8. Импорт ключей")
            print("9. Показать статус ключей")
            print("10. Настройки")
            print("0. Выход")
            print("=" * 60)
            choice = input("\nВыберите действие (0-10): ").strip()
            if choice == '1':
                self.console.print_header()
                file_path = self.file_selector.select_file_gui("Выберите файл для шифрования")
                if file_path and os.path.exists(file_path):
                    self.encrypt_file(file_path)
                input("\nНажмите Enter для продолжения...")
            elif choice == '2':
                self.console.print_header()
                file_path = self.file_selector.select_file_gui("Выберите файл для расшифровки")
                if file_path and os.path.exists(file_path):
                    self.decrypt_file(file_path)
                input("\nНажмите Enter для продолжения...")
            elif choice == '3':
                self.console.print_header()
                folder_path = self.file_selector.select_folder_gui("Выберите папку для шифрования")
                if folder_path and os.path.exists(folder_path):
                    print("\nВведите расширения файлов для обработки (через запятую)")
                    print("Оставьте пустым для обработки всех файлов: ", end="")
                    extensions_input = input().strip()
                    extensions = []
                    if extensions_input:
                        extensions = [ext.strip() for ext in extensions_input.split(',')]
                        extensions = [ext if ext.startswith('.') else f'.{ext}' for ext in extensions]
                    self.encrypt_folder(folder_path, extensions)
                input("\nНажмите Enter для продолжения...")
            elif choice == '4':
                self.console.print_header()
                folder_path = self.file_selector.select_folder_gui("Выберите папку для расшифровки")
                if folder_path and os.path.exists(folder_path):
                    self.decrypt_folder(folder_path)
                input("\nНажмите Enter для продолжения...")
            elif choice == '5':
                self.generate_symmetric_key()
                input("\nНажмите Enter для продолжения...")
            elif choice == '6':
                self.generate_rsa_keys()
                input("\nНажмите Enter для продолжения...")
            elif choice == '7':
                self.export_all_keys()
                input("\nНажмите Enter для продолжения...")
            elif choice == '8':
                self.import_all_keys()
                input("\nНажмите Enter для продолжения...")
            elif choice == '9':
                self.show_key_status()
            elif choice == '10':
                self.settings_menu()
            elif choice == '0':
                print("\nЗавершение работы...")
                print("Все ключи остаются в папке 'keys/'")
                break
            else:
                print("Неверный выбор!")
                time.sleep(1)
    def settings_menu(self):
        while True:
            self.console.print_header()
            print("НАСТРОЙКИ СИСТЕМЫ")
            print("=" * 60)
            print(f"1. Многопоточность: {'ВКЛЮЧЕНА' if self.use_multithreading else 'ВЫКЛЮЧЕНА'}")
            print(f"2. Количество потоков: {self.max_workers}")
            print(f"3. Цифровая подпись: {'ВКЛЮЧЕНА' if self.use_digital_signature else 'ВЫКЛЮЧЕНА'}")
            print("4. Назад в главное меню")
            print("=" * 60)
            choice = input("\nВыберите настройку (1-4): ").strip()
            if choice == '1':
                self.use_multithreading = not self.use_multithreading
                status = "ВКЛЮЧЕНА" if self.use_multithreading else "ВЫКЛЮЧЕНА"
                print(f"\nМногопоточность {status}")
                time.sleep(1)
            elif choice == '2':
                max_possible = os.cpu_count() or 16
                print(f"\nТекущее количество потоков: {self.max_workers}")
                print(f"Доступно ядер/потоков в системе: {max_possible}")
                while True:
                    try:
                        new_count = int(input(f"Введите новое количество потоков (1-{max_possible}): ").strip())
                        if 1 <= new_count <= max_possible:
                            self.max_workers = new_count
                            self.parallel_encryptor = ParallelEncryptor(self.console, self.max_workers)
                            print(f"Количество потоков изменено на {new_count}")
                            break
                        else:
                            print(f"Введите число от 1 до {max_possible}!")
                    except ValueError:
                        print("Введите число!")
                time.sleep(1)
            elif choice == '3':
                self.use_digital_signature = not self.use_digital_signature
                status = "ВКЛЮЧЕНА" if self.use_digital_signature else "ВЫКЛЮЧЕНА"
                print(f"\nЦифровая подпись {status}")
                if self.use_digital_signature and not self.key_manager.rsa_private_key:
                    print("RSA ключи для подписи не найдены.")
                    choice = input("Сгенерировать RSA ключи? (Y/n): ").strip().lower()
                    if choice in ['', 'y', 'yes', 'да']:
                        self.generate_rsa_keys()
                time.sleep(1)
            elif choice == '4':
                break
            else:
                print("Неверный выбор!")
                time.sleep(1)
def main():
    try:
        print("Загрузка системы шифрования AES-256...")
        system = AESCryptoSystem()
        system.main_menu()
    except KeyboardInterrupt:
        print("\n\nПрограмма прервана пользователем.")
    except Exception as e:
        print(f"\nКритическая ошибка: {e}")
        import traceback
        traceback.print_exc()
        input("Нажмите Enter для выхода...")
if __name__ == "__main__":
    main()
