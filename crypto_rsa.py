import base64
import os
import sys
import json
import time
import threading
import subprocess
import concurrent.futures
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
import hashlib
def check_and_install_packages():
    required_packages = ['cryptography']
    try:
        import tkinter
        from tkinter import filedialog
    except ImportError:
        print("Предупреждение: Tkinter не установлен. Графический интерфейс будет недоступен.")
        print("Установите Tkinter: sudo apt-get install python3-tk (Linux) или установите через установщик Python (Windows)")
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
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.exceptions import InvalidSignature
try:
    import tkinter as tk
    from tkinter import filedialog
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False
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
    def encrypt_chunk(self, chunk: bytes, session_key: bytes, iv: bytes, chunk_num: int) -> Tuple[int, bytes]:
        try:
            block_iv = bytes([iv[i] ^ ((chunk_num >> (8 * i)) & 0xFF) for i in range(min(16, len(iv)))])
            block_iv = bytes([block_iv[i] ^ os.urandom(1)[0] for i in range(len(block_iv))])
            cipher = Cipher(
                algorithms.AES(session_key),
                modes.CFB(block_iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(chunk) + encryptor.finalize()
            with self.lock:
                self.processed_blocks += 1
            return chunk_num, (block_iv, encrypted)
        except Exception as e:
            return chunk_num, None
    def decrypt_chunk(self, chunk: bytes, session_key: bytes, iv: bytes, chunk_num: int) -> Tuple[int, bytes]:
        try:
            block_iv = bytes([iv[i] ^ ((chunk_num >> (8 * i)) & 0xFF) for i in range(min(16, len(iv)))])
            cipher = Cipher(
                algorithms.AES(session_key),
                modes.CFB(block_iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(chunk) + decryptor.finalize()
            with self.lock:
                self.processed_blocks += 1
            return chunk_num, decrypted
        except Exception as e:
            return chunk_num, None
    def parallel_encrypt(self, file_data: bytes, session_key: bytes, iv: bytes) -> bytes:
        chunk_size = self.BLOCK_SIZE
        chunks = [file_data[i:i + chunk_size] for i in range(0, len(file_data), chunk_size)]
        self.processed_blocks = 0
        self.total_blocks = len(chunks)
        encrypted_data = bytearray()
        block_ivs = [None] * len(chunks)
        with ThreadPoolManager(max_workers=self.max_workers) as pool:
            futures = []
            for i, chunk in enumerate(chunks):
                future = pool.submit(self.encrypt_chunk, chunk, session_key, iv, i)
                futures.append(future)
            for future in concurrent.futures.as_completed(futures):
                chunk_num, result = future.result()
                if result is not None:
                    block_iv, encrypted = result
                    block_ivs[chunk_num] = block_iv
                    encrypted_data.extend(encrypted)
        result = bytearray()
        for block_iv in block_ivs:
            result.extend(block_iv)
        result.extend(encrypted_data)
        return bytes(result)
    def parallel_decrypt(self, encrypted_data: bytes, session_key: bytes, iv: bytes, num_blocks: int) -> bytes:
        block_size = 16
        total_iv_size = num_blocks * block_size
        block_ivs_data = encrypted_data[:total_iv_size]
        actual_encrypted_data = encrypted_data[total_iv_size:]
        chunk_size = self.BLOCK_SIZE
        chunks = [actual_encrypted_data[i:i + chunk_size] for i in range(0, len(actual_encrypted_data), chunk_size)]
        self.processed_blocks = 0
        self.total_blocks = len(chunks)
        decrypted_chunks = [None] * len(chunks)
        with ThreadPoolManager(max_workers=self.max_workers) as pool:
            futures = []
            for i, chunk in enumerate(chunks):
                block_iv = block_ivs_data[i*block_size:(i+1)*block_size]
                future = pool.submit(self.decrypt_chunk, chunk, session_key, block_iv, i)
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
        spinner_thread = threading.Thread(target=ConsoleManager.show_spinner, args=(message, delay))
        spinner_thread.do_run = True
        spinner_thread.start()
        return spinner_thread
class SessionManager:
    @staticmethod
    def export_session(private_key_pem: str, public_key_pem: str,
                       other_public_key_pem: Optional[str], key_size: int,
                       max_workers: int) -> str:
        session_data = {
            "timestamp": datetime.now().isoformat(),
            "key_size": key_size,
            "private_key": private_key_pem,
            "public_key": public_key_pem,
            "other_public_key": other_public_key_pem,
            "session_id": os.urandom(16).hex(),
            "max_workers": max_workers
        }
        filename = f"session_{int(time.time())}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(session_data, f, indent=2)
        return filename
    @staticmethod
    def import_session(filename: str) -> Optional[Dict[str, Any]]:
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                session_data = json.load(f)
            required_keys = ['private_key', 'public_key', 'key_size']
            if all(key in session_data for key in required_keys):
                return session_data
            else:
                return None
        except Exception:
            return None
    @staticmethod
    def find_latest_session() -> Optional[str]:
        session_files = sorted(Path('.').glob('session_*.json'),
                             key=lambda x: x.stat().st_mtime,
                             reverse=True)
        return str(session_files[0]) if session_files else None
class FileSelector:
    @staticmethod
    def select_file_gui(title="Выберите файл"):
        if not TKINTER_AVAILABLE:
            print("GUI недоступен.")
            return None
        root = tk.Tk()
        root.withdraw()
        file_path = filedialog.askopenfilename(title=title)
        root.destroy()
        return file_path
    @staticmethod
    def select_folder_gui(title="Выберите папку"):
        if not TKINTER_AVAILABLE:
            print("GUI недоступен.")
            return None
        root = tk.Tk()
        root.withdraw()
        folder_path = filedialog.askdirectory(title=title)
        root.destroy()
        return folder_path
class SecureMessagingApp:
    def __init__(self):
        self.key_size = 4096
        self.private_key = None
        self.public_key = None
        self.other_public_key = None
        self.session_key = None
        self.session_loaded = False
        self.max_workers = min(os.cpu_count() or 4, 8)
        self.use_multithreading = True
        self.use_digital_signature = True
        self.use_timestamp = True
        self.parallel_encryptor = None
        self.console = ConsoleManager()
        self.session_manager = SessionManager()
        self.file_selector = FileSelector()
        self.initialize()
    def initialize(self):
        self.console.print_header()
        print("Инициализация системы...")
        self.parallel_encryptor = ParallelEncryptor(self.console, self.max_workers)
        latest_session = self.session_manager.find_latest_session()
        if latest_session:
            print(f"Найдена сессия: {latest_session}")
            choice = input("Загрузить сессию? (Y/n): ").strip().lower()
            if choice in ['', 'y', 'yes', 'да']:
                self.load_session(latest_session)
                return
        self.console.clear_lines(2)
        print("1. Сгенерировать новые ключи")
        print("2. Импортировать сессию из файла")
        print("3. Восстановить сессию из ключей")
        while True:
            choice = input("\nВыберите действие (1-3): ").strip()
            if choice == '1':
                self.generate_keys()
                break
            elif choice == '2':
                self.console.print_header()
                filename = self.file_selector.select_file_gui("Выберите файл сессии")
                if filename:
                    self.load_session(filename)
                break
            elif choice == '3':
                self.recover_from_keys()
                break
            else:
                print("Неверный выбор. Попробуйте снова.")
    def load_session(self, filename: str):
        self.console.print_header()
        print(f"Загрузка сессии из {filename}...")
        spinner_thread = self.console.show_spinner_threaded("Загрузка сессии")
        try:
            session_data = self.session_manager.import_session(filename)
            if session_data:
                self.key_size = session_data['key_size']
                if 'max_workers' in session_data:
                    self.max_workers = session_data['max_workers']
                    self.parallel_encryptor = ParallelEncryptor(self.console, self.max_workers)
                self.private_key = serialization.load_pem_private_key(
                    session_data['private_key'].encode('utf-8'),
                    password=None,
                    backend=default_backend()
                )
                self.public_key = self.private_key.public_key()
                if session_data['other_public_key']:
                    self.other_public_key = serialization.load_pem_public_key(
                        session_data['other_public_key'].encode('utf-8'),
                        backend=default_backend()
                    )
                spinner_thread.do_run = False
                spinner_thread.join()
                print(f"\rСессия успешно загружена из {filename}")
                self.session_loaded = True
                return True
            else:
                raise ValueError("Неверный формат сессии")
        except Exception as e:
            spinner_thread.do_run = False
            spinner_thread.join()
            print(f"\rОшибка загрузки сессии: {e}")
            return False
    def save_session_auto(self):
        if self.private_key and self.public_key:
            try:
                private_key_pem = self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode('utf-8')
                public_key_pem = self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
                other_public_key_pem = None
                if self.other_public_key:
                    other_public_key_pem = self.other_public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ).decode('utf-8')
                filename = self.session_manager.export_session(
                    private_key_pem, public_key_pem, other_public_key_pem,
                    self.key_size, self.max_workers
                )
                print(f"Сессия автоматически сохранена в {filename}")
                return filename
            except Exception as e:
                print(f"Ошибка сохранения сессии: {e}")
                return None
    def recover_from_keys(self):
        self.console.print_header()
        print("\nВосстановление сессии из ключей:")
        print("Введите ваш приватный ключ (PEM формат):")
        print("Введите 'END' на новой строке для завершения")
        private_lines = []
        while True:
            line = input()
            if line.strip().upper() == 'END':
                break
            private_lines.append(line)
        print("\nВведите публичный ключ собеседника (если есть):")
        print("Введите 'END' на новой строке для завершения или 'SKIP' для пропуска")
        public_lines = []
        while True:
            line = input()
            if line.strip().upper() in ['END', 'SKIP']:
                break
            public_lines.append(line)
        try:
            self.private_key = serialization.load_pem_private_key(
                '\n'.join(private_lines).encode('utf-8'),
                password=None,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
            if public_lines and public_lines[0].upper() != 'SKIP':
                self.other_public_key = serialization.load_pem_public_key(
                    '\n'.join(public_lines).encode('utf-8'),
                    backend=default_backend()
                )
            print("Сессия восстановлена успешно!")
            self.save_session_auto()
        except Exception as e:
            print(f"Ошибка восстановления сессии: {e}")
    def generate_keys(self):
        self.console.print_header()
        print(f"\nГенерация ключей RSA-{self.key_size}...")
        spinner_thread = self.console.show_spinner_threaded("Генерация ключей")
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        spinner_thread.do_run = False
        spinner_thread.join()
        print("\rКлючи успешно сгенерированы!          ")
    def show_public_key(self):
        if not self.public_key:
            print("Сначала сгенерируйте ключи!")
            return
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        self.console.print_header()
        print("ВАШ ПУБЛИЧНЫЙ КЛЮЧ:\n")
        print(pem)
        print("\n" + "=" * 60)
        input("\nНажмите Enter для продолжения...")
    def import_public_key(self):
        self.console.print_header()
        print("Вставьте публичный ключ собеседника ниже:")
        print("Введите 'END' на новой строке для завершения")
        lines = []
        while True:
            line = input()
            if line.strip().upper() == 'END':
                break
            lines.append(line)
        try:
            self.other_public_key = serialization.load_pem_public_key(
                '\n'.join(lines).encode('utf-8'),
                backend=default_backend()
            )
            print("Публичный ключ успешно импортирован!")
            self.save_session_auto()
            return True
        except Exception as e:
            print(f"Ошибка импорта ключа: {e}")
            return False
    def create_signature(self, data: bytes) -> bytes:
        if not self.private_key:
            raise ValueError("Приватный ключ не найден")
        signature = self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    def verify_signature(self, data: bytes, signature: bytes, public_key=None) -> bool:
        if public_key is None:
            if not self.other_public_key:
                raise ValueError("Публичный ключ для проверки не найден")
            public_key = self.other_public_key
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
    def calculate_checksum(self, data: bytes) -> bytes:
        return hashlib.sha256(data).digest()
    def encrypt_message(self):
        if not self.other_public_key:
            print("Сначала импортируйте публичный ключ собеседника!")
            return
        self.console.print_header()
        message = input("\nВведите сообщение для шифрования: ")
        if not message:
            print("Сообщение не может быть пустым!")
            return
        try:
            spinner_thread = self.console.show_spinner_threaded("Шифрование")
            if self.use_timestamp:
                timestamp = datetime.now().isoformat()
                message_with_timestamp = f"[{timestamp}] {message}"
                message_bytes = message_with_timestamp.encode()
            else:
                message_bytes = message.encode()
            checksum = self.calculate_checksum(message_bytes)
            self.session_key = os.urandom(32)
            encrypted_key = self.other_public_key.encrypt(
                self.session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            iv = os.urandom(16)
            cipher = Cipher(
                algorithms.AES(self.session_key),
                modes.CFB(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            encrypted_message = encryptor.update(message_bytes) + encryptor.finalize()
            signature = None
            if self.use_digital_signature and self.private_key:
                signature = self.create_signature(message_bytes)
            if signature:
                result = base64.b64encode(
                    len(encrypted_key).to_bytes(4, 'big') +
                    encrypted_key +
                    iv +
                    len(signature).to_bytes(4, 'big') +
                    signature +
                    checksum +
                    encrypted_message
                ).decode()
            else:
                result = base64.b64encode(
                    len(encrypted_key).to_bytes(4, 'big') +
                    encrypted_key +
                    iv +
                    checksum +
                    encrypted_message
                ).decode()
            spinner_thread.do_run = False
            spinner_thread.join()
            self.console.print_header()
            print("ЗАШИФРОВАННОЕ СООБЩЕНИЕ:\n")
            print(result)
            print("\n" + "=" * 60)
            input("\nНажмите Enter для продолжения...")
        except Exception as e:
            if 'spinner_thread' in locals():
                spinner_thread.do_run = False
                spinner_thread.join()
            print(f"Ошибка шифрования: {e}")
    def decrypt_message(self):
        if not self.private_key:
            print("Сначала сгенерируйте ключи!")
            return
        self.console.print_header()
        print("Вставьте зашифрованное сообщение:")
        print("Введите 'END' на новой строке для завершения")
        lines = []
        while True:
            line = input()
            if line.strip().upper() == 'END':
                break
            lines.append(line)
        encrypted = '\n'.join(lines)
        try:
            spinner_thread = self.console.show_spinner_threaded("Расшифровка")
            data = base64.b64decode(encrypted)
            key_len = int.from_bytes(data[:4], 'big')
            encrypted_key = data[4:4+key_len]
            iv = data[4+key_len:4+key_len+16]
            signature = None
            signature_len = 0
            checksum_len = 32
            offset = 4 + key_len + 16
            if len(data) > offset + 4:
                signature_len = int.from_bytes(data[offset:offset+4], 'big')
                if signature_len > 0:
                    signature = data[offset+4:offset+4+signature_len]
                    checksum = data[offset+4+signature_len:offset+4+signature_len+checksum_len]
                    encrypted_message = data[offset+4+signature_len+checksum_len:]
                else:
                    checksum = data[offset+4:offset+4+checksum_len]
                    encrypted_message = data[offset+4+checksum_len:]
            else:
                checksum = data[offset:offset+checksum_len]
                encrypted_message = data[offset+checksum_len:]
            session_key = self.private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            cipher = Cipher(
                algorithms.AES(session_key),
                modes.CFB(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            message_bytes = decryptor.update(encrypted_message) + decryptor.finalize()
            calculated_checksum = self.calculate_checksum(message_bytes)
            checksum_valid = checksum == calculated_checksum
            spinner_thread.do_run = False
            spinner_thread.join()
            message_text = message_bytes.decode()
            timestamp = None
            if message_text.startswith('[') and ']' in message_text:
                end_timestamp = message_text.find(']')
                if end_timestamp != -1:
                    timestamp = message_text[1:end_timestamp]
                    message_text = message_text[end_timestamp+2:]
            self.console.print_header()
            print("РАСШИФРОВАННОЕ СООБЩЕНИЕ:\n")
            if timestamp:
                print(f"Время отправки: {timestamp}")
                print(f"Сообщение: {message_text}")
            else:
                print(message_text)
            if checksum_valid:
                print("\n✓ Контрольная сумма совпадает")
            else:
                print(f"\n⚠ Контрольная сумма НЕ совпадает!")
                print(f"Ожидалось: {checksum.hex()}")
                print(f"Получено: {calculated_checksum.hex()}")
            if signature and self.other_public_key:
                if self.verify_signature(message_bytes, signature):
                    print("✓ Цифровая подпись ПОДТВЕРЖДЕНА")
                else:
                    print("⚠ Цифровая подпись НЕВЕРНА!")
            elif signature:
                print("⚠ Есть цифровая подпись, но нет ключа для проверки")
            else:
                print("⚠ Цифровая подпись отсутствует")
            print("\n" + "=" * 60)
            input("\nНажмите Enter для продолжения...")
        except Exception as e:
            if 'spinner_thread' in locals():
                spinner_thread.do_run = False
                spinner_thread.join()
            print(f"Ошибка расшифровки: {e}")
    def encrypt_file_with_signature(self, file_path: str, output_path: str = None) -> bool:
        try:
            print(f"Шифрование файла: {file_path}")
            with open(file_path, 'rb') as f:
                file_data = f.read()
            file_size = len(file_data)
            use_multithreading = self.use_multithreading and file_size > self.parallel_encryptor.BLOCK_SIZE
            session_key = os.urandom(32)
            encrypted_key = self.other_public_key.encrypt(
                session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            iv = os.urandom(16)
            checksum = self.calculate_checksum(file_data)
            signature = None
            if self.use_digital_signature and self.private_key:
                signature = self.create_signature(file_data)
            spinner_thread = self.console.show_spinner_threaded("Шифрование файла")
            if use_multithreading:
                print(f"Используется многопоточное шифрование ({self.max_workers} потоков)...")
                encrypted_data = self.parallel_encryptor.parallel_encrypt(file_data, session_key, iv)
            else:
                print("Используется однопоточное шифрование...")
                cipher = Cipher(
                    algorithms.AES(session_key),
                    modes.CFB(iv),
                    backend=default_backend()
                )
                encryptor = cipher.encryptor()
                encrypted_data = encryptor.update(file_data) + encryptor.finalize()
            spinner_thread.do_run = False
            spinner_thread.join()
            if not output_path:
                output_path = file_path + ".enc"
            with open(output_path, 'wb') as f:
                f.write(len(encrypted_key).to_bytes(4, 'big'))
                f.write(encrypted_key)
                f.write(iv)
                if signature:
                    f.write(len(signature).to_bytes(4, 'big'))
                    f.write(signature)
                else:
                    f.write((0).to_bytes(4, 'big'))
                f.write(checksum)
                f.write(encrypted_data)
            print(f"\nФайл успешно зашифрован: {output_path}")
            if signature:
                print("✓ Добавлена цифровая подпись")
            print(f"✓ Добавлена контрольная сумма")
            return True
        except Exception as e:
            if 'spinner_thread' in locals():
                spinner_thread.do_run = False
                spinner_thread.join()
            print(f"Ошибка шифрования файла: {e}")
            return False
    def decrypt_file_with_signature(self, file_path: str, output_path: str = None) -> bool:
        try:
            print(f"Расшифровка файла: {file_path}")
            with open(file_path, 'rb') as f:
                data = f.read()
            key_len = int.from_bytes(data[:4], 'big')
            encrypted_key = data[4:4+key_len]
            iv = data[4+key_len:4+key_len+16]
            signature_len = int.from_bytes(data[4+key_len+16:4+key_len+20], 'big')
            if signature_len > 0:
                signature = data[4+key_len+20:4+key_len+20+signature_len]
                checksum = data[4+key_len+20+signature_len:4+key_len+20+signature_len+32]
                encrypted_data = data[4+key_len+20+signature_len+32:]
            else:
                signature = None
                checksum = data[4+key_len+20:4+key_len+20+32]
                encrypted_data = data[4+key_len+20+32:]
            session_key = self.private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            use_multithreading = self.use_multithreading and len(encrypted_data) > self.parallel_encryptor.BLOCK_SIZE
            spinner_thread = self.console.show_spinner_threaded("Расшифровка файла")
            if use_multithreading:
                print(f"Используется многопоточная расшифровка ({self.max_workers} потоков)...")
                num_blocks = (len(encrypted_data) + self.parallel_encryptor.BLOCK_SIZE - 1) // self.parallel_encryptor.BLOCK_SIZE
                decrypted_data = self.parallel_encryptor.parallel_decrypt(encrypted_data, session_key, iv, num_blocks)
            else:
                print("Используется однопоточная расшифровка...")
                cipher = Cipher(
                    algorithms.AES(session_key),
                    modes.CFB(iv),
                    backend=default_backend()
                )
                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
            spinner_thread.do_run = False
            spinner_thread.join()
            calculated_checksum = self.calculate_checksum(decrypted_data)
            checksum_valid = checksum == calculated_checksum
            if checksum_valid:
                print("✓ Контрольная сумма совпадает")
            else:
                print(f"\n⚠ Контрольная сумма НЕ совпадает!")
                print(f"Ожидалось: {checksum.hex()}")
                print(f"Получено: {calculated_checksum.hex()}")
            if signature and self.other_public_key:
                if self.verify_signature(decrypted_data, signature):
                    print("✓ Цифровая подпись ПОДТВЕРЖДЕНА")
                else:
                    print("⚠ Цифровая подпись НЕВЕРНА!")
            elif signature:
                print("⚠ Есть цифровая подпись, но нет ключа для проверки")
            else:
                print("⚠ Цифровая подпись отсутствует")
            if not output_path:
                if file_path.endswith('.enc'):
                    output_path = file_path[:-4]
                else:
                    output_path = file_path + '.decrypted'
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            print(f"\nФайл успешно расшифрован: {output_path}")
            return True
        except Exception as e:
            if 'spinner_thread' in locals():
                spinner_thread.do_run = False
                spinner_thread.join()
            print(f"Ошибка расшифровки файла: {e}")
            return False
    def encrypt_file(self):
        if not self.other_public_key:
            print("Сначала импортируйте публичный ключ собеседника!")
            return
        self.console.print_header()
        file_path = self.file_selector.select_file_gui("Выберите файл для шифрования")
        if not file_path:
            print("Файл не выбран!")
            return
        if not os.path.exists(file_path):
            print("Файл не найден!")
            return
        self.encrypt_file_with_signature(file_path)
    def decrypt_file(self):
        if not self.private_key:
            print("Сначала сгенерируйте ключи!")
            return
        self.console.print_header()
        file_path = self.file_selector.select_file_gui("Выберите файл для расшифровки")
        if not file_path:
            print("Файл не выбран!")
            return
        if not os.path.exists(file_path):
            print("Файл не найден!")
            return
        self.decrypt_file_with_signature(file_path)
    def encrypt_folder_batch(self):
        if not self.other_public_key:
            print("Сначала импортируйте публичный ключ собеседника!")
            return
        self.console.print_header()
        print("ПАКЕТНОЕ ШИФРОВАНИЕ ФАЙЛОВ В ПАПКЕ\n")
        folder_path = self.file_selector.select_folder_gui("Выберите папку для шифрования")
        if not folder_path:
            print("Папка не выбрана!")
            return
        if not os.path.exists(folder_path) or not os.path.isdir(folder_path):
            print("Папка не найдена!")
            return
        print("\nВведите расширения файлов для обработки (через запятую)")
        print("Оставьте пустым для обработки всех файлов: ", end="")
        extensions_input = input().strip()
        extensions = []
        if extensions_input:
            extensions = [ext.strip().lower() for ext in extensions_input.split(',')]
            extensions = [ext if ext.startswith('.') else f'.{ext}' for ext in extensions]
        files_to_process = []
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                if extensions:
                    if any(file_path.lower().endswith(ext) for ext in extensions):
                        files_to_process.append(file_path)
                else:
                    files_to_process.append(file_path)
        if not files_to_process:
            print("Файлы для обработки не найдены!")
            return
        print(f"\nНайдено файлов для обработки: {len(files_to_process)}")
        print("\nПараметры обработки:")
        print(f"Использовать многопоточность: {'Да' if self.use_multithreading else 'Нет'}")
        print(f"Добавлять цифровую подпись: {'Да' if self.use_digital_signature else 'Нет'}")
        confirm = input("\nНачать пакетное шифрование? (Y/n): ").strip().lower()
        if confirm not in ['', 'y', 'yes', 'да']:
            print("Операция отменена")
            return
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_folder = os.path.join(folder_path, f"encrypted_{timestamp}")
        os.makedirs(output_folder, exist_ok=True)
        successful = 0
        failed = 0
        for i, file_path in enumerate(files_to_process, 1):
            print(f"\n[{i}/{len(files_to_process)}] Обработка: {os.path.basename(file_path)}")
            try:
                relative_path = os.path.relpath(os.path.dirname(file_path), folder_path)
                if relative_path == '.':
                    relative_path = ''
                output_subfolder = os.path.join(output_folder, relative_path)
                os.makedirs(output_subfolder, exist_ok=True)
                output_file = os.path.join(output_subfolder, os.path.basename(file_path) + ".enc")
                if self.encrypt_file_with_signature(file_path, output_file):
                    successful += 1
                else:
                    failed += 1
            except Exception as e:
                print(f"Ошибка при обработке файла {file_path}: {e}")
                failed += 1
        print(f"\n{'='*60}")
        print("ПАКЕТНОЕ ШИФРОВАНИЕ ЗАВЕРШЕНО")
        print(f"Успешно: {successful}")
        print(f"С ошибками: {failed}")
        print(f"Результаты сохранены в: {output_folder}")
        print(f"{'='*60}")
        input("\nНажмите Enter для продолжения...")
    def decrypt_folder_batch(self):
        if not self.private_key:
            print("Сначала сгенерируйте ключи!")
            return
        self.console.print_header()
        print("ПАКЕТНАЯ РАСШИФРОВКА ФАЙЛОВ В ПАПКЕ\n")
        folder_path = self.file_selector.select_folder_gui("Выберите папку для расшифровки")
        if not folder_path:
            print("Папка не выбрана!")
            return
        if not os.path.exists(folder_path) or not os.path.isdir(folder_path):
            print("Папка не найдена!")
            return
        encrypted_files = []
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                if file.endswith('.enc'):
                    encrypted_files.append(os.path.join(root, file))
        if not encrypted_files:
            print("Зашифрованных файлов (.enc) не найдено!")
            return
        print(f"\nНайдено зашифрованных файлов: {len(encrypted_files)}")
        print("\nПараметры обработки:")
        print(f"Использовать многопоточность: {'Да' if self.use_multithreading else 'Нет'}")
        print(f"Проверять цифровую подпись: {'Да' if self.use_digital_signature else 'Нет'}")
        confirm = input("\nНачать пакетную расшифровку? (Y/n): ").strip().lower()
        if confirm not in ['', 'y', 'yes', 'да']:
            print("Операция отменена")
            return
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_folder = os.path.join(folder_path, f"decrypted_{timestamp}")
        os.makedirs(output_folder, exist_ok=True)
        successful = 0
        failed = 0
        for i, file_path in enumerate(encrypted_files, 1):
            print(f"\n[{i}/{len(encrypted_files)}] Обработка: {os.path.basename(file_path)}")
            try:
                relative_path = os.path.relpath(os.path.dirname(file_path), folder_path)
                if relative_path == '.':
                    relative_path = ''
                output_subfolder = os.path.join(output_folder, relative_path)
                os.makedirs(output_subfolder, exist_ok=True)
                output_file = os.path.join(output_subfolder, os.path.basename(file_path)[:-4])
                if self.decrypt_file_with_signature(file_path, output_file):
                    successful += 1
                else:
                    failed += 1
            except Exception as e:
                print(f"Ошибка при обработке файла {file_path}: {e}")
                failed += 1
        print(f"\n{'='*60}")
        print("ПАКЕТНАЯ РАСШИФРОВКА ЗАВЕРШЕНА")
        print(f"Успешно: {successful}")
        print(f"С ошибками: {failed}")
        print(f"Результаты сохранены в: {output_folder}")
        print(f"{'='*60}")
        input("\nНажмите Enter для продолжения...")
    def change_key_size(self):
        self.console.print_header()
        print(f"\nТекущий размер ключа: {self.key_size} бит")
        print("Доступные размеры: 4096, 8192")
        while True:
            try:
                new_size = int(input("Введите новый размер ключа: ").strip())
                if new_size in [4096, 8192]:
                    self.key_size = new_size
                    print(f"Размер ключа изменен на {new_size} бит")
                    print("Не забудьте сгенерировать новые ключи!")
                    break
                else:
                    print("Доступны только размеры 4096 или 8192 бит!")
            except ValueError:
                print("Введите число (4096 или 8192)!")
    def change_thread_count(self):
        self.console.print_header()
        max_possible = os.cpu_count() or 16
        print(f"\nТекущее количество потоков: {self.max_workers}")
        print(f"Доступно ядер/потоков в системе: {max_possible}")
        print(f"Рекомендуется: от 2 до {min(16, max_possible)} потоков")
        while True:
            try:
                new_count = int(input(f"Введите новое количество потоков (1-{max_possible}): ").strip())
                if 1 <= new_count <= max_possible:
                    self.max_workers = new_count
                    self.parallel_encryptor = ParallelEncryptor(self.console, self.max_workers)
                    print(f"Количество потоков изменено на {new_count}")
                    if self.private_key:
                        self.save_session_auto()
                    break
                else:
                    print(f"Введите число от 1 до {max_possible}!")
            except ValueError:
                print("Введите число!")
    def toggle_multithreading(self):
        self.use_multithreading = not self.use_multithreading
        status = "ВКЛЮЧЕНА" if self.use_multithreading else "ВЫКЛЮЧЕНА"
        print(f"\nМногопоточность {status}")
        time.sleep(1)
    def toggle_digital_signature(self):
        self.use_digital_signature = not self.use_digital_signature
        status = "ВКЛЮЧЕНА" if self.use_digital_signature else "ВЫКЛЮЧЕНА"
        print(f"\nЦифровая подпись {status}")
        time.sleep(1)
    def toggle_timestamp(self):
        self.use_timestamp = not self.use_timestamp
        status = "ВКЛЮЧЕН" if self.use_timestamp else "ВЫКЛЮЧЕН"
        print(f"\nTimestamp в сообщениях {status}")
        time.sleep(1)
    def show_status(self):
        self.console.print_header()
        print("СТАТУС СЕССИИ:")
        print("=" * 60)
        key_status = "СГЕНЕРИРОВАНЫ" if self.private_key else "ОТСУТСТВУЮТ"
        print(f"Ваши ключи: {key_status}")
        if self.private_key:
            print(f"Размер ключа: {self.key_size} бит")
        other_key_status = "ИМПОРТИРОВАН" if self.other_public_key else "ОТСУТСТВУЕТ"
        print(f"Ключ собеседника: {other_key_status}")
        threading_status = "ВКЛЮЧЕНА" if self.use_multithreading else "ВЫКЛЮЧЕНА"
        print(f"Многопоточность: {threading_status}")
        print(f"Количество потоков: {self.max_workers}")
        print(f"Доступно ядер CPU: {os.cpu_count() or 'N/A'}")
        signature_status = "ВКЛЮЧЕНА" if self.use_digital_signature else "ВЫКЛЮЧЕНА"
        print(f"Цифровая подпись: {signature_status}")
        timestamp_status = "ВКЛЮЧЕН" if self.use_timestamp else "ВЫКЛЮЧЕН"
        print(f"Timestamp в сообщениях: {timestamp_status}")
        print(f"Графический интерфейс: {'Доступен' if TKINTER_AVAILABLE else 'Недоступен'}")
        latest_session = self.session_manager.find_latest_session()
        if latest_session:
            session_time = datetime.fromtimestamp(os.path.getmtime(latest_session))
            print(f"Последняя сессия: {session_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        input("\nНажмите Enter для продолжения...")
    def main_menu(self):
        while True:
            self.console.print_header()
            if self.private_key:
                print("[✓] Ваши ключи готовы")
            else:
                print("[!] Ключи не сгенерированы")
            if self.other_public_key:
                print("[✓] Ключ собеседника загружен")
            else:
                print("[!] Ключ собеседника отсутствует")
            threading_status = "✓ ВКЛ" if self.use_multithreading else "✗ ВЫКЛ"
            print(f"[{threading_status}] Многопоточность ({self.max_workers} потоков)")
            signature_status = "✓ ВКЛ" if self.use_digital_signature else "✗ ВЫКЛ"
            print(f"[{signature_status}] Цифровая подпись")
            timestamp_status = "✓ ВКЛ" if self.use_timestamp else "✗ ВЫКЛ"
            print(f"[{timestamp_status}] Timestamp в сообщениях")
            print("=" * 60)
            print("1. Сгенерировать новые ключи")
            print("2. Показать мой публичный ключ")
            print("3. Импортировать ключ собеседника")
            print("4. Зашифровать сообщение")
            print("5. Расшифровать сообщение")
            print("6. Зашифровать файл")
            print("7. Расшифровать файл")
            print("8. Пакетное шифрование папки")
            print("9. Пакетная расшифровка папки")
            print(f"10. Изменить размер ключа (сейчас: {self.key_size})")
            print(f"11. Изменить количество потоков (сейчас: {self.max_workers})")
            print(f"12. Вкл/Выкл многопоточность (сейчас: {'ВКЛ' if self.use_multithreading else 'ВЫКЛ'})")
            print(f"13. Вкл/Выкл цифровую подпись (сейчас: {'ВКЛ' if self.use_digital_signature else 'ВЫКЛ'})")
            print(f"14. Вкл/Выкл timestamp в сообщениях (сейчас: {'ВКЛ' if self.use_timestamp else 'ВЫКЛ'})")
            print("15. Показать статус сессии")
            print("0. Выход")
            print("=" * 60)
            choice = input("\nВыберите действие (0-15): ").strip()
            if choice == '1':
                self.generate_keys()
            elif choice == '2':
                self.show_public_key()
            elif choice == '3':
                self.import_public_key()
            elif choice == '4':
                self.encrypt_message()
            elif choice == '5':
                self.decrypt_message()
            elif choice == '6':
                self.encrypt_file()
            elif choice == '7':
                self.decrypt_file()
            elif choice == '8':
                self.encrypt_folder_batch()
            elif choice == '9':
                self.decrypt_folder_batch()
            elif choice == '10':
                self.change_key_size()
            elif choice == '11':
                self.change_thread_count()
            elif choice == '12':
                self.toggle_multithreading()
            elif choice == '13':
                self.toggle_digital_signature()
            elif choice == '14':
                self.toggle_timestamp()
            elif choice == '15':
                self.show_status()
            elif choice == '0':
                print("\nЗавершение работы...")
                print("Все ключи удалены из памяти.")
                break
            else:
                print("Неверный выбор!")
                time.sleep(1)
def main():
    try:
        app = SecureMessagingApp()
        app.main_menu()
    except KeyboardInterrupt:
        print("\n\nПрограмма прервана.")
    except Exception as e:
        print(f"\nКритическая ошибка: {e}")
        input("Нажмите Enter для выхода...")
if __name__ == "__main__":
    main()
