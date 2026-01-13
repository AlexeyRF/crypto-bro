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
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key

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
        print("КРИПТОГРАФИЧЕСКАЯ СИСТЕМА НА ЭЛЛИПТИЧЕСКИХ КРИВЫХ")
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
                       other_public_key_pem: Optional[str], curve_name: str, 
                       max_workers: int, signature_algorithm: str) -> str:
        
        session_data = {
            "timestamp": datetime.now().isoformat(),
            "curve_name": curve_name,
            "private_key": private_key_pem,
            "public_key": public_key_pem,
            "other_public_key": other_public_key_pem,
            "session_id": os.urandom(16).hex(),
            "max_workers": max_workers,
            "signature_algorithm": signature_algorithm
        }
        
        filename = f"ecc_session_{int(time.time())}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(session_data, f, indent=2)
        
        return filename
    
    @staticmethod
    def import_session(filename: str) -> Optional[Dict[str, Any]]:
        
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                session_data = json.load(f)
            
            required_keys = ['private_key', 'public_key', 'curve_name']
            if all(key in session_data for key in required_keys):
                return session_data
            else:
                return None
        except Exception:
            return None
    
    @staticmethod
    def find_latest_session() -> Optional[str]:
        
        session_files = sorted(Path('.').glob('ecc_session_*.json'), 
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

class SecureMessagingAppECC:
    def __init__(self):
        
        self.available_curves = {
            'SECP256R1': ec.SECP256R1,
            'SECP384R1': ec.SECP384R1,
            'SECP521R1': ec.SECP521R1,
            'SECP256K1': ec.SECP256K1,
        }
        
        
        self.available_signature_algs = {
            'ECDSA-SHA256': (ec.ECDSA(hashes.SHA256()), hashes.SHA256),
            'ECDSA-SHA384': (ec.ECDSA(hashes.SHA384()), hashes.SHA384),
            'ECDSA-SHA512': (ec.ECDSA(hashes.SHA512()), hashes.SHA512),
        }
        
        self.selected_curve = 'SECP256R1'
        self.private_key = None
        self.public_key = None
        self.other_public_key = None
        self.session_key = None
        self.session_loaded = False
        self.max_workers = min(os.cpu_count() or 4, 8)
        self.use_multithreading = True
        self.use_digital_signature = True
        self.use_timestamp = True
        self.signature_algorithm = 'ECDSA-SHA256'
        self.parallel_encryptor = None
        self.console = ConsoleManager()
        self.session_manager = SessionManager()
        self.file_selector = FileSelector()
        
        self.initialize()
    
    def show_curve_help(self):
        
        self.console.print_header()
        print("СПРАВКА ПО ВЫБОРУ ЭЛЛИПТИЧЕСКИХ КРИВЫХ")
        print("=" * 60)
        print("\n📊 СРАВНЕНИЕ КРИВЫХ:")
        print("-" * 40)
        print("1. SECP256R1 (P-256):")
        print("   • Безопасность: ~128 бит")
        print("   • Рекомендуется: ✅ ЛУЧШИЙ ВЫБОР для большинства случаев")
        print("   • Применение: TLS, SSH, документы, общая безопасность")
        print("   • Размер ключа: 32 байта")
        print("   • Скорость: Высокая")
        
        print("\n2. SECP384R1 (P-384):")
        print("   • Безопасность: ~192 бит")
        print("   • Рекомендуется: ✅ Высокая безопасность")
        print("   • Применение: Военные, государственные, банковские данные")
        print("   • Размер ключа: 48 байт")
        print("   • Скорость: Средняя")
        
        print("\n3. SECP521R1 (P-521):")
        print("   • Безопасность: ~256 бит")
        print("   • Рекомендуется: ✅ Максимальная безопасность")
        print("   • Применение: Сверхсекретные данные, долгосрочное хранение")
        print("   • Размер ключа: 66 байт")
        print("   • Скорость: Низкая")
        
        print("\n4. SECP256K1:")
        print("   • Безопасность: ~128 бит")
        print("   • Рекомендуется: ⚠ Только для совместимости с Bitcoin")
        print("   • Применение: Криптовалюты, блокчейн")
        print("   • Размер ключа: 32 байта")
        print("   • Скорость: Высокая")
        
        print("\n" + "=" * 60)
        print("🏆 РЕКОМЕНДАЦИИ:")
        print("-" * 40)
        print("• НОВИЧКАМ и ДЛЯ ОБЩЕГО ИСПОЛЬЗОВАНИЯ:")
        print("  → Выберите SECP256R1")
        
        print("\n• ДЛЯ ВЫСОКОЙ БЕЗОПАСНОСТИ (документы, пароли):")
        print("  → Выберите SECP384R1")
        
        print("\n• ДЛЯ МАКСИМАЛЬНОЙ БЕЗОПАСНОСТИ (гос. тайны, долгосрочное):")
        print("  → Выберите SECP521R1")
        
        print("\n• ТОЛЬКО ДЛЯ КРИПТОВАЛЮТ И БЛОКЧЕЙН:")
        print("  → Выберите SECP256K1")
        
        print("\n" + "=" * 60)
        input("\nНажмите Enter для продолжения...")
    
    def show_signature_algorithm_help(self):
        
        self.console.print_header()
        print("СПРАВКА ПО АЛГОРИТМАМ ПОДПИСИ")
        print("=" * 60)
        print("\n📊 СРАВНЕНИЕ АЛГОРИТМОВ:")
        print("-" * 40)
        print("1. ECDSA-SHA256:")
        print("   • Хэш-функция: SHA-256 (256 бит)")
        print("   • Рекомендуется: ✅ СОВМЕСТИМЫЙ С SECP256R1")
        print("   • Совместимость: Широкая, современные системы")
        print("   • Производительность: Высокая")
        print("   • Размер подписи: ~64-72 байта")
        
        print("\n2. ECDSA-SHA384:")
        print("   • Хэш-функция: SHA-384 (384 бит)")
        print("   • Рекомендуется: ✅ СОВМЕСТИМЫЙ С SECP384R1")
        print("   • Совместимость: Современные системы, высокая безопасность")
        print("   • Производительность: Средняя")
        print("   • Размер подписи: ~96-104 байта")
        
        print("\n3. ECDSA-SHA512:")
        print("   • Хэш-функция: SHA-512 (512 бит)")
        print("   • Рекомендуется: ✅ СОВМЕСТИМЫЙ С SECP521R1")
        print("   • Совместимость: Максимальная безопасность")
        print("   • Производительность: Низкая")
        print("   • Размер подписи: ~132-140 байт")
        
        print("\n" + "=" * 60)
        print("🔗 РЕКОМЕНДАЦИИ ПО СОВМЕСТИМОСТИ:")
        print("-" * 40)
        print("• Для SECP256R1 → ECDSA-SHA256")
        print("• Для SECP384R1 → ECDSA-SHA384")
        print("• Для SECP521R1 → ECDSA-SHA512")
        print("• Для SECP256K1 → ECDSA-SHA256")
        
        print("\n📈 ОБЩАЯ РЕКОМЕНДАЦИЯ:")
        print("-" * 40)
        print("• Оставьте значение по умолчанию ECDSA-SHA256")
        print("• Измените только если нужно точное соответствие кривой")
        
        print("\n" + "=" * 60)
        input("\nНажмите Enter для продолжения...")
    
    def initialize(self):
        self.console.print_header()
        print("Инициализация системы...")
                
        self.parallel_encryptor = ParallelEncryptor(self.console, self.max_workers)
        latest_session = self.session_manager.find_latest_session()
        if latest_session:
            print(f"\nНайдена сессия: {latest_session}")
            choice = input("Загрузить сессию? (Y/n): ").strip().lower()
            if choice in ['', 'y', 'yes', 'да']:
                self.load_session(latest_session)
                return
        
        self.console.clear_lines(2)
        print("\n1. Сгенерировать новые ключи")
        print("2. Импортировать сессию из файла")
        print("3. Восстановить сессию из ключей")
        print("4. Справка по выбору кривых")
        print("5. Справка по алгоритмам подписи")
        
        while True:
            choice = input("\nВыберите действие (1-5): ").strip()
            
            if choice == '1':
                self.choose_curve_and_algorithm()
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
            elif choice == '4':
                self.show_curve_help()
                self.console.print_header()
                print("Продолжим настройку...")
                print("1. Сгенерировать новые ключи")
                print("2. Импортировать сессию из файла")
                print("3. Восстановить сессию из ключей")
                print("4. Справка по выбору кривых")
                print("5. Справка по алгоритмам подписи")
            elif choice == '5':
                self.show_signature_algorithm_help()
                self.console.print_header()
                print("Продолжим настройку...")
                print("1. Сгенерировать новые ключи")
                print("2. Импортировать сессию из файла")
                print("3. Восстановить сессию из ключей")
                print("4. Справка по выбору кривых")
                print("5. Справка по алгоритмам подписи")
            else:
                print("Неверный выбор. Попробуйте снова.")
    
    def choose_curve_and_algorithm(self):
        
        self.console.print_header()
        print("ВЫБОР КОНФИГУРАЦИИ")
        print("=" * 60)
        
        print("\nДоступные эллиптические кривые:")
        for i, curve_name in enumerate(self.available_curves.keys(), 1):
            if curve_name == 'SECP256R1':
                print(f"{i}. {curve_name} ✅ РЕКОМЕНДУЕТСЯ")
            else:
                print(f"{i}. {curve_name}")
        
        while True:
            try:
                choice = int(input(f"\nВыберите кривую (1-{len(self.available_curves)}): ").strip())
                if 1 <= choice <= len(self.available_curves):
                    self.selected_curve = list(self.available_curves.keys())[choice-1]
                    print(f"Выбрана кривая: {self.selected_curve}")
                    break
                else:
                    print(f"Введите число от 1 до {len(self.available_curves)}")
            except ValueError:
                print("Введите число!")
        
        print("\nДоступные алгоритмы подписи:")
        for i, alg_name in enumerate(self.available_signature_algs.keys(), 1):
            if alg_name == 'ECDSA-SHA256':
                print(f"{i}. {alg_name} ✅ ПО УМОЛЧАНИЮ")
            else:
                print(f"{i}. {alg_name}")
        
        while True:
            try:
                choice = int(input(f"\nВыберите алгоритм подписи (1-{len(self.available_signature_algs)}): ").strip())
                if 1 <= choice <= len(self.available_signature_algs):
                    self.signature_algorithm = list(self.available_signature_algs.keys())[choice-1]
                    print(f"Выбран алгоритм: {self.signature_algorithm}")
                    break
                else:
                    print(f"Введите число от 1 до {len(self.available_signature_algs)}")
            except ValueError:
                print("Введите число!")
        
        print("\n" + "=" * 60)
        print(f"КОНФИГУРАЦИЯ УСТАНОВЛЕНА:")
        print(f"• Кривая: {self.selected_curve}")
        print(f"• Алгоритм подписи: {self.signature_algorithm}")
        print("=" * 60)
        
        time.sleep(1)
    
    def load_session(self, filename: str):
        
        self.console.print_header()
        print(f"Загрузка сессии из {filename}...")
        
        spinner_thread = self.console.show_spinner_threaded("Загрузка сессии")
        
        try:
            session_data = self.session_manager.import_session(filename)
            
            if session_data:
                self.selected_curve = session_data['curve_name']
                
                if 'max_workers' in session_data:
                    self.max_workers = session_data['max_workers']
                    self.parallel_encryptor = ParallelEncryptor(self.console, self.max_workers)
                
                if 'signature_algorithm' in session_data:
                    self.signature_algorithm = session_data['signature_algorithm']
                
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
                    self.selected_curve, self.max_workers, self.signature_algorithm
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
        print(f"\nГенерация ключей на кривой {self.selected_curve}...")
        
        spinner_thread = self.console.show_spinner_threaded("Генерация ключей")
        
        try:
            curve_class = self.available_curves[self.selected_curve]
            self.private_key = ec.generate_private_key(
                curve_class(),
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
            
            spinner_thread.do_run = False
            spinner_thread.join()
            
            print(f"\rКлючи успешно сгенерированы на кривой {self.selected_curve}!")
            
        except Exception as e:
            if spinner_thread:
                spinner_thread.do_run = False
                spinner_thread.join()
            print(f"\rОшибка генерации ключей: {e}")
    
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
        print(f"\nКривая: {self.selected_curve}")
        print(f"Размер ключа: {len(pem)} символов")
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
    
    def derive_shared_key(self, public_key=None):
        
        if public_key is None:
            if not self.other_public_key:
                raise ValueError("Публичный ключ собеседника не найден")
            public_key = self.other_public_key
        
        
        shared_secret = self.private_key.exchange(ec.ECDH(), public_key)
        
        
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'encryption',
            backend=default_backend()
        ).derive(shared_secret)
        
        return derived_key
    
    def create_signature(self, data: bytes) -> bytes:
        
        if not self.private_key:
            raise ValueError("Приватный ключ не найден")
        
        signature_algorithm, _ = self.available_signature_algs[self.signature_algorithm]
        
        signature = self.private_key.sign(
            data,
            signature_algorithm
        )
        return signature
    
    def verify_signature(self, data: bytes, signature: bytes, public_key=None) -> bool:
        
        if public_key is None:
            if not self.other_public_key:
                raise ValueError("Публичный ключ для проверки не найден")
            public_key = self.other_public_key
        
        _, hash_class = self.available_signature_algs[self.signature_algorithm]
        
        try:
            public_key.verify(
                signature,
                data,
                ec.ECDSA(hash_class())
            )
            return True
        except InvalidSignature:
            return False
        except Exception:
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
            
            
            curve_class = self.available_curves[self.selected_curve]
            ephemeral_private_key = ec.generate_private_key(
                curve_class(),
                backend=default_backend()
            )
            ephemeral_public_key = ephemeral_private_key.public_key()
            
            
            shared_key = ephemeral_private_key.exchange(ec.ECDH(), self.other_public_key)
            
            
            session_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'message-encryption',
                backend=default_backend()
            ).derive(shared_key)
            
            
            iv = os.urandom(16)
            cipher = Cipher(
                algorithms.AES(session_key),
                modes.CFB(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            encrypted_message = encryptor.update(message_bytes) + encryptor.finalize()
            
            
            signature = None
            if self.use_digital_signature and self.private_key:
                signature = self.create_signature(message_bytes)
            
            
            ephemeral_pub_key_bytes = ephemeral_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            
            result_data = b''
            
            
            result_data += len(ephemeral_pub_key_bytes).to_bytes(4, 'big')
            result_data += ephemeral_pub_key_bytes
            
            
            result_data += iv
            
            
            if signature:
                result_data += len(signature).to_bytes(4, 'big')
                result_data += signature
            
            
            result_data += checksum
            
            
            result_data += encrypted_message
            
            
            result = base64.b64encode(result_data).decode('utf-8')
            
            spinner_thread.do_run = False
            spinner_thread.join()
            
            self.console.print_header()
            print("ЗАШИФРОВАННОЕ СООБЩЕНИЕ:\n")
            print(result)
            print(f"\nИспользована кривая: {self.selected_curve}")
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
            ephemeral_pub_key_bytes = data[4:4+key_len]
            ephemeral_public_key = serialization.load_pem_public_key(
                ephemeral_pub_key_bytes,
                backend=default_backend()
            )
            
            
            iv = data[4+key_len:4+key_len+16]
            
            
            remaining = data[4+key_len+16:]
            
            
            signature = None
            signature_len = 0
            checksum_len = 32  
            
            offset = 0
            
            
            if len(remaining) > 4:
                signature_len = int.from_bytes(remaining[offset:offset+4], 'big')
                if signature_len > 0:
                    signature = remaining[offset+4:offset+4+signature_len]
                    checksum = remaining[offset+4+signature_len:offset+4+signature_len+checksum_len]
                    encrypted_message = remaining[offset+4+signature_len+checksum_len:]
                else:
                    checksum = remaining[offset+4:offset+4+checksum_len]
                    encrypted_message = remaining[offset+4+checksum_len:]
            else:
                checksum = remaining[offset:offset+checksum_len]
                encrypted_message = remaining[offset+checksum_len:]
            
            
            shared_key = self.private_key.exchange(ec.ECDH(), ephemeral_public_key)
            
            
            session_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'message-encryption',
                backend=default_backend()
            ).derive(shared_key)
            
            
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
            
            
            message_text = message_bytes.decode('utf-8')
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
            
            print(f"\nИспользована кривая: {self.selected_curve}")
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
            
            
            curve_class = self.available_curves[self.selected_curve]
            ephemeral_private_key = ec.generate_private_key(
                curve_class(),
                backend=default_backend()
            )
            ephemeral_public_key = ephemeral_private_key.public_key()
            
            
            shared_key = ephemeral_private_key.exchange(ec.ECDH(), self.other_public_key)
            
            
            session_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'file-encryption',
                backend=default_backend()
            ).derive(shared_key)
            
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
            
            
            ephemeral_pub_key_bytes = ephemeral_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            if not output_path:
                output_path = file_path + ".enc"
            
            with open(output_path, 'wb') as f:
                
                f.write(len(ephemeral_pub_key_bytes).to_bytes(4, 'big'))
                f.write(ephemeral_pub_key_bytes)
                
                
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
            print(f"Использована кривая: {self.selected_curve}")
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
            ephemeral_pub_key_bytes = data[4:4+key_len]
            ephemeral_public_key = serialization.load_pem_public_key(
                ephemeral_pub_key_bytes,
                backend=default_backend()
            )
            
            
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
            
            
            shared_key = self.private_key.exchange(ec.ECDH(), ephemeral_public_key)
            
            
            session_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'file-encryption',
                backend=default_backend()
            ).derive(shared_key)
            
            
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
            print(f"Использована кривая: {self.selected_curve}")
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
        print(f"Кривая: {self.selected_curve}")
        print(f"Использовать многопоточность: {'Да' if self.use_multithreading else 'Нет'}")
        print(f"Добавлять цифровую подпись: {'Да' if self.use_digital_signature else 'Нет'}")
        print(f"Алгоритм подписи: {self.signature_algorithm}")
        
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
        print(f"Кривая: {self.selected_curve}")
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
        print(f"Кривая: {self.selected_curve}")
        print(f"Использовать многопоточность: {'Да' if self.use_multithreading else 'Нет'}")
        print(f"Проверять цифровую подпись: {'Да' if self.use_digital_signature else 'Нет'}")
        print(f"Алгоритм подписи: {self.signature_algorithm}")
        
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
        print(f"Кривая: {self.selected_curve}")
        print(f"Успешно: {successful}")
        print(f"С ошибками: {failed}")
        print(f"Результаты сохранены в: {output_folder}")
        print(f"{'='*60}")
        input("\nНажмите Enter для продолжения...")
    
    def change_curve(self):
        
        self.console.print_header()
        print(f"\nТекущая кривая: {self.selected_curve}")
        print("Доступные кривые:")
        
        for i, curve_name in enumerate(self.available_curves.keys(), 1):
            if curve_name == self.selected_curve:
                print(f"{i}. {curve_name} ← ТЕКУЩАЯ")
            else:
                print(f"{i}. {curve_name}")
        
        while True:
            try:
                choice = int(input(f"\nВыберите кривую (1-{len(self.available_curves)}): ").strip())
                if 1 <= choice <= len(self.available_curves):
                    new_curve = list(self.available_curves.keys())[choice-1]
                    
                    if new_curve != self.selected_curve:
                        self.selected_curve = new_curve
                        print(f"Кривая изменена на: {self.selected_curve}")
                        
                        
                        if self.selected_curve == 'SECP256R1' or self.selected_curve == 'SECP256K1':
                            self.signature_algorithm = 'ECDSA-SHA256'
                        elif self.selected_curve == 'SECP384R1':
                            self.signature_algorithm = 'ECDSA-SHA384'
                        elif self.selected_curve == 'SECP521R1':
                            self.signature_algorithm = 'ECDSA-SHA512'
                        
                        print(f"Алгоритм подписи установлен: {self.signature_algorithm}")
                        print("⚠ Для применения изменений перегенерируйте ключи!")
                        
                        if self.private_key:
                            self.save_session_auto()
                    break
                else:
                    print(f"Введите число от 1 до {len(self.available_curves)}!")
            except ValueError:
                print("Введите число!")
        
        time.sleep(1)
    
    def change_signature_algorithm(self):
        
        self.console.print_header()
        print(f"\nТекущий алгоритм подписи: {self.signature_algorithm}")
        print("Доступные алгоритмы:")
        
        for i, alg_name in enumerate(self.available_signature_algs.keys(), 1):
            if alg_name == self.signature_algorithm:
                print(f"{i}. {alg_name} ← ТЕКУЩИЙ")
            else:
                print(f"{i}. {alg_name}")
        
        while True:
            try:
                choice = int(input(f"\nВыберите алгоритм (1-{len(self.available_signature_algs)}): ").strip())
                if 1 <= choice <= len(self.available_signature_algs):
                    new_alg = list(self.available_signature_algs.keys())[choice-1]
                    
                    if new_alg != self.signature_algorithm:
                        self.signature_algorithm = new_alg
                        print(f"Алгоритм подписи изменен на: {self.signature_algorithm}")
                        
                        if self.private_key:
                            self.save_session_auto()
                    break
                else:
                    print(f"Введите число от 1 до {len(self.available_signature_algs)}!")
            except ValueError:
                print("Введите число!")
        
        time.sleep(1)
    
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
            print(f"Эллиптическая кривая: {self.selected_curve}")
        other_key_status = "ИМПОРТИРОВАН" if self.other_public_key else "ОТСУТСТВУЕТ"
        print(f"Ключ собеседника: {other_key_status}")
        
        print(f"Алгоритм подписи: {self.signature_algorithm}")
        signature_status = "ВКЛЮЧЕНА" if self.use_digital_signature else "ВЫКЛЮЧЕНА"
        print(f"Цифровая подпись: {signature_status}")
        
        timestamp_status = "ВКЛЮЧЕН" if self.use_timestamp else "ВЫКЛЮЧЕН"
        print(f"Timestamp в сообщениях: {timestamp_status}")
        
        threading_status = "ВКЛЮЧЕНА" if self.use_multithreading else "ВЫКЛЮЧЕНА"
        print(f"Многопоточность: {threading_status}")
        print(f"Количество потоков: {self.max_workers}")
        print(f"Доступно ядер CPU: {os.cpu_count() or 'N/A'}")
        
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
                print(f"[✓] Ключи ({self.selected_curve}) готовы")
            else:
                print("[!] Ключи не сгенерированы")
            
            if self.other_public_key:
                print("[✓] Ключ собеседника загружен")
            else:
                print("[!] Ключ собеседника отсутствует")
            
            threading_status = "✓ ВКЛ" if self.use_multithreading else "✗ ВЫКЛ"
            print(f"[{threading_status}] Многопоточность ({self.max_workers} потоков)")
            
            signature_status = "✓ ВКЛ" if self.use_digital_signature else "✗ ВЫКЛ"
            print(f"[{signature_status}] Цифровая подпись ({self.signature_algorithm})")
            
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
            print(f"10. Изменить кривую (сейчас: {self.selected_curve})")
            print(f"11. Изменить алгоритм подписи (сейчас: {self.signature_algorithm})")
            print(f"12. Изменить количество потоков (сейчас: {self.max_workers})")
            print(f"13. Вкл/Выкл многопоточность (сейчас: {'ВКЛ' if self.use_multithreading else 'ВЫКЛ'})")
            print(f"14. Вкл/Выкл цифровую подпись (сейчас: {'ВКЛ' if self.use_digital_signature else 'ВЫКЛ'})")
            print(f"15. Вкл/Выкл timestamp в сообщениях (сейчас: {'ВКЛ' if self.use_timestamp else 'ВЫКЛ'})")
            print("16. Показать статус сессии")
            print("17. Справка по кривым")
            print("18. Справка по алгоритмам подписи")
            print("0. Выход")
            print("=" * 60)
            
            choice = input("\nВыберите действие (0-18): ").strip()
            
            if choice == '1':
                self.choose_curve_and_algorithm()
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
                self.change_curve()
            elif choice == '11':
                self.change_signature_algorithm()
            elif choice == '12':
                self.change_thread_count()
            elif choice == '13':
                self.toggle_multithreading()
            elif choice == '14':
                self.toggle_digital_signature()
            elif choice == '15':
                self.toggle_timestamp()
            elif choice == '16':
                self.show_status()
            elif choice == '17':
                self.show_curve_help()
            elif choice == '18':
                self.show_signature_algorithm_help()
            elif choice == '0':
                print("\nЗавершение работы...")
                print("Все ключи удалены из памяти.")
                break
            else:
                print("Неверный выбор!")
                time.sleep(1)

def main():
    try:
        app = SecureMessagingAppECC()
        app.main_menu()
    except KeyboardInterrupt:
        print("\n\nПрограмма прервана.")
    except Exception as e:
        print(f"\nКритическая ошибка: {e}")
        input("Нажмите Enter для выхода...")

if __name__ == "__main__":
    main()