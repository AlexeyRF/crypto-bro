import base64
import os
import sys
import json
import time
import threading
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
import shutil

def check_and_install_packages():
    required_packages = ['cryptography']
    
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
    def show_spinner(delay: float = 0.1):
        spinner = ['|', '/', '-', '\\']
        idx = 0
        while getattr(threading.current_thread(), "do_run", True):
            sys.stdout.write(f"\r[{spinner[idx % len(spinner)]}] Обработка...")
            sys.stdout.flush()
            idx += 1
            time.sleep(delay)
        sys.stdout.write('\r' + ' ' * 30 + '\r')
    
    @staticmethod
    def progress_bar(iteration: int, total: int, prefix: str = '', length: int = 50):
        percent = ("{0:.1f}").format(100 * (iteration / float(total)))
        filled_length = int(length * iteration // total)
        bar = '█' * filled_length + '░' * (length - filled_length)
        sys.stdout.write(f'\r{prefix} |{bar}| {percent}%')
        if iteration == total:
            sys.stdout.write('\n')
        sys.stdout.flush()

class SessionManager:
    
    @staticmethod
    def export_session(private_key_pem: str, public_key_pem: str, 
                       other_public_key_pem: Optional[str], key_size: int) -> str:
        session_data = {
            "timestamp": datetime.now().isoformat(),
            "key_size": key_size,
            "private_key": private_key_pem,
            "public_key": public_key_pem,
            "other_public_key": other_public_key_pem,
            "session_id": os.urandom(16).hex()
        }
        
        filename = f"session_{int(time.time())}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(session_data, f, indent=2)
        
        return filename
    
    @staticmethod
    def import_session(filename: str) -> Optional[Dict[str, Any]]:
        """Импорт сессии из JSON файла"""
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

class SecureMessagingApp:
    def __init__(self):
        self.key_size = 4096
        self.private_key = None
        self.public_key = None
        self.other_public_key = None
        self.session_key = None
        self.session_loaded = False
        self.console = ConsoleManager()
        self.session_manager = SessionManager()
        self.initialize()
    
    def initialize(self):
        """Автоматическая инициализация при запуске"""
        self.console.print_header()
        print("Инициализация системы...")
        
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
                filename = input("Введите имя файла сессии: ").strip()
                self.load_session(filename)
                break
            elif choice == '3':
                self.recover_from_keys()
                break
            else:
                print("Неверный выбор. Попробуйте снова.")
    
    def load_session(self, filename: str):
        spinner_thread = threading.Thread(target=self.console.show_spinner)
        spinner_thread.start()
        
        try:
            session_data = self.session_manager.import_session(filename)
            
            if session_data:
                self.key_size = session_data['key_size']
                
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
        """Автоматическое сохранение сессии после получения ключа собеседника"""
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
                    private_key_pem, public_key_pem, other_public_key_pem, self.key_size
                )
                
                print(f"Сессия автоматически сохранена в {filename}")
                return filename
                
            except Exception as e:
                print(f"Ошибка сохранения сессии: {e}")
                return None
    
    def recover_from_keys(self):
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
        print(f"\nГенерация ключей RSA-{self.key_size}...")

        for i in range(101):
            self.console.progress_bar(i, 100, prefix='Генерация ключей:', length=40)
            time.sleep(0.02) 
        
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        print("\nКлючи успешно сгенерированы!")
    
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
    
    def encrypt_message(self):
        if not self.other_public_key:
            print("Сначала импортируйте публичный ключ собеседника!")
            return
        
        message = input("\nВведите сообщение для шифрования: ")
        
        if not message:
            print("Сообщение не может быть пустым!")
            return
        
        try:
            print("Шифрование...")
            self.session_key = os.urandom(32)
            for i in range(101):
                self.console.progress_bar(i, 100, prefix='Шифрование:', length=40)
                time.sleep(0.01)
            
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
            encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
            
            result = base64.b64encode(
                len(encrypted_key).to_bytes(4, 'big') + 
                encrypted_key + 
                iv + 
                encrypted_message
            ).decode()
            
            self.console.print_header()
            print("ЗАШИФРОВАННОЕ СООБЩЕНИЕ:\n")
            print(result)
            print("\n" + "=" * 60)
            input("\nНажмите Enter для продолжения...")
            
        except Exception as e:
            print(f"Ошибка шифрования: {e}")
    
    def decrypt_message(self):
        if not self.private_key:
            print("Сначала сгенерируйте ключи!")
            return
        
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
            print("Расшифровка...")
            for i in range(101):
                self.console.progress_bar(i, 100, prefix='Расшифровка:', length=40)
                time.sleep(0.01)
            
            data = base64.b64decode(encrypted)
            key_len = int.from_bytes(data[:4], 'big')
            encrypted_key = data[4:4+key_len]
            iv = data[4+key_len:4+key_len+16]
            encrypted_message = data[4+key_len+16:]
            
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
            message = decryptor.update(encrypted_message) + decryptor.finalize()
            
            self.console.print_header()
            print("РАСШИФРОВАННОЕ СООБЩЕНИЕ:\n")
            print(message.decode())
            print("\n" + "=" * 60)
            input("\nНажмите Enter для продолжения...")
            
        except Exception as e:
            print(f"Ошибка расшифровки: {e}")
    
    def encrypt_file(self):
        if not self.other_public_key:
            print("Сначала импортируйте публичный ключ собеседника!")
            return
        
        file_path = input("\nВведите путь к файлу: ").strip()
        
        if not os.path.exists(file_path):
            print("Файл не найден!")
            return
        
        try:
            print(f"Шифрование файла: {file_path}")
            
            with open(file_path, 'rb') as f:
                file_size = os.path.getsize(file_path)
                file_data = f.read()
            
            for i in range(0, file_size, 1024):
                progress = min(i, file_size)
                self.console.progress_bar(progress, file_size, prefix='Шифрование файла:', length=40)
                time.sleep(0.001)
            
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
            cipher = Cipher(
                algorithms.AES(session_key),
                modes.CFB(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(file_data) + encryptor.finalize()
            
            output_path = file_path + ".enc"
            with open(output_path, 'wb') as f:
                f.write(len(encrypted_key).to_bytes(4, 'big'))
                f.write(encrypted_key)
                f.write(iv)
                f.write(encrypted_data)
            
            self.console.progress_bar(file_size, file_size, prefix='Шифрование файла:', length=40)
            print(f"\nФайл успешно зашифрован: {output_path}")
            
        except Exception as e:
            print(f"Ошибка шифрования файла: {e}")
    
    def decrypt_file(self):
        if not self.private_key:
            print("Сначала сгенерируйте ключи!")
            return
        
        file_path = input("\nВведите путь к зашифрованному файлу: ").strip()
        
        if not os.path.exists(file_path):
            print("Файл не найден!")
            return
        
        try:
            print(f"Расшифровка файла: {file_path}")
            
            with open(file_path, 'rb') as f:
                data = f.read()
            
            file_size = len(data)
            for i in range(0, file_size, 1024):
                progress = min(i, file_size)
                self.console.progress_bar(progress, file_size, prefix='Расшифровка файла:', length=40)
                time.sleep(0.001)
            
            key_len = int.from_bytes(data[:4], 'big')
            encrypted_key = data[4:4+key_len]
            iv = data[4+key_len:4+key_len+16]
            encrypted_data = data[4+key_len+16:]
            
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
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            if file_path.endswith('.enc'):
                output_path = file_path[:-4] + '.decrypted'
            else:
                output_path = file_path + '.decrypted'
            
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            self.console.progress_bar(file_size, file_size, prefix='Расшифровка файла:', length=40)
            print(f"\nФайл успешно расшифрован: {output_path}")
            
        except Exception as e:
            print(f"Ошибка расшифровки файла: {e}")
    
    def change_key_size(self):
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
    
    def show_status(self):
        self.console.print_header()
        
        print("СТАТУС СЕССИИ:")
        print("-" * 60)
        key_status = "СГЕНЕРИРОВАНЫ" if self.private_key else "ОТСУТСТВУЮТ"
        print(f"Ваши ключи: {key_status}")
        
        if self.private_key:
            print(f"Размер ключа: {self.key_size} бит")
        
        other_key_status = "ИМПОРТИРОВАН" if self.other_public_key else "ОТСУТСТВУЕТ"
        print(f"Ключ собеседника: {other_key_status}")
        latest_session = self.session_manager.find_latest_session()
        if latest_session:
            session_time = datetime.fromtimestamp(os.path.getmtime(latest_session))
            print(f"Последняя сессия: {session_time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        print("-" * 60)
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
            
            print("-" * 60)
            print("1. Сгенерировать новые ключи")
            print("2. Показать мой публичный ключ")
            print("3. Импортировать ключ собеседника")
            print("4. Зашифровать сообщение")
            print("5. Расшифровать сообщение")
            print("6. Зашифровать файл")
            print("7. Расшифровать файл")
            print(f"8. Изменить размер ключа (сейчас: {self.key_size})")
            print("9. Показать статус сессии")
            print("0. Выход")
            print("=" * 60)
            
            choice = input("\nВыберите действие (0-9): ").strip()
            
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
                self.change_key_size()
            elif choice == '9':
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
        print("\n\nПрограмма прервана пользователем.")
    except Exception as e:
        print(f"\nКритическая ошибка: {e}")
        input("Нажмите Enter для выхода...")

if __name__ == "__main__":
    main()
