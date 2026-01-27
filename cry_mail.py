import sys
import time
import ssl
import email
from email.mime.text import MIMEText
import smtplib
import imaplib
from bs4 import BeautifulSoup
from PySide6.QtGui import QIcon, Qt, QAction
from PySide6.QtCore import QTimer, QDate, QDateTime, QLocale, QThread, Signal, Slot
from PySide6.QtWidgets import *
from PySide6.QtWebEngineWidgets import QWebEngineView
import base64
import os
import json
import hashlib
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
import threading
try:
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import utils
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    CRYPTO_AVAILABLE = True
except ImportError:
    print("Библиотека cryptography не установлена. Криптографические функции будут недоступны.")
    print("Установите: pip install cryptography")
    CRYPTO_AVAILABLE = False

class PasswordManager:
    """Менеджер для безопасного хранения паролей"""
    def __init__(self, storage_file="saved_passwords.enc"):
        self.storage_file = Path(storage_file)
        self.passwords = {}
        self.master_password_hash = None
        self.master_password_salt = None
    
    def set_master_password(self, master_password: str) -> bool:
        """Установка мастер-пароля"""
        try:
            self.master_password_salt = os.urandom(32)
            self.master_password_hash = hashlib.pbkdf2_hmac(
                'sha256',
                master_password.encode('utf-8'),
                self.master_password_salt,
                100000,
                dklen=32
            )
            with open(self.storage_file, 'wb') as f:
                f.write(self.master_password_salt)
                f.write(self.master_password_hash)
            return True
        except Exception as e:
            print(f"Ошибка установки мастер-пароля: {e}")
            return False
    
    def verify_master_password(self, master_password: str) -> bool:
        """Проверка мастер-пароля"""
        try:
            if not self.storage_file.exists():
                return False
            
            with open(self.storage_file, 'rb') as f:
                self.master_password_salt = f.read(32)
                stored_hash = f.read(32)
            
            test_hash = hashlib.pbkdf2_hmac(
                'sha256',
                master_password.encode('utf-8'),
                self.master_password_salt,
                100000,
                dklen=32
            )
            return stored_hash == test_hash
        except Exception as e:
            print(f"Ошибка проверки мастер-пароля: {e}")
            return False
    
    def has_master_password(self) -> bool:
        """Проверка наличия установленного мастер-пароля"""
        return self.storage_file.exists()
    
    def encrypt_password(self, plaintext: str, master_password: str) -> Optional[str]:
        """Шифрование пароля"""
        try:
            key = hashlib.pbkdf2_hmac(
                'sha256',
                master_password.encode('utf-8'),
                b'password_encryption',
                100000,
                dklen=32
            )
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
            result = base64.b64encode(iv + encrypted).decode('utf-8')
            return result
        except Exception as e:
            print(f"Ошибка шифрования пароля: {e}")
            return None
    
    def decrypt_password(self, encrypted_data: str, master_password: str) -> Optional[str]:
        """Расшифровка пароля"""
        try:
            data = base64.b64decode(encrypted_data)
            if len(data) < 16:
                print(f"Ошибка: данные слишком короткие ({len(data)} байт)")
                return None
            
            iv = data[:16]
            encrypted = data[16:]
            
            key = hashlib.pbkdf2_hmac(
                'sha256',
                master_password.encode('utf-8'),
                b'password_encryption',
                100000,
                dklen=32
            )
            
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(encrypted) + decryptor.finalize()
            
            try:
                return decrypted.decode('utf-8')
            except UnicodeDecodeError:
                return decrypted.decode('latin-1')
        except Exception as e:
            print(f"Ошибка расшифровки пароля: {e}")
            return None
    
    def save_email_password(self, email: str, password: str, smtp_server: Tuple[str, int],
                           imap_server: Tuple[str, int], master_password: str):
        """Сохранение пароля почты"""
        try:
            # ПРОВЕРЯЕМ мастер-пароль перед сохранением
            if not self.verify_master_password(master_password):
                print("Неверный мастер-пароль при сохранении пароля почты")
                return False
            
            encrypted_password = self.encrypt_password(password, master_password)
            if not encrypted_password:
                print("Не удалось зашифровать пароль")
                return False
            
            data = {
                'password': encrypted_password,
                'smtp_server': [smtp_server[0], smtp_server[1]],
                'imap_server': [imap_server[0], imap_server[1]],
                'timestamp': datetime.now().isoformat()
            }
            
            all_data = {}
            data_file = self.storage_file.with_suffix('.json')
            if data_file.exists():
                try:
                    with open(data_file, 'r', encoding='utf-8') as f:
                        all_data = json.load(f)
                except json.JSONDecodeError:
                    print(f"Ошибка чтения файла {data_file}, создаем новый")
                    all_data = {}
            
            all_data[email] = data
            
            with open(data_file, 'w', encoding='utf-8') as f:
                json.dump(all_data, f, indent=2, ensure_ascii=False)
            
            print(f"Пароль для {email} успешно сохранен")
            return True
        except Exception as e:
            print(f"Ошибка сохранения пароля: {e}")
            return False
    
    def get_saved_accounts(self) -> List[str]:
        """Получение списка сохраненных аккаунтов"""
        try:
            data_file = self.storage_file.with_suffix('.json')
            if data_file.exists():
                with open(data_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                return list(data.keys())
            return []
        except Exception as e:
            print(f"Ошибка получения сохраненных аккаунтов: {e}")
            return []
    
    def load_email_password(self, email: str, master_password: str) -> Optional[Dict[str, Any]]:
        """Загрузка пароля почты"""
        try:
            # ПРОВЕРЯЕМ мастер-пароль перед загрузкой
            if not self.verify_master_password(master_password):
                print("Неверный мастер-пароль при загрузке пароля почты")
                return None
            
            data_file = self.storage_file.with_suffix('.json')
            if not data_file.exists():
                return None
            
            with open(data_file, 'r', encoding='utf-8') as f:
                all_data = json.load(f)
            
            if email not in all_data:
                return None
            
            data = all_data[email]
            password = self.decrypt_password(data['password'], master_password)
            if not password:
                return None
            
            return {
                'password': password,
                'smtp_server': tuple(data['smtp_server']),
                'imap_server': tuple(data['imap_server'])
            }
        except Exception as e:
            print(f"Ошибка загрузки пароля: {e}")
            return None

class EmailUpdaterThread(QThread):
    """
    Фоновый поток, отвечающий за проверки почты.
    Режимы работы:
      - 'inbox' : периодическая проверка наличия новых сообщений в Inbox (интервал 30 сек).
                  При переходе в вкладку Inbox запускается немедленная проверка.
      - 'sent'  : однократная проверка при переходе в вкладку Sent.
      - 'none'  : проверки не выполняются.
    """
    update_started = Signal()
    update_finished = Signal()
    inbox_checked = Signal()  # emitted when inbox check completed (main thread should refresh inbox)
    sent_checked = Signal()   # emitted when sent check requested (main thread should refresh sent)

    def __init__(self, email_client):
        super().__init__()
        self.email_client = email_client
        self.running = True
        self.mode = 'none'
        self.inbox_interval = 30  # seconds
        self.last_inbox_check = datetime.min
        self._immediate_inbox_check = False
        self._need_sent_check = False

    @Slot(str)
    def setMode(self, mode: str):
        """Set current mode: 'inbox', 'sent', 'none'"""
        self.mode = mode
        if mode == 'inbox':
            # force immediate check on switching to inbox
            self._immediate_inbox_check = True
        elif mode == 'sent':
            # request one-shot sent check
            self._need_sent_check = True

    @Slot()
    def requestImmediateInboxCheck(self):
        self._immediate_inbox_check = True

    @Slot()
    def requestSentCheck(self):
        self._need_sent_check = True

    def run(self):
        while self.running:
            try:
                now = datetime.now()
                if self.mode == 'inbox':
                    should_check = False
                    if self._immediate_inbox_check:
                        should_check = True
                        self._immediate_inbox_check = False
                    else:
                        if (now - self.last_inbox_check).total_seconds() >= self.inbox_interval:
                            should_check = True

                    if should_check:
                        self.last_inbox_check = now
                        self.update_started.emit()
                        try:
                            # Проверяем IMAP живость и ищем новые сообщения (UNSEEN) — только сетевые операции здесь
                            if self.email_client.is_imap_alive():
                                try:
                                    with self.email_client.imap_lock:
                                        self.email_client.serverIMAP.select('inbox')
                                        status, messages = self.email_client.serverIMAP.search(None, 'UNSEEN')
                                        if status == 'OK' and messages and messages[0]:
                                            message_nums = messages[0].split()
                                            max_messages_per_check = 10
                                            new_messages = []
                                            for num in message_nums[:max_messages_per_check]:
                                                try:
                                                    status, message = self.email_client.serverIMAP.fetch(num, '(RFC822 UID)')
                                                    if status != 'OK':
                                                        continue

                                                    uid = None
                                                    for part in message:
                                                        if isinstance(part, tuple) and len(part) > 0:
                                                            for item in part:
                                                                if isinstance(item, bytes) and b'UID' in item:
                                                                    try:
                                                                        uid_match = re.search(rb'UID\s+(\d+)', item)
                                                                        if uid_match:
                                                                            uid = int(uid_match.group(1))
                                                                    except:
                                                                        pass

                                                    if uid and uid <= getattr(self.email_client.updater_thread, 'last_processed_uid', 0):
                                                        continue

                                                    if uid:
                                                        # store last processed uid in thread to avoid races
                                                        if hasattr(self.email_client.updater_thread, 'last_processed_uid'):
                                                            self.email_client.updater_thread.last_processed_uid = max(getattr(self.email_client.updater_thread, 'last_processed_uid', 0), uid)
                                                        else:
                                                            self.email_client.updater_thread.last_processed_uid = uid

                                                    for part in message:
                                                        if isinstance(part, tuple) and len(part) == 2:
                                                            email_data = part[1]
                                                            if email_data:
                                                                try:
                                                                    emailMessage = email.message_from_bytes(email_data)
                                                                    sender = email.utils.parseaddr(emailMessage['From'])[1]
                                                                    subject = emailMessage['Subject']
                                                                    subject = self.email_client.decodeUTF8(subject)

                                                                    if num not in self.email_client.seen_message_ids:
                                                                        self.email_client.seen_message_ids.add(num)
                                                                        new_messages.append((sender, subject))
                                                                except Exception as e:
                                                                    print(f"Ошибка обработки письма в потоке: {e}")
                                                                    continue
                                                except Exception as e:
                                                    print(f"Ошибка обработки отдельного письма в потоке: {e}")
                                                    continue

                                            if new_messages:
                                                # delegate key requests check (may send key replies)
                                                try:
                                                    self.email_client.checkForKeyRequests()
                                                except Exception as e:
                                                    print(f"Ошибка при checkForKeyRequests в потоке: {e}")
                                except: pass
                        except (imaplib.IMAP4.abort, imaplib.IMAP4.error, ConnectionError) as e:
                            print(f"IMAP ошибка в потоке, переподключаемся: {e}")
                            try:
                                self.email_client.reconnect_imap()
                            except Exception as e2:
                                print(f"Ошибка переподключения IMAP из потока: {e2}")
                        except Exception as e:
                            print(f"Общая ошибка при проверке inbox в потоке: {e}")
                        # notify main thread to refresh UI inbox list
                        self.inbox_checked.emit()
                        self.update_finished.emit()

                elif self.mode == 'sent' and self._need_sent_check:
                    # One-shot: notify main thread to refresh Sent folder
                    self._need_sent_check = False
                    self.update_started.emit()
                    # (Don't perform heavy UI updates in thread; main thread will refreshSentList)
                    self.sent_checked.emit()
                    self.update_finished.emit()

            except Exception as e:
                print(f"Критическая ошибка в потоке обновления: {e}")

            # Sleep a short time to remain responsive to mode changes/requests.
            for _ in range(5):
                if not self.running:
                    break
                self.msleep(200)

    def stop(self):
        self.running = False
        self.wait(2000)


class CryptoManager:
    """Менеджер криптографических операций"""
    def __init__(self, keys_dir="keys"):
        self.keys_dir = Path(keys_dir)
        self.keys_dir.mkdir(exist_ok=True)
        self.curve_name = 'SECP521R1'
        self.signature_algorithm = 'ECDSA-SHA512'
        self.use_timestamp = True
        self.use_digital_signature = True
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
        self.private_key = None
        self.public_key = None
        self.contact_keys = {}
        self.sent_messages = {}
        self.load_keys()
        self.load_sent_messages()
    
    def load_keys(self):
        """Загрузка ключей из файлов"""
        private_key_path = self.keys_dir / "private.pem"
        public_key_path = self.keys_dir / "public.pem"
        
        if private_key_path.exists() and public_key_path.exists():
            try:
                with open(private_key_path, 'rb') as f:
                    self.private_key = serialization.load_pem_private_key(
                        f.read(),
                        password=None,
                        backend=default_backend()
                    )
                with open(public_key_path, 'rb') as f:
                    self.public_key = serialization.load_pem_public_key(
                        f.read(),
                        backend=default_backend()
                    )
                print("Ключи загружены из файлов")
            except Exception as e:
                print(f"Ошибка загрузки ключей: {e}")
                self.generate_keys()
        else:
            self.generate_keys()
        
        contacts_dir = self.keys_dir / "contacts"
        contacts_dir.mkdir(exist_ok=True)
        
        for key_file in contacts_dir.glob("*.pem"):
            email = key_file.stem
            try:
                with open(key_file, 'rb') as f:
                    public_key = serialization.load_pem_public_key(
                        f.read(),
                        backend=default_backend()
                    )
                    self.contact_keys[email] = public_key
                    print(f"Загружен ключ для {email}")
            except Exception as e:
                print(f"Ошибка загрузки ключа для {email}: {e}")
    
    def load_sent_messages(self):
        """Загрузка отправленных сообщений"""
        sent_file = self.keys_dir / "sent_messages.json"
        if sent_file.exists():
            try:
                with open(sent_file, 'r', encoding='utf-8') as f:
                    self.sent_messages = json.load(f)
                print(f"Загружено {len(self.sent_messages)} отправленных сообщений")
            except Exception as e:
                print(f"Ошибка загрузки отправленных сообщений: {e}")
                self.sent_messages = {}
    
    def save_sent_messages(self):
        """Сохранение отправленных сообщений"""
        sent_file = self.keys_dir / "sent_messages.json"
        try:
            with open(sent_file, 'w', encoding='utf-8') as f:
                json.dump(self.sent_messages, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Ошибка сохранения отправленных сообщений: {e}")
    
    def add_sent_message(self, message_id: str, encrypted_text: str, plaintext: str, recipient: str):
        """Добавление отправленного сообщения"""
        self.sent_messages[message_id] = {
            'encrypted': encrypted_text,
            'plaintext': plaintext,
            'recipient': recipient,
            'timestamp': datetime.now().isoformat(),
            'curve': self.curve_name,
            'signature_algorithm': self.signature_algorithm
        }
        self.save_sent_messages()
    
    def get_sent_message(self, message_id: str):
        """Получение отправленного сообщения"""
        return self.sent_messages.get(message_id)
    
    def get_all_sent_messages(self):
        """Получение всех отправленных сообщений"""
        return self.sent_messages
    
    def generate_keys(self):
        """Генерация новых ключей"""
        if not CRYPTO_AVAILABLE:
            return False
        
        try:
            curve_class = self.available_curves[self.curve_name]
            self.private_key = ec.generate_private_key(
                curve_class(),
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
            
            private_key_path = self.keys_dir / "private.pem"
            public_key_path = self.keys_dir / "public.pem"
            
            with open(private_key_path, 'wb') as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            with open(public_key_path, 'wb') as f:
                f.write(self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            
            print(f"Сгенерированы новые ключи на кривой {self.curve_name}")
            return True
        except Exception as e:
            print(f"Ошибка генерации ключей: {e}")
            return False
    
    def get_public_key_pem(self):
        """Получение публичного ключа в PEM формате"""
        if not self.public_key:
            return None
        
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
    
    def save_contact_key(self, email: str, public_key_pem: str):
        """Сохранение публичного ключа контакта"""
        if not CRYPTO_AVAILABLE:
            return False
        
        try:
            contacts_dir = self.keys_dir / "contacts"
            contacts_dir.mkdir(exist_ok=True)
            
            key_path = contacts_dir / f"{email}.pem"
            with open(key_path, 'w') as f:
                f.write(public_key_pem)
            
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            self.contact_keys[email] = public_key
            print(f"Ключ для {email} сохранен")
            return True
        except Exception as e:
            print(f"Ошибка сохранения ключа: {e}")
            return False
    
    def has_contact_key(self, email: str) -> bool:
        """Проверка наличия ключа для контакта"""
        return email in self.contact_keys
    
    def clean_text(self, text: str) -> str:
        """Очистка текста от лишних пробелов и переносов строк"""
        text = text.strip()
        text = re.sub(r'\s+', ' ', text)
        text = ''.join(char for char in text if char.isprintable() or char in '\n\r\t')
        return text
    
    def encrypt_message(self, plaintext: str, recipient_email: str) -> Tuple[str, str]:
        """Шифрование сообщения, возвращает (зашифрованный текст, message_id)"""
        if not CRYPTO_AVAILABLE:
            return plaintext, ""
        
        if recipient_email not in self.contact_keys:
            raise ValueError(f"Публичный ключ для {recipient_email} не найден")
        
        try:
            if self.use_timestamp:
                timestamp = datetime.now().isoformat()
                message = f"[{timestamp}] {plaintext}"
            else:
                message = plaintext
            
            message_bytes = message.encode('utf-8')
            
            curve_class = self.available_curves[self.curve_name]
            ephemeral_private_key = ec.generate_private_key(
                curve_class(),
                backend=default_backend()
            )
            ephemeral_public_key = ephemeral_private_key.public_key()
            
            shared_key = ephemeral_private_key.exchange(
                ec.ECDH(),
                self.contact_keys[recipient_email]
            )
            
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
                signature_algorithm, _ = self.available_signature_algs[self.signature_algorithm]
                signature = self.private_key.sign(
                    message_bytes,
                    signature_algorithm
                )
            
            checksum = hashlib.sha256(message_bytes).digest()
            
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
            else:
                result_data += (0).to_bytes(4, 'big')
            
            result_data += checksum
            result_data += encrypted_message
            
            encrypted_b64 = base64.b64encode(result_data).decode('utf-8')
            message_id = hashlib.sha256(encrypted_b64.encode()).hexdigest()[:16]
            
            formatted = f"---MESSAGE BEGIN---\n{encrypted_b64}\n---MESSAGE END---"
            return formatted, message_id
        except Exception as e:
            print(f"Ошибка шифрования: {e}")
            return plaintext, ""
    
    def decrypt_message(self, encrypted_data: str, sender_email: str = None, is_sent_message: bool = False) -> Dict[str, Any]:
        """Расшифровка сообщения"""
        if not CRYPTO_AVAILABLE or not self.private_key:
            return {"message": encrypted_data, "is_encrypted": False, "error": "Криптография недоступна"}
        
        try:
            encrypted_data = self.clean_text(encrypted_data)
            data = base64.b64decode(encrypted_data)
            
            key_len = int.from_bytes(data[:4], 'big')
            ephemeral_pub_key_bytes = data[4:4+key_len]
            ephemeral_public_key = serialization.load_pem_public_key(
                ephemeral_pub_key_bytes,
                backend=default_backend()
            )
            
            iv = data[4+key_len:4+key_len+16]
            offset = 4 + key_len + 16
            
            signature_len = int.from_bytes(data[offset:offset+4], 'big')
            offset += 4
            
            signature = None
            if signature_len > 0:
                signature = data[offset:offset+signature_len]
                offset += signature_len
            
            checksum = data[offset:offset+32]
            offset += 32
            
            encrypted_message = data[offset:]
            
            shared_key = self.private_key.exchange(
                ec.ECDH(),
                ephemeral_public_key
            )
            
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
            
            calculated_checksum = hashlib.sha256(message_bytes).digest()
            checksum_valid = checksum == calculated_checksum
            
            if not checksum_valid:
                return {"message": encrypted_data, "is_encrypted": False,
                        "error": "Контрольная сумма не совпадает"}
            
            message_text = message_bytes.decode('utf-8', errors='ignore')
            
            timestamp = None
            if message_text.startswith('[') and ']' in message_text:
                end_timestamp = message_text.find(']')
                if end_timestamp != -1:
                    timestamp = message_text[1:end_timestamp]
                    message_text = message_text[end_timestamp+2:].strip()
            
            signature_valid = False
            signature_error = None
            
            if signature and sender_email and not is_sent_message:
                if sender_email in self.contact_keys:
                    try:
                        signature_algorithm, hash_class = self.available_signature_algs[self.signature_algorithm]
                        self.contact_keys[sender_email].verify(
                            signature,
                            message_bytes,
                            signature_algorithm
                        )
                        signature_valid = True
                    except InvalidSignature:
                        signature_error = "Подпись неверна"
                    except Exception as e:
                        signature_error = f"Ошибка проверки подписи: {str(e)}"
                else:
                    signature_error = "Публичный ключ отправителя не найден"
            elif signature and is_sent_message:
                try:
                    signature_algorithm, hash_class = self.available_signature_algs[self.signature_algorithm]
                    self.public_key.verify(
                        signature,
                        message_bytes,
                        signature_algorithm
                    )
                    signature_valid = True
                except InvalidSignature:
                    signature_error = "Подпись неверна"
                except Exception as e:
                    signature_error = f"Ошибка проверки подписи: {str(e)}"
            
            return {
                "message": message_text,
                "timestamp": timestamp,
                "signature": signature is not None,
                "signature_valid": signature_valid,
                "signature_error": signature_error,
                "checksum_valid": checksum_valid,
                "is_encrypted": True
            }
        except Exception as e:
            print(f"Ошибка расшифровки: {e}")
            return {"message": encrypted_data, "is_encrypted": False,
                    "error": f"Ошибка расшифровки: {str(e)}"}
    
    def is_encrypted_message(self, text: str) -> bool:
        """Проверка, является ли сообщение зашифрованным"""
        text_clean = self.clean_text(text)
        return "---MESSAGE BEGIN---" in text_clean and "---MESSAGE END---" in text_clean
    
    def extract_encrypted_content(self, text: str) -> Optional[str]:
        """Извлечение зашифрованного содержимого из текста"""
        text_clean = self.clean_text(text)
        if not self.is_encrypted_message(text_clean):
            return None
        
        start = text_clean.find("---MESSAGE BEGIN---") + len("---MESSAGE BEGIN---")
        end = text_clean.find("---MESSAGE END---")
        if start == -1 or end == -1:
            return None
        
        encrypted_content = text_clean[start:end].strip()
        return encrypted_content
    
    def try_decrypt_any_text(self, text: str, sender_email: str = None, is_sent_message: bool = False) -> Dict[str, Any]:
        """Попытка расшифровать любой текст (с маркерами или без)"""
        text_clean = self.clean_text(text)
        encrypted_content = self.extract_encrypted_content(text_clean)
        
        if encrypted_content:
            result = self.decrypt_message(encrypted_content, sender_email, is_sent_message)
            if result["is_encrypted"]:
                return result
            else:
                return {"message": text_clean, "is_encrypted": False,
                        "error": "Сообщение содержит маркеры, но расшифровка не удалась"}
        
        if (len(text_clean) > 50 and
            all(c.isalnum() or c in '+/=' for c in text_clean) and
            len(text_clean) % 4 == 0):
            try:
                result = self.decrypt_message(text_clean, sender_email, is_sent_message)
                if result["is_encrypted"]:
                    return result
            except:
                pass
        
        return {"message": text_clean, "is_encrypted": False,
                "error": "Сообщение не является зашифрованным"}

class MasterPasswordDialog(QDialog):
    """Диалог для установки/ввода мастер-пароля"""
    def __init__(self, mode="setup", parent=None):
        super().__init__(parent)
        self.mode = mode
        
        if mode == "setup":
            self.setWindowTitle("Установка мастер-пароля")
            title = "Установите мастер-пароль для защиты сохраненных паролей"
        else:
            self.setWindowTitle("Ввод мастер-пароля")
            title = "Введите мастер-пароль для доступа к сохраненным данным"
        
        layout = QVBoxLayout()
        title_label = QLabel(title)
        title_label.setWordWrap(True)
        layout.addWidget(title_label)
        
        self.password_label = QLabel("Мастер-пароль:")
        self.password_field = QLineEdit()
        self.password_field.setEchoMode(QLineEdit.Password)
        
        self.confirm_label = QLabel("Подтверждение:")
        self.confirm_field = QLineEdit()
        self.confirm_field.setEchoMode(QLineEdit.Password)
        
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_field)
        
        if mode == "setup":
            layout.addWidget(self.confirm_label)
            layout.addWidget(self.confirm_field)
        
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
        self.setLayout(layout)
        self.resize(400, 200)
    
    def get_password(self):
        return self.password_field.text()
    
    def get_confirmation(self):
        return self.confirm_field.text()

class LoginWindow(QDialog):
    def __init__(self, password_manager, parent=None):
        super().__init__(parent)
        self.password_manager = password_manager
        self.setWindowTitle('Добро пожаловать')
        self.setWindowIcon(QIcon(self.style().standardPixmap(QStyle.SP_VistaShield)))
        self.setWindowModality(Qt.ApplicationModal)
        
        self.tabWidget = QTabWidget()
        
        self.loginTab = QWidget()
        self.emailLabel = QLabel('Email:')
        self.emailField = QComboBox()
        self.emailField.setEditable(True)
        self.emailField.setPlaceholderText('example@primer.ru')
        
        self.passwordLabel = QLabel('Пароль:')
        self.passwordField = QLineEdit()
        self.passwordField.setEchoMode(QLineEdit.Password)
        self.passwordField.setPlaceholderText('Пароль или пароль приложения')
        
        self.rememberCheckbox = QCheckBox('Запомнить пароль')
        self.rememberCheckbox.setChecked(False)
        
        layout = QGridLayout()
        layout.addWidget(self.emailLabel, 0, 0)
        layout.addWidget(self.emailField, 0, 1, 1, 2)
        layout.addWidget(self.passwordLabel, 1, 0)
        layout.addWidget(self.passwordField, 1, 1, 1, 2)
        layout.addWidget(self.rememberCheckbox, 3, 0, 1, 3)
        self.loginTab.setLayout(layout)
        self.tabWidget.addTab(self.loginTab, 'Вход')
        
        self.serverTab = QWidget()
        self.serverPresetLabel = QLabel('Предустановки:')
        self.serverPresetCombo = QComboBox()
        self.serverPresetCombo.addItem("Выберите сервис...", ("", "", "", ""))
        self.serverPresetCombo.addItem("Яндекс (Yandex)", ("smtp.yandex.ru", "465", "imap.yandex.ru", "993"))
        self.serverPresetCombo.addItem("Gmail (Google)", ("smtp.gmail.com", "465", "imap.gmail.com", "993"))
        self.serverPresetCombo.addItem("Mail.ru", ("smtp.mail.ru", "465", "imap.mail.ru", "993"))
        self.serverPresetCombo.addItem("Outlook/Hotmail", ("smtp-mail.outlook.com", "587", "outlook.office365.com", "993"))
        self.serverPresetCombo.currentIndexChanged.connect(self.fillServerPreset)
        
        self.smtpLabel = QLabel('SMTP сервер:')
        self.smtpField = QLineEdit('smtp.yandex.ru')
        self.smtpPortField = QLineEdit('465')
        self.smtpPortLabel = QLabel('Порт:')
        
        self.imapLabel = QLabel('IMAP сервер:')
        self.imapField = QLineEdit('imap.yandex.ru')
        self.imapPortField = QLineEdit('993')
        self.imapPortLabel = QLabel('Порт:')
        
        layout = QGridLayout()
        layout.addWidget(self.serverPresetLabel, 0, 0)
        layout.addWidget(self.serverPresetCombo, 0, 1, 1, 3)
        layout.addWidget(self.smtpLabel, 1, 0)
        layout.addWidget(self.smtpField, 1, 1)
        layout.addWidget(self.smtpPortLabel, 1, 2)
        layout.addWidget(self.smtpPortField, 1, 3)
        layout.addWidget(self.imapLabel, 2, 0)
        layout.addWidget(self.imapField, 2, 1)
        layout.addWidget(self.imapPortLabel, 2, 2)
        layout.addWidget(self.imapPortField, 2, 3)
        self.serverTab.setLayout(layout)
        self.tabWidget.addTab(self.serverTab, 'Настройки SMTP/IMAP')
        
        self.cryptoTab = QWidget()
        self.cryptoCheckbox = QCheckBox('Включить криптографию')
        self.cryptoCheckbox.setChecked(CRYPTO_AVAILABLE)
        self.cryptoCheckbox.setEnabled(CRYPTO_AVAILABLE)
        
        self.curveLabel = QLabel('Эллиптическая кривая:')
        self.curveCombo = QComboBox()
        self.curveCombo.addItems(['SECP256R1', 'SECP384R1', 'SECP521R1', 'SECP256K1'])
        self.curveCombo.setCurrentText('SECP521R1')
        self.curveCombo.setEnabled(CRYPTO_AVAILABLE)
        
        self.signatureLabel = QLabel('Алгоритм подписи:')
        self.signatureCombo = QComboBox()
        self.signatureCombo.addItems(['ECDSA-SHA256', 'ECDSA-SHA384', 'ECDSA-SHA512'])
        self.signatureCombo.setCurrentText('ECDSA-SHA512')
        self.signatureCombo.setEnabled(CRYPTO_AVAILABLE)
        
        self.timestampCheckbox = QCheckBox('Добавлять timestamp')
        self.timestampCheckbox.setChecked(True)
        self.timestampCheckbox.setEnabled(CRYPTO_AVAILABLE)
        
        self.signatureCheckbox = QCheckBox('Использовать цифровую подпись')
        self.signatureCheckbox.setChecked(True)
        self.signatureCheckbox.setEnabled(CRYPTO_AVAILABLE)
        
        self.showPublicKeyButton = QPushButton('Показать мой публичный ключ')
        self.showPublicKeyButton.clicked.connect(self.showPublicKey)
        self.showPublicKeyButton.setEnabled(CRYPTO_AVAILABLE)
        
        layout = QGridLayout()
        layout.addWidget(self.cryptoCheckbox, 0, 0, 1, 2)
        layout.addWidget(self.curveLabel, 1, 0)
        layout.addWidget(self.curveCombo, 1, 1)
        layout.addWidget(self.signatureLabel, 2, 0)
        layout.addWidget(self.signatureCombo, 2, 1)
        layout.addWidget(self.timestampCheckbox, 3, 0, 1, 2)
        layout.addWidget(self.signatureCheckbox, 4, 0, 1, 2)
        layout.addWidget(self.showPublicKeyButton, 5, 0, 1, 2)
        
        if not CRYPTO_AVAILABLE:
            warning = QLabel('<font color="red">Криптография недоступна. Установите библиотеку cryptography.</font>')
            layout.addWidget(warning, 6, 0, 1, 2)
        
        self.cryptoTab.setLayout(layout)
        self.tabWidget.addTab(self.cryptoTab, 'Криптография')
        
        self.loginButton = QPushButton('Войти')
        
        layout = QVBoxLayout()
        layout.addWidget(self.tabWidget)
        layout.addWidget(self.loginButton, alignment=Qt.AlignRight)
        self.setLayout(layout)
        self.loginButton.clicked.connect(self.accept)
        
        self.saved_accounts = self.password_manager.get_saved_accounts()
        if self.saved_accounts:
            self.emailField.addItems(self.saved_accounts)
            self.emailField.currentTextChanged.connect(self.on_email_changed)
    
    def on_email_changed(self):
        """Обработка изменения email"""
        email = self.emailField.currentText().strip()
        if email in self.saved_accounts:
            QTimer.singleShot(100, lambda: self.load_saved_account(email))
    
    def load_saved_account(self, email):
        """Загрузка сохраненного аккаунта"""
        if not email or email not in self.saved_accounts:
            return
        
        dialog = MasterPasswordDialog(mode="enter", parent=self)
        if dialog.exec() == QDialog.Accepted:
            master_password = dialog.get_password()
            if not master_password:
                return
            
            # ЯВНАЯ ПРОВЕРКА мастер-пароля через хэш
            if not self.password_manager.verify_master_password(master_password):
                QMessageBox.warning(self, "Ошибка", "Неверный мастер-пароль")
                return
            
            data = self.password_manager.load_email_password(email, master_password)
            if data:
                self.passwordField.setText(data['password'])
                self.smtpField.setText(data['smtp_server'][0])
                self.smtpPortField.setText(str(data['smtp_server'][1]))
                self.imapField.setText(data['imap_server'][0])
                self.imapPortField.setText(str(data['imap_server'][1]))
                QMessageBox.information(self, "Успех", "Данные аккаунта загружены")
            else:
                QMessageBox.warning(self, "Ошибка", "Неверный мастер-пароль или повреждены данные")
    
    def fillServerPreset(self, index):
        """Заполняет поля серверов из предустанвки"""
        data = self.serverPresetCombo.itemData(index)
        if data and data[0]:
            smtp_server, smtp_port, imap_server, imap_port = data
            self.smtpField.setText(smtp_server)
            self.smtpPortField.setText(smtp_port)
            self.imapField.setText(imap_server)
            self.imapPortField.setText(imap_port)
    
    def showPublicKey(self):
        """Показ публичного ключа"""
        if not CRYPTO_AVAILABLE:
            QMessageBox.warning(self, "Ошибка", "Криптография недоступна")
            return
        
        crypto = CryptoManager()
        public_key = crypto.get_public_key_pem()
        if public_key:
            dialog = QDialog(self)
            dialog.setWindowTitle("Ваш публичный ключ")
            layout = QVBoxLayout()
            text = QTextEdit()
            text.setPlainText(public_key)
            text.setReadOnly(True)
            copy_button = QPushButton("Копировать в буфер")
            copy_button.clicked.connect(lambda: QApplication.clipboard().setText(public_key))
            layout.addWidget(QLabel("Это ваш публичный ключ. Отправьте его собеседникам:"))
            layout.addWidget(text)
            layout.addWidget(copy_button)
            dialog.setLayout(layout)
            dialog.exec()
    
    def getEmail(self):
        return self.emailField.currentText().strip()
    
    def getPassword(self):
        return self.passwordField.text()
    
    def getSMTPServerInfo(self):
        return self.smtpField.text().strip(), int(self.smtpPortField.text())
    
    def getIMAPServerInfo(self):
        return self.imapField.text().strip(), int(self.imapPortField.text())
    
    def isCryptoEnabled(self):
        return self.cryptoCheckbox.isChecked() and CRYPTO_AVAILABLE
    
    def getCryptoConfig(self):
        return {
            'curve': self.curveCombo.currentText(),
            'signature': self.signatureCombo.currentText(),
            'timestamp': self.timestampCheckbox.isChecked(),
            'digital_signature': self.signatureCheckbox.isChecked()
        }
    
    def getRememberPassword(self):
        return self.rememberCheckbox.isChecked()

class EmailClient(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Почта')
        self.setWindowIcon(QIcon(self.style().standardPixmap(QStyle.SP_DirHomeIcon)))
        
        self.smtp_connected = False
        self.imap_connected = False
        self.in_tray = False
        self.seen_message_ids = set()
        self.imap_lock = threading.Lock()
        
        self.password_manager = PasswordManager()
        
        if not self.password_manager.has_master_password():
            dialog = MasterPasswordDialog(mode="setup", parent=self)
            if dialog.exec() == QDialog.Accepted:
                password = dialog.get_password()
                confirm = dialog.get_confirmation()
                if password and password == confirm:
                    if not self.password_manager.set_master_password(password):
                        QMessageBox.critical(self, "Ошибка", "Не удалось установить мастер-пароль")
                        sys.exit(0)
                else:
                    QMessageBox.warning(self, "Ошибка", "Пароли не совпадают или пусты")
                    sys.exit(0)
            else:
                sys.exit(0)
        
        self.loginWindow = LoginWindow(self.password_manager)
        if self.loginWindow.exec() == QDialog.Accepted:
            self.username = self.loginWindow.getEmail()
            self.password = self.loginWindow.getPassword()
            self.smtpServer = self.loginWindow.getSMTPServerInfo()
            self.imapServer = self.loginWindow.getIMAPServerInfo()
            self.crypto_enabled = self.loginWindow.isCryptoEnabled()
            self.crypto_config = self.loginWindow.getCryptoConfig()
            self.remember_password = self.loginWindow.getRememberPassword()
        else:
            sys.exit(0)
        
        if self.remember_password:
            dialog = MasterPasswordDialog(mode="enter", parent=self)
            if dialog.exec() == QDialog.Accepted:
                master_password = dialog.get_password()
                if master_password:
                    # ЯВНАЯ ПРОВЕРКА мастер-пароля перед сохранением
                    if not self.password_manager.verify_master_password(master_password):
                        QMessageBox.warning(self, "Ошибка", "Неверный мастер-пароль")
                    else:
                        if not self.password_manager.save_email_password(
                            self.username,
                            self.password,
                            self.smtpServer,
                            self.imapServer,
                            master_password
                        ):
                            QMessageBox.warning(self, "Предупреждение",
                                              "Не удалось сохранить пароль. Данные не будут сохранены.")
        
        if self.crypto_enabled:
            self.crypto = CryptoManager()
            self.crypto.curve_name = self.crypto_config['curve']
            self.crypto.signature_algorithm = self.crypto_config['signature']
            self.crypto.use_timestamp = self.crypto_config['timestamp']
            self.crypto.use_digital_signature = self.crypto_config['digital_signature']
        else:
            self.crypto = None
        
        self.initConnections()
        self.createUI()
        
        # Создаем и настраиваем фоновый поток — он будет управляться переключением вкладок
        self.updater_thread = EmailUpdaterThread(self)
        self.updater_thread.update_started.connect(self.onUpdateStarted)
        # Подключаем сигналы конкретных завершений к обновлению соответствующих вкладок в GUI
        self.updater_thread.inbox_checked.connect(self.on_inbox_checked)
        self.updater_thread.sent_checked.connect(self.on_sent_checked)
        self.updater_thread.start()
        
        # Устанавливаем начальный режим в соответствии с текущей вкладкой
        current_index = self.tabs.currentIndex() if hasattr(self, 'tabs') else 0
        # 0 = Inbox, 1 = Sent, 2 = New Mail, 3 = Decrypt
        if current_index == 0:
            self.updater_thread.setMode('inbox')
        elif current_index == 1:
            self.updater_thread.setMode('sent')
        else:
            self.updater_thread.setMode('none')
        
        # Таймер для проверки соединений (оставляем как есть)
        self.connection_timer = QTimer()
        self.connection_timer.timeout.connect(self.check_connections)
        self.connection_timer.start(60000)
        
        self.resize(600, 800)
    
    def createSystemTray(self):
        """Создание системного трея"""
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon(self.style().standardPixmap(QStyle.SP_ComputerIcon)))
        
        tray_menu = QMenu()
        show_action = QAction("Показать", self)
        show_action.triggered.connect(self.showNormal)
        tray_menu.addAction(show_action)
        tray_menu.addSeparator()
        exit_action = QAction("Выйти", self)
        exit_action.triggered.connect(self.quitApplication)
        tray_menu.addAction(exit_action)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()
    
    def quitApplication(self):
        """Выход из приложения"""
        try:
            self.updater_thread.stop()
        except Exception:
            pass
        try:
            self.updater_thread.wait(2000)
        except Exception:
            pass
        try:
            self.tray_icon.hide()
        except Exception:
            pass
        QApplication.quit()
    
    def closeEvent(self, event):
        """Обработка закрытия окна - сворачивание в трей"""
        if self.in_tray:
            event.accept()
        else:
            event.ignore()
            self.hide()
            self.in_tray = True
    
    def showNormal(self):
        """Показ окна из трея"""
        super().showNormal()
        self.raise_()
        self.activateWindow()
        self.in_tray = False
    
    def check_connections(self):
        """Периодическая проверка соединений"""
        try:
            if not self.is_imap_alive():
                print("IMAP соединение разорвано, переподключаемся...")
                self.reconnect_imap()
            if not self.smtp_connected:
                print("SMTP соединение разорвано, переподключаемся...")
                self.connectSMTP()
        except Exception as e:
            print(f"Ошибка проверки соединений: {e}")
    
    def is_imap_alive(self):
        """Проверка живости IMAP соединения"""
        try:
            with self.imap_lock:
                if hasattr(self, 'serverIMAP') and self.imap_connected:
                    self.serverIMAP.noop()
                    return True
        except Exception as e:
            print(f"IMAP соединение не живо: {e}")
        return False
    
    def reconnect_imap(self):
        """Переподключение IMAP"""
        try:
            with self.imap_lock:
                if hasattr(self, 'serverIMAP'):
                    try:
                        self.serverIMAP.logout()
                    except:
                        pass
                self.connectIMAP(silent=False)
        except Exception as e:
            print(f"Ошибка переподключения IMAP: {e}")
    
    def createUI(self):
        """Создание пользовательского интерфейса"""
        self.tabs = QTabWidget()
        self.tabs.currentChanged.connect(self.on_tab_changed)
        
        self.inboxTab = QWidget()
        self.inboxLayout = QVBoxLayout()
        self.inboxList = QListWidget()
        self.inboxList.itemDoubleClicked.connect(self.showEmail)
        
        self.keywordLabel = QLabel()
        self.keywordLabel.setText(f'Фильтр: ')
        self.keywordField = QLineEdit()
        self.keywordField.editingFinished.connect(self.refreshInboxList)
        
        self.inboxLayout.addWidget(self.keywordLabel)
        self.inboxLayout.addWidget(self.keywordField)
        self.inboxLayout.addWidget(self.inboxList)
        self.inboxTab.setLayout(self.inboxLayout)
        
        self.sentTab = QWidget()
        self.sentLayout = QVBoxLayout()
        self.sentList = QListWidget()
        self.sentList.itemDoubleClicked.connect(self.showEmail)
        
        self.refreshSentButton = QPushButton("Обновить")
        self.refreshSentButton.clicked.connect(self.refreshSentList)
        
        self.sentLayout.addWidget(self.refreshSentButton)
        self.sentLayout.addWidget(self.sentList)
        self.sentTab.setLayout(self.sentLayout)
        
        self.newMailTab = QWidget()
        self.sendLayout = QVBoxLayout()
        
        self.toLabel = QLabel('<b>Кому:</b>')
        self.toField = QLineEdit()
        
        self.subjectLabel = QLabel('<b>Тема:</b>')
        self.subjectField = QLineEdit()
        
        self.messageLabel = QLabel('<b>Сообщение:</b>')
        self.messageField = QTextEdit()
        
        self.cryptoButtonsLayout = QHBoxLayout()
        self.encryptButton = QPushButton('Зашифровать')
        self.encryptButton.clicked.connect(self.encryptMessage)
        self.encryptButton.setEnabled(self.crypto_enabled)
        
        self.importKeyButton = QPushButton('Импортировать ключ')
        self.importKeyButton.clicked.connect(self.importPublicKey)
        self.importKeyButton.setEnabled(self.crypto_enabled)
        
        self.cryptoButtonsLayout.addWidget(self.encryptButton)
        self.cryptoButtonsLayout.addWidget(self.importKeyButton)
        
        self.sendButton = QPushButton('Отправить')
        self.sendButton.clicked.connect(self.sendEmail)
        
        self.sendLayout.addWidget(self.toLabel)
        self.sendLayout.addWidget(self.toField)
        self.sendLayout.addWidget(self.subjectLabel)
        self.sendLayout.addWidget(self.subjectField)
        self.sendLayout.addWidget(self.messageLabel)
        self.sendLayout.addWidget(self.messageField)
        self.sendLayout.addLayout(self.cryptoButtonsLayout)
        self.sendLayout.addWidget(self.sendButton)
        self.newMailTab.setLayout(self.sendLayout)
        
        self.decryptTab = QWidget()
        self.decryptLayout = QVBoxLayout()
        
        self.decryptLabel = QLabel('<b>Ручная расшифровка сообщения:</b>')
        self.decryptText = QTextEdit()
        self.decryptText.setPlaceholderText("Вставьте зашифрованный текст здесь...")
        
        self.decryptButton = QPushButton('Расшифровать')
        self.decryptButton.clicked.connect(self.manualDecrypt)
        self.decryptButton.setEnabled(self.crypto_enabled)
        
        self.decryptResult = QTextEdit()
        self.decryptResult.setReadOnly(True)
        self.decryptResult.setPlaceholderText("Результат расшифровки появится здесь...")
        
        self.decryptLayout.addWidget(self.decryptLabel)
        self.decryptLayout.addWidget(self.decryptText)
        self.decryptLayout.addWidget(self.decryptButton)
        self.decryptLayout.addWidget(QLabel('<b>Результат:</b>'))
        self.decryptLayout.addWidget(self.decryptResult)
        self.decryptTab.setLayout(self.decryptLayout)
        
        self.tabs.addTab(self.inboxTab, 'Входящие')
        self.tabs.addTab(self.sentTab, 'Отправленные')
        self.tabs.addTab(self.newMailTab, 'Новое письмо')
        self.tabs.addTab(self.decryptTab, 'Ручная расшифровка')
        
        mainLayout = QVBoxLayout()
        mainLayout.addWidget(self.tabs)
        self.setLayout(mainLayout)
        
        self.createSystemTray()
    
    def manualDecrypt(self):
        """Ручная расшифровка текста"""
        if not self.crypto_enabled:
            QMessageBox.warning(self, "Ошибка", "Криптография отключена")
            return
        
        text = self.decryptText.toPlainText().strip()
        if not text:
            QMessageBox.warning(self, "Ошибка", "Введите текст для расшифровки")
            return
        
        try:
            result = self.crypto.try_decrypt_any_text(text, is_sent_message=True)
            if result["is_encrypted"]:
                output = f"✅ Успешно расшифровано!\n\n"
                if result.get('timestamp'):
                    output += f"Время отправки: {result['timestamp']}\n\n"
                output += f"Сообщение:\n{result['message']}\n\n"
                if result.get('signature'):
                    if result.get('signature_valid'):
                        output += "✓ Подпись подтверждена\n"
                    elif result.get('signature_error'):
                        output += f"⚠ {result['signature_error']}\n"
                    else:
                        output += "⚠ Подпись неверна\n"
                if result.get('checksum_valid') is not None:
                    if result['checksum_valid']:
                        output += "✓ Контрольная сумма совпадает\n"
                    else:
                        output += "⚠ Контрольная сумма не совпадает\n"
            else:
                output = f"❌ Не удалось расшифровать\n\n"
                output += f"Ошибка: {result.get('error', 'Неизвестная ошибка')}\n\n"
                output += f"Исходный текст:\n{text}"
            
            self.decryptResult.setPlainText(output)
        except Exception as e:
            self.decryptResult.setPlainText(f"Ошибка при расшифровке: {str(e)}")
    
    def initConnections(self):
        """Инициализирует SMTP и IMAP соединения"""
        error = False
        error_details = []
        
        if not self.connectSMTP():
            error = True
            error_details.append("Не удалось подключиться к SMTP серверу")
        
        if not self.connectIMAP():
            error = True
            error_details.append("Не удалось подключиться к IMAP серверу")
        
        if error:
            errorMessage = QMessageBox()
            errorMessage.setWindowIcon(QIcon(self.style().standardPixmap(QStyle.SP_MessageBoxCritical)))
            errorMessage.setIcon(QMessageBox.Critical)
            errorMessage.setText("Ошибка подключения")
            errorMessage.setInformativeText("\n\n".join(error_details))
            errorMessage.setWindowTitle("Ошибка авторизации")
            errorMessage.exec()
            sys.exit(0)
    
    def connectSMTP(self, silent=False):
        """Подключение к SMTP серверу"""
        try:
            if self.smtpServer[1] == 587:
                self.serverSMTP = smtplib.SMTP(self.smtpServer[0], self.smtpServer[1])
                self.serverSMTP.starttls()
            else:
                context = ssl.create_default_context()
                context.set_ciphers('DEFAULT@SECLEVEL=1')
                self.serverSMTP = smtplib.SMTP_SSL(
                    self.smtpServer[0],
                    self.smtpServer[1],
                    context=context
                )
            self.serverSMTP.login(self.username, self.password)
            self.smtp_connected = True
            if not silent:
                print(f"SMTP подключение успешно: {self.smtpServer[0]}:{self.smtpServer[1]}")
            return True
        except Exception as e:
            self.smtp_connected = False
            if not silent:
                print(f"Ошибка подключения SMTP: {e}")
            return False
    
    def connectIMAP(self, silent=False):
        """Подключение к IMAP серверу"""
        try:
            context = ssl.create_default_context()
            context.set_ciphers('DEFAULT@SECLEVEL=1')
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            self.serverIMAP = imaplib.IMAP4_SSL(
                host=self.imapServer[0],
                port=self.imapServer[1],
                ssl_context=context
            )
            response = self.serverIMAP.login(self.username, self.password)
            self.imap_connected = True
            if not silent:
                print(f"IMAP подключение успешно: {self.imapServer[0]}:{self.imapServer[1]}")
            return True
        except Exception as e:
            self.imap_connected = False
            if not silent:
                print(f"Ошибка подключения IMAP: {e}")
            return False
    
    def logOut(self):
        """Выход из системы"""
        try:
            if self.smtp_connected:
                self.serverSMTP.quit()
        except:
            pass
        try:
            if self.imap_connected:
                with self.imap_lock:
                    self.serverIMAP.logout()
        except:
            pass
        self.quitApplication()
    
    def getInitMessageNum(self):
        """Подсчет сообщений при запуске"""
        try:
            with self.imap_lock:
                if self.imap_connected:
                    self.serverIMAP.select('inbox')
                    status, messages = self.serverIMAP.search(None, 'ALL')
                    if status == 'OK':
                        for num in messages[0].split():
                            self.seen_message_ids.add(num)
                        return len(messages[0].split())
        except Exception as e:
            print(f"Ошибка при подсчете сообщений: {e}")
        return 0
    
    @Slot()
    def onUpdateStarted(self):
        """Начало обновления"""
        pass
    
    @Slot()
    def onUpdateFinished(self):
        """Окончание обновления (не используется напрямую теперь)"""
        pass

    @Slot()
    def on_inbox_checked(self):
        """Slot called when updater thread finished inbox check — refresh inbox in GUI thread"""
        try:
            self.refreshInboxList()
        except Exception as e:
            print(f"Ошибка при обновлении списка входящих из GUI: {e}")

    @Slot()
    def on_sent_checked(self):
        """Slot called when updater thread requested sent refresh — refresh sent in GUI thread"""
        try:
            self.refreshSentList()
        except Exception as e:
            print(f"Ошибка при обновлении списка отправленных из GUI: {e}")

    def checkForKeyRequests(self):
        """Проверка запросов на публичный ключ"""
        if not self.crypto_enabled:
            return
        
        try:
            with self.imap_lock:
                if self.imap_connected:
                    self.serverIMAP.select('inbox')
                    # ОПТИМИЗАЦИЯ: Проверяем только непрочитанные сообщения для запросов ключа
                    status, messages = self.serverIMAP.search(None, 'UNSEEN')
                    if status != 'OK':
                        return
                    
                    for num in messages[0].split()[::-1]:
                        try:
                            status, message = self.serverIMAP.fetch(num, '(RFC822)')
                            if status != 'OK':
                                continue
                            
                            emailMessage = email.message_from_bytes(message[0][1])
                            sender = email.utils.parseaddr(emailMessage['From'])[1]
                            body = ""
                            
                            if emailMessage.is_multipart():
                                for part in emailMessage.walk():
                                    content_type = part.get_content_type()
                                    content_disposition = str(part.get("Content-Disposition"))
                                    if "attachment" not in content_disposition:
                                        if "text/plain" in content_type:
                                            body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                                            break
                            else:
                                body = emailMessage.get_payload(decode=True).decode('utf-8', errors='ignore')
                            
                            if "get_public_key" in body.lower():
                                print(f"Обнаружен запрос ключа от {sender}")
                                self.sendPublicKey(sender)
                        except Exception as e:
                            print(f"Ошибка при обработке письма: {e}")
                            continue
        except Exception as e:
            print(f"Ошибка при проверке запросов ключа: {e}")
    
    def sendPublicKey(self, to_email):
        """Отправка публичного ключа"""
        if not self.crypto_enabled:
            return
        
        public_key = self.crypto.get_public_key_pem()
        if not public_key:
            return
        
        message = MIMEText(f"Мой публичный ключ:\n\n{public_key}", _charset='utf-8')
        message['Subject'] = 'Публичный ключ'
        message['From'] = self.username
        message['To'] = to_email
        message.add_header('Disposition-Notification-To', self.username)
        message.add_header('Message-ID', email.utils.make_msgid())
        
        try:
            if not self.smtp_connected:
                self.connectSMTP(silent=True)
            if self.smtp_connected:
                self.serverSMTP.send_message(message)
                print(f"Публичный ключ отправлен на {to_email}")
        except Exception as e:
            print(f"Ошибка отправки публичного ключа: {e}")
            self.smtp_connected = False
    
    def refreshSentList(self):
        """Обновление списка отправленных"""
        try:
            with self.imap_lock:
                if not self.imap_connected:
                    if not self.connectIMAP(silent=True):
                        return
                
                self.sentList.clear()
                # try common sent folders
                try:
                    self.serverIMAP.select('Sent')
                except:
                    # fallback to 'Sent Items' or other names
                    try:
                        self.serverIMAP.select('Sent Items')
                    except:
                        pass
                
                # ОПТИМИЗАЦИЯ: Ограничиваем количество загружаемых сообщений
                status, messages = self.serverIMAP.search(None, 'ALL')
                if status != 'OK':
                    return
                
                items = []
                message_nums = messages[0].split()
                # Берем только последние 50 сообщений для отображения
                for num in message_nums[-50:]:
                    try:
                        status, message = self.serverIMAP.fetch(num, '(RFC822)')
                        if status != 'OK':
                            continue
                        
                        emailMessage = email.message_from_bytes(message[0][1])
                        subject = emailMessage['Subject']
                        subject = self.decodeUTF8(subject)
                        
                        body = self.getEmailBody(emailMessage)
                        decrypted_text = None
                        is_encrypted = False
                        
                        if self.crypto_enabled:
                            sent_messages = self.crypto.get_all_sent_messages()
                            for msg_id, msg_data in sent_messages.items():
                                encrypted_in_body = msg_data.get('encrypted', '')
                                if encrypted_in_body and encrypted_in_body in body:
                                    decrypted_text = msg_data.get('plaintext', '')
                                    is_encrypted = True
                                    subject = f"🔒 {subject}"
                                    break
                            
                            if not decrypted_text and self.crypto.is_encrypted_message(body):
                                is_encrypted = True
                                subject = f"🔒 {subject}"
                            else:
                                clean_body = body.strip()
                                if (len(clean_body) > 50 and
                                    all(c.isalnum() or c in '+/=' for c in clean_body) and
                                    len(clean_body) % 4 == 0):
                                    is_encrypted = True
                                    subject = f"🔐 {subject} (без маркеров)"
                        
                        item = QListWidgetItem(f'{subject}')
                        if is_encrypted:
                            item.setIcon(self.style().standardIcon(QStyle.SP_MessageBoxInformation))
                        else:
                            item.setIcon(self.style().standardIcon(QStyle.SP_ArrowForward))
                        item.email = emailMessage
                        item.from_ = emailMessage['From']
                        item.to = emailMessage['To']
                        item.is_encrypted = is_encrypted
                        item.is_sent = True
                        item.decrypted_text = decrypted_text
                        items.append(item)
                    except Exception as e:
                        print(f"Ошибка при обработке письма: {e}")
                        continue
                
                for item in items[::-1]:
                    self.sentList.addItem(item)
        except Exception as e:
            print(f"Ошибка при обновлении отправленных: {e}")
            self.imap_connected = False
    
    def refreshInboxList(self):
        """Обновление списка входящих"""
        try:
            with self.imap_lock:
                if not self.imap_connected:
                    if not self.connectIMAP(silent=True):
                        return
                
                self.inboxList.clear()
                self.serverIMAP.select('inbox')
                
                keyword = self.keywordField.text()
                if keyword:
                    # Поиск по ключевому слову в теме
                    status, messages = self.serverIMAP.search(None, f'SUBJECT "{keyword}"')
                else:
                    # ОПТИМИЗАЦИЯ: Загружаем только последние 100 сообщений
                    status, messages = self.serverIMAP.search(None, 'ALL')
                
                if status != 'OK':
                    return
                
                items = []
                message_nums = messages[0].split()
                # Берем только последние 100 сообщений для отображения
                for num in message_nums[-100:][::-1]:
                    try:
                        status, message = self.serverIMAP.fetch(num, '(RFC822)')
                        if status != 'OK':
                            continue
                        
                        emailMessage = email.message_from_bytes(message[0][1])
                        subject = emailMessage['Subject']
                        subject = self.decodeUTF8(subject)
                        
                        is_encrypted = False
                        if self.crypto_enabled:
                            body = self.getEmailBody(emailMessage)
                            if self.crypto.is_encrypted_message(body):
                                is_encrypted = True
                                subject = f"🔒 {subject}"
                            else:
                                clean_body = body.strip()
                                if (len(clean_body) > 50 and
                                    all(c.isalnum() or c in '+/=' for c in clean_body) and
                                    len(clean_body) % 4 == 0):
                                    is_encrypted = True
                                    subject = f"🔐 {subject} (без маркеров)"
                        
                        item = QListWidgetItem(f'{subject}')
                        if is_encrypted:
                            item.setIcon(self.style().standardIcon(QStyle.SP_MessageBoxInformation))
                        else:
                            item.setIcon(self.style().standardIcon(QStyle.SP_ArrowForward))
                        item.email = emailMessage
                        item.from_ = emailMessage['From']
                        item.to = emailMessage['To']
                        item.is_encrypted = is_encrypted
                        item.is_sent = False
                        items.append(item)
                    except Exception as e:
                        print(f"Ошибка при обработке письма: {e}")
                        continue
                
                for item in items:
                    self.inboxList.addItem(item)
        except Exception as e:
            print(f"Ошибка при обновлении входящих: {e}")
            self.imap_connected = False
    
    def getEmailBody(self, emailMessage) -> str:
        """Извлечение тела письма"""
        body = ""
        if emailMessage.is_multipart():
            for part in emailMessage.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                if "attachment" not in content_disposition:
                    if "text/plain" in content_type:
                        body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                        break
                    elif "text/html" in content_type:
                        html_body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                        try:
                            body = BeautifulSoup(html_body, 'html.parser').get_text()
                        except:
                            body = html_body.replace('\n', ' ')
                        break
        else:
            body = emailMessage.get_payload(decode=True).decode('utf-8', errors='ignore')
        return body
    
    def hasCyrillic(self, text: str) -> bool:
        """Проверка на наличие кириллицы"""
        cyrillic = 'абвгдеёжзийклмнопрстуфхцчшщъыьэюя'
        text_lower = text.lower()
        return any(char in text_lower for char in cyrillic)
    
    def hasEnglishOnly(self, text: str) -> bool:
        """Проверка, что текст содержит только английские буквы, цифры и спецсимволы"""
        import re
        pattern = r'^[a-zA-Z0-9\s!@#$%^&*()_+\-=\[\]{};\'\\:"|,.<>\/?`~]+$'
        return bool(re.match(pattern, text)) and not self.hasCyrillic(text)
    
    def showEmail(self, item):
        """Показать письмо в новом окне"""
        emailMessage = item.email
        to = self.decodeUTF8(emailMessage['To'])
        from_ = self.decodeUTF8(email.utils.parseaddr(emailMessage['From'])[1])
        subject = self.decodeUTF8(emailMessage['Subject'])
        body = self.getEmailBody(emailMessage)
        sender_email = email.utils.parseaddr(from_)[1]
        
        is_encrypted = getattr(item, 'is_encrypted', False)
        has_cyrillic = self.hasCyrillic(body)
        english_only = self.hasEnglishOnly(body)
        
        window = QDialog()
        window.setWindowTitle(subject)
        window.setWindowIcon(QIcon(self.style().standardPixmap(QStyle.SP_FileDialogContentsView)))
        
        layout = QVBoxLayout()
        
        infoLayout = QGridLayout()
        infoLayout.addWidget(QLabel('<b>От:</b>'), 0, 0)
        infoLayout.addWidget(QLabel(from_), 0, 1)
        infoLayout.addWidget(QLabel('<b>Кому:</b>'), 1, 0)
        infoLayout.addWidget(QLabel(to), 1, 1)
        infoLayout.addWidget(QLabel('<b>Тема:</b>'), 2, 0)
        infoLayout.addWidget(QLabel(subject), 2, 1)
        
        if is_encrypted:
            infoLayout.addWidget(QLabel('<b>Статус:</b>'), 3, 0)
            infoLayout.addWidget(QLabel('<font color="green">🔒 Зашифровано</font>'), 3, 1)
        
        layout.addLayout(infoLayout)
        
        bodyLabel = QWebEngineView()
        
        if is_encrypted and self.crypto_enabled:
            decrypted_text = getattr(item, 'decrypted_text', None)
            if decrypted_text:
                display_text = f"""
                <html>
                <head>
                <style>
                    body {{ font-family: Arial; padding: 20px; }}
                    .decrypted {{ background-color:
                    .encrypted {{ background-color:
                </style>
                </head>
                <body>
                    <h3>Расшифрованное сообщение (из сохраненных данных):</h3>
                    <div class="decrypted">
                        <p><strong>Сообщение:</strong> {decrypted_text}</p>
                    </div>
                    <h3>Исходный зашифрованный текст:</h3>
                    <div class="encrypted">
                """
                display_text += body.replace('<', '&lt;').replace('>', '&gt;')
                display_text += "</div></body></html>"
                bodyLabel.setHtml(display_text)
            else:
                decrypted = self.crypto.try_decrypt_any_text(body,
                                                            sender_email if not getattr(item, 'is_sent', False) else None,
                                                            getattr(item, 'is_sent', False))
                if decrypted["is_encrypted"]:
                    display_text = f"""
                    <html>
                    <head>
                    <style>
                        body {{ font-family: Arial; padding: 20px; }}
                        .decrypted {{ background-color:
                        .signature-valid {{ color: green; font-weight: bold; }}
                        .signature-invalid {{ color: orange; font-weight: bold; }}
                        .signature-error {{ color: red; font-weight: bold; }}
                        .encrypted {{ background-color:
                    </style>
                    </head>
                    <body>
                        <h3>Расшифрованное сообщение:</h3>
                        <div class="decrypted">
                            <p><strong>Сообщение:</strong> {decrypted['message']}</p>
                    """
                    if decrypted.get('timestamp'):
                        display_text += f'<p><strong>Время отправки:</strong> {decrypted["timestamp"]}</p>'
                    
                    if decrypted.get('signature'):
                        if decrypted.get('signature_valid'):
                            display_text += '<p><strong>Подпись:</strong> <span class="signature-valid">✓ ПОДТВЕРЖДЕНА</span></p>'
                        elif decrypted.get('signature_error'):
                            display_text += f'<p><strong>Подпись:</strong> <span class="signature-error">⚠ {decrypted["signature_error"]}</span></p>'
                        else:
                            display_text += '<p><strong>Подпись:</strong> <span class="signature-invalid">⚠ НЕВЕРНА</span></p>'
                    else:
                        display_text += '<p><strong>Подпись:</strong> отсутствует</p>'
                    
                    if decrypted.get('checksum_valid') is not None:
                        if decrypted['checksum_valid']:
                            display_text += '<p><strong>Контрольная сумма:</strong> ✓ СОВПАДАЕТ</p>'
                        else:
                            display_text += '<p><strong>Контрольная сумма:</strong> ⚠ НЕ СОВПАДАЕТ</p>'
                    
                    display_text += """
                        </div>
                        <h3>Исходный зашифрованный текст:</h3>
                        <div class="encrypted">
                    """
                    display_text += body.replace('<', '&lt;').replace('>', '&gt;')
                    display_text += "</div></body></html>"
                    bodyLabel.setHtml(display_text)
                else:
                    bodyLabel.setHtml(f"""
                    <html>
                    <body style="font-family: Arial; padding: 20px;">
                        <h3>Не удалось расшифровать сообщение:</h3>
                        <p style="color: red;">{decrypted.get('error', 'Неизвестная ошибка')}</p>
                        <h3>Исходный текст:</h3>
                        <pre style="background-color: #f5f5f5; padding: 15px; border-radius: 5px;">
                        {body}
                        </pre>
                    </body>
                    </html>
                    """)
        else:
            bodyLabel.setHtml(f"<pre>{body}</pre>")
        
        layout.addWidget(QLabel("<b>Содержимое:</b>"))
        layout.addWidget(bodyLabel)
        
        buttonLayout = QHBoxLayout()
        copyButton = QPushButton("Копировать текст")
        copyButton.clicked.connect(lambda: QApplication.clipboard().setText(body))
        
        if (self.crypto_enabled and english_only and len(body) > 10) or (is_encrypted and self.crypto_enabled):
            decryptButton = QPushButton("Расшифровать" if not is_encrypted else "Повторить расшифровку")
            decryptButton.clicked.connect(lambda: self.decryptAndShow(body, window, sender_email, getattr(item, 'is_sent', False)))
            buttonLayout.addWidget(decryptButton)
        
        buttonLayout.addWidget(copyButton)
        closeButton = QPushButton("Закрыть")
        closeButton.clicked.connect(window.close)
        buttonLayout.addWidget(closeButton)
        
        layout.addLayout(buttonLayout)
        window.setLayout(layout)
        window.resize(800, 600)
        window.exec()
    
    def decryptAndShow(self, text, parent_window, sender_email, is_sent=False):
        """Расшифровка и показ сообщения"""
        if not self.crypto_enabled:
            QMessageBox.warning(parent_window, "Ошибка", "Криптография отключена")
            return
        
        try:
            decrypted = self.crypto.try_decrypt_any_text(text,
                                                        sender_email if not is_sent else None,
                                                        is_sent)
            dialog = QDialog(parent_window)
            dialog.setWindowTitle("Результат расшифровки")
            layout = QVBoxLayout()
            
            if decrypted["is_encrypted"]:
                if decrypted.get('timestamp'):
                    layout.addWidget(QLabel(f"<b>Время отправки:</b> {decrypted['timestamp']}"))
                
                layout.addWidget(QLabel("<b>Сообщение:</b>"))
                text_edit = QTextEdit()
                text_edit.setPlainText(decrypted['message'])
                text_edit.setReadOnly(True)
                layout.addWidget(text_edit)
                
                if decrypted.get('signature'):
                    if decrypted.get('signature_valid'):
                        layout.addWidget(QLabel("<b>Подпись:</b> <font color='green'>✓ ПОДТВЕРЖДЕНА</font>"))
                    elif decrypted.get('signature_error'):
                        layout.addWidget(QLabel(f"<b>Подпись:</b> <font color='orange'>⚠ {decrypted['signature_error']}</font>"))
                    else:
                        layout.addWidget(QLabel("<b>Подпись:</b> <font color='red'>⚠ НЕВЕРНА</font>"))
                else:
                    layout.addWidget(QLabel("<b>Подпись:</b> отсутствует"))
                
                if decrypted.get('checksum_valid') is not None:
                    if decrypted['checksum_valid']:
                        layout.addWidget(QLabel("<b>Контрольная сумма:</b> <font color='green'>✓ СОВПАДАЕТ</font>"))
                    else:
                        layout.addWidget(QLabel("<b>Контрольная сумма:</b> <font color='red'>⚠ НЕ СОВПАДАЕТ</font>"))
            else:
                layout.addWidget(QLabel(f"<b>Результат:</b> <font color='red'>{decrypted.get('error', 'Не удалось расшифровать')}</font>"))
                layout.addWidget(QLabel("<i>Сообщение не является зашифрованным или произошла ошибка</i>"))
            
            dialog.setLayout(layout)
            dialog.resize(500, 400)
            dialog.exec()
        except Exception as e:
            QMessageBox.critical(parent_window, "Ошибка", f"Не удалось расшифровать: {str(e)}")
    
    def encryptMessage(self):
        """Шифрование сообщения перед отправкой"""
        if not self.crypto_enabled:
            QMessageBox.warning(self, "Ошибка", "Криптография отключена")
            return
        
        recipient = self.toField.text().strip()
        if not recipient:
            QMessageBox.warning(self, "Ошибка", "Введите адрес получателя")
            return
        
        message = self.messageField.toPlainText().strip()
        if not message:
            QMessageBox.warning(self, "Ошибка", "Введите сообщение для шифрования")
            return
        
        if not self.crypto.has_contact_key(recipient):
            reply = QMessageBox.question(
                self,
                "Ключ не найден",
                f"Публичный ключ для {recipient} не найден. Хотите импортировать ключ?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                self.importPublicKeyForRecipient(recipient)
                return
            else:
                QMessageBox.warning(self, "Предупреждение",
                                   "Сообщение будет отправлено без шифрования")
                return
        
        try:
            encrypted, message_id = self.crypto.encrypt_message(message, recipient)
            self.messageField.setPlainText(encrypted)
            self.crypto.add_sent_message(message_id, encrypted, message, recipient)
            QMessageBox.information(self, "Успех", f"Сообщение зашифровано (ID: {message_id})")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка шифрования: {str(e)}")
    
    def importPublicKey(self):
        """Импорт публичного ключа"""
        if not self.crypto_enabled:
            QMessageBox.warning(self, "Ошибка", "Криптография отключена")
            return
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Импорт публичного ключа")
        layout = QVBoxLayout()
        
        layout.addWidget(QLabel("Введите email:"))
        email_edit = QLineEdit()
        layout.addWidget(email_edit)
        
        layout.addWidget(QLabel("Введите публичный ключ (PEM формат):"))
        key_edit = QTextEdit()
        layout.addWidget(key_edit)
        
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(dialog.accept)
        button_box.rejected.connect(dialog.reject)
        layout.addWidget(button_box)
        
        dialog.setLayout(layout)
        
        if dialog.exec() == QDialog.Accepted:
            email = email_edit.text().strip()
            key = key_edit.toPlainText().strip()
            if email and key:
                if self.crypto.save_contact_key(email, key):
                    QMessageBox.information(self, "Успех", f"Ключ для {email} успешно импортирован")
                else:
                    QMessageBox.critical(self, "Ошибка", "Ошибка импорта ключа")
    
    def importPublicKeyForRecipient(self, recipient):
        """Импорт ключа для конкретного получателя"""
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Импорт ключа для {recipient}")
        layout = QVBoxLayout()
        
        layout.addWidget(QLabel(f"Введите публичный ключ для {recipient} (PEM формат):"))
        key_edit = QTextEdit()
        layout.addWidget(key_edit)
        
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(dialog.accept)
        button_box.rejected.connect(dialog.reject)
        layout.addWidget(button_box)
        
        dialog.setLayout(layout)
        
        if dialog.exec() == QDialog.Accepted:
            key = key_edit.toPlainText().strip()
            if key:
                if self.crypto.save_contact_key(recipient, key):
                    QMessageBox.information(self, "Успех", f"Ключ для {recipient} успешно импортирован")
                    self.encryptMessage()
                else:
                    QMessageBox.critical(self, "Ошибка", "Ошибка импорта ключа")
    
    def sendEmail(self):
        """Отправка письма"""
        if not self.toField.text().strip():
            QMessageBox.warning(self, "Ошибка", "Введите адрес получателя")
            return
        
        if not self.subjectField.text().strip():
            QMessageBox.warning(self, "Ошибка", "Введите тему письма")
            return
        
        message = MIMEText(self.messageField.toPlainText(), _charset='utf-8')
        message['Subject'] = self.subjectField.text()
        message['From'] = self.username
        message['To'] = self.toField.text()
        message.add_header('Disposition-Notification-To', self.username)
        message.add_header('Message-ID', email.utils.make_msgid())
        
        success = False
        for attempt in range(2):
            try:
                if not self.smtp_connected:
                    if not self.connectSMTP(silent=True):
                        continue
                print(f"Попытка отправки письма (попытка {attempt + 1})...")
                self.serverSMTP.send_message(message)
                success = True
                break
            except Exception as e:
                print(f"Ошибка соединения при отправке: {e}")
                self.smtp_connected = False
                if attempt == 0:
                    if not self.connectSMTP(silent=True):
                        continue
        
        if success:
            print('Письмо успешно отправлено!')
            QMessageBox.information(self, "Успех", "Письмо успешно отправлено")
            
            try:
                with self.imap_lock:
                    if self.imap_connected:
                        import time
                        self.serverIMAP.append('Sent', None,
                                              imaplib.Time2Internaldate(time.time()),
                                              str(message).encode('utf-8'))
                        print("Письмо сохранено в папке Sent")
            except Exception as e:
                print(f'Ошибка IMAP при сохранении в отправленные: {e}')
                self.imap_connected = False
            
            QTimer.singleShot(1000, self.refreshSentList)
            self.toField.clear()
            self.subjectField.clear()
            self.messageField.clear()
        else:
            QMessageBox.critical(self, "Ошибка",
                               "Не удалось отправить письмо. Проверьте подключение к интернету.")
    
    @staticmethod
    def decodeUTF8(subject):
        """Декодирование UTF-8 строк"""
        if subject is None:
            return "(без темы)"
        
        decoded = ''.join(
            text if isinstance(text, str) else text.decode(charset or 'utf-8', errors='ignore')
            for text, charset in email.header.decode_header(subject)
        )
        return decoded

    @Slot(int)
    def on_tab_changed(self, index: int):
        """
        Управление режимом фонового потока в зависимости от активной вкладки:
         - При переключении на Inbox (index 0) — немедленная проверка и затем периодическая каждые 30 секунд.
         - При переключении на Sent (index 1) — однократная проверка.
         - При переключении на другие вкладки — отключаем проверки.
        """
        try:
            if index == 0:
                # Inbox
                if hasattr(self, 'updater_thread'):
                    self.updater_thread.setMode('inbox')
                    self.updater_thread.requestImmediateInboxCheck()
            elif index == 1:
                # Sent
                if hasattr(self, 'updater_thread'):
                    self.updater_thread.setMode('sent')
                    self.updater_thread.requestSentCheck()
            else:
                if hasattr(self, 'updater_thread'):
                    self.updater_thread.setMode('none')
        except Exception as e:
            print(f"Ошибка при изменении вкладки: {e}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    client = EmailClient()
    client.show()
    sys.exit(app.exec())
