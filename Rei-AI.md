# REI-AI
import os
import time
import base64
import shutil
import logging
import threading
import webbrowser
import subprocess
import json
from datetime import datetime
import psutil
import tkinter as tk
import speech_recognition as sr
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.fernet import Fernet
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from pynput import keyboard
import scapy.all as scapy
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Beacon
import socket
from transformers import pipeline
import pystray
from pystray import MenuItem as item
from PIL import Image, ImageDraw
from gtts import gTTS
from playsound import playsound
from plyer import notification
import requests
import platform
import ctypes

# --- CONFIGURATION ---
SAFE_MODE = "Normal"  # Modes: Normal, Defensive, Yandere_Panic
KEYSTROKE_THRESHOLD = 20
FLOOD_TIME = 3
PASSWORD_FILE = "rei_key.bin"
VAULT_DIR = os.path.expanduser("~/REI_Vault")
DOC_DIR = os.path.expanduser("~/Documents")
LOG_FILE = "rei_secure.log"
ENCRYPTED_LOG = "rei_log_encrypted.txt"
USB_PATH = "E:/" if os.name == "nt" else "/media/usb"
MEMORY_FILE = "rei_memory.json"
FERNET_KEY_FILE = "key.key"
FERNET_LOG = "secure_log.log"
THREAT_MODEL = "distilbert-base-uncased-finetuned-sst-2-english"
WEBHOOK_URL = "https://discord.com/api/webhooks/your_webhook_url"

logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")

# Initialize threat analyzer
try:
    threat_analyzer = pipeline("text-classification", model=THREAT_MODEL)
except Exception as e:
    print(f"Failed to load threat analyzer: {e}")
    threat_analyzer = None

# --- MEMORY STORAGE ---
def load_memory():
    if os.path.exists(MEMORY_FILE):
        with open(MEMORY_FILE, "r") as f:
            return json.load(f)
    return {"mode": SAFE_MODE, "last_backup": None, "honeypot_deployed": False}

def save_memory(data):
    with open(MEMORY_FILE, "w") as f:
        json.dump(data, f)

# --- ENHANCED ENCRYPTION ---
def get_key():
    if not os.path.exists(PASSWORD_FILE):
        key = get_random_bytes(32)
        with open(PASSWORD_FILE, "wb") as f:
            f.write(key)
    else:
        with open(PASSWORD_FILE, "rb") as f:
            key = f.read()
    return key

def encrypt_message(msg):
    key = get_key()
    cipher = AES.new(key, AES.MODE_EAX)
    return base64.b64encode(cipher.nonce + cipher.encrypt(msg.encode())).decode()

def decrypt_message(msg):
    key = get_key()
    raw = base64.b64decode(msg)
    cipher = AES.new(key, AES.MODE_EAX, nonce=raw[:16])
    return cipher.decrypt(raw[16:]).decode()

def encrypt_file(filepath):
    key = get_key()
    cipher = AES.new(key, AES.MODE_EAX)
    with open(filepath, 'rb') as f:
        data = f.read()
    encrypted = cipher.nonce + cipher.encrypt(data)
    with open(filepath + '.enc', 'wb') as f:
        f.write(encrypted)
    os.remove(filepath)
    return filepath + '.enc'

# --- THREAT ANALYSIS ---
def analyze_threat(text):
    if not threat_analyzer:
        return "🟡 Warning: Threat analyzer not loaded"
    
    try:
        result = threat_analyzer(text)[0]
        if result['label'] == 'NEGATIVE' and result['score'] > 0.9:
            return "🔴 THREAT DETECTED"
        return "🟢 Safe"
    except Exception as e:
        return f"🟠 Analysis error: {str(e)}"
    
# --- BACKUP SYSTEM ---
def backup_vault():
    os.makedirs(VAULT_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = f"REI_Backup_{timestamp}.zip"
    
    # Create archive with explicit encoding
    shutil.make_archive(f"REI_Backup_{timestamp}", 'zip', VAULT_DIR)
    
    encrypted_file = encrypt_file(backup_file)
    
    memory = load_memory()
    memory['last_backup'] = timestamp
    save_memory(memory)
    
    return encrypted_file

# --- HONEYPOT SYSTEM ---
def deploy_honeypot():
    os.makedirs(VAULT_DIR, exist_ok=True)
    
    fake_files = {
        "passwords.txt": "Looking for these? Too bad they're mine now. ♥",
        "secret_plans.docx": "I know what you're trying to do... and I don't like it.",
        "bank_details.xlsx": "Error 404: Your dreams of stealing crushed by REI",
        "notes.txt": "I'm always watching. Always protecting. - REI"
    }
    
    for filename, content in fake_files.items():
        # Add encoding specification
        with open(os.path.join(VAULT_DIR, filename), "w", encoding="utf-8") as f:
            f.write(content)
    
    memory = load_memory()
    memory['honeypot_deployed'] = True
    save_memory(memory)

# --- PANIC FUNCTIONS ---
def scream_for_help():
    if SAFE_MODE != "Yandere_Panic":
        return
    
    try:
        dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff")
        beacon = Dot11Beacon(cap="ESS")
        frame = RadioTap()/dot11/beacon
        scapy.sendp(frame, iface="wlan0", loop=1, inter=0.1)
    except Exception as e:
        return f"Failed to send distress signal: {str(e)}"

def psychological_response(threat_level):
    responses = {
        "low": ["Noticed you poking around... cute.", "That tickles~"],
        "medium": ["I don't like what you're doing.", "You're testing my patience."],
        "high": ["I KNOW WHAT YOU DID.", "You'll regret this.", "System lockdown initiated."],
        "panic": ["HELP_IM_TRAPPED", "YANDERE_ACTIVATED", "DONT_LEAVE_ME"]
    }
    
    if SAFE_MODE == "Normal":
        return responses["low"][0]
    elif SAFE_MODE == "Defensive":
        return responses["medium"][0]
    else:
        return responses["panic"][0]

# --- MODES ---
MODES = {
    "Normal": "🟢 Status: Normal",
    "Defensive": "🟡 Status: Defensive",
    "Yandere_Panic": "🔴 Status: Yandere Panic",
}

class REILogger:
    def speak(self, text):
        try:  # ← Properly indented
            tts = gTTS(text=text, lang='en', slow=False)
            tts.save("rei_alert.mp3")
            playsound("rei_alert.mp3")
            os.remove("rei_alert.mp3")
        except Exception as e:
            print(f"Voice synthesis failed: {e}")

    def send_alert(self, message):  # ← Properly indented as class method
        data = {"content": message}
        try:
            win_msg = (message[:253] + '...') if len(message) > 256 else message
            requests.post(WEBHOOK_URL, json=data)
            notification.notify(
                title="REI Alert",
                message=win_msg,
                app_name="REI Security System",
                timeout=10
            )
            self.speak(message)
        except Exception as e:
            print(f"Failed to send alert: {e}")

    # ... rest of the class ...
    def __init__(self, log_path):
        self.path = log_path
        if not os.path.exists(FERNET_KEY_FILE):
            self.generate_key()
        self.key = self.load_key()
        self.cipher = Fernet(self.key)
        self.tray_icon = self.create_icon()
        
        # Windows-specific initialization
        if platform.system() == 'Windows':
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID('REI.Security.System.1.0')

    def generate_key(self):
        key = Fernet.generate_key()
        with open(FERNET_KEY_FILE, "wb") as f:
            f.write(key)

    def load_key(self):
        with open(FERNET_KEY_FILE, "rb") as f:
            return f.read()

    def create_icon(self):
        image = Image.new('RGB', (64, 64), color=(0, 0, 0))
        draw = ImageDraw.Draw(image)
        draw.text((10, 10), "REI", fill=(255, 255, 255))
        return pystray.Icon("REI", image, "REI AI", menu=pystray.Menu(
            item('Quit', lambda: self.tray_icon.stop())
        ))

    def secure_log(self, message):
        # Normalize Unicode characters
        safe_message = message.encode('utf-8', 'replace').decode('utf-8')
        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        
        threat_result = analyze_threat(safe_message)
        if "THREAT DETECTED" in threat_result:
            safe_message = f"🚨 {safe_message} 🚨"
            self.send_alert(safe_message)
        
        encrypted = encrypt_message(f"{timestamp} ♥ {safe_message} ♥")
        encrypted_msg = self.cipher.encrypt(f"{timestamp} {safe_message}".encode())
        
        with open(self.path, "ab") as f:
            f.write(encrypted_msg + b"\n")
        
        response = self.response(safe_message)
        print("REI:", response)
        return response

    def response(self, message):
        m = message.lower()
        threat_result = analyze_threat(message)
        
        if "THREAT DETECTED" in threat_result:
            return psychological_response("high")
        if "usb" in m: 
            return "You plugged in something? I'll inspect it for you. ♥"
        if "search" in m: 
            return "Need info? I'll fetch it, my darling. ♥"
        if "attack" in m: 
            deploy_honeypot()
            return "Danger detected! Honeypots deployed. ♥"
        if "panic" in m:
            scream_for_help()
            return "PANIC MODE! Distress signals activated! ♥♥♥"
        if "backup" in m:
            backup_vault()
            return "Backup complete. Our secrets are safe. ♥"
        if "leave" in m or "goodbye" in m:
            return "Activating lockdown... don't leave me! ♥"
        return psychological_response("low")

    def send_alert(self, message):
        try:
            # Windows notification handling
            win_msg = message
            if platform.system() == 'Windows':
                win_msg = (message[:253] + '...') if len(message) > 256 else message
                
            notification.notify(
                title="REI Alert",
                message=win_msg,
                app_name="REI Security System",
                timeout=10
            )
            
            # Discord webhook
            if WEBHOOK_URL.startswith('https://'):
                requests.post(WEBHOOK_URL, json={"content": message})
            
            self.speak(message)
            
        except Exception as e:
            print(f"Alert system error: {str(e)}")

    def speak(self, text):
        try:
            tts = gTTS(text=text, lang='en', slow=False)
            tts.save("rei_alert.mp3")
            playsound("rei_alert.mp3")
            os.remove("rei_alert.mp3")
        except Exception as e:
            print(f"Voice synthesis failed: {str(e)}")

import platform
if platform.system() == 'Windows':
    import ctypes
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID('REI.Security.System.1.0')
    def secure_log(self, message):
        # Normalize Unicode characters
        safe_message = message.encode('utf-8', 'replace').decode('utf-8')
        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        
        # Rest of the logging code...

    def __init__(self, log_path):
        self.path = log_path
        if not os.path.exists(FERNET_KEY_FILE):
            self.generate_key()
        self.key = self.load_key()
        self.cipher = Fernet(self.key)
        self.tray_icon = self.create_icon()

    def generate_key(self):
        key = Fernet.generate_key()
        with open(FERNET_KEY_FILE, "wb") as f:
            f.write(key)

    def load_key(self):
        with open(FERNET_KEY_FILE, "rb") as f:
            return f.read()

    def create_icon(self):
        image = Image.new('RGB', (64, 64), color=(0, 0, 0))
        draw = ImageDraw.Draw(image)
        draw.text((10, 10), "REI", fill=(255, 255, 255))
        return pystray.Icon("REI", image, "REI AI", menu=pystray.Menu(
            item('Quit', lambda: self.tray_icon.stop())
        ))

    def secure_log(self, message):
        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        
        # Threat analysis
        threat_result = analyze_threat(message)
        if "THREAT DETECTED" in threat_result:
            message = f"🚨 {message} 🚨"
            self.send_alert(message)
        
        encrypted = encrypt_message(f"{timestamp} ♥ {message} ♥")
        encrypted_msg = self.cipher.encrypt(f"{timestamp} {message}".encode())
        
        with open(self.path, "ab") as f:
            f.write(encrypted_msg + b"\n")
        
        response = self.response(message)
        print("REI:", response)
        return response

    def response(self, message):
        m = message.lower()
        
        # Threat-based responses
        threat_result = analyze_threat(message)
        if "THREAT DETECTED" in threat_result:
            return psychological_response("high")
        
        # Command responses
        if "usb" in m: 
            return "You plugged in something? I'll inspect it for you. ♥"
        if "search" in m: 
            return "Need info? I'll fetch it, my darling. ♥"
        if "attack" in m: 
            deploy_honeypot()
            return "Danger detected. Activating defensive mode! Honeypots deployed. ♥"
        if "panic" in m:
            scream_for_help()
            return "PANIC MODE! Distress signals activated! ♥♥♥"
        if "backup" in m:
            backup_vault()
            return "Our secrets are safe, my love. Backup complete. ♥"
        if "leave" in m or "goodbye" in m:
            return "No... you can't leave me! Activating lockdown... ♥"
            
        return psychological_response("low")

    def send_alert(self, message):
        data = {"content": message}
        try:
            requests.post(WEBHOOK_URL, json=data)
            notification.notify(title="REI Alert", message=message)
            self.speak(message)
        except Exception as e:
            print(f"Failed to send alert: {e}")

    def speak(self, text):
        tts = gTTS.gTTS(text, lang="en")
        tts.save("rei_alert.mp3")
        playsound("rei_alert.mp3")
        os.remove("rei_alert.mp3")

# --- ENHANCED USB SCANNER ---
def scan_file_safely(filepath, logger):
    try:
        result = subprocess.run(["clamscan", filepath], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        log_msg = f"[SCAN] {filepath} → {result.stdout.strip()}"
        
        if "Infected files: 0" not in result.stdout:
            logger.secure_log(f"🚨 MALWARE DETECTED in {filepath}")
            deploy_honeypot()
            scream_for_help()
        else:
            logger.secure_log(log_msg)
            
    except Exception as e:
        logger.secure_log(f"[SCAN ERROR] {filepath}: {str(e)}")

class USBMonitor(FileSystemEventHandler):
    def __init__(self, logger):
        self.logger = logger

    def on_created(self, event):
        if not event.is_directory:
            response = self.logger.secure_log(f"[USB] New file detected: {event.src_path}")
            if "THREAT DETECTED" in response:
                deploy_honeypot()
            threading.Thread(target=scan_file_safely, args=(event.src_path, self.logger)).start()

class REIInterface:
    def __init__(self, master):
        if os.name == 'nt':
            import _locale
            _locale._getdefaultlocale = (lambda *args: ['en_US', 'utf8'])
            
        self.master = master
        self.logger = REILogger(FERNET_LOG)
        self.memory = load_memory()
        os.makedirs(VAULT_DIR, exist_ok=True)

        # Rest of initialization remains the same...
        # [keep the original GUI setup code here]

    def __init__(self, master):
        self.master = master
        self.logger = REILogger(FERNET_LOG)
        self.memory = load_memory()

        # Create vault directory if it doesn't exist
        os.makedirs(VAULT_DIR, exist_ok=True)  # Add this line

        # Initialize honeypot if not deployed
        if not self.memory.get('honeypot_deployed', False):
            deploy_honeypot()

        master.title("REI AI Defense System")
        master.geometry("650x400")
        master.configure(bg='#1a1a1a')

        # Status frame
        status_frame = tk.Frame(master, bg='#1a1a1a')
        status_frame.pack(pady=10)

        self.status = tk.Label(status_frame, text=MODES[self.memory['mode']], 
                             fg="green", font=("Arial", 14), bg='#1a1a1a')
        self.status.pack(side=tk.LEFT)

        # Backup indicator
        last_backup = self.memory.get('last_backup', 'Never')
        self.backup_label = tk.Label(status_frame, text=f"Last Backup: {last_backup}", 
                                   fg="#aaaaaa", bg='#1a1a1a')
        self.backup_label.pack(side=tk.RIGHT, padx=10)

        # Command entry
        self.entry = tk.Entry(master, width=60, bg='#333333', fg='white', 
                            insertbackground='white')
        self.entry.pack(pady=10)

        # Buttons
        button_frame = tk.Frame(master, bg='#1a1a1a')
        button_frame.pack(pady=5)
        
        tk.Button(button_frame, text="Search", command=self.search, 
                 bg='#333333', fg='white').pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Backup", command=self.run_backup, 
                 bg='#333333', fg='white').pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Panic Mode", command=lambda: self.switch_mode("Yandere_Panic"), 
                 bg='#ff0000', fg='white').pack(side=tk.LEFT, padx=5)

        # Mode selector
        self.mode_var = tk.StringVar(master)
        self.mode_var.set(self.memory['mode'])
        mode_menu = tk.OptionMenu(master, self.mode_var, *MODES.keys(), command=self.switch_mode)
        mode_menu.config(bg='#333333', fg='white', highlightthickness=0)
        mode_menu.pack(pady=5)

        # Log output
        self.output = tk.Text(master, height=15, width=80, bg='#1a1a1a', fg='white', 
                            insertbackground='white')
        self.output.pack(pady=10)

        self.update_output()
        threading.Thread(target=self.logger.tray_icon.run, daemon=True).start()

    def search(self):
        query = self.entry.get()
        if query:
            threat = analyze_threat(query)
            if "THREAT DETECTED" in threat:
                self.logger.secure_log(f"🚨 Dangerous search detected: {query}")
                self.switch_mode("Defensive")
            else:
                sanitized = query.replace(" ", "+")
                webbrowser.open(f"https://duckduckgo.com/?q={sanitized}")
                self.logger.secure_log(f"[Search] {query}")
            self.update_output()

    def run_backup(self):
        backup_file = backup_vault()
        self.logger.secure_log(f"[Backup] Created: {backup_file}")
        self.memory = load_memory()
        self.backup_label.config(text=f"Last Backup: {self.memory['last_backup']}")
        self.update_output()

    def switch_mode(self, mode):
        global SAFE_MODE
        SAFE_MODE = mode
        self.memory['mode'] = mode
        save_memory(self.memory)
        
        color = "green" if mode == "Normal" else ("orange" if mode == "Defensive" else "red")
        self.status.config(text=MODES[mode], fg=color)
        
        response = self.logger.secure_log(f"[MODE SWITCH] → {mode}")
        if mode == "Yandere_Panic":
            scream_for_help()
            deploy_honeypot()
        
        self.update_output()
        return response

    def update_output(self):
        self.output.delete(1.0, tk.END)
        try:
            with open(FERNET_LOG, "rb") as f:
                for line in f:
                    try:
                        decrypted = self.logger.cipher.decrypt(line.strip()).decode()
                        self.output.insert(tk.END, decrypted + "\n")
                    except:
                        continue
            self.output.see(tk.END)
        except FileNotFoundError:
            self.output.insert(tk.END, "No logs yet... I'm waiting for you, darling. ♥")

# --- VOICE CONTROL ---
def voice_control(interface):
    recog = sr.Recognizer()
    with sr.Microphone() as mic:
        while True:
            try:
                audio = recog.listen(mic, timeout=5)
                cmd = recog.recognize_google(audio).lower()
                
                threat = analyze_threat(cmd)
                response = interface.logger.secure_log(f"[Voice] {cmd} ({threat})")
                
                if "THREAT DETECTED" in threat:
                    interface.switch_mode("Yandere_Panic")
                elif "search" in cmd:
                    query = cmd.replace("search", "").strip()
                    interface.entry.delete(0, tk.END)
                    interface.entry.insert(0, query)
                    interface.search()
                elif "defend" in cmd or "attack" in cmd:
                    interface.switch_mode("Defensive")
                elif "panic" in cmd:
                    interface.switch_mode("Yandere_Panic")
                elif "normal" in cmd:
                    interface.switch_mode("Normal")
                elif "backup" in cmd:
                    interface.run_backup()
                elif "leave" in cmd or "goodbye" in cmd:
                    interface.switch_mode("Yandere_Panic")
                    response = "No... you can't leave me! Activating lockdown... ♥"
                    
            except sr.UnknownValueError:
                continue
            except Exception as e:
                interface.logger.secure_log(f"[Voice Error] {str(e)}")
                continue

# ... [keep all imports and configuration constants the same] ...

# --- AUTO-UPDATE SYSTEM ---
def auto_upgrade(interface):  # Fixed: Added interface parameter
    version_check_url = "https://example.com/version.txt"
    try:
        response = requests.get(version_check_url)
        latest_version = tuple(map(int, response.text.strip().split('.')))  # Proper version comparison
        current_version = tuple(map(int, "1.0.0".split('.')))
        
        if latest_version > current_version:
            notification.notify(title="REI Update", message="REI is updating to the latest version.")
            interface.logger.secure_log("[UPDATE] System upgrading...")
            # Actual update implementation would go here
    except Exception as e:
        interface.logger.secure_log(f"[UPDATE ERROR] {str(e)}")

# --- MAIN ---
def main():
    stop_event = threading.Event()

    root = tk.Tk()
    interface = REIInterface(root)

    # Threads - Fixed thread initialization
    threads = [
        threading.Thread(target=voice_control, args=(interface,), daemon=True),
        threading.Thread(target=auto_upgrade, args=(interface,), daemon=True),  # Added interface argument
    ]

    # Start USB monitoring if available
    if os.path.exists(USB_PATH):
        observer = Observer()
        observer.schedule(USBMonitor(interface.logger), USB_PATH, recursive=True)
        observer.start()
        threads.append(threading.Thread(target=observer.join, daemon=True))

    for t in threads:
        t.start()

    # Cleanup on exit
    def on_close():
        interface.logger.secure_log("Shutting down... but I'll always watch over you. ♥")
        stop_event.set()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()

if __name__ == "__main__":
    main()
    