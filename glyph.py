import sys
import json
import secrets
import string
import hashlib
import re
import hmac
import csv
from pathlib import Path
from base64 import urlsafe_b64encode, urlsafe_b64decode
from typing import Optional, Dict, Any
from urllib.parse import urlparse

# --- PySide6 Imports ---
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QLabel, QFrame, QFormLayout,
    QStackedWidget, QScrollArea, QDialog, QMessageBox, QFileDialog, QCheckBox
)
from PySide6.QtCore import (
    Qt, QTimer, QPoint, QPropertyAnimation, Property, Signal, QFile, QEvent,
    QIODevice, QStandardPaths, QTextStream, QRunnable, QThreadPool, QObject
)
from PySide6.QtGui import QCursor, QColor, QIntValidator, QGuiApplication
from PySide6.QtSvgWidgets import QSvgWidget

# --- Third-Party Library Imports ---
import requests
import argon2
from argon2.low_level import hash_secret_raw, Type as Argon2Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from zxcvbn import zxcvbn
import resources_rc # Your compiled .qrc file

# ===================================================================
# --- Configuration & Settings Management ---
# ===================================================================

def get_app_data_path() -> Path:
    """Gets the OS-specific application data directory and creates it if needed."""
    path_str = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppLocalDataLocation)
    if not path_str: return Path(".").resolve() # Fallback for rare cases
    # The application name set in main() will be appended automatically by Qt.
    app_dir = Path(path_str)
    app_dir.mkdir(parents=True, exist_ok=True)
    return app_dir

# --- Global Constants ---
APP_DATA_DIR = get_app_data_path()
VAULT_FILE = APP_DATA_DIR / "vault.bin"
MASTER_FILE = APP_DATA_DIR / "master.bin"
VAULT_HMAC_FILE = APP_DATA_DIR / "vault.hmac"
SETTINGS_FILE = APP_DATA_DIR / "settings.json"
KDF_PARAMS_FILE = APP_DATA_DIR / "kdf.json"
SALT_SIZE = 16

DEFAULT_SETTINGS = {
    "auto_lock_timeout_seconds": 300,
    "clipboard_clear_seconds": 30,
    "password_generation": { "length": 20, "include_uppercase": True, "include_lowercase": True, "include_numbers": True, "include_symbols": True, },
    "commands": { "generate": "/pr", "update": "/pw", "remove": "/r", "rename": "/n", "dashboard": "/dash", "settings": "/settings", "exit": "/exit", "upgrade": "/upgrade" }
}

def load_settings() -> dict:
    """Loads settings from the JSON file, merging with defaults for any missing keys."""
    if not SETTINGS_FILE.exists(): return DEFAULT_SETTINGS
    try:
        with open(SETTINGS_FILE, "r") as f: settings = json.load(f)
        for key, value in DEFAULT_SETTINGS.items():
            if isinstance(value, dict):
                settings.setdefault(key, {})
                for sub_key, sub_value in value.items():
                    if isinstance(settings[key], dict): settings[key].setdefault(sub_key, sub_value)
            else: settings.setdefault(key, value)
        return settings
    except (json.JSONDecodeError, IOError): return DEFAULT_SETTINGS

def save_settings(settings: dict):
    """Saves the provided settings dictionary to its JSON file."""
    with open(SETTINGS_FILE, "w") as f: json.dump(settings, f, indent=4)

# ===================================================================
# --- Cryptography & Utility Functions ---
# ===================================================================

RECOMMENDED_KDF_PARAMS: Dict[str, Any] = {
    "time_cost": 3, "memory_cost": 65536, "parallelism": 4,
    "hash_len": 64, "type_str": "id"
}

def load_kdf_params() -> Optional[Dict[str, Any]]:
    if not KDF_PARAMS_FILE.exists(): return None
    try:
        with open(KDF_PARAMS_FILE, "r") as f: return json.load(f)
    except (json.JSONDecodeError, IOError): return None

def save_kdf_params(params: Dict[str, Any], path=KDF_PARAMS_FILE):
    try:
        with open(path, "w") as f: json.dump(params, f, indent=4)
    except IOError as e: print(f"Could not save KDF parameters: {e}")

def derive_keys(password: str, salt: bytes, kdf_params: Dict[str, Any]) -> Optional[tuple[bytes, bytes]]:
    try:
        type_map = {"d": Argon2Type.D, "i": Argon2Type.I, "id": Argon2Type.ID}
        argon2_type = type_map.get(kdf_params.get("type_str", "id").lower(), Argon2Type.ID)
        derived_key_material = hash_secret_raw(
            secret=password.encode(), salt=salt, time_cost=kdf_params["time_cost"],
            memory_cost=kdf_params["memory_cost"], parallelism=kdf_params["parallelism"],
            hash_len=kdf_params["hash_len"], type=argon2_type
        )
        return derived_key_material[:32], derived_key_material[32:]
    except (argon2.exceptions.HashingError, KeyError) as e:
        print(f"Key derivation failed: {e}"); return None

def verify_vault_integrity(hmac_key: bytes, vault_path=VAULT_FILE, hmac_path=VAULT_HMAC_FILE) -> bool:
    if not vault_path.exists() or not hmac_path.exists(): return True
    try:
        stored_hmac = hmac_path.read_bytes(); vault_data = vault_path.read_bytes()
        expected_hmac = hmac.new(hmac_key, vault_data, hashlib.sha256).digest()
        return hmac.compare_digest(stored_hmac, expected_hmac)
    except Exception: return False

def save_vault_with_integrity(vault_data: dict, encryption_key: bytes, hmac_key: bytes, vault_path=VAULT_FILE, hmac_path=VAULT_HMAC_FILE):
    try:
        json_data = json.dumps(vault_data).encode()
        nonce = secrets.token_bytes(12)
        encrypted_blob = AESGCM(encryption_key).encrypt(nonce, json_data, None)
        full_blob = nonce + encrypted_blob
        new_hmac = hmac.new(hmac_key, full_blob, hashlib.sha256).digest()
        vault_path.write_bytes(full_blob); hmac_path.write_bytes(new_hmac)
    except Exception as e: print(f"Vault Save Error: {e}")

def load_vault_with_integrity(encryption_key: bytes) -> Optional[dict]:
    if not VAULT_FILE.exists(): return {}
    try:
        full_blob = VAULT_FILE.read_bytes()
        nonce, ciphertext = full_blob[:12], full_blob[12:]
        decrypted_json = AESGCM(encryption_key).decrypt(nonce, ciphertext, None)
        return json.loads(decrypted_json)
    except (InvalidTag, json.JSONDecodeError, ValueError, IndexError, Exception): return None

def load_stylesheet() -> str:
    file = QFile(":/styles/modern_glyph.qss")
    if not file.open(QIODevice.OpenModeFlag.ReadOnly | QIODevice.OpenModeFlag.Text): return ""
    stream = QTextStream(file); stylesheet = stream.readAll(); file.close()
    return stylesheet

def save_master_salt(salt: bytes): MASTER_FILE.write_bytes(salt)
def load_master_salt() -> Optional[bytes]: return MASTER_FILE.read_bytes() if MASTER_FILE.exists() else None

def generate_password(settings: dict) -> str:
    gen_settings = settings.get("password_generation", DEFAULT_SETTINGS["password_generation"])
    length = gen_settings.get("length", 20)
    char_map = { "include_uppercase": string.ascii_uppercase, "include_lowercase": string.ascii_lowercase, "include_numbers": string.digits, "include_symbols": "!@#$%^&*()" }
    chars = "".join(v for k, v in char_map.items() if gen_settings.get(k, True))
    if not chars: return "Cannot generate password with no character sets"
    return ''.join(secrets.choice(chars) for _ in range(length))

def calculate_strength(password: str) -> int:
    if not password: return 0
    results = zxcvbn(password); score = results.get("score", 0)
    score_map = { 0: 10, 1: 30, 2: 55, 3: 80, 4: 100 }
    return score_map.get(score, 0)

def parse_csv_for_import(file_path: Path) -> list:
    """Parses a CSV file for password entries, accommodating common browser formats."""
    found_items = []
    # Common header names mapped to our internal keys
    name_keys = ['name', 'title']
    url_keys = ['url', 'login_uri', 'website']
    password_keys = ['password', 'login_password']

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Make all header keys lowercase for case-insensitive matching
                row_lower = {k.lower().strip(): v for k, v in row.items() if k}

                password = next((row_lower[key] for key in password_keys if key in row_lower), None)
                if not password:
                    continue # Skip rows without a password

                name = next((row_lower[key] for key in name_keys if key in row_lower), None)
                if name and name.strip():
                    found_items.append({'name': name.strip(), 'password': password})
                    continue

                url = next((row_lower[key] for key in url_keys if key in row_lower), None)
                if url:
                    try:
                        # Extract domain from URL as a fallback name
                        domain = urlparse(url).netloc
                        if domain:
                           found_items.append({'name': domain.replace('www.', ''), 'password': password})
                    except:
                        continue # Skip if URL is malformed
    except Exception as e:
        print(f"Error parsing CSV file: {e}")
        return []

    return found_items

# ===================================================================
# --- Background Task Workers ---
# ===================================================================

class TaskSignals(QObject):
    breach_check_complete = Signal(str, bool)

class BreachChecker(QRunnable):
    def __init__(self, site_key: str, password: str, signals: TaskSignals):
        super().__init__()
        self.site_key = site_key; self.password = password; self.signals = signals

    def run(self):
        try:
            sha1_hash = hashlib.sha1(self.password.encode()).hexdigest().upper()
            prefix, suffix = sha1_hash[:5], sha1_hash[5:]
            api_url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(api_url, timeout=5)
            if response.status_code == 200:
                hashes = (line.split(':')[0] for line in response.text.splitlines())
                if suffix in hashes:
                    self.signals.breach_check_complete.emit(self.site_key, True)
                    return
        except requests.RequestException: pass
        self.signals.breach_check_complete.emit(self.site_key, False)

# ===================================================================
# --- Reusable UI Component Classes ---
# ===================================================================

class IconButton(QPushButton):
    def __init__(self, icon_name: str, tooltip: str = ""):
        super().__init__()
        self.svg_widget = QSvgWidget(f":/icons/{icon_name}.svg")
        self.svg_widget.setFixedSize(16, 16)
        layout = QHBoxLayout(self); layout.setContentsMargins(0,0,0,0)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.svg_widget)
        self.setFixedSize(32, 32); self.setToolTip(tooltip)
        self.setCursor(QCursor(Qt.CursorShape.PointingHandCursor)); self.setProperty("class", "icon-button")
    def set_icon(self, icon_name: str): self.svg_widget.load(f":/icons/{icon_name}.svg")

class SearchInputWidget(QWidget):
    textChanged = Signal(str)
    def __init__(self, parent=None):
        super().__init__(parent); self.setObjectName("SearchContainer"); self.setMaximumWidth(320); self.setFixedHeight(40)
        layout = QHBoxLayout(self); layout.setContentsMargins(15, 0, 15, 0); layout.setSpacing(10)
        icon = QSvgWidget(":/icons/search.svg"); icon.setFixedSize(16, 16)
        self.line_edit = QLineEdit(); self.line_edit.setObjectName("SearchLineEdit"); self.line_edit.setPlaceholderText("Search...")
        self.line_edit.textChanged.connect(self.textChanged.emit); layout.addWidget(icon); layout.addWidget(self.line_edit)
    def text(self) -> str: return self.line_edit.text()
    def focus_input(self): self.line_edit.setFocus()

class StrengthBar(QWidget):
    def __init__(self, strength: int, breached: bool = False):
        super().__init__()
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        self.bar_widget = QWidget()
        self.bar_widget.setFixedHeight(6)
        layout.addWidget(self.bar_widget, 1)

        self.status_stack = QStackedWidget()
        self.status_stack.setFixedWidth(45)
        layout.addWidget(self.status_stack, 0)

        self.percentage_label = QLabel()
        self.percentage_label.setObjectName("StrengthLabel")
        self.percentage_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        self.breach_icon_container = QWidget()
        icon_layout = QHBoxLayout(self.breach_icon_container)
        icon_layout.setContentsMargins(0, 0, 0, 0)
        icon_layout.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        icon_layout.addWidget(QSvgWidget(":/icons/shield-alert.svg"))

        self.status_stack.addWidget(self.percentage_label)
        self.status_stack.addWidget(self.breach_icon_container)

        self.update_state(strength, breached)

    def update_state(self, strength: int, breached: bool):
        stylesheet = ""
        if breached:
            stylesheet = "background-color: #e74c3c; border-radius: 3px;"
            self.setToolTip("Warning: This password has appeared in a data breach and is not secure.")
            self.status_stack.setCurrentWidget(self.breach_icon_container)
        else:
            fill_color = "#e74c3c"
            if strength > 65: fill_color = "#2ecc71"
            elif strength > 40: fill_color = "#f39c12"
            bg_color, stop_pos = "#333333", strength / 100.0
            if strength == 0: stylesheet = f"background-color:{bg_color};border-radius:3px;"
            elif strength == 100: stylesheet = f"background-color:{fill_color};border-radius:3px;"
            else: stylesheet = f"""background-color:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:{stop_pos}{fill_color},stop:{stop_pos + 0.001}{bg_color});border-radius:3px;"""
            self.setToolTip(f"Password strength: {strength}%")
            self.percentage_label.setText(f"{strength}%")
            self.status_stack.setCurrentWidget(self.percentage_label)
        self.bar_widget.setStyleSheet(stylesheet.strip())

# ===================================================================
# --- Dialog and View Classes ---
# ===================================================================

class ChangePasswordDialog(QDialog):
    password_change_requested = Signal(str, str)
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Change Master Password")
        self.setObjectName("ChangePasswordDialog")
        self.setMinimumWidth(450); self.setModal(True)
        layout = QVBoxLayout(self); layout.setContentsMargins(25, 25, 25, 25); layout.setSpacing(15)
        title = QLabel("Change Master Password"); title.setObjectName("WizardTitle"); layout.addWidget(title)
        self.error_label = QLabel(); self.error_label.setObjectName("ErrorLabel"); self.error_label.setWordWrap(True); self.error_label.hide(); layout.addWidget(self.error_label)
        form_layout = QFormLayout(); form_layout.setSpacing(15)
        self.current_pw_input = QLineEdit(); self.current_pw_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.new_pw_input = QLineEdit(); self.new_pw_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_pw_input = QLineEdit(); self.confirm_pw_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.new_pw_input.textChanged.connect(self._update_strength_bar)
        form_layout.addRow("Current Password:", self.current_pw_input); form_layout.addRow("New Password:", self.new_pw_input)
        self.strength_bar_container = QWidget(); self.strength_bar_layout = QVBoxLayout(self.strength_bar_container); self.strength_bar_layout.setContentsMargins(0, 5, 0, 5)
        form_layout.addRow("", self.strength_bar_container); self._update_strength_bar("")
        form_layout.addRow("Confirm New Password:", self.confirm_pw_input); layout.addLayout(form_layout)
        button_layout = QHBoxLayout(); button_layout.addStretch()
        cancel_btn = QPushButton("Cancel"); cancel_btn.clicked.connect(self.reject)
        self.ok_btn = QPushButton("Change Password"); self.ok_btn.setDefault(True); self.ok_btn.clicked.connect(self.validate_and_accept)
        button_layout.addWidget(cancel_btn); button_layout.addWidget(self.ok_btn); layout.addLayout(button_layout)
    def _update_strength_bar(self, text: str):
        while self.strength_bar_layout.count():
            child = self.strength_bar_layout.takeAt(0)
            if child.widget(): child.widget().deleteLater()
        self.strength_bar_layout.addWidget(StrengthBar(calculate_strength(text)))
    def validate_and_accept(self):
        new_pw = self.new_pw_input.text()
        if not self.current_pw_input.text(): self.show_error("Current password cannot be empty."); return
        if new_pw != self.confirm_pw_input.text(): self.show_error("New passwords do not match."); return
        strength = zxcvbn(new_pw)
        if strength["score"] < 2:
            feedback = "Password is too weak."
            if "feedback" in strength and strength["feedback"]["warning"]: feedback += f" {strength['feedback']['warning']}"
            self.show_error(feedback)
            return
        self.password_change_requested.emit(self.current_pw_input.text(), new_pw)
    def show_error(self, message: str): self.error_label.setText(message); self.error_label.show()
    def on_success(self): self.accept()
    def on_failure(self, message: str): self.show_error(message)

class SettingsView(QWidget):
    settings_saved = Signal(dict)
    application_reset_requested = Signal()
    export_vault_requested = Signal(str)
    import_vault_requested = Signal()
    change_password_requested = Signal()
    def __init__(self, current_settings: dict, back_callback, parent=None):
        super().__init__(parent); self.setObjectName("SettingsView"); self.settings = current_settings.copy()
        self.main_layout = QVBoxLayout(self); self.main_layout.setContentsMargins(0, 0, 0, 0); self.main_layout.setSpacing(0)
        header_frame = self._create_frame("SettingsHeader"); header_layout = QHBoxLayout(header_frame); header_layout.setContentsMargins(25, 20, 25, 20)
        title = QLabel("Settings"); title.setObjectName("DashboardTitle")
        header_layout.addWidget(title); header_layout.addStretch(); self.main_layout.addWidget(header_frame)
        scroll_area = QScrollArea(); scroll_area.setWidgetResizable(True); scroll_area.setObjectName("SettingsScrollArea"); content_widget = QWidget(); scroll_area.setWidget(content_widget)
        content_layout = QVBoxLayout(content_widget); content_layout.setContentsMargins(25, 25, 25, 25); content_layout.setSpacing(25)
        top_layout = QHBoxLayout(); top_layout.setSpacing(25)
        top_layout.addWidget(self._create_security_group()); top_layout.addWidget(self._create_password_gen_group())
        content_layout.addLayout(top_layout)
        content_layout.addWidget(self._create_data_management_group()); content_layout.addWidget(self._create_command_group()); content_layout.addWidget(self._create_danger_zone_group())
        content_layout.addStretch(); self.main_layout.addWidget(scroll_area, 1)
        footer_frame = self._create_frame("SettingsFooter"); footer_layout = QHBoxLayout(footer_frame); footer_layout.setContentsMargins(25, 15, 25, 15); footer_layout.addStretch()
        cancel_btn = QPushButton("Cancel"); cancel_btn.clicked.connect(back_callback); save_btn = QPushButton("Save"); save_btn.setDefault(True); save_btn.clicked.connect(self.save_and_exit)
        footer_layout.addWidget(cancel_btn); footer_layout.addWidget(save_btn); self.main_layout.addWidget(footer_frame)
    def save_and_exit(self):
        gen_settings = { "length": int(self.pw_len_input.text() or 20), "include_uppercase": self.pw_uppercase_check.isChecked(), "include_lowercase": self.pw_lowercase_check.isChecked(), "include_numbers": self.pw_numbers_check.isChecked(), "include_symbols": self.pw_symbols_check.isChecked() }
        updated_settings = { "auto_lock_timeout_seconds": int(self.auto_lock_input.text() or 0), "clipboard_clear_seconds": int(self.clipboard_input.text() or 0), "password_generation": gen_settings, "commands": {key: ui['label'].text() for key, ui in self.command_ui.items()} }
        self.settings_saved.emit(updated_settings)
    def _create_security_group(self) -> QFrame:
        self.auto_lock_input = self._create_minimal_line_edit(self.settings["auto_lock_timeout_seconds"], 0, 3600)
        self.clipboard_input = self._create_minimal_line_edit(self.settings["clipboard_clear_seconds"], 0, 300)
        return self._create_settings_group("Security", [(QLabel("Auto-lock after inactivity (seconds):"), self.auto_lock_input), (QLabel("Clear clipboard after (seconds):"), self.clipboard_input)])
    def _create_password_gen_group(self) -> QFrame:
        group_frame = self._create_frame("SettingsGroup"); layout = QVBoxLayout(group_frame); layout.setSpacing(15)
        title_label = QLabel("Password Generation"); title_label.setObjectName("SettingsSectionTitle"); layout.addWidget(title_label)
        gen_settings = self.settings.get("password_generation", DEFAULT_SETTINGS["password_generation"])
        form_layout = QFormLayout(); form_layout.setSpacing(15)
        self.pw_len_input = self._create_minimal_line_edit(gen_settings.get("length", 20), 8, 128)
        form_layout.addRow(QLabel("Default length:"), self.pw_len_input); layout.addLayout(form_layout)
        self.pw_uppercase_check = QCheckBox("Include Uppercase (A-Z)"); self.pw_uppercase_check.setChecked(gen_settings.get("include_uppercase", True))
        self.pw_lowercase_check = QCheckBox("Include Lowercase (a-z)"); self.pw_lowercase_check.setChecked(gen_settings.get("include_lowercase", True))
        self.pw_numbers_check = QCheckBox("Include Numbers (0-9)"); self.pw_numbers_check.setChecked(gen_settings.get("include_numbers", True))
        self.pw_symbols_check = QCheckBox("Include Symbols (!@#$..)"); self.pw_symbols_check.setChecked(gen_settings.get("include_symbols", True))
        layout.addWidget(self.pw_uppercase_check); layout.addWidget(self.pw_lowercase_check); layout.addWidget(self.pw_numbers_check); layout.addWidget(self.pw_symbols_check)
        return group_frame
    def _create_data_management_group(self) -> QFrame:
        group_frame = self._create_frame("SettingsGroup")
        layout = QVBoxLayout(group_frame)
        layout.setSpacing(15)

        title_label = QLabel("Data Management")
        title_label.setObjectName("SettingsSectionTitle")
        layout.addWidget(title_label)

        self.data_actions_widget = QWidget()
        self.data_actions_widget.setObjectName("DataActionsWidget")
        data_actions_layout = QHBoxLayout(self.data_actions_widget)
        data_actions_layout.setContentsMargins(0,0,0,0)
        data_actions_layout.setSpacing(10)

        import_btn = QPushButton("Import from file...")
        import_btn.clicked.connect(self.import_vault_requested.emit)

        export_btn = QPushButton("Export Vault...")
        export_btn.clicked.connect(self._enter_export_confirmation_mode)

        data_actions_layout.addWidget(QLabel("Manage your vault data:"))
        data_actions_layout.addStretch()
        data_actions_layout.addWidget(import_btn)
        data_actions_layout.addWidget(export_btn)

        layout.addWidget(self.data_actions_widget)

        self.export_confirm_widget = QWidget()
        self.export_confirm_widget.hide()
        confirm_layout = QVBoxLayout(self.export_confirm_widget)
        confirm_layout.setContentsMargins(0, 15, 0, 0)
        confirm_layout.setSpacing(10)

        warning_label = QLabel("<b>SECURITY WARNING:</b> The exported file will be <b>UNENCRYPTED</b> and contain all passwords in plain text. Handle this file with extreme care.")
        warning_label.setWordWrap(True)
        warning_label.setObjectName("WarningLabel")

        export_button_layout = QHBoxLayout()
        export_button_layout.addStretch()
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self._cancel_export_confirmation_mode)
        proceed_btn = QPushButton("Proceed to Export")
        proceed_btn.setObjectName("DangerButton")
        proceed_btn.clicked.connect(self._proceed_with_export)
        export_button_layout.addWidget(cancel_btn)
        export_button_layout.addWidget(proceed_btn)

        confirm_layout.addWidget(warning_label)
        confirm_layout.addLayout(export_button_layout)
        layout.addWidget(self.export_confirm_widget)

        return group_frame

    def _enter_export_confirmation_mode(self):
        self.data_actions_widget.hide()
        self.export_confirm_widget.show()

    def _cancel_export_confirmation_mode(self):
        self.export_confirm_widget.hide()
        self.data_actions_widget.show()

    def _proceed_with_export(self):
        # --- FIX: Simplify export to only offer CSV ---
        file_path, _ = QFileDialog.getSaveFileName(self, "Export Vault", "glyph_export.csv", "CSV Files (*.csv)")
        if file_path:
            self.export_vault_requested.emit(file_path)
        self._cancel_export_confirmation_mode()

    def _create_danger_zone_group(self) -> QFrame:
        group_frame = self._create_frame("SettingsGroup"); layout = QVBoxLayout(group_frame); layout.setSpacing(15)
        title_label = QLabel("Danger Zone"); title_label.setObjectName("DangerSectionTitle"); layout.addWidget(title_label)
        change_pw_btn = QPushButton("Change Master Password..."); change_pw_btn.clicked.connect(self.change_password_requested.emit)
        change_pw_desc = QLabel("Change the master password used to encrypt your vault."); change_pw_desc.setWordWrap(True)
        layout.addWidget(change_pw_desc); layout.addWidget(change_pw_btn, 0, Qt.AlignmentFlag.AlignLeft)
        line = QFrame(); line.setFrameShape(QFrame.Shape.HLine); line.setFrameShadow(QFrame.Shadow.Sunken); layout.addWidget(line)
        self.danger_zone_layout = QVBoxLayout(); layout.addLayout(self.danger_zone_layout)
        self.danger_default_widget = QWidget(); default_layout = QVBoxLayout(self.danger_default_widget); default_layout.setContentsMargins(0,0,0,0); default_layout.setSpacing(15)
        reset_desc = QLabel("Permanently delete your entire vault and all settings. This cannot be undone."); reset_desc.setWordWrap(True)
        reset_btn = QPushButton("Reset Application"); reset_btn.setObjectName("DangerButton"); reset_btn.clicked.connect(self._enter_reset_confirmation_mode)
        default_layout.addWidget(reset_desc); default_layout.addWidget(reset_btn, 0, Qt.AlignmentFlag.AlignLeft)
        self.danger_confirm_widget = QWidget(); self.danger_confirm_widget.hide(); confirm_layout = QVBoxLayout(self.danger_confirm_widget); confirm_layout.setContentsMargins(0,0,0,0); confirm_layout.setSpacing(15)
        confirm_desc = QLabel("To proceed, please type <b>RESET</b> into the box below and click confirm."); confirm_desc.setWordWrap(True)
        self.confirm_input = QLineEdit(); self.confirm_input.setObjectName("ResetConfirmInput"); self.confirm_input.setPlaceholderText("Type 'RESET' here"); self.confirm_input.textChanged.connect(self._check_reset_confirmation_text)
        button_layout = QHBoxLayout(); self.confirm_reset_btn = QPushButton("Confirm Permanent Reset"); self.confirm_reset_btn.setObjectName("ConfirmResetButton"); self.confirm_reset_btn.setEnabled(False); self.confirm_reset_btn.clicked.connect(self.application_reset_requested.emit)
        cancel_btn = QPushButton("Cancel"); cancel_btn.clicked.connect(self._cancel_reset_confirmation_mode)
        button_layout.addWidget(cancel_btn); button_layout.addWidget(self.confirm_reset_btn)
        confirm_layout.addWidget(confirm_desc); confirm_layout.addWidget(self.confirm_input); confirm_layout.addLayout(button_layout)
        self.danger_zone_layout.addWidget(self.danger_default_widget); self.danger_zone_layout.addWidget(self.danger_confirm_widget)
        return group_frame
    def _enter_reset_confirmation_mode(self): self.danger_default_widget.hide(); self.danger_confirm_widget.show(); self.confirm_input.setFocus()
    def _cancel_reset_confirmation_mode(self): self.confirm_input.clear(); self.danger_confirm_widget.hide(); self.danger_default_widget.show()
    def _check_reset_confirmation_text(self, text: str): self.confirm_reset_btn.setEnabled(text == "RESET")
    def _create_frame(self, name: str) -> QFrame: f = QFrame(); f.setObjectName(name); return f
    def _create_minimal_line_edit(self, value: int, min_val: int, max_val: int) -> QLineEdit: le = QLineEdit(str(value)); le.setValidator(QIntValidator(min_val, max_val, self)); le.setObjectName("SettingsInput"); return le
    def _create_settings_group(self, title: str, widgets: list) -> QFrame:
        group_frame = self._create_frame("SettingsGroup"); layout = QVBoxLayout(group_frame); layout.setSpacing(15); title_label = QLabel(title); title_label.setObjectName("SettingsSectionTitle"); layout.addWidget(title_label)
        form_layout = QFormLayout(); form_layout.setSpacing(15); form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
        for label, widget in widgets: form_layout.addRow(label, widget)
        layout.addLayout(form_layout); return group_frame
    def _create_command_group(self) -> QFrame:
        group_frame = self._create_frame("SettingsGroup"); layout = QVBoxLayout(group_frame); layout.setSpacing(15); title_label = QLabel("Commands"); title_label.setObjectName("SettingsSectionTitle"); layout.addWidget(title_label)
        desc_label = QLabel("Click the edit icon to change a command shortcut."); desc_label.setObjectName("SettingsDescription"); layout.addWidget(desc_label)
        self.command_ui = {}; cmap = {"generate": "Generate new password", "update": "Update existing password", "remove": "Remove entry", "rename": "Rename entry", "dashboard": "Open dashboard", "settings": "Open settings", "upgrade": "Upgrade vault security", "exit": "Quit application"}
        for key, desc in cmap.items():
            command = self.settings.get("commands", {}).get(key, DEFAULT_SETTINGS["commands"][key])
            row_widget = self._create_command_row(key, desc, command)
            layout.addWidget(row_widget)
        return group_frame
    def _create_command_row(self, key: str, description: str, command: str) -> QWidget:
        row_widget = QWidget(); row_layout = QHBoxLayout(row_widget); row_layout.setContentsMargins(0, 0, 0, 0); row_layout.setSpacing(10)
        desc_label, cmd_label = QLabel(description), QLabel(command); cmd_label.setObjectName("CommandLabel"); cmd_editor = QLineEdit(command); cmd_editor.setObjectName("SettingsInput"); cmd_editor.hide()
        edit_btn, save_btn, cancel_btn = IconButton("edit", "Edit"), IconButton("check", "Save"), IconButton("x", "Cancel"); save_btn.hide(); cancel_btn.hide()
        row_layout.addWidget(desc_label); row_layout.addStretch(); row_layout.addWidget(cmd_label); row_layout.addWidget(cmd_editor); row_layout.addWidget(edit_btn); row_layout.addWidget(save_btn); row_layout.addWidget(cancel_btn)
        self.command_ui[key] = {'label': cmd_label, 'editor': cmd_editor, 'edit_btn': edit_btn, 'save_btn': save_btn, 'cancel_btn': cancel_btn}
        edit_btn.clicked.connect(lambda _, k=key: self.set_edit_mode(k, True)); save_btn.clicked.connect(lambda _, k=key: self.save_command_edit(k)); cancel_btn.clicked.connect(lambda _, k=key: self.set_edit_mode(k, False)); cmd_editor.returnPressed.connect(lambda _, k=key: self.save_command_edit(k))
        return row_widget
    def set_edit_mode(self, key: str, is_editing: bool):
        ui = self.command_ui[key]
        if not is_editing: ui['editor'].setText(ui['label'].text())
        ui['label'].setVisible(not is_editing); ui['edit_btn'].setVisible(not is_editing); ui['editor'].setVisible(is_editing); ui['save_btn'].setVisible(is_editing); ui['cancel_btn'].setVisible(is_editing)
        if is_editing: ui['editor'].setFocus(); ui['editor'].selectAll()
    def save_command_edit(self, key: str):
        ui = self.command_ui[key]; new_text = ui['editor'].text().strip()
        if new_text.startswith("/") and " " not in new_text: ui['label'].setText(new_text)
        self.set_edit_mode(key, False)

class ImportReviewDialog(QDialog):
    """A dialog to review and confirm CSV import data."""
    import_confirmed = Signal(list)

    def __init__(self, import_data: list, existing_keys: list, parent=None):
        super().__init__(parent)
        self.import_data = import_data
        self.existing_keys = existing_keys

        self.setWindowTitle("Review Import")
        self.setObjectName("ImportReviewDialog")
        self.setMinimumSize(750, 550)
        self.setModal(True)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        title = QLabel("Review Items to Import")
        title.setObjectName("WizardTitle")
        desc = QLabel("Select the items you wish to import. Items marked as 'Conflict' already exist in your vault and will be updated if imported.")
        desc.setObjectName("WizardDescription")
        desc.setWordWrap(True)

        main_layout.addWidget(title)
        main_layout.addWidget(desc)

        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["", "Name", "Password", "Status"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(0, 40)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(3, 100)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionMode(QTableWidget.SelectionMode.NoSelection)

        main_layout.addWidget(self.table)

        options_layout = QHBoxLayout()
        self.show_passwords_check = QCheckBox("Show Passwords")
        self.show_passwords_check.stateChanged.connect(self.toggle_password_visibility)
        select_all_btn = QPushButton("Select All")
        select_all_btn.clicked.connect(lambda: self.set_all_checked(True))
        select_none_btn = QPushButton("Select None")
        select_none_btn.clicked.connect(lambda: self.set_all_checked(False))
        options_layout.addWidget(self.show_passwords_check)
        options_layout.addStretch()
        options_layout.addWidget(select_all_btn)
        options_layout.addWidget(select_none_btn)
        main_layout.addLayout(options_layout)

        button_layout = QHBoxLayout()
        button_layout.addStretch()
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        import_btn = QPushButton("Import Selected")
        import_btn.setDefault(True)
        import_btn.clicked.connect(self.confirm_import)
        button_layout.addWidget(cancel_btn)
        button_layout.addWidget(import_btn)
        main_layout.addLayout(button_layout)

        self.populate_table()

    def populate_table(self):
        self.table.setRowCount(len(self.import_data))
        for row, item_data in enumerate(self.import_data):
            name = item_data['name'].lower()
            password = item_data['password']
            status = "Conflict" if name in self.existing_keys else "New"

            check_item = QTableWidgetItem()
            check_item.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
            check_item.setCheckState(Qt.CheckState.Checked)

            name_item = QTableWidgetItem(name)
            name_item.setFlags(name_item.flags() & ~Qt.ItemFlag.ItemIsEditable)

            pw_item = QTableWidgetItem("••••••••••••")
            pw_item.setData(Qt.ItemDataRole.UserRole, password) # Store real password
            pw_item.setFlags(pw_item.flags() & ~Qt.ItemFlag.ItemIsEditable)

            status_item = QTableWidgetItem(status)
            status_item.setFlags(status_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if status == "Conflict":
                status_item.setForeground(QColor("#f39c12")) # Orange

            self.table.setItem(row, 0, check_item)
            self.table.setItem(row, 1, name_item)
            self.table.setItem(row, 2, pw_item)
            self.table.setItem(row, 3, status_item)

    def toggle_password_visibility(self, state: int):
        is_visible = (state == Qt.CheckState.Checked.value)
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 2)
            if item:
                real_password = item.data(Qt.ItemDataRole.UserRole)
                item.setText(real_password if is_visible else "••••••••••••")

    def set_all_checked(self, checked: bool):
        check_state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item:
                item.setCheckState(check_state)

    def confirm_import(self):
        selected_items = []
        for row in range(self.table.rowCount()):
            check_item = self.table.item(row, 0)
            if check_item and check_item.checkState() == Qt.CheckState.Checked:
                name_item = self.table.item(row, 1)
                pw_item = self.table.item(row, 2)
                if name_item and pw_item:
                    name = name_item.text()
                    password = pw_item.data(Qt.ItemDataRole.UserRole)
                    selected_items.append({'name': name, 'password': password})
        if selected_items:
            self.import_confirmed.emit(selected_items)
        self.accept()

class DashboardWindow(QWidget):
    settings_updated = Signal(dict)
    request_app_reset = Signal()
    request_vault_export = Signal(str)
    request_password_change = Signal()

    def __init__(self, vault: dict, settings: dict, parent_glyph, parent=None):
        super().__init__(parent)
        self.vault = vault; self.settings = settings; self.parent_glyph = parent_glyph
        self.parent_glyph.vault_updated.connect(self.refresh_table_data)
        self.setWindowTitle("Glyph - Dashboard"); self.setMinimumSize(1000, 680); self.setObjectName("Dashboard")
        main_layout = QVBoxLayout(self); main_layout.setContentsMargins(0, 0, 0, 0)
        self.stacked_widget = QStackedWidget(); main_layout.addWidget(self.stacked_widget)
        self.table_view_widget = self._create_table_view()
        self.settings_view_widget = SettingsView(self.settings, self.show_table_view)

        self.settings_view_widget.application_reset_requested.connect(self.parent_glyph.reset_application)
        self.settings_view_widget.export_vault_requested.connect(self.parent_glyph.export_vault)
        self.settings_view_widget.change_password_requested.connect(self.parent_glyph.show_change_password_dialog)
        self.settings_view_widget.settings_saved.connect(self.on_settings_saved)
        self.settings_view_widget.import_vault_requested.connect(self.parent_glyph._handle_import_request)


        self.stacked_widget.addWidget(self.table_view_widget); self.stacked_widget.addWidget(self.settings_view_widget)
        self.setWindowModality(Qt.WindowModality.ApplicationModal)
        self.editing_row = -1; self.is_adding_new = False; self.row_pending_deletion = -1
        self.installEventFilter(self)

    def eventFilter(self, watched, event):
        if event.type() in [QEvent.Type.KeyPress, QEvent.Type.MouseButtonPress]: self.parent_glyph.reset_auto_lock_timer()
        return super().eventFilter(watched, event)

    def refresh_table_data(self):
        self.vault = self.parent_glyph.vault
        self.populate_table()

    def _create_table_view(self) -> QWidget:
        table_view_widget = QWidget(); layout = QVBoxLayout(table_view_widget); layout.setContentsMargins(25, 20, 25, 20); layout.setSpacing(15)
        title_row_layout = QHBoxLayout(); title = QLabel("All Passwords"); title.setObjectName("DashboardTitle")
        self.search_input = SearchInputWidget(); self.search_input.textChanged.connect(self.filter_table)
        add_btn = IconButton("plus", "Add New Entry"); add_btn.clicked.connect(self.add_new_entry)
        settings_btn = IconButton("settings", "Settings"); settings_btn.clicked.connect(self.show_settings_view)
        title_row_layout.addWidget(title); title_row_layout.addStretch(); title_row_layout.addWidget(self.search_input)
        title_row_layout.addWidget(add_btn); title_row_layout.addWidget(settings_btn); layout.addLayout(title_row_layout)

        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Website", "Password", "Strength", "Actions"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed); self.table.setColumnWidth(2, 170)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed); self.table.setColumnWidth(3, 180)

        self.table.verticalHeader().setVisible(False); self.table.setShowGrid(True); self.table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.table.setSelectionMode(QTableWidget.SelectionMode.NoSelection); self.table.verticalHeader().setDefaultSectionSize(60)
        self.populate_table(); layout.addWidget(self.table); return table_view_widget

    def populate_table(self):
        # Prevent editing state from persisting after a refresh
        self.editing_row = -1
        self.is_adding_new = False
        self.row_pending_deletion = -1

        current_filter = self.search_input.text()
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)

        sorted_items = sorted(self.vault.items(), key=lambda item: item[1].get('name', item[0]).lower())
        self.table.setRowCount(len(sorted_items))

        for r, (key, data) in enumerate(sorted_items):
            self.table.setItem(r, 0, QTableWidgetItem(data.get("name", key)))
            self.table.setItem(r, 1, QTableWidgetItem("••••••••••••"))
            self.table.setCellWidget(r, 2, StrengthBar(data.get("strength", 0), data.get("breached", False)))
            self.table.setCellWidget(r, 3, self.create_actions_cell(r))

        self.filter_table(current_filter)
        self.table.setSortingEnabled(True)

    def create_actions_cell(self, row: int) -> QWidget:
        container = QWidget(); layout = QHBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(5)
        buttons = [IconButton("edit", "Edit"), IconButton("eye", "Show/Hide"), IconButton("copy", "Copy"), IconButton("trash", "Delete")]
        layout.addStretch(); [layout.addWidget(btn) for btn in buttons]; layout.addStretch()
        buttons[0].clicked.connect(lambda: self.start_editing(row))
        buttons[1].clicked.connect(lambda: self.toggle_password_visibility(row))
        buttons[2].clicked.connect(lambda: self.copy_to_clipboard(row))
        buttons[3].clicked.connect(lambda: self.delete_entry(row))
        return container

    def _enter_edit_mode(self, row: int, is_new: bool = False):
        if self.editing_row != -1 or self.row_pending_deletion != -1: self.populate_table()
        self.editing_row, self.is_adding_new = row, is_new
        if is_new: site_name, password = "", ""
        else:
            site_item = self.table.item(row, 0)
            if not site_item: self.cancel_editing(); return
            site_name = site_item.text(); password = self.parent_glyph._get_decrypted_password(site_name)
            if password is None: self.cancel_editing(); return
            self.editing_row_data = {"site": site_name, "password": password}
        
        # Website input widget
        site_widget = QWidget()
        site_layout = QHBoxLayout(site_widget)
        site_layout.setContentsMargins(0,0,0,0)
        site_layout.setSpacing(5)
        site_editor = QLineEdit(site_name)
        site_editor.setObjectName("inline-editor")
        site_layout.addWidget(site_editor)
        site_layout.addSpacing(35 + 5) 
        
        # Password input widget
        pw_widget = QWidget()
        pw_layout = QHBoxLayout(pw_widget)
        pw_layout.setContentsMargins(0,0,0,0)
        pw_layout.setSpacing(5)
        pw_editor = QLineEdit(password)
        pw_editor.setObjectName("inline-editor")
        gen_btn = IconButton("refresh", "Generate Password")
        gen_btn.setFixedSize(35, 35)
        gen_btn.clicked.connect(lambda: pw_editor.setText(generate_password(self.settings)))
        pw_layout.addWidget(pw_editor)
        pw_layout.addWidget(gen_btn)

        self.table.setCellWidget(row, 0, site_widget)
        self.table.setCellWidget(row, 1, pw_widget)
        self.table.setCellWidget(row, 2, QWidget())
        site_editor.setFocus()

        action_container = QWidget(); action_layout = QHBoxLayout(action_container)
        action_layout.setContentsMargins(0,0,0,0); action_layout.setSpacing(5)
        save_btn, cancel_btn = IconButton("check", "Save"), IconButton("x", "Cancel")
        action_layout.addStretch(); action_layout.addWidget(save_btn); action_layout.addWidget(cancel_btn); action_layout.addStretch()
        save_btn.clicked.connect(self.save_editing); cancel_btn.clicked.connect(self.cancel_editing)
        self.table.setCellWidget(row, 3, action_container)

    # --- THIS IS THE CORRECTED METHOD ---
    def add_new_entry(self):
        """Creates a new, blank row at the top of the table for a new entry."""
        if self.editing_row != -1 or self.row_pending_deletion != -1:
            self.populate_table()
        
        # 1. Insert a new row at the top (index 0)
        self.table.insertRow(0)
        
        # 2. Enter edit mode for this newly created row
        self._enter_edit_mode(0, is_new=True)

    def start_editing(self, row: int):
        self._enter_edit_mode(row, is_new=False)

    def save_editing(self):
        site_widget = self.table.cellWidget(self.editing_row, 0)
        pw_widget = self.table.cellWidget(self.editing_row, 1)
        if not site_widget or not pw_widget: self.cancel_editing(); return
        site_editor = site_widget.findChild(QLineEdit)
        pw_editor = pw_widget.findChild(QLineEdit)
        if not site_editor or not pw_editor: self.cancel_editing(); return

        s_new, p_new = site_editor.text().strip().lower(), pw_editor.text()

        if not s_new: self.parent_glyph.flash_feedback(QColor("#e74c3c")); self.parent_glyph.show_temp_message("Website name cannot be empty", 1500); return
        s_old = s_new if self.is_adding_new else self.editing_row_data["site"].lower()
        if self.parent_glyph.update_entry(s_old, s_new, p_new):
            # No need to manually set vault, parent signal will trigger refresh
            self.populate_table()

    def cancel_editing(self):
        if self.editing_row != -1: self.populate_table()

    def filter_table(self, text: str):
        text_lower = text.lower()
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item:
                is_match = text_lower in item.text().lower()
                self.table.setRowHidden(row, not is_match)

    def toggle_password_visibility(self, row: int):
        site_item = self.table.item(row, 0)
        pw_item = self.table.item(row, 1)
        if not pw_item or not site_item: return
        is_hidden = pw_item.text() == "••••••••••••"
        password = self.parent_glyph._get_decrypted_password(site_item.text())
        if password: pw_item.setText(password if is_hidden else "••••••••••••")

    def copy_to_clipboard(self, row: int):
        site_item = self.table.item(row, 0)
        if not site_item: return
        password = self.parent_glyph._get_decrypted_password(site_item.text())
        if password: self.parent_glyph.copy_password_to_clipboard(password)

    def delete_entry(self, row: int):
        if self.row_pending_deletion != -1: self.populate_table()
        self.row_pending_deletion = row
        cw = QWidget(); ly = QHBoxLayout(cw); ly.setContentsMargins(0,0,0,0); ly.setSpacing(5)
        confirm_label = QLabel("Delete?"); confirm_label.setObjectName("ConfirmLabel")
        confirm_btn = IconButton("check", "Confirm"); cancel_btn = IconButton("x", "Cancel")
        ly.addStretch(); ly.addWidget(confirm_label); ly.addWidget(confirm_btn); ly.addWidget(cancel_btn); ly.addStretch()
        confirm_btn.clicked.connect(self._confirm_delete)
        cancel_btn.clicked.connect(self.populate_table)
        self.table.setCellWidget(row, 3, cw)

    def _confirm_delete(self):
        site_item = self.table.item(self.row_pending_deletion, 0)
        if site_item: self.parent_glyph.remove_entry(site_item.text())
        # The parent's remove_entry signal will trigger a table refresh

    def on_settings_saved(self, new_settings: dict): self.settings_updated.emit(new_settings); self.show_table_view()
    def show_table_view(self): self.stacked_widget.setCurrentWidget(self.table_view_widget)
    def show_settings_view(self): self.stacked_widget.setCurrentWidget(self.settings_view_widget)

class SetupWizard(QDialog):
    setup_complete = Signal(str)
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Glyph - First Time Setup")
        self.setObjectName("SetupWizard")
        self.setMinimumSize(520, 480); self.setModal(True)
        main_layout = QVBoxLayout(self); main_layout.setContentsMargins(0, 0, 0, 0)
        self.stacked_widget = QStackedWidget(); main_layout.addWidget(self.stacked_widget)
        self.welcome_page = self._create_welcome_page()
        self.password_page = self._create_password_page()
        self.finish_page = self._create_finish_page()
        self.stacked_widget.addWidget(self.welcome_page); self.stacked_widget.addWidget(self.password_page); self.stacked_widget.addWidget(self.finish_page)
    def reject(self):
        app = QApplication.instance();
        if app: app.quit()
        super().reject()
    def _create_page_layout(self) -> tuple[QWidget, QVBoxLayout]:
        page = QWidget(); layout = QVBoxLayout(page); layout.setContentsMargins(40, 30, 40, 30); layout.setSpacing(15); layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        return page, layout
    def _create_welcome_page(self) -> QWidget:
        page, layout = self._create_page_layout()
        icon = QSvgWidget(":/icons/glyph-logo.svg"); icon.setFixedSize(64, 64); layout.addWidget(icon, 0, Qt.AlignmentFlag.AlignCenter); layout.addSpacing(10)
        title = QLabel("Welcome to Glyph"); title.setObjectName("WizardTitle"); title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc = QLabel("Glyph is a simple, secure, and local-first password manager. Let's get your secure vault set up."); desc.setObjectName("WizardDescription"); desc.setWordWrap(True); desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title); layout.addWidget(desc); layout.addStretch()
        next_btn = QPushButton("Get Started"); next_btn.setDefault(True); next_btn.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(1))
        layout.addWidget(next_btn, 0, Qt.AlignmentFlag.AlignCenter); return page
    def _create_password_page(self) -> QWidget:
        page, layout = self._create_page_layout()
        title = QLabel("Create Your Master Password"); title.setObjectName("WizardTitle")
        desc = QLabel("This is the <b>only</b> password you'll have to remember. It protects your entire vault, so make it strong and unique. <b>We cannot recover it for you.</b>"); desc.setObjectName("WizardDescription"); desc.setWordWrap(True)
        layout.addWidget(title); layout.addWidget(desc); layout.addSpacing(20)
        self.password_input = QLineEdit(); self.password_input.setEchoMode(QLineEdit.EchoMode.Password); self.password_input.setPlaceholderText("Enter new master password"); self.password_input.setObjectName("PasswordSetupInput"); self.password_input.textChanged.connect(self._update_strength_bar)
        self.confirm_input = QLineEdit(); self.confirm_input.setEchoMode(QLineEdit.EchoMode.Password); self.confirm_input.setPlaceholderText("Confirm master password"); self.confirm_input.setObjectName("PasswordSetupInput")
        form_layout = QFormLayout(); form_layout.setSpacing(15); form_layout.addRow("Password:", self.password_input); form_layout.addRow("Confirm:", self.confirm_input)
        self.strength_bar_container = QWidget(); self.strength_bar_layout = QVBoxLayout(self.strength_bar_container); self.strength_bar_layout.setContentsMargins(0, 5, 0, 5); self._update_strength_bar("")
        self.error_label = QLabel(""); self.error_label.setObjectName("ErrorLabel"); self.error_label.setWordWrap(True); self.error_label.hide()
        layout.addLayout(form_layout); layout.addWidget(self.strength_bar_container); layout.addWidget(self.error_label); layout.addStretch()
        button_layout = QHBoxLayout(); back_btn = QPushButton("Back"); back_btn.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(0)); next_btn = QPushButton("Create Vault"); next_btn.setDefault(True); next_btn.clicked.connect(self._validate_and_proceed)
        button_layout.addWidget(back_btn); button_layout.addStretch(); button_layout.addWidget(next_btn)
        layout.addLayout(button_layout); return page
    def _update_strength_bar(self, text: str):
        while self.strength_bar_layout.count():
            child = self.strength_bar_layout.takeAt(0)
            if child.widget(): child.widget().deleteLater()
        self.strength_bar_layout.addWidget(StrengthBar(calculate_strength(text)))
    def _validate_and_proceed(self):
        pw, confirm_pw = self.password_input.text(), self.confirm_input.text()
        if pw != confirm_pw: self.error_label.setText("The passwords do not match."); self.error_label.show(); return
        strength = zxcvbn(pw)
        if strength["score"] < 2:
            feedback = "Password is too weak."
            if "feedback" in strength and strength["feedback"]["warning"]: feedback += f" {strength['feedback']['warning']}"
            self.error_label.setText(feedback); self.error_label.show(); return
        self.error_label.hide(); self.stacked_widget.setCurrentIndex(2)
    def _create_finish_page(self) -> QWidget:
        page, layout = self._create_page_layout()
        icon = QSvgWidget(":/icons/check-circle.svg"); icon.setFixedSize(64, 64); layout.addWidget(icon, 0, Qt.AlignmentFlag.AlignCenter); layout.addSpacing(10)
        title = QLabel("Setup Complete!"); title.setObjectName("WizardTitle"); title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc = QLabel("Your encrypted vault has been created. Click Finish to launch the application."); desc.setObjectName("WizardDescription"); desc.setWordWrap(True); desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title); layout.addWidget(desc); layout.addStretch()
        finish_btn = QPushButton("Finish & Launch Glyph"); finish_btn.setDefault(True); finish_btn.clicked.connect(self._finish_setup)
        layout.addWidget(finish_btn, 0, Qt.AlignmentFlag.AlignCenter); return page
    def _finish_setup(self): self.setup_complete.emit(self.password_input.text()); self.accept()

# ===================================================================
# --- Main Application Class ---
# ===================================================================

class Glyph(QWidget):
    vault_updated = Signal()
    def _get_flash_color(self): return self._flash_color_val
    def _set_flash_color(self, color): self._flash_color_val = color; self.input.setStyleSheet(f"#MainInput {{ border-bottom-color: {color.name()}; }}")
    flash_color_property = Property(QColor, _get_flash_color, _set_flash_color)

    def __init__(self):
        super().__init__()
        self.threadpool = QThreadPool()
        self.task_signals = TaskSignals()
        self.task_signals.breach_check_complete.connect(self._on_breach_check_complete)
        self.setWindowTitle("Glyph"); self.setWindowFlags(Qt.WindowType.Window | Qt.WindowType.FramelessWindowHint); self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self._setup_ui(); self.settings = load_settings()
        self.vault: Dict[str, Any] = {}; self.salt: Optional[bytes] = None; self.encryption_key: Optional[bytes] = None; self.hmac_key: Optional[bytes] = None
        self.kdf_params: Optional[Dict[str, Any]] = None
        self.awaiting: Optional[tuple[str, str]] = None; self.dashboard: Optional[DashboardWindow] = None; self.default_placeholder = "Search or /cmd site"
        self.persistent_prompt: Optional[str] = None; self.in_master_stage = True
        self.default_master_placeholder = "Enter master password…"
        self.input.setPlaceholderText(self.default_master_placeholder)
        self._flash_color_val = QColor("#3a3a3a"); self.flash_animation = QPropertyAnimation(self, b"flash_color_property", self)
        self.flash_animation.setDuration(600); self.flash_animation.setEndValue(QColor("#3a3a3a"))
        self.last_copied_password: Optional[str] = None; self.auto_lock_timer = QTimer(self); self.auto_lock_timer.setSingleShot(True)
        self.auto_lock_timer.timeout.connect(self.lock_application); self.installEventFilter(self)
        self.change_password_dialog = None
        self.awaiting_upgrade_decision = False
        self.last_entered_password = ""

    def _setup_ui(self):
        self.setFixedSize(450, 150)
        self.container = QWidget(self); self.container.setObjectName("Container"); main_layout = QVBoxLayout(self.container); main_layout.setContentsMargins(0, 0, 0, 0); main_layout.setSpacing(0)
        title_layout = QHBoxLayout(); title_layout.setContentsMargins(30, 10, 15, 0); title_layout.setSpacing(0)
        title_label = QLabel("Glyph"); title_label.setObjectName("TitleLabel"); close_btn = QPushButton("×"); close_btn.setObjectName("CloseButton"); close_btn.clicked.connect(self.close)
        close_btn.setFocusPolicy(Qt.FocusPolicy.NoFocus); title_layout.addWidget(title_label); title_layout.addStretch(); title_layout.addWidget(close_btn); main_layout.addLayout(title_layout)
        input_layout = QVBoxLayout(); input_layout.setContentsMargins(30, 5, 30, 35)
        self.input = QLineEdit(); self.input.setObjectName("MainInput"); self.input.setEchoMode(QLineEdit.EchoMode.Password); self.input.setContextMenuPolicy(Qt.ContextMenuPolicy.NoContextMenu); self.input.returnPressed.connect(self.on_return_pressed)
        input_layout.addWidget(self.input)
        main_layout.addLayout(input_layout); central_layout = QHBoxLayout(self); central_layout.addWidget(self.container)

    def _on_breach_check_complete(self, site_key: str, is_breached: bool):
        if self.vault and site_key in self.vault:
            self.vault[site_key]['breached'] = is_breached
            self.save_vault()
            self.vault_updated.emit()

    def open_dashboard(self):
        if self.vault is not None:
            if not self.dashboard or not self.dashboard.isVisible():
                self.dashboard = DashboardWindow(self.vault, self.settings, self)
            self.dashboard.show(); self.dashboard.activateWindow()

    def on_settings_updated(self, new_settings: dict):
        self.settings = new_settings; save_settings(self.settings)
        self.reset_auto_lock_timer()
        if self.dashboard and self.dashboard.isVisible(): self.dashboard.settings = new_settings
        self.show_temp_message("Settings saved", 1500)

    def export_vault(self, file_path_str: str):
        # --- FIX: Simplified export logic for CSV only ---
        file_path = Path(file_path_str)
        plain_vault = []
        for key, entry_data in self.vault.items():
            password = self._get_decrypted_password(key)
            if password is not None:
                plain_vault.append({"name": entry_data.get("name", key), "password": password})
        
        try:
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['name', 'password'])
                for item in plain_vault:
                    writer.writerow([item['name'], item['password']])
            self.show_temp_message(f"Vault exported to {file_path.name}", 2000)
            self.flash_feedback(QColor("#2ecc71"))
        except IOError as e:
            self.show_temp_message(f"Error exporting file: {e}", 3000)
            self.flash_feedback(QColor("#e74c3c"))

    def show_change_password_dialog(self):
        self.change_password_dialog = ChangePasswordDialog(self.dashboard)
        self.change_password_dialog.password_change_requested.connect(self.perform_master_password_change)
        self.change_password_dialog.exec()

    def _create_encrypted_entry(self, site_name: str, password: str, breached: bool = False) -> Optional[Dict[str, Any]]:
        if not self.encryption_key: return None
        return self._create_encrypted_entry_with_key(site_name, password, self.encryption_key, breached)

    def _create_encrypted_entry_with_key(self, site_name: str, password: str, encryption_key: bytes, breached: bool = False) -> Optional[Dict[str, Any]]:
        """Creates a fully-formed, encrypted entry dictionary, preserving all metadata."""
        try:
            entry_key = AESGCM.generate_key(bit_length=256)
            key_wrap_nonce = secrets.token_bytes(12)
            pw_nonce = secrets.token_bytes(12)
            wrapped_key = AESGCM(encryption_key).encrypt(key_wrap_nonce, entry_key, None)
            enc_pw = AESGCM(entry_key).encrypt(pw_nonce, password.encode(), None)
            return {
                "name": site_name,
                "strength": calculate_strength(password),
                "breached": breached,
                "key_wrap_nonce": urlsafe_b64encode(key_wrap_nonce).decode(),
                "pw_nonce": urlsafe_b64encode(pw_nonce).decode(),
                "wrapped_entry_key": urlsafe_b64encode(wrapped_key).decode(),
                "encrypted_password": urlsafe_b64encode(enc_pw).decode()
            }
        except Exception:
            return None

    def _re_encrypt_and_save_vault(self, new_encryption_key: bytes, new_hmac_key: bytes, new_kdf_params: dict) -> tuple[bool, Optional[str], Optional[dict]]:
        """Atomically re-encrypts the vault and saves all critical files."""
        new_encrypted_vault = {}
        for key, entry in self.vault.items():
            plain_password = self._get_decrypted_password(key)
            if plain_password is None:
                return False, f"Decryption failed for '{entry.get('name', key)}'.", None

            new_entry_data = self._create_encrypted_entry_with_key(
                site_name=entry.get("name", key),
                password=plain_password,
                encryption_key=new_encryption_key,
                breached=entry.get("breached", False)
            )
            if new_entry_data is None:
                return False, f"Re-encryption failed for '{entry.get('name', key)}'.", None
            new_encrypted_vault[key] = new_entry_data

        VAULT_FILE_TMP = VAULT_FILE.with_suffix('.tmp')
        VAULT_HMAC_FILE_TMP = VAULT_HMAC_FILE.with_suffix('.tmp')
        KDF_PARAMS_FILE_TMP = KDF_PARAMS_FILE.with_suffix('.tmp')
        
        try:
            save_kdf_params(new_kdf_params, path=KDF_PARAMS_FILE_TMP)
            save_vault_with_integrity(new_encrypted_vault, new_encryption_key, new_hmac_key, VAULT_FILE_TMP, VAULT_HMAC_FILE_TMP)

            if not verify_vault_integrity(new_hmac_key, VAULT_FILE_TMP, VAULT_HMAC_FILE_TMP):
                raise IOError("Verification of new vault file failed.")

            KDF_PARAMS_FILE_TMP.replace(KDF_PARAMS_FILE)
            VAULT_FILE_TMP.replace(VAULT_FILE)
            VAULT_HMAC_FILE_TMP.replace(VAULT_HMAC_FILE)

        except Exception as e:
            KDF_PARAMS_FILE_TMP.unlink(missing_ok=True)
            VAULT_FILE_TMP.unlink(missing_ok=True)
            VAULT_HMAC_FILE_TMP.unlink(missing_ok=True)
            return False, f"Failed to save new vault: {e}", None

        return True, None, new_encrypted_vault

    def perform_master_password_change(self, old_pw: str, new_pw: str):
        if self.salt is None or self.kdf_params is None or self.hmac_key is None:
            if self.change_password_dialog: self.change_password_dialog.on_failure("Critical error: Session state is invalid.")
            return

        old_derived = derive_keys(old_pw, self.salt, self.kdf_params)
        if not old_derived or not hmac.compare_digest(old_derived[1], self.hmac_key):
            if self.change_password_dialog: self.change_password_dialog.on_failure("Incorrect current password.")
            return

        new_kdf_params = RECOMMENDED_KDF_PARAMS
        new_derived = derive_keys(new_pw, self.salt, new_kdf_params)
        if not new_derived:
            if self.change_password_dialog: self.change_password_dialog.on_failure("Internal error deriving new keys.")
            return

        new_encryption_key, new_hmac_key = new_derived
        success, error_msg, new_vault = self._re_encrypt_and_save_vault(new_encryption_key, new_hmac_key, new_kdf_params)

        if success and new_vault is not None:
            self.encryption_key = new_encryption_key
            self.hmac_key = new_hmac_key
            self.vault = new_vault
            self.kdf_params = new_kdf_params
            if self.change_password_dialog: self.change_password_dialog.on_success()
            if self.dashboard: self.dashboard.close()
            self.lock_application("Master password changed. Session locked.")
        else:
            if self.change_password_dialog: self.change_password_dialog.on_failure(error_msg or "An unknown error occurred.")

    def perform_security_upgrade(self, master_password: str):
        if self.salt is None:
            self.show_temp_message("Security upgrade failed: session state invalid.", 3000); return

        new_kdf_params = RECOMMENDED_KDF_PARAMS
        new_derived = derive_keys(master_password, self.salt, new_kdf_params)
        if not new_derived:
            self.show_temp_message("Security upgrade failed: could not derive new keys.", 3000); return
        
        new_encryption_key, new_hmac_key = new_derived
        success, error_msg, new_vault = self._re_encrypt_and_save_vault(new_encryption_key, new_hmac_key, new_kdf_params)

        if success and new_vault is not None:
            self.encryption_key = new_encryption_key
            self.hmac_key = new_hmac_key
            self.vault = new_vault
            self.kdf_params = new_kdf_params
            self.flash_feedback(QColor("#2ecc71"))
            self.show_temp_message("Vault security successfully upgraded!", 2500)
            QTimer.singleShot(500, self._transition_to_main_ui)
        else:
            self.show_temp_message(error_msg or "Security upgrade failed.", 3000)

    def first_stage_unlock(self):
        pw = self.input.text()
        if not pw: return
        self.salt = load_master_salt()
        if self.salt is None:
            self.flash_feedback(QColor("#e74c3c")); self.show_temp_message("FATAL: Master salt file missing.", 3000); return
        loaded_params = load_kdf_params()
        self.kdf_params = loaded_params or RECOMMENDED_KDF_PARAMS

        upgrade_needed = False
        if not loaded_params or any(self.kdf_params.get(k, 0) < v for k, v in RECOMMENDED_KDF_PARAMS.items() if isinstance(v, int)):
            upgrade_needed = True
        
        derived = derive_keys(pw, self.salt, self.kdf_params)
        if not derived:
            self.flash_feedback(QColor("#e74c3c")); self.show_temp_message("Key derivation failed internally.", 3000); return
        self.encryption_key, self.hmac_key = derived
        if not verify_vault_integrity(self.hmac_key) or (loaded_vault := load_vault_with_integrity(self.encryption_key)) is None:
            self.flash_feedback(QColor("#e74c3c")); self.show_temp_message("Wrong password or corrupt vault", 2500)
            self.encryption_key, self.hmac_key = None, None; self.input.clear(); return
        self.vault = loaded_vault; self.flash_feedback(QColor("#2ecc71"))
        if upgrade_needed:
            self.awaiting_upgrade_decision = True
            self.last_entered_password = pw
            self.input.clear(); self.input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.persistent_prompt = "Type UPGRADE to proceed, or Enter to skip."
            self._maybe_reset_placeholder(); self.show_temp_message("Security Upgrade Recommended", 4000)
            return
        QTimer.singleShot(500, self._transition_to_main_ui)

    def handle_upgrade_decision(self):
        text = self.input.text().strip().upper()
        self.input.clear(); self.awaiting_upgrade_decision = False; self.persistent_prompt = None
        if text == "UPGRADE": self.perform_security_upgrade(self.last_entered_password)
        else: self.show_temp_message("Upgrade skipped.", 2000); QTimer.singleShot(500, self._transition_to_main_ui)
        self.last_entered_password = ""

    def _handle_initial_setup(self, master_password: str):
        self.salt = secrets.token_bytes(SALT_SIZE); save_master_salt(self.salt)
        self.kdf_params = RECOMMENDED_KDF_PARAMS; save_kdf_params(self.kdf_params)
        derived = derive_keys(master_password, self.salt, self.kdf_params)
        if not derived:
            app = QApplication.instance();
            if app: app.quit()
            return
        self.encryption_key, self.hmac_key = derived
        self.vault = {}; self.save_vault()
        self.show(); self.flash_feedback(QColor("#2ecc71")); QTimer.singleShot(500, self._transition_to_main_ui)

    def reset_application(self):
        if self.dashboard: self.dashboard.close()
        for f in [VAULT_FILE, MASTER_FILE, VAULT_HMAC_FILE, SETTINGS_FILE, KDF_PARAMS_FILE]: f.unlink(missing_ok=True)
        app = QApplication.instance()
        if app: app.quit()

    def eventFilter(self, watched, event):
        if not self.in_master_stage and event.type() in [QEvent.Type.KeyPress, QEvent.Type.MouseButtonPress]: self.reset_auto_lock_timer()
        return super().eventFilter(watched, event)
    def reset_auto_lock_timer(self):
        timeout_seconds = self.settings.get("auto_lock_timeout_seconds", 300)
        if timeout_seconds > 0 and not self.in_master_stage: self.auto_lock_timer.start(timeout_seconds * 1000)
    def lock_application(self, reason_msg: Optional[str] = None):
        if self.in_master_stage: return
        self.in_master_stage = True; self.encryption_key, self.hmac_key, self.vault, self.kdf_params = None, None, {}, None
        self.awaiting, self.persistent_prompt = None, None; self.input.clear()
        self.input.setEchoMode(QLineEdit.EchoMode.Password); self.input.setPlaceholderText(self.default_master_placeholder)
        if self.dashboard and self.dashboard.isVisible(): self.dashboard.close(); self.dashboard = None
        self.auto_lock_timer.stop(); self.flash_feedback(QColor("#3498db"))
        message = reason_msg or "Session locked due to inactivity."
        self.show_temp_message(message, 2000)
    def copy_password_to_clipboard(self, password: str):
        if not password: return
        clipboard = QGuiApplication.clipboard(); clipboard.setText(password); self.last_copied_password = password
        clear_seconds = self.settings.get("clipboard_clear_seconds", 30)
        if clear_seconds > 0: QTimer.singleShot(clear_seconds * 1000, self.clear_clipboard_if_unchanged)
    def clear_clipboard_if_unchanged(self):
        clipboard = QGuiApplication.clipboard()
        if clipboard.text() == self.last_copied_password: clipboard.clear(); self.last_copied_password = None
    def flash_feedback(self, color): self.flash_animation.stop(); self.flash_animation.setStartValue(color); self._set_flash_color(color); self.flash_animation.start()
    def mousePressEvent(self, event): self.oldPos = event.globalPosition().toPoint()
    def mouseMoveEvent(self, event):
        delta = QPoint(event.globalPosition().toPoint() - self.oldPos); self.move(self.x() + delta.x(), self.y() + delta.y()); self.oldPos = event.globalPosition().toPoint()
    def on_return_pressed(self):
        if self.awaiting_upgrade_decision: self.handle_upgrade_decision()
        elif self.in_master_stage: self.first_stage_unlock()
        else: self.process_command()
    def show_temp_message(self, message: str, duration_ms: int = 1500):
        self.input.clear(); self.input.setPlaceholderText(message); QTimer.singleShot(duration_ms, self._maybe_reset_placeholder)
    def _maybe_reset_placeholder(self):
        current = self.persistent_prompt or (self.default_master_placeholder if self.in_master_stage else self.default_placeholder)
        if self.input.placeholderText() != current: self.input.setPlaceholderText(current)
    def _transition_to_main_ui(self):
        self.input.clear(); self.input.setPlaceholderText(self.default_placeholder)
        self.input.setEchoMode(QLineEdit.EchoMode.Normal); self.in_master_stage = False; self.reset_auto_lock_timer()
    def save_vault(self):
        if self.encryption_key and self.hmac_key and self.vault is not None: save_vault_with_integrity(self.vault, self.encryption_key, self.hmac_key)
    def _get_decrypted_password(self, site_key: str) -> Optional[str]:
        if self.vault is None or self.encryption_key is None: return None
        entry = self.vault.get(site_key.lower())
        if not entry: return None
        try:
            key_wrap_nonce = urlsafe_b64decode(entry["key_wrap_nonce"]); pw_nonce = urlsafe_b64decode(entry["pw_nonce"])
            wrapped_key = urlsafe_b64decode(entry["wrapped_entry_key"]); enc_pw = urlsafe_b64decode(entry["encrypted_password"])
            entry_key = AESGCM(self.encryption_key).decrypt(key_wrap_nonce, wrapped_key, None)
            return AESGCM(entry_key).decrypt(pw_nonce, enc_pw, None).decode()
        except (InvalidTag, KeyError, Exception): return None
    def copy_from_command(self, site_key: str):
        password = self._get_decrypted_password(site_key)
        if password: self.copy_password_to_clipboard(password); self.flash_feedback(QColor("#2ecc71")); self.show_temp_message("Copied to clipboard")
        else: self.flash_feedback(QColor("#e74c3c")); self.show_temp_message("DECRYPTION FAILED")

    def update_entry(self, s_old: str, s_new: str, p_new: str) -> bool:
        if self.vault is None or self.encryption_key is None: return False
        s_old_lower, s_new_lower = s_old.lower(), s_new.lower()
        if s_old_lower != s_new_lower and s_new_lower in self.vault:
            self.flash_feedback(QColor("#e74c3c")); self.show_temp_message(f"Error: '{s_new}' already exists."); return False
        
        is_breached = self.vault.get(s_old_lower, {}).get("breached", False) if s_old_lower == s_new_lower else False
        
        new_entry_data = self._create_encrypted_entry(s_new_lower, p_new, breached=is_breached)
        if not new_entry_data: return False
        
        if s_old_lower in self.vault and s_old_lower != s_new_lower:
            del self.vault[s_old_lower]

        self.vault[s_new_lower] = new_entry_data
        self.save_vault()

        if not is_breached:
            self.threadpool.start(BreachChecker(s_new_lower, p_new, self.task_signals))
        return True

    def remove_entry(self, site_name: str):
        site_key = site_name.lower()
        if self.vault is not None and site_key in self.vault:
            del self.vault[site_key]
            self.save_vault()
            self.vault_updated.emit()

    def process_command(self):
        text = self.input.text().strip(); self.input.clear()
        cmds = self.settings.get("commands", DEFAULT_SETTINGS["commands"])
        if self.awaiting:
            if not text: self.awaiting = None; self.persistent_prompt = None; self.flash_feedback(QColor("#3498db")); self.show_temp_message("Operation cancelled"); return
            mode, target = self.awaiting; self.awaiting = None; self.persistent_prompt = None
            if mode in ('new', 'pw'):
                if self.update_entry(target, target, text): self.copy_password_to_clipboard(text); self.flash_feedback(QColor("#2ecc71")); self.show_temp_message("Saved & copied")
            elif mode == 'n':
                new_name_lower = text.lower()
                old_pw = self._get_decrypted_password(target)
                if old_pw is not None and self.update_entry(target, new_name_lower, old_pw):
                    self.copy_from_command(new_name_lower)
                    self.flash_feedback(QColor("#2ecc71")); self.show_temp_message("Renamed & copied")
            return
        if not text: return
        text_lower = text.lower()
        if text_lower == cmds["dashboard"]: self.open_dashboard(); return
        if text_lower == cmds["settings"]:
            self.open_dashboard()
            if self.dashboard: self.dashboard.show_settings_view()
            return
        if text_lower == cmds["exit"]: self.close(); return
        if text_lower == cmds["upgrade"]:
            self.show_temp_message("To upgrade, change your master password in Settings.", 4000)
            return
        if text.startswith("/"):
            try: cmd_text, site = text.split(" ", 1)
            except ValueError: cmd_text, site = text, None
            if not site: self.flash_feedback(QColor("#e74c3c")); self.show_temp_message("Error: Command requires a sitename"); return
            site_lower = site.lower()
            if cmd_text == cmds["generate"]:
                pw = generate_password(self.settings)
                if self.update_entry(site_lower, site_lower, pw):
                    self.copy_password_to_clipboard(pw)
                    self.flash_feedback(QColor("#2ecc71")); self.show_temp_message("Generated & copied")
            elif self.vault is None or site_lower not in self.vault: self.flash_feedback(QColor("#e74c3c")); self.show_temp_message(f"Error: '{site}' not found")
            elif cmd_text == cmds["update"]: self.awaiting = ("pw", site_lower); self.persistent_prompt = f"New password for {self.vault[site_lower].get('name', site)}:"; self._maybe_reset_placeholder()
            elif cmd_text == cmds["rename"]: self.awaiting = ("n", site_lower); self.persistent_prompt = f"New name for {self.vault[site_lower].get('name', site)}:"; self._maybe_reset_placeholder()
            elif cmd_text == cmds["remove"]: self.remove_entry(site); self.flash_feedback(QColor("#2ecc71")); self.show_temp_message(f"Removed '{site}'")
            else: self.flash_feedback(QColor("#e74c3c")); self.show_temp_message("Error: Unknown command")
            return
        if self.vault is not None and text_lower in self.vault: self.copy_from_command(text_lower)
        else:
            self.awaiting = ("new", text.lower()); self.persistent_prompt = f"Password for new site '{text.lower()}':"; self._maybe_reset_placeholder()

    def _handle_import_request(self):
        """Handles the request to import a vault from a file."""
        file_path, _ = QFileDialog.getOpenFileName(self, "Import Passwords from CSV", "", "CSV Files (*.csv)")
        if not file_path:
            return

        parsed_data = parse_csv_for_import(Path(file_path))

        if not parsed_data:
            QMessageBox.information(self, "Import Failed", "No valid password entries could be found in the selected file.")
            return

        review_dialog = ImportReviewDialog(parsed_data, list(self.vault.keys()), self.dashboard)
        review_dialog.import_confirmed.connect(self._perform_import)
        review_dialog.exec()

    def _perform_import(self, items_to_import: list):
        """Performs the actual import operation based on user selection."""
        if not items_to_import:
            return

        new_count = 0
        update_count = 0

        for item in items_to_import:
            name_lower = item['name'].lower()
            password = item['password']

            if name_lower in self.vault:
                update_count += 1
            else:
                new_count += 1

            self.update_entry(name_lower, name_lower, password)

        self.vault_updated.emit()

        summary_message = "Import Complete!\n\n"
        if new_count > 0:
            summary_message += f"Added {new_count} new entries.\n"
        if update_count > 0:
            summary_message += f"Updated {update_count} existing entries.\n"

        QMessageBox.information(self, "Import Successful", summary_message)

def main():
    """Main entry point for the application."""
    app = QApplication(sys.argv)
    
    # --- PERMANENT FIX for data path ---
    # This ensures Qt always knows where to save data, even when run as a script.
    app.setApplicationName("Glyph")
    app.setOrganizationName("Glyph") # Often the same for simple apps

    app.setStyleSheet(load_stylesheet())
    is_new_install = not MASTER_FILE.exists()
    window = Glyph()
    if is_new_install:
        wizard = SetupWizard()
        wizard.setup_complete.connect(window._handle_initial_setup)
        if not wizard.exec(): sys.exit(0)
    else: window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()