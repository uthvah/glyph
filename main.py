import sys
import json
import secrets
import string
import hashlib
import re
import hmac
from pathlib import Path
from base64 import urlsafe_b64encode, urlsafe_b64decode
from typing import Optional

from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QLabel, QFrame, QFormLayout, 
    QStackedWidget, QScrollArea
)
from PySide6.QtCore import (
    Qt, QTimer, QPoint, QPropertyAnimation, Property, Signal, QFile, QEvent,
    QIODevice, QStandardPaths, QTextStream
)
from PySide6.QtGui import QCursor, QColor, QIntValidator, QGuiApplication
from PySide6.QtSvgWidgets import QSvgWidget

import argon2
from argon2.low_level import hash_secret_raw, Type as Argon2Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import resources_rc # This will be generated from your .qrc file

# --- Configuration & Settings Management ---
def get_app_data_path() -> Path:
    """Gets the standard application data directory for the current OS."""
    path_str = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppLocalDataLocation)
    if not path_str: return Path(".").resolve()
    app_dir = Path(path_str) / "Glyph"
    app_dir.mkdir(parents=True, exist_ok=True)
    return app_dir

APP_DATA_DIR = get_app_data_path()
VAULT_FILE = APP_DATA_DIR / "vault.bin"
MASTER_FILE = APP_DATA_DIR / "master.bin"
VAULT_HMAC_FILE = APP_DATA_DIR / "vault.hmac"
SETTINGS_FILE = APP_DATA_DIR / "settings.json"
SALT_SIZE = 16

DEFAULT_SETTINGS = {
    "auto_lock_timeout_seconds": 300,
    "clipboard_clear_seconds": 30,
    "password_generation_length": 20,
    "commands": {
        "generate": "/pr", "update": "/pw", "remove": "/r", "rename": "/n",
        "dashboard": "/dash", "settings": "/settings", "exit": "/exit"
    }
}

def load_settings() -> dict:
    if not SETTINGS_FILE.exists(): return DEFAULT_SETTINGS
    try:
        with open(SETTINGS_FILE, "r") as f: settings = json.load(f)
        for key, value in DEFAULT_SETTINGS.items():
            if key == "commands" and isinstance(value, dict):
                settings.setdefault(key, {})
                for cmd_key, cmd_val in value.items():
                    if isinstance(settings[key], dict): settings[key].setdefault(cmd_key, cmd_val)
            else: settings.setdefault(key, value)
        return settings
    except(json.JSONDecodeError, IOError): return DEFAULT_SETTINGS

def save_settings(settings: dict):
    with open(SETTINGS_FILE, "w") as f: json.dump(settings, f, indent=4)

# --- Crypto & Utility Functions ---
ARGON2_TIME_COST = 3; ARGON2_MEMORY_COST = 65536; ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 64; ARGON2_TYPE = Argon2Type.ID

def derive_keys(password: str, salt: bytes) -> Optional[tuple[bytes, bytes]]:
    try:
        derived_key_material = hash_secret_raw(secret=password.encode(), salt=salt, time_cost=ARGON2_TIME_COST, memory_cost=ARGON2_MEMORY_COST, parallelism=ARGON2_PARALLELISM, hash_len=ARGON2_HASH_LEN, type=ARGON2_TYPE)
        if len(derived_key_material) != 64: return None
        return derived_key_material[:32], derived_key_material[32:]
    except argon2.exceptions.HashingError: return None

def verify_vault_integrity(hmac_key: bytes) -> bool:
    if not VAULT_FILE.exists() or not VAULT_HMAC_FILE.exists(): return True
    try:
        stored_hmac = VAULT_HMAC_FILE.read_bytes(); vault_data = VAULT_FILE.read_bytes()
        expected_hmac = hmac.new(hmac_key, vault_data, hashlib.sha256).digest()
        return hmac.compare_digest(stored_hmac, expected_hmac)
    except Exception: return False

def save_vault_with_integrity(vault_data: dict, encryption_key: bytes, hmac_key: bytes):
    try:
        json_data = json.dumps(vault_data).encode()
        nonce = secrets.token_bytes(12)
        encrypted_blob = AESGCM(encryption_key).encrypt(nonce, json_data, None)
        full_blob = nonce + encrypted_blob
        new_hmac = hmac.new(hmac_key, full_blob, hashlib.sha256).digest()
        VAULT_FILE.write_bytes(full_blob); VAULT_HMAC_FILE.write_bytes(new_hmac)
    except Exception as e: print(f"Vault Save Error: {e}")

def load_vault_with_integrity(encryption_key: bytes) -> Optional[dict]:
    if not VAULT_FILE.exists(): return {}
    try:
        full_blob = VAULT_FILE.read_bytes()
        nonce, ciphertext = full_blob[:12], full_blob[12:]
        decrypted_json = AESGCM(encryption_key).decrypt(nonce, ciphertext, None)
        return json.loads(decrypted_json)
    except (InvalidTag, json.JSONDecodeError, ValueError): return None
    except Exception: return None

def load_stylesheet() -> str:
    file = QFile(":/styles/modern_glyph.qss")
    if not file.open(QIODevice.OpenModeFlag.ReadOnly | QIODevice.OpenModeFlag.Text):
        print("Warning: Could not open stylesheet from resources.")
        return ""
    stream = QTextStream(file); stylesheet = stream.readAll(); file.close()
    return stylesheet

def save_master_salt(salt: bytes): MASTER_FILE.write_bytes(salt)
def load_master_salt() -> Optional[bytes]: return MASTER_FILE.read_bytes() if MASTER_FILE.exists() else None
def generate_password(length: int = 20) -> str:
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    return ''.join(secrets.choice(chars) for _ in range(length))
def calculate_strength(password: str) -> int:
    if not password: return 0
    strength, length = 0, len(password)
    strength += (25 if length >= 8 else 0) + (15 if length >= 12 else 0) + (10 if length >= 16 else 0)
    if re.search(r"[a-z]", password): strength += 10
    if re.search(r"[A-Z]", password): strength += 15
    if re.search(r"\d", password): strength += 15
    if re.search(r"[!@#$%^&*()]", password): strength += 10
    return min(100, strength)

# --- UI CLASSES ---
class IconButton(QPushButton):
    def __init__(self, icon_name: str, tooltip: str = ""):
        super().__init__()
        self.svg_widget = QSvgWidget(f":/icons/{icon_name}.svg")
        self.svg_widget.setFixedSize(18, 18)
        layout = QHBoxLayout(self)
        layout.addWidget(self.svg_widget)
        self.setFixedSize(40, 40); self.setToolTip(tooltip)
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
    def __init__(self, strength: int):
        super().__init__()
        layout = QHBoxLayout(self); layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(10)
        bar_widget = QWidget(); bar_widget.setFixedHeight(6)
        fill_color = "#e74c3c"
        if strength > 65: fill_color = "#2ecc71"
        elif strength > 40: fill_color = "#f39c12"
        bg_color, stop_pos = "#333333", strength / 100.0
        if strength == 0: stylesheet = f"background-color:{bg_color};border-radius:3px;"
        elif strength == 100: stylesheet = f"background-color:{fill_color};border-radius:3px;"
        else: stylesheet = f"""background-color:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:{stop_pos}{fill_color},stop:{stop_pos + 0.001}{bg_color});border-radius:3px;"""
        bar_widget.setStyleSheet(stylesheet.strip())
        text_label = QLabel(f"{strength}%"); text_label.setObjectName("StrengthLabel"); text_label.setFixedWidth(45); text_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(bar_widget, 1); layout.addWidget(text_label, 0)

class SettingsView(QWidget):
    settings_saved = Signal(dict)
    def __init__(self, current_settings: dict, back_callback, parent=None):
        super().__init__(parent); self.setObjectName("SettingsView"); self.settings = current_settings.copy()
        self.main_layout = QVBoxLayout(self); self.main_layout.setContentsMargins(0, 0, 0, 0); self.main_layout.setSpacing(0)
        header_frame = self._create_frame("SettingsHeader"); header_layout = QHBoxLayout(header_frame); header_layout.setContentsMargins(25, 20, 25, 20)
        back_btn = IconButton("arrow-left", "Back to Dashboard"); back_btn.clicked.connect(back_callback); title = QLabel("Settings"); title.setObjectName("DashboardTitle")
        header_layout.addWidget(back_btn); header_layout.addWidget(title); header_layout.addStretch(); self.main_layout.addWidget(header_frame)
        scroll_area = QScrollArea(); scroll_area.setWidgetResizable(True); scroll_area.setObjectName("SettingsScrollArea"); content_widget = QWidget(); scroll_area.setWidget(content_widget)
        content_layout = QVBoxLayout(content_widget); content_layout.setContentsMargins(25, 25, 25, 25); content_layout.setSpacing(25)
        top_layout = QHBoxLayout(); top_layout.setSpacing(25)
        self.auto_lock_input = self._create_minimal_line_edit(self.settings["auto_lock_timeout_seconds"], 0, 3600)
        self.clipboard_input = self._create_minimal_line_edit(self.settings["clipboard_clear_seconds"], 0, 300)
        self.pw_len_input = self._create_minimal_line_edit(self.settings["password_generation_length"], 8, 128)
        top_layout.addWidget(self._create_settings_group("Security", [(QLabel("Auto-lock after inactivity (seconds):"), self.auto_lock_input), (QLabel("Clear clipboard after (seconds):"), self.clipboard_input)]))
        top_layout.addWidget(self._create_settings_group("Password Generation", [(QLabel("Default generated password length:"), self.pw_len_input)])); content_layout.addLayout(top_layout)
        content_layout.addWidget(self._create_command_group()); content_layout.addStretch(); self.main_layout.addWidget(scroll_area, 1)
        footer_frame = self._create_frame("SettingsFooter"); footer_layout = QHBoxLayout(footer_frame); footer_layout.setContentsMargins(25, 15, 25, 15); footer_layout.addStretch()
        cancel_btn = QPushButton("Cancel"); cancel_btn.clicked.connect(back_callback); save_btn = QPushButton("Save"); save_btn.setDefault(True); save_btn.clicked.connect(self.save_and_exit)
        footer_layout.addWidget(cancel_btn); footer_layout.addWidget(save_btn); self.main_layout.addWidget(footer_frame)
    def save_and_exit(self):
        updated_settings = {"auto_lock_timeout_seconds": int(self.auto_lock_input.text() or 0), "clipboard_clear_seconds": int(self.clipboard_input.text() or 0), "password_generation_length": int(self.pw_len_input.text() or 8), "commands": {key: ui['label'].text() for key, ui in self.command_ui.items()}}
        self.settings_saved.emit(updated_settings)
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
        self.command_ui = {}; cmap = {"generate": "Generate new password", "update": "Update existing password", "remove": "Remove entry", "rename": "Rename entry", "dashboard": "Open dashboard", "settings": "Open settings", "exit": "Quit application"}
        for key, desc in cmap.items(): command = self.settings.get("commands", {}).get(key, DEFAULT_SETTINGS["commands"][key]); row_widget = self._create_command_row(key, desc, command); layout.addWidget(row_widget)
        return group_frame
    def _create_command_row(self, key: str, description: str, command: str) -> QWidget:
        row_widget = QWidget(); row_layout = QHBoxLayout(row_widget); row_layout.setContentsMargins(0, 0, 0, 0); row_layout.setSpacing(10)
        desc_label, cmd_label = QLabel(description), QLabel(command); cmd_label.setObjectName("CommandLabel"); cmd_editor = QLineEdit(command); cmd_editor.setObjectName("SettingsInput"); cmd_editor.hide()
        edit_btn, save_btn, cancel_btn = IconButton("edit", "Edit"), IconButton("check", "Save"), IconButton("x", "Cancel"); save_btn.hide(); cancel_btn.hide()
        row_layout.addWidget(desc_label); row_layout.addStretch(); row_layout.addWidget(cmd_label); row_layout.addWidget(cmd_editor); row_layout.addWidget(edit_btn); row_layout.addWidget(save_btn); row_layout.addWidget(cancel_btn)
        self.command_ui[key] = {'label': cmd_label, 'editor': cmd_editor, 'edit_btn': edit_btn, 'save_btn': save_btn, 'cancel_btn': cancel_btn}
        edit_btn.clicked.connect(lambda: self.set_edit_mode(key, True)); save_btn.clicked.connect(lambda: self.save_command_edit(key)); cancel_btn.clicked.connect(lambda: self.set_edit_mode(key, False)); cmd_editor.returnPressed.connect(lambda: self.save_command_edit(key))
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

class DashboardWindow(QWidget):
    settings_updated = Signal(dict)
    def __init__(self, vault: dict, settings: dict, parent_glyph, parent=None):
        super().__init__(parent); self.vault, self.settings, self.parent_glyph = vault, settings, parent_glyph
        self.setWindowTitle("Glyph - Dashboard"); self.setMinimumSize(1000, 580); self.setObjectName("Dashboard")
        main_layout = QVBoxLayout(self); main_layout.setContentsMargins(0, 0, 0, 0)
        self.stacked_widget = QStackedWidget(); main_layout.addWidget(self.stacked_widget)
        self.table_view_widget = self._create_table_view()
        self.settings_view_widget = SettingsView(self.settings, self.show_table_view)
        self.stacked_widget.addWidget(self.table_view_widget); self.stacked_widget.addWidget(self.settings_view_widget)
        self.settings_view_widget.settings_saved.connect(self.on_settings_saved)
        self.setWindowModality(Qt.WindowModality.ApplicationModal)
        self.editing_row = -1; self.is_adding_new = False
        self.row_pending_deletion = -1
        self.installEventFilter(self)
    def eventFilter(self, watched, event):
        if event.type() in [QEvent.Type.KeyPress, QEvent.Type.MouseButtonPress]: self.parent_glyph.reset_auto_lock_timer()
        return super().eventFilter(watched, event)
    def _create_table_view(self) -> QWidget:
        table_view_widget = QWidget(); layout = QVBoxLayout(table_view_widget); layout.setContentsMargins(25, 20, 25, 20); layout.setSpacing(15)
        title_row_layout = QHBoxLayout(); title = QLabel("All Passwords"); title.setObjectName("DashboardTitle")
        self.search_input = SearchInputWidget(); self.search_input.textChanged.connect(self.filter_table)
        add_btn = IconButton("plus", "Add New Entry"); add_btn.clicked.connect(self.add_new_entry)
        settings_btn = IconButton("settings", "Settings"); settings_btn.clicked.connect(self.show_settings_view)
        title_row_layout.addWidget(title); title_row_layout.addStretch(); title_row_layout.addWidget(self.search_input)
        title_row_layout.addWidget(add_btn); title_row_layout.addWidget(settings_btn); layout.addLayout(title_row_layout)
        self.table = QTableWidget(); self.table.setColumnCount(4); self.table.setHorizontalHeaderLabels(["Website", "Password", "Strength", ""])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch); self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed); self.table.setColumnWidth(2, 150)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed); self.table.setColumnWidth(3, 220)
        self.table.verticalHeader().setVisible(False); self.table.setShowGrid(True); self.table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.table.setSelectionMode(QTableWidget.SelectionMode.NoSelection); self.table.verticalHeader().setDefaultSectionSize(60)
        self.populate_table(); layout.addWidget(self.table); return table_view_widget
    def on_settings_saved(self, new_settings: dict): self.settings_updated.emit(new_settings); self.show_table_view()
    def show_table_view(self): self.stacked_widget.setCurrentWidget(self.table_view_widget)
    def show_settings_view(self): self.stacked_widget.setCurrentWidget(self.settings_view_widget)
    def populate_table(self):
        self.editing_row, self.is_adding_new, self.row_pending_deletion = -1, False, -1
        self.table.setSortingEnabled(False); self.table.setRowCount(0)
        sorted_items = sorted(self.vault.items(), key=lambda item: item[1].get('name', item[0]).lower())
        self.table.setRowCount(len(sorted_items))
        for r, (key, data) in enumerate(sorted_items):
            self.table.setItem(r, 0, QTableWidgetItem(data.get("name", key))); self.table.setItem(r, 1, QTableWidgetItem("••••••••••••"))
            self.table.setCellWidget(r, 2, StrengthBar(data.get("strength", 0))); self.create_actions_cell(r)
        self.filter_table(self.search_input.text()); self.table.setSortingEnabled(True)
    def create_actions_cell(self, row: int):
        cw = QWidget(); ly = QHBoxLayout(cw); ly.setContentsMargins(0, 0, 15, 0); ly.setSpacing(10); ly.setAlignment(Qt.AlignmentFlag.AlignCenter)
        eb, tb, cb, db = IconButton("edit", "Edit"), IconButton("eye", "Show/Hide"), IconButton("copy", "Copy"), IconButton("trash", "Delete")
        ly.addWidget(eb); ly.addWidget(tb); ly.addWidget(cb); ly.addWidget(db); eb.clicked.connect(lambda _, r=row: self.start_editing(r))
        tb.clicked.connect(lambda _, r=row: self.toggle_password_visibility(r)); cb.clicked.connect(lambda _, r=row: self.copy_to_clipboard(r)); db.clicked.connect(lambda _, r=row: self.delete_entry(r))
        self.table.setCellWidget(row, 3, cw)
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
        site_editor = QLineEdit(site_name); site_editor.setObjectName("inline-editor"); site_widget = QWidget(); site_layout = QHBoxLayout(site_widget); site_layout.setContentsMargins(0, 0, 0, 0); site_layout.addWidget(site_editor); site_layout.addStretch()
        pw_editor = QLineEdit(password); pw_editor.setObjectName("inline-editor"); pw_widget = QWidget(); pw_layout = QHBoxLayout(pw_widget); pw_layout.setContentsMargins(0, 0, 0, 0); pw_layout.setSpacing(5)
        gen_btn = IconButton("refresh", "Generate Password"); gen_btn.setFixedSize(35, 35); pw_layout.addWidget(pw_editor); pw_layout.addWidget(gen_btn); pw_layout.addStretch()
        gen_btn.clicked.connect(lambda: pw_editor.setText(generate_password(self.settings.get("password_generation_length", 20))))
        self.table.setCellWidget(row, 0, site_widget); self.table.setCellWidget(row, 1, pw_widget); self.table.setCellWidget(row, 2, QWidget()); site_editor.setFocus()
        cw = QWidget(); ly = QHBoxLayout(cw); ly.setContentsMargins(0, 0, 15, 0); ly.setSpacing(10); ly.setAlignment(Qt.AlignmentFlag.AlignCenter)
        save_btn, cancel_btn = IconButton("check", "Save"), IconButton("x", "Cancel"); ly.addWidget(save_btn); ly.addWidget(cancel_btn)
        save_btn.clicked.connect(self.save_editing); cancel_btn.clicked.connect(self.cancel_editing); self.table.setCellWidget(row, 3, cw)
    def add_new_entry(self):
        if self.editing_row != -1 or self.row_pending_deletion != -1: self.populate_table()
        self.table.insertRow(0); self._enter_edit_mode(0, is_new=True)
    def start_editing(self, row: int): self._enter_edit_mode(row, is_new=False)
    def save_editing(self):
        if self.editing_row == -1: return
        site_widget = self.table.cellWidget(self.editing_row, 0); pw_widget = self.table.cellWidget(self.editing_row, 1)
        if not isinstance(site_widget, QWidget) or not isinstance(pw_widget, QWidget): self.cancel_editing(); return
        site_editor = site_widget.findChild(QLineEdit); pw_editor = pw_widget.findChild(QLineEdit)
        if not site_editor or not pw_editor: self.cancel_editing(); return
        s_new, p_new = site_editor.text().strip(), pw_editor.text()
        if not s_new: self.parent_glyph.flash_feedback(QColor("#e74c3c")); self.parent_glyph.show_temp_message("Website name cannot be empty", 1500); return
        s_old = s_new if self.is_adding_new else self.editing_row_data["site"]
        if self.parent_glyph.update_entry(s_old, s_new, p_new): self.vault = self.parent_glyph.vault; self.populate_table()
    def cancel_editing(self):
        if self.editing_row != -1: self.populate_table()
    def filter_table(self, text: str):
        text_lower = text.lower()
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            is_match = text_lower in item.text().lower() if item else False
            self.table.setRowHidden(row, not is_match)
    def toggle_password_visibility(self, row: int):
        if self.editing_row != -1 or self.row_pending_deletion != -1: return
        pw_item, site_item = self.table.item(row, 1), self.table.item(row, 0)
        if not pw_item or not site_item: return
        is_hidden = pw_item.text() == "••••••••••••"; password = self.parent_glyph._get_decrypted_password(site_item.text())
        if password: pw_item.setText(password if is_hidden else "••••••••••••")
    def copy_to_clipboard(self, row: int):
        if self.editing_row != -1 or self.row_pending_deletion != -1: return
        site_item = self.table.item(row, 0)
        if not site_item: return
        password = self.parent_glyph._get_decrypted_password(site_item.text())
        if password: self.parent_glyph.copy_password_to_clipboard(password)
    def delete_entry(self, row: int):
        if self.row_pending_deletion != -1: self.populate_table()
        self.row_pending_deletion = row
        cw = QWidget(); ly = QHBoxLayout(cw); ly.setContentsMargins(0, 0, 15, 0); ly.setSpacing(10); ly.setAlignment(Qt.AlignmentFlag.AlignCenter)
        confirm_label = QLabel("Delete?"); confirm_label.setObjectName("ConfirmLabel")
        confirm_btn = IconButton("check", "Confirm"); cancel_btn = IconButton("x", "Cancel")
        ly.addWidget(confirm_label); ly.addStretch(); ly.addWidget(confirm_btn); ly.addWidget(cancel_btn)
        confirm_btn.clicked.connect(self._confirm_delete)
        cancel_btn.clicked.connect(self.populate_table)
        self.table.setCellWidget(row, 3, cw)
    def _confirm_delete(self):
        if self.row_pending_deletion == -1: return
        site_item = self.table.item(self.row_pending_deletion, 0)
        if site_item: self.parent_glyph.remove_entry(site_item.text())
        self.vault = self.parent_glyph.vault; self.populate_table()

class Glyph(QWidget):
    def _get_flash_color(self): return self._flash_color_val
    def _set_flash_color(self, color): self._flash_color_val = color; self.input.setStyleSheet(f"#MainInput {{ border-bottom-color: {color.name()}; }}")
    flash_color_property = Property(QColor, _get_flash_color, _set_flash_color)

    def __init__(self):
        super().__init__(); self.setWindowTitle("Glyph"); self.setWindowFlags(Qt.WindowType.Window | Qt.WindowType.FramelessWindowHint); self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.is_new_install = not MASTER_FILE.exists(); self._setup_ui(); self.settings = load_settings()
        self.vault = {}; self.salt: Optional[bytes] = None; self.encryption_key: Optional[bytes] = None; self.hmac_key: Optional[bytes] = None
        self.awaiting: Optional[tuple[str, str]] = None; self.dashboard: Optional[DashboardWindow] = None; self.default_placeholder = "Search or /cmd site"
        self.persistent_prompt: Optional[str] = None; self.in_master_stage = True
        self.default_master_placeholder = "Create a new master password…" if self.is_new_install else "Enter master password…"
        self.input.setPlaceholderText(self.default_master_placeholder)
        self._flash_color_val = QColor("#3a3a3a"); self.flash_animation = QPropertyAnimation(self, b"flash_color_property", self)
        self.flash_animation.setDuration(600); self.flash_animation.setEndValue(QColor("#3a3a3a"))
        self.last_copied_password: Optional[str] = None; self.auto_lock_timer = QTimer(self); self.auto_lock_timer.setSingleShot(True)
        self.auto_lock_timer.timeout.connect(self.lock_application); self.installEventFilter(self)
    def _setup_ui(self):
        confirm_height = 45 if self.is_new_install else 0; self.setFixedSize(450, 150 + confirm_height)
        self.container = QWidget(self); self.container.setObjectName("Container"); main_layout = QVBoxLayout(self.container); main_layout.setContentsMargins(0, 0, 0, 0); main_layout.setSpacing(0)
        title_layout = QHBoxLayout(); title_layout.setContentsMargins(30, 10, 15, 0); title_layout.setSpacing(0)
        title_label = QLabel("Glyph"); title_label.setObjectName("TitleLabel"); close_btn = QPushButton("×"); close_btn.setObjectName("CloseButton"); close_btn.clicked.connect(self.close)
        close_btn.setFocusPolicy(Qt.FocusPolicy.NoFocus); title_layout.addWidget(title_label); title_layout.addStretch(); title_layout.addWidget(close_btn); main_layout.addLayout(title_layout)
        input_layout = QVBoxLayout(); input_layout.setContentsMargins(30, 5, 30, 10 if self.is_new_install else 35)
        self.input = QLineEdit(); self.input.setObjectName("MainInput"); self.input.setEchoMode(QLineEdit.EchoMode.Password); self.input.setContextMenuPolicy(Qt.ContextMenuPolicy.NoContextMenu); self.input.returnPressed.connect(self.on_return_pressed)
        input_layout.addWidget(self.input)
        self.confirm_input = QLineEdit(); self.confirm_input.setObjectName("MainInput"); self.confirm_input.setEchoMode(QLineEdit.EchoMode.Password); self.confirm_input.setPlaceholderText("Confirm master password…")
        self.confirm_input.setVisible(self.is_new_install); input_layout.addWidget(self.confirm_input)
        main_layout.addLayout(input_layout); central_layout = QHBoxLayout(self); central_layout.addWidget(self.container)
    def eventFilter(self, watched, event):
        if not self.in_master_stage and event.type() in [QEvent.Type.KeyPress, QEvent.Type.MouseButtonPress]: self.reset_auto_lock_timer()
        return super().eventFilter(watched, event)
    def reset_auto_lock_timer(self):
        timeout_seconds = self.settings.get("auto_lock_timeout_seconds", 300)
        if timeout_seconds > 0 and not self.in_master_stage: self.auto_lock_timer.start(timeout_seconds * 1000)
    def lock_application(self):
        if self.in_master_stage: return
        self.in_master_stage = True; self.encryption_key, self.hmac_key, self.vault = None, None, {}
        self.awaiting, self.persistent_prompt = None, None; self.input.clear(); self.confirm_input.clear()
        self.input.setEchoMode(QLineEdit.EchoMode.Password); self.input.setPlaceholderText(self.default_master_placeholder)
        if self.dashboard and self.dashboard.isVisible(): self.dashboard.close(); self.dashboard = None
        self.auto_lock_timer.stop(); self.flash_feedback(QColor("#3498db")); self.show_temp_message("Session locked due to inactivity.", 2000)
    def copy_password_to_clipboard(self, password: str):
        if not password: return
        clipboard = QGuiApplication.clipboard(); clipboard.setText(password); self.last_copied_password = password
        clear_seconds = self.settings.get("clipboard_clear_seconds", 30)
        if clear_seconds > 0: QTimer.singleShot(clear_seconds * 1000, self.clear_clipboard_if_unchanged)
    def clear_clipboard_if_unchanged(self):
        clipboard = QGuiApplication.clipboard()
        if clipboard.text() == self.last_copied_password: clipboard.clear(); self.last_copied_password = None
    def open_dashboard(self):
        if self.vault is not None:
            if not self.dashboard or not self.dashboard.isVisible():
                self.dashboard = DashboardWindow(self.vault, self.settings, self); self.dashboard.settings_updated.connect(self.on_settings_updated)
            self.dashboard.show(); self.dashboard.activateWindow()
    def on_settings_updated(self, new_settings: dict):
        self.settings = new_settings; save_settings(self.settings); self.reset_auto_lock_timer(); self.show_temp_message("Settings saved", 1500)
    def flash_feedback(self, color):
        self.flash_animation.stop(); self.flash_animation.setStartValue(color); self._set_flash_color(color); self.flash_animation.start()
    def mousePressEvent(self, event): self.oldPos = event.globalPosition().toPoint()
    def mouseMoveEvent(self, event):
        delta = QPoint(event.globalPosition().toPoint() - self.oldPos); self.move(self.x() + delta.x(), self.y() + delta.y()); self.oldPos = event.globalPosition().toPoint()
    def on_return_pressed(self): (self.first_stage_unlock if self.in_master_stage else self.process_command)()
    def show_temp_message(self, message: str, duration_ms: int = 1500):
        self.input.clear(); self.input.setPlaceholderText(message); QTimer.singleShot(duration_ms, self._maybe_reset_placeholder)
    def _maybe_reset_placeholder(self):
        current = self.persistent_prompt or (self.default_master_placeholder if self.in_master_stage else self.default_placeholder)
        if self.input.placeholderText() != current: self.input.setPlaceholderText(current)
    def first_stage_unlock(self):
        pw = self.input.text();
        if not pw: return
        if self.is_new_install:
            if pw != self.confirm_input.text(): self.flash_feedback(QColor("#e74c3c")); self.show_temp_message("Passwords do not match"); return
            if len(pw) < 12: self.flash_feedback(QColor("#e74c3c")); self.show_temp_message("Password must be at least 12 characters"); return
            if not (re.search(r"[a-z]", pw) and re.search(r"[A-Z]", pw) and re.search(r"\d", pw) and re.search(r"[!@#$%^&*()]", pw)):
                self.flash_feedback(QColor("#e74c3c")); self.show_temp_message("Must include uppercase, lowercase, number, and symbol"); return
            self.salt = secrets.token_bytes(SALT_SIZE); save_master_salt(self.salt)
        else: self.salt = load_master_salt()
        if not self.salt:
            self.flash_feedback(QColor("#e74c3c")); self.show_temp_message("FATAL: Master salt file missing.", 3000); return
        derived = derive_keys(pw, self.salt)
        if not derived: self.flash_feedback(QColor("#e74c3c")); self.show_temp_message("Key derivation failed internally.", 3000); return
        self.encryption_key, self.hmac_key = derived
        if not verify_vault_integrity(self.hmac_key) or (loaded_vault := load_vault_with_integrity(self.encryption_key)) is None:
            self.flash_feedback(QColor("#e74c3c")); self.show_temp_message("Wrong password or corrupt vault", 2500)
            self.encryption_key, self.hmac_key = None, None; self.input.clear(); self.confirm_input.clear(); return
        self.vault = loaded_vault; self.flash_feedback(QColor("#2ecc71")); QTimer.singleShot(500, self._transition_to_main_ui)
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
        try:
            entry_key = AESGCM.generate_key(bit_length=256); key_wrap_nonce = secrets.token_bytes(12); pw_nonce = secrets.token_bytes(12)
            wrapped_key = AESGCM(self.encryption_key).encrypt(key_wrap_nonce, entry_key, None); enc_pw = AESGCM(entry_key).encrypt(pw_nonce, p_new.encode(), None)
            if s_old_lower in self.vault and s_old_lower != s_new_lower: del self.vault[s_old_lower]
            self.vault[s_new_lower] = {"name": s_new, "strength": calculate_strength(p_new), "key_wrap_nonce": urlsafe_b64encode(key_wrap_nonce).decode(), "pw_nonce": urlsafe_b64encode(pw_nonce).decode(), "wrapped_entry_key": urlsafe_b64encode(wrapped_key).decode(), "encrypted_password": urlsafe_b64encode(enc_pw).decode()}
            self.save_vault(); return True
        except Exception: return False
    def remove_entry(self, site_name: str):
        if self.vault is not None and site_name.lower() in self.vault: del self.vault[site_name.lower()]; self.save_vault()
    def process_command(self):
        text = self.input.text().strip(); self.input.clear()
        cmds = self.settings.get("commands", DEFAULT_SETTINGS["commands"])
        if self.awaiting:
            if not text: self.awaiting = None; self.persistent_prompt = None; self.flash_feedback(QColor("#3498db")); self.show_temp_message("Operation cancelled"); return
            mode, target = self.awaiting; self.awaiting = None; self.persistent_prompt = None
            if mode in ('new', 'pw'):
                if self.update_entry(target, target, text): self.copy_password_to_clipboard(text); self.flash_feedback(QColor("#2ecc71")); self.show_temp_message("Saved & copied")
            elif mode == 'n':
                old_pw = self._get_decrypted_password(target)
                if old_pw is not None and self.update_entry(target, text, old_pw): self.copy_from_command(text); self.flash_feedback(QColor("#2ecc71")); self.show_temp_message("Renamed & copied")
            return
        if not text: return
        text_lower = text.lower()
        if text_lower == cmds["dashboard"]: self.open_dashboard(); return
        if text_lower == cmds["settings"]:
            self.open_dashboard()
            if self.dashboard: self.dashboard.show_settings_view()
            return
        if text_lower == cmds["exit"]: self.close(); return
        if text.startswith("/"):
            try: cmd_text, site = text.split(" ", 1)
            except ValueError: cmd_text, site = text, None
            if not site: self.flash_feedback(QColor("#e74c3c")); self.show_temp_message("Error: Command requires a sitename"); return
            site_lower = site.lower()
            if cmd_text == cmds["generate"]:
                pw = generate_password(self.settings.get("password_generation_length", 20))
                if self.update_entry(site, site, pw): self.copy_password_to_clipboard(pw); self.flash_feedback(QColor("#2ecc71")); self.show_temp_message("Generated & copied")
            elif self.vault is None or site_lower not in self.vault: self.flash_feedback(QColor("#e74c3c")); self.show_temp_message(f"Error: '{site}' not found")
            elif cmd_text == cmds["update"]: self.awaiting = ("pw", site_lower); self.persistent_prompt = f"New password for {self.vault[site_lower].get('name', site)}:"; self._maybe_reset_placeholder()
            elif cmd_text == cmds["rename"]: self.awaiting = ("n", site_lower); self.persistent_prompt = f"New name for {self.vault[site_lower].get('name', site)}:"; self._maybe_reset_placeholder()
            elif cmd_text == cmds["remove"]: self.remove_entry(site); self.flash_feedback(QColor("#2ecc71")); self.show_temp_message(f"Removed '{site}'")
            else: self.flash_feedback(QColor("#e74c3c")); self.show_temp_message("Error: Unknown command")
            return
        if self.vault is not None and text_lower in self.vault: self.copy_from_command(text_lower)
        else: self.awaiting = ("new", text); self.persistent_prompt = f"Password for new site '{text}':"; self._maybe_reset_placeholder()

def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(load_stylesheet())
    window = Glyph()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()