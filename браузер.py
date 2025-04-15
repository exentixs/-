import os
import sys
import json
import sqlite3
from cryptography.fernet import Fernet
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLineEdit, QPushButton, QToolBar, QTabWidget, QLabel,
                             QListWidget, QFrame, QMessageBox, QInputDialog, QMenu,
                             QDialog, QFormLayout, QComboBox, QCheckBox, QSpinBox,
                             QListWidgetItem, QFileDialog, QAction)
from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEngineProfile, QWebEnginePage, QWebEngineSettings
from PyQt5.QtCore import QUrl, Qt, QSize, QPoint, QStandardPaths, QDir, QCoreApplication
from PyQt5.QtGui import QIcon, QPixmap, QFont, QColor
from PyQt5.QtWebEngineCore import QWebEngineUrlRequestInterceptor


class UrlInterceptor(QWebEngineUrlRequestInterceptor):
    def __init__(self, parent=None):
        super().__init__(parent)

    def interceptRequest(self, info):
        info.setHttpHeader(b"Accept", b"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
        info.setHttpHeader(b"Accept-Language", b"en-US,en;q=0.5")
        info.setHttpHeader(b"Accept-Encoding", b"gzip, deflate, br")


class SecureDatabase:
    def __init__(self):
        self.db_path = os.path.join(QStandardPaths.writableLocation(QStandardPaths.AppDataLocation), "browser_data.db")
        self.key = self._get_or_create_key()
        self.cipher = Fernet(self.key)
        self._init_db()

    def _get_or_create_key(self):
        key_file = os.path.join(QStandardPaths.writableLocation(QStandardPaths.AppDataLocation), "browser_key.key")
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            os.makedirs(os.path.dirname(key_file), exist_ok=True)
            with open(key_file, 'wb') as f:
                f.write(key)
            return key

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                encrypted_data BLOB NOT NULL
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                url TEXT NOT NULL,
                title TEXT NOT NULL,
                visit_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')

        conn.commit()
        conn.close()

    def encrypt_data(self, data):
        return self.cipher.encrypt(json.dumps(data).encode())

    def decrypt_data(self, encrypted_data):
        return json.loads(self.cipher.decrypt(encrypted_data).decode())

    def add_user(self, name, profile_data):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        encrypted_data = self.encrypt_data(json.dumps(profile_data))
        cursor.execute('INSERT INTO users (name, encrypted_data) VALUES (?, ?)', (name, encrypted_data))
        conn.commit()
        conn.close()

    def get_user(self, name):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT encrypted_data FROM users WHERE name = ?', (name,))
        result = cursor.fetchone()
        conn.close()
        if result:
            return json.loads(self.decrypt_data(result[0]))
        return None

    def add_history_item(self, user_id, url, title):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('INSERT INTO history (user_id, url, title) VALUES (?, ?, ?)', (user_id, url, title))
        conn.commit()
        conn.close()

    def get_user_history(self, user_id, limit=100):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT url, title, visit_time FROM history WHERE user_id = ? ORDER BY visit_time DESC LIMIT ?',
                       (user_id, limit))
        results = cursor.fetchall()
        conn.close()
        return results


class BrowserTab(QWebEngineView):
    def __init__(self, profile, parent=None):
        super().__init__(parent)
        self.profile = profile
        self.browser_window = parent
        self.interceptor = UrlInterceptor()
        self.page().profile().setUrlRequestInterceptor(self.interceptor)
        self.apply_settings()
        self.page().profile().setHttpCacheType(QWebEngineProfile.DiskHttpCache)
        self.page().profile().setPersistentCookiesPolicy(QWebEngineProfile.ForcePersistentCookies)
        self.page().urlChanged.connect(self.handle_url_changed)

    def apply_settings(self):
        settings = self.page().settings()
        profile_settings = self.profile.settings
        settings.setAttribute(QWebEngineSettings.JavascriptEnabled, profile_settings.get("enable_javascript", True))
        settings.setAttribute(QWebEngineSettings.PluginsEnabled, profile_settings.get("enable_plugins", True))
        settings.setAttribute(QWebEngineSettings.LocalStorageEnabled, profile_settings.get("enable_cookies", True))
        settings.setAttribute(QWebEngineSettings.DnsPrefetchEnabled, True)
        settings.setAttribute(QWebEngineSettings.FullScreenSupportEnabled, True)
        settings.setAttribute(QWebEngineSettings.PlaybackRequiresUserGesture, False)
        settings.setAttribute(QWebEngineSettings.WebGLEnabled, True)
        settings.setAttribute(QWebEngineSettings.Accelerated2dCanvasEnabled, True)
        settings.setAttribute(QWebEngineSettings.AutoLoadIconsForPage, True)
        settings.setAttribute(QWebEngineSettings.ScreenCaptureEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebRTCPublicInterfacesOnly, False)
        settings.setAttribute(QWebEngineSettings.AutoLoadImages, profile_settings.get("enable_media", True))

    def handle_url_changed(self, url):
        if self.browser_window and url.isValid():
            self.browser_window.update_urlbar(url, self)

    def createWindow(self, window_type):
        if window_type == QWebEnginePage.WebBrowserTab and self.browser_window:
            return self.browser_window.add_new_tab(QUrl(self.profile.get_homepage()))
        return super().createWindow(window_type)


class UserProfile:
    def __init__(self, name, db):
        self.name = name
        self.db = db
        self.settings = self._load_settings()

    def _load_settings(self):
        profile_data = self.db.get_user(self.name)
        if profile_data:
            return profile_data

        default_settings = {
            "search_engine": "https://ya.ru/search/?text={query}",
            "home_page": "https://ya.ru",
            "default_zoom": 100,
            "enable_javascript": True,
            "enable_plugins": True,
            "enable_cookies": True,
            "do_not_track": False,
            "password_protection": False,
            "extensions": [],
            "open_links_in_new_tab": True,
            "theme": "light",
            "font_size": 16,
            "enable_media": True,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }

        self.db.add_user(self.name, default_settings)
        return default_settings

    def get_homepage(self):
        return self.settings.get("home_page")

    def get_search_engine(self):
        return self.settings.get("search_engine")

    def save_settings(self):
        self.db.add_user(self.name, self.settings)


class BrowserWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure MultiUser Browser")
        self.setMinimumSize(1024, 768)
        self.db = SecureDatabase()
        self.current_profile = None
        self.profiles = []
        self.load_profiles()
        self.init_ui()

        if not self.profiles:
            self.create_default_profile()
        else:
            try:
                self.switch_profile(self.profiles[0])
            except Exception as e:
                print(f"Ошибка при загрузке профиля: {e}")
                self.create_default_profile()

    def create_default_profile(self):
        default_profile = UserProfile("Default", self.db)
        self.profiles.append(default_profile)
        self.update_profile_list()
        self.switch_profile(default_profile)

    def load_profiles(self):
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT name FROM users')
        results = cursor.fetchall()
        conn.close()

        for (name,) in results:
            try:
                self.profiles.append(UserProfile(name, self.db))
            except Exception as e:
                print(f"Ошибка загрузки профиля {name}: {e}")

    def init_ui(self):
        main_widget = QWidget()
        main_layout = QHBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)

        # Sidebar
        sidebar = QFrame()
        sidebar.setFrameShape(QFrame.StyledPanel)
        sidebar.setFixedWidth(200)
        sidebar.setStyleSheet("background-color: #f5f5f5;")
        sidebar_layout = QVBoxLayout()
        sidebar_layout.setContentsMargins(5, 5, 5, 5)

        self.profile_list = QListWidget()
        self.profile_list.setStyleSheet("""
            QListWidget { border: 1px solid #ddd; border-radius: 4px; padding: 2px; }
            QListWidget::item { padding: 5px; }
            QListWidget::item:hover { background-color: #e0e0e0; }
            QListWidget::item:selected { background-color: #4285f4; color: white; }
        """)
        self.profile_list.itemClicked.connect(self.on_profile_selected)
        self.update_profile_list()

        new_profile_btn = QPushButton("+ Новый профиль")
        new_profile_btn.setStyleSheet("""
            QPushButton { background-color: #4285f4; color: white; border: none; padding: 8px; border-radius: 4px; }
            QPushButton:hover { background-color: #3367d6; }
        """)
        new_profile_btn.clicked.connect(self.create_new_profile)

        sidebar_layout.addWidget(QLabel("Профили:"))
        sidebar_layout.addWidget(self.profile_list)
        sidebar_layout.addWidget(new_profile_btn)
        sidebar_layout.addStretch()
        sidebar.setLayout(sidebar_layout)

        # Main area
        main_area = QWidget()
        main_area_layout = QVBoxLayout()
        main_area_layout.setContentsMargins(0, 0, 0, 0)
        main_area_layout.setSpacing(0)

        # Toolbar
        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setStyleSheet("QToolBar { background-color: #f5f5f5; border: none; padding: 2px; }")

        # Navigation buttons
        back_btn = QPushButton()
        back_btn.setIcon(QIcon.fromTheme("go-previous"))
        back_btn.setStyleSheet("QPushButton { border: none; padding: 5px; }")
        back_btn.clicked.connect(self.navigate_back)
        toolbar.addWidget(back_btn)

        forward_btn = QPushButton()
        forward_btn.setIcon(QIcon.fromTheme("go-next"))
        forward_btn.setStyleSheet("QPushButton { border: none; padding: 5px; }")
        forward_btn.clicked.connect(self.navigate_forward)
        toolbar.addWidget(forward_btn)

        refresh_btn = QPushButton()
        refresh_btn.setIcon(QIcon.fromTheme("view-refresh"))
        refresh_btn.setStyleSheet("QPushButton { border: none; padding: 5px; }")
        refresh_btn.clicked.connect(self.refresh_page)
        toolbar.addWidget(refresh_btn)

        home_btn = QPushButton()
        home_btn.setIcon(QIcon.fromTheme("go-home"))
        home_btn.setStyleSheet("QPushButton { border: none; padding: 5px; }")
        home_btn.clicked.connect(self.navigate_home)
        toolbar.addWidget(home_btn)

        new_tab_btn = QPushButton()
        new_tab_btn.setIcon(QIcon.fromTheme("tab-new"))
        new_tab_btn.setStyleSheet("QPushButton { border: none; padding: 5px; }")
        new_tab_btn.clicked.connect(lambda: self.add_new_tab(QUrl(self.current_profile.get_homepage())))
        toolbar.addWidget(new_tab_btn)

        self.url_bar = QLineEdit()
        self.url_bar.setStyleSheet("""
            QLineEdit {
                border: 1px solid #ddd;
                border-radius: 15px;
                padding: 5px 15px;
                background: white;
                selection-background-color: #b5d5ff;
            }
            QLineEdit:focus {
                border: 1px solid #4285f4;
            }
        """)
        self.url_bar.setPlaceholderText("Поиск или введите адрес")
        self.url_bar.returnPressed.connect(self.navigate_to_url)
        toolbar.addWidget(self.url_bar)

        settings_btn = QPushButton()
        settings_btn.setIcon(QIcon.fromTheme("preferences-system"))
        settings_btn.setStyleSheet("QPushButton { border: none; padding: 5px; }")
        settings_btn.clicked.connect(self.show_settings)
        toolbar.addWidget(settings_btn)

        history_btn = QPushButton()
        history_btn.setIcon(QIcon.fromTheme("view-history"))
        history_btn.setStyleSheet("QPushButton { border: none; padding: 5px; }")
        history_btn.clicked.connect(self.show_history)
        toolbar.addWidget(history_btn)

        self.profile_btn = QPushButton()
        self.profile_btn.setIcon(QIcon("default_avatar.png"))
        self.profile_btn.setIconSize(QSize(24, 24))
        self.profile_btn.setStyleSheet("""
            QPushButton { border: none; border-radius: 12px; padding: 2px; }
            QPushButton:hover { background-color: #e0e0e0; }
        """)
        self.profile_btn.clicked.connect(self.show_profile_menu)
        toolbar.addWidget(self.profile_btn)

        # Tab widget
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane { border: none; }
            QTabBar::tab {
                background: #f5f5f5;
                border: 1px solid #ddd;
                border-bottom: none;
                padding: 8px;
                min-width: 100px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected { background: white; border-bottom: 2px solid #4285f4; }
            QTabBar::tab:hover { background: #e0e0e0; }
        """)
        self.tabs.setTabsClosable(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.tabs.currentChanged.connect(self.tab_changed)
        self.tabs.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tabs.customContextMenuRequested.connect(self.show_tab_context_menu)

        main_area_layout.addWidget(toolbar)
        main_area_layout.addWidget(self.tabs)
        main_area.setLayout(main_area_layout)

        main_layout.addWidget(sidebar)
        main_layout.addWidget(main_area)

    def update_profile_list(self):
        self.profile_list.clear()
        for profile in self.profiles:
            self.profile_list.addItem(profile.name)

    def create_new_profile(self):
        name, ok = QInputDialog.getText(self, "Новый профиль", "Введите имя профиля:")
        if ok and name:
            try:
                new_profile = UserProfile(name, self.db)
                self.profiles.append(new_profile)
                self.update_profile_list()
                self.switch_profile(new_profile)
            except Exception as e:
                QMessageBox.warning(self, "Ошибка", f"Не удалось создать профиль: {e}")

    def switch_profile(self, profile):
        self.current_profile = profile
        self.profile_btn.setText(profile.name)
        self.tabs.clear()
        self.add_new_tab(QUrl(profile.get_homepage()), "Домашняя страница")

    def add_new_tab(self, url, label="Новая вкладка"):
        browser = BrowserTab(self.current_profile, self)
        browser.setUrl(url)
        tab_index = self.tabs.addTab(browser, label)
        self.tabs.setCurrentIndex(tab_index)

        def update_url(qurl):
            self.update_urlbar(qurl, browser)

        def update_title():
            title = browser.page().title()
            short_title = (title[:15] + '...') if len(title) > 15 else title
            self.tabs.setTabText(tab_index, short_title)

            if self.current_profile:
                conn = sqlite3.connect(self.db.db_path)
                cursor = conn.cursor()
                cursor.execute('SELECT id FROM users WHERE name = ?', (self.current_profile.name,))
                user_id = cursor.fetchone()[0]
                conn.close()
                self.db.add_history_item(user_id, browser.url().toString(), title)

        browser.urlChanged.connect(update_url)
        browser.loadFinished.connect(update_title)

        return browser

    def show_tab_context_menu(self, position):
        menu = QMenu()
        new_tab_action = QAction("Новая вкладка", self)
        new_tab_action.triggered.connect(lambda: self.add_new_tab(QUrl(self.current_profile.get_homepage())))
        menu.addAction(new_tab_action)

        reload_action = QAction("Обновить", self)
        reload_action.triggered.connect(self.refresh_page)
        menu.addAction(reload_action)

        menu.exec_(self.tabs.mapToGlobal(position))

    def on_profile_selected(self, item):
        profile_name = item.text()
        for profile in self.profiles:
            if profile.name == profile_name:
                self.switch_profile(profile)
                break

    def show_profile_menu(self):
        menu = QMenu(self)
        menu.setStyleSheet("""
            QMenu { background-color: white; border: 1px solid #ddd; padding: 5px; }
            QMenu::item { padding: 5px 20px; }
            QMenu::item:selected { background-color: #e0e0e0; }
        """)

        for profile in self.profiles:
            action = menu.addAction(profile.name)
            action.triggered.connect(lambda _, p=profile: self.switch_profile(p))

        menu.addSeparator()
        menu.addAction("Управление профилями", self.manage_profiles)
        menu.exec_(self.profile_btn.mapToGlobal(QPoint(0, self.profile_btn.height())))

    def show_settings(self):
        if not self.current_profile:
            return

        dialog = SettingsDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            for i in range(self.tabs.count()):
                browser = self.tabs.widget(i)
                if isinstance(browser, BrowserTab):
                    browser.apply_settings()
            self.current_profile.save_settings()

    def show_history(self):
        if not self.current_profile:
            return

        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE name = ?', (self.current_profile.name,))
        user_id = cursor.fetchone()[0]
        history = self.db.get_user_history(user_id)
        conn.close()

        dialog = QDialog(self)
        dialog.setWindowTitle("История просмотров")
        dialog.setFixedSize(600, 400)

        layout = QVBoxLayout()
        history_list = QListWidget()

        for url, title, visit_time in history:
            item = QListWidgetItem(f"{title}\n{url}\n{visit_time}")
            history_list.addItem(item)

        history_list.itemDoubleClicked.connect(lambda item: self.navigate_to_history_item(item))
        layout.addWidget(history_list)
        dialog.setLayout(layout)
        dialog.exec_()

    def navigate_to_history_item(self, item):
        url = item.text().split('\n')[1]
        if self.current_profile.settings.get("open_links_in_new_tab", True):
            self.add_new_tab(QUrl(url))
        else:
            current_browser = self.tabs.currentWidget()
            if current_browser:
                current_browser.setUrl(QUrl(url))

    def manage_profiles(self):
        QMessageBox.information(self, "Управление профилями", "Здесь будет управление профилями")

    def navigate_back(self):
        current_browser = self.tabs.currentWidget()
        if current_browser:
            current_browser.back()

    def navigate_forward(self):
        current_browser = self.tabs.currentWidget()
        if current_browser:
            current_browser.forward()

    def refresh_page(self):
        current_browser = self.tabs.currentWidget()
        if current_browser:
            current_browser.reload()

    def navigate_home(self):
        if self.current_profile:
            current_browser = self.tabs.currentWidget()
            if current_browser:
                current_browser.setUrl(QUrl(self.current_profile.get_homepage()))

    def navigate_to_url(self):
        url = self.url_bar.text()
        if not url.startswith(('http://', 'https://')):
            if '.' in url:
                url = 'http://' + url
            else:
                search_engine = self.current_profile.get_search_engine()
                url = search_engine.replace("{query}", url)

        current_browser = self.tabs.currentWidget()
        if current_browser:
            current_browser.setUrl(QUrl(url))
        else:
            self.add_new_tab(QUrl(url))

    def update_urlbar(self, q, browser=None):
        if browser != self.tabs.currentWidget():
            return
        self.url_bar.setText(q.toString())
        self.url_bar.setCursorPosition(0)

    def close_tab(self, index):
        if self.tabs.count() < 2:
            return
        self.tabs.removeTab(index)

    def tab_changed(self, index):
        if index >= 0:
            browser = self.tabs.widget(index)
            if browser:
                self.update_urlbar(browser.url(), browser)


class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Настройки браузера")
        self.setFixedSize(600, 400)
        self.settings = parent.current_profile.settings if parent and hasattr(parent, 'current_profile') else {}
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        tabs = QTabWidget()

        # General tab
        general_tab = QWidget()
        general_layout = QFormLayout()

        self.search_engine_combo = QComboBox()
        engines = [
            ("Яндекс", "https://ya.ru/search/?text={query}"),
            ("Google", "https://www.google.com/search?q={query}"),
            ("DuckDuckGo", "https://duckduckgo.com/?q={query}"),
            ("Bing", "https://www.bing.com/search?q={query}")
        ]
        for name, url in engines:
            self.search_engine_combo.addItem(name, url)

        current_engine = self.settings.get("search_engine", "https://ya.ru/search/?text={query}")
        index = self.search_engine_combo.findData(current_engine)
        self.search_engine_combo.setCurrentIndex(index if index >= 0 else 0)
        general_layout.addRow("Поисковая система:", self.search_engine_combo)

        self.home_page_edit = QLineEdit(self.settings.get("home_page", "https://ya.ru"))
        general_layout.addRow("Домашняя страница:", self.home_page_edit)

        self.zoom_spin = QSpinBox()
        self.zoom_spin.setRange(50, 200)
        self.zoom_spin.setValue(self.settings.get("default_zoom", 100))
        general_layout.addRow("Масштаб по умолчанию (%):", self.zoom_spin)

        self.new_tab_check = QCheckBox("Открывать ссылки в новой вкладке")
        self.new_tab_check.setChecked(self.settings.get("open_links_in_new_tab", True))
        general_layout.addRow(self.new_tab_check)

        general_tab.setLayout(general_layout)

        # Security tab
        security_tab = QWidget()
        security_layout = QFormLayout()

        self.js_check = QCheckBox("Включить JavaScript")
        self.js_check.setChecked(self.settings.get("enable_javascript", True))
        security_layout.addRow(self.js_check)

        self.plugins_check = QCheckBox("Включить плагины")
        self.plugins_check.setChecked(self.settings.get("enable_plugins", True))
        security_layout.addRow(self.plugins_check)

        self.cookies_check = QCheckBox("Разрешить cookies")
        self.cookies_check.setChecked(self.settings.get("enable_cookies", True))
        security_layout.addRow(self.cookies_check)

        self.media_check = QCheckBox("Включить медиа (аудио/видео)")
        self.media_check.setChecked(self.settings.get("enable_media", True))
        security_layout.addRow(self.media_check)

        self.dnt_check = QCheckBox("Не отслеживать (DNT)")
        self.dnt_check.setChecked(self.settings.get("do_not_track", False))
        security_layout.addRow(self.dnt_check)

        security_tab.setLayout(security_layout)

        tabs.addTab(general_tab, "Основные")
        tabs.addTab(security_tab, "Безопасность")

        button_box = QHBoxLayout()
        save_btn = QPushButton("Сохранить")
        save_btn.clicked.connect(self.save_settings)
        cancel_btn = QPushButton("Отмена")
        cancel_btn.clicked.connect(self.reject)

        button_box.addStretch()
        button_box.addWidget(save_btn)
        button_box.addWidget(cancel_btn)

        layout.addWidget(tabs)
        layout.addLayout(button_box)
        self.setLayout(layout)

    def save_settings(self):
        self.settings["search_engine"] = self.search_engine_combo.currentData()
        self.settings["home_page"] = self.home_page_edit.text()
        self.settings["default_zoom"] = self.zoom_spin.value()
        self.settings["enable_javascript"] = self.js_check.isChecked()
        self.settings["enable_plugins"] = self.plugins_check.isChecked()
        self.settings["enable_cookies"] = self.cookies_check.isChecked()
        self.settings["enable_media"] = self.media_check.isChecked()
        self.settings["do_not_track"] = self.dnt_check.isChecked()
        self.settings["open_links_in_new_tab"] = self.new_tab_check.isChecked()
        self.accept()


def main():
    QCoreApplication.setAttribute(Qt.AA_ShareOpenGLContexts)
    os.environ["QT_API"] = "pyqt5"  # Для предотвращения предупреждения QSocketNotifier

    if sys.platform == 'linux':
        os.environ['QTWEBENGINE_CHROMIUM_FLAGS'] = '--no-sandbox --enable-features=WebRTCPipeWireCapturer'

    app = QApplication(sys.argv)
    app.setApplicationName("Secure MultiUser Browser")
    app.setStyle('Fusion')

    try:
        from PyQt5.QtWebEngineWidgets import QWebEngineView
    except ImportError:
        print("Требуется установить PyQtWebEngine: sudo dnf install python3-qt5-webengine")
        sys.exit(1)

    browser = BrowserWindow()
    browser.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()