import os
import sys
import json
import sqlite3
import webbrowser
from datetime import datetime
from cryptography.fernet import Fernet
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLineEdit, QPushButton, QToolBar, QTabWidget, QLabel,
                             QListWidget, QFrame, QMessageBox, QInputDialog, QMenu,
                             QDialog, QFormLayout, QComboBox, QCheckBox, QSpinBox,
                             QListWidgetItem, QFileDialog, QAction, QGraphicsDropShadowEffect,
                             QGroupBox, QScrollArea, QButtonGroup, QRadioButton, QSlider,
                             QStackedWidget, QTableWidget, QTableWidgetItem, QHeaderView)
from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEngineProfile, QWebEnginePage, QWebEngineSettings
from PyQt5.QtCore import QUrl, Qt, QSize, QPoint, QStandardPaths, QDir, QCoreApplication, QSettings, QTimer
from PyQt5.QtGui import QIcon, QPixmap, QFont, QColor, QPalette, QKeySequence, QPainter, QLinearGradient
from PyQt5.QtWebEngineCore import QWebEngineUrlRequestInterceptor, QWebEngineUrlRequestInfo


# Установка атрибутов Qt ДО создания QApplication
QCoreApplication.setAttribute(Qt.AA_EnableHighDpiScaling)
QCoreApplication.setAttribute(Qt.AA_UseHighDpiPixmaps)
QCoreApplication.setAttribute(Qt.AA_ShareOpenGLContexts)


class PrivacyRequestInterceptor(QWebEngineUrlRequestInterceptor):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.block_trackers = True
        self.force_https = True
        self.phishing_protection = True
        self.cookie_policy = 1  # 0 - все, 1 - только посещаемые, 2 - none
        self.visited_domains = set()
        self.block_ads = True
        self.ad_block_list = self.load_ad_block_list()

    def load_ad_block_list(self):
        try:
            with open('ad_block_list.txt', 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except:
            return [
                "doubleclick.net", "adservice.google.com", "googleads.g.doubleclick.net",
                "pagead2.googlesyndication.com", "ad.doubleclick.net", "ads.pubmatic.com",
                "ads.youtube.com", "securepubads.g.doubleclick.net", "adform.net"
            ]

    def interceptRequest(self, info):
        url = info.requestUrl().toString()
        domain = QUrl(url).host()

        # Блокировка рекламы
        if self.block_ads and any(ad_domain in domain for ad_domain in self.ad_block_list):
            info.block(True)
            return

        # Блокировка трекеров
        if self.block_trackers and any(
                tracker in url for tracker in ["google-analytics.com", "facebook.com/tr", "doubleclick.net"]):
            info.block(True)
            return

        # Принудительное HTTPS
        if self.force_https and url.startswith("http://"):
            secure_url = url.replace("http://", "https://")
            info.redirect(QUrl(secure_url))

        # Защита от фишинга
        if self.phishing_protection and self.is_phishing(url):
            info.block(True)
            return

        # Управление cookie
        if self.cookie_policy == 2:  # Блокировать все
            info.setHttpHeader(b"Cookie", b"")
        elif self.cookie_policy == 1:  # Только посещаемые
            if domain not in self.visited_domains:
                info.setHttpHeader(b"Cookie", b"")
            else:
                self.visited_domains.add(domain)

    def is_phishing(self, url):
        return False


class PrivateProfile(QWebEngineProfile):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setPersistentCookiesPolicy(QWebEngineProfile.NoPersistentCookies)
        self.setCachePath("")
        self.setPersistentStoragePath("")


class BrowserDatabase:
    def __init__(self):
        data_dir = QStandardPaths.writableLocation(QStandardPaths.AppDataLocation)

        if not os.path.exists(data_dir):
            try:
                os.makedirs(data_dir, mode=0o755, exist_ok=True)
            except Exception as e:
                print(f"Error creating data directory: {e}")
                data_dir = os.path.expanduser("~")

        self.db_path = os.path.join(data_dir, "browser_data.db")
        print(f"Database path: {self.db_path}")

        try:
            self._init_db()
        except sqlite3.Error as e:
            print(f"Database initialization error: {e}")
            raise

    def _init_db(self):
        try:
            if not os.path.exists(self.db_path):
                open(self.db_path, 'w').close()
                os.chmod(self.db_path, 0o644)

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("PRAGMA table_info(users)")
            columns = cursor.fetchall()
            column_names = [col[1] for col in columns]

            if not columns:
                cursor.execute('''
                    CREATE TABLE users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT UNIQUE NOT NULL,
                        password TEXT,
                        settings TEXT NOT NULL
                    )
                ''')
            elif 'password' not in column_names:
                cursor.execute('ALTER TABLE users ADD COLUMN password TEXT')

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

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS bookmarks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    url TEXT NOT NULL,
                    title TEXT NOT NULL,
                    folder TEXT DEFAULT 'Other',
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS downloads (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    url TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    finish_time TIMESTAMP,
                    status TEXT DEFAULT 'in_progress',
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS extensions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    enabled BOOLEAN DEFAULT 1,
                    path TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    site TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
            ''')

            cursor.execute('SELECT COUNT(*) FROM users')
            if cursor.fetchone()[0] == 0:
                cursor.execute('INSERT INTO users (name, password, settings) VALUES (?, ?, ?)',
                               ('Default', None, json.dumps({})))
                conn.commit()

            conn.commit()
            conn.close()

        except sqlite3.Error as e:
            print(f"Database error: {e}")
            raise
        except Exception as e:
            print(f"General error: {e}")
            raise

    def get_users(self):
        """Получить список всех пользователей"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT id, name, password FROM users')
            results = cursor.fetchall()
            conn.close()
            return results
        except sqlite3.Error as e:
            print(f"Error getting users: {e}")
            return []

    def add_history_item(self, user_id, url, title):
        if user_id == -1:  # Не сохранять для приватного режима
            return

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('INSERT INTO history (user_id, url, title) VALUES (?, ?, ?)',
                           (user_id, url, title))
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            print(f"Error adding history item: {e}")

    def get_history(self, user_id, limit=100):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT url, title, visit_time FROM history 
                WHERE user_id = ? 
                ORDER BY visit_time DESC 
                LIMIT ?''',
                           (user_id, limit))
            results = cursor.fetchall()
            conn.close()
            return results
        except sqlite3.Error as e:
            print(f"Error getting history: {e}")
            return []

    def clear_history(self, user_id):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM history WHERE user_id = ?', (user_id,))
            conn.commit()
            conn.close()
            return True
        except sqlite3.Error as e:
            print(f"Error clearing history: {e}")
            return False

    def add_user(self, name, password=None):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (name, password, settings) VALUES (?, ?, ?)',
                           (name, password, json.dumps({})))
            conn.commit()
            user_id = cursor.lastrowid
            conn.close()
            return user_id
        except sqlite3.Error as e:
            print(f"Error adding user: {e}")
            return None

    def delete_user(self, user_id):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
            conn.commit()
            conn.close()
            return True
        except sqlite3.Error as e:
            print(f"Error deleting user: {e}")
            return False

    def check_password(self, user_id, password):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT password FROM users WHERE id = ?', (user_id,))
            result = cursor.fetchone()
            conn.close()

            if result:
                stored_password = result[0]
                return stored_password is None or stored_password == password
            return False
        except sqlite3.Error as e:
            print(f"Error checking password: {e}")
            return False

    def get_downloads(self, user_id):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT url, file_path, start_time, finish_time, status 
                FROM downloads 
                WHERE user_id = ?
                ORDER BY start_time DESC
            ''', (user_id,))
            results = cursor.fetchall()
            conn.close()
            return results
        except sqlite3.Error as e:
            print(f"Error getting downloads: {e}")
            return []

    def add_download(self, user_id, url, file_path):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO downloads (user_id, url, file_path) 
                VALUES (?, ?, ?)
            ''', (user_id, url, file_path))
            conn.commit()
            conn.close()
            return True
        except sqlite3.Error as e:
            print(f"Error adding download: {e}")
            return False

    def update_download(self, download_id, status, finish_time=None):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            if finish_time:
                cursor.execute('''
                    UPDATE downloads 
                    SET status = ?, finish_time = ? 
                    WHERE id = ?
                ''', (status, finish_time, download_id))
            else:
                cursor.execute('''
                    UPDATE downloads 
                    SET status = ? 
                    WHERE id = ?
                ''', (status, download_id))
            conn.commit()
            conn.close()
            return True
        except sqlite3.Error as e:
            print(f"Error updating download: {e}")
            return False

    def get_extensions(self, user_id):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, name, version, enabled FROM extensions 
                WHERE user_id = ?
            ''', (user_id,))
            results = cursor.fetchall()
            conn.close()
            return results
        except sqlite3.Error as e:
            print(f"Error getting extensions: {e}")
            return []

    def add_extension(self, user_id, name, version, path):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO extensions (user_id, name, version, path) 
                VALUES (?, ?, ?, ?)
            ''', (user_id, name, version, path))
            conn.commit()
            conn.close()
            return True
        except sqlite3.Error as e:
            print(f"Error adding extension: {e}")
            return False

    def toggle_extension(self, extension_id, enabled):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE extensions 
                SET enabled = ? 
                WHERE id = ?
            ''', (enabled, extension_id))
            conn.commit()
            conn.close()
            return True
        except sqlite3.Error as e:
            print(f"Error toggling extension: {e}")
            return False

    def remove_extension(self, extension_id):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM extensions WHERE id = ?', (extension_id,))
            conn.commit()
            conn.close()
            return True
        except sqlite3.Error as e:
            print(f"Error removing extension: {e}")
            return False

    def add_password(self, user_id, site, username, password):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO passwords (user_id, site, username, password) 
                VALUES (?, ?, ?, ?)
            ''', (user_id, site, username, password))
            conn.commit()
            conn.close()
            return True
        except sqlite3.Error as e:
            print(f"Error adding password: {e}")
            return False

    def get_passwords(self, user_id):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, site, username, password FROM passwords 
                WHERE user_id = ?
            ''', (user_id,))
            results = cursor.fetchall()
            conn.close()
            return results
        except sqlite3.Error as e:
            print(f"Error getting passwords: {e}")
            return []

    def remove_password(self, password_id):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM passwords WHERE id = ?', (password_id,))
            conn.commit()
            conn.close()
            return True
        except sqlite3.Error as e:
            print(f"Error removing password: {e}")
            return False


class BrowserTab(QWebEngineView):
    def __init__(self, profile, is_private=False, parent=None):
        super().__init__(parent)
        self.profile = profile
        self.is_private = is_private
        self.browser = parent
        self.apply_settings()

        # Настройки для улучшения производительности видео
        self.page().profile().setHttpCacheType(QWebEngineProfile.MemoryHttpCache)
        self.page().profile().setPersistentCookiesPolicy(
            QWebEngineProfile.NoPersistentCookies if is_private
            else QWebEngineProfile.AllowPersistentCookies
        )

        # Включение аппаратного ускорения и поддержки всех форматов видео
        settings = self.page().settings()
        settings.setAttribute(QWebEngineSettings.Accelerated2dCanvasEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebGLEnabled, True)
        settings.setAttribute(QWebEngineSettings.PlaybackRequiresUserGesture, False)
        settings.setAttribute(QWebEngineSettings.AllowRunningInsecureContent, True)
        settings.setAttribute(QWebEngineSettings.LocalContentCanAccessRemoteUrls, True)
        settings.setAttribute(QWebEngineSettings.ScreenCaptureEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebRTCPublicInterfacesOnly, False)
        settings.setAttribute(QWebEngineSettings.AllowGeolocationOnInsecureOrigins, True)
        settings.setAttribute(QWebEngineSettings.AllowWindowActivationFromJavaScript, True)
        settings.setAttribute(QWebEngineSettings.FullScreenSupportEnabled, True)
        settings.setAttribute(QWebEngineSettings.JavascriptCanOpenWindows, True)
        settings.setAttribute(QWebEngineSettings.JavascriptCanAccessClipboard, True)
        settings.setAttribute(QWebEngineSettings.LocalStorageEnabled, True)
        settings.setAttribute(QWebEngineSettings.JavascriptEnabled, True)
        settings.setAttribute(QWebEngineSettings.PluginsEnabled, True)
        settings.setAttribute(QWebEngineSettings.AutoLoadImages, True)
        settings.setAttribute(QWebEngineSettings.ErrorPageEnabled, True)
        settings.setAttribute(QWebEngineSettings.HyperlinkAuditingEnabled, False)

        self.page().urlChanged.connect(self.on_url_changed)
        self.page().loadFinished.connect(self.on_load_finished)

    def apply_settings(self):
        settings = self.page().settings()
        settings.setAttribute(QWebEngineSettings.JavascriptEnabled, True)
        settings.setAttribute(QWebEngineSettings.LocalStorageEnabled, not self.is_private)
        settings.setAttribute(QWebEngineSettings.WebRTCPublicInterfacesOnly, True)
        settings.setAttribute(QWebEngineSettings.Accelerated2dCanvasEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebGLEnabled, True)
        settings.setAttribute(QWebEngineSettings.AllowRunningInsecureContent, False)
        settings.setAttribute(QWebEngineSettings.FullScreenSupportEnabled, True)
        settings.setAttribute(QWebEngineSettings.ScreenCaptureEnabled, True)
        settings.setAttribute(QWebEngineSettings.PlaybackRequiresUserGesture, False)
        settings.setAttribute(QWebEngineSettings.AllowGeolocationOnInsecureOrigins, True)
        settings.setAttribute(QWebEngineSettings.AllowWindowActivationFromJavaScript, True)

    def on_url_changed(self, url):
        if self.browser:
            self.browser.update_urlbar(url, self)

            if not self.is_private and hasattr(self.browser, 'current_user_id'):
                self.browser.db.add_history_item(self.browser.current_user_id, url.toString(), self.title())

    def on_load_finished(self, success):
        if success and self.browser:
            title = self.page().title()
            idx = self.browser.tabs.indexOf(self)
            if idx != -1:
                self.browser.tabs.setTabText(idx, title[:15] + '...' if len(title) > 15 else title)

    def createWindow(self, window_type):
        if window_type == QWebEnginePage.WebBrowserTab and self.browser:
            return self.browser.create_tab(is_private=self.is_private)
        return super().createWindow(window_type)


class GradientWidget(QWidget):
    def paintEvent(self, event):
        painter = QPainter(self)
        gradient = QLinearGradient(0, 0, 0, self.height())
        gradient.setColorAt(0, QColor(15, 23, 42))
        gradient.setColorAt(1, QColor(30, 41, 59))
        painter.fillRect(self.rect(), gradient)


class BrowserWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Browser")
        self.setMinimumSize(1024, 768)

        # Инициализация компонентов
        self.db = BrowserDatabase()
        self.settings = QSettings("SecureBrowser", "Settings")
        self.current_user_id = -1
        self.private_profile = PrivateProfile()
        self.interceptor = PrivacyRequestInterceptor()

        # Настройки по умолчанию
        self.load_settings()

        # Установка домашней страницы на Яндекс
        if not self.settings.contains("home_page"):
            self.home_page = "https://ya.ru"
            self.settings.setValue("home_page", self.home_page)
        else:
            self.home_page = self.settings.value("home_page", "https://ya.ru")

        # Инициализация UI
        self.init_ui()
        self.passwords_list = QListWidget()  # Добавлено исправление здесь

        # Автоматически входим в дефолтный профиль
        self.login_to_default_profile()

        # Создаем первую вкладку
        self.create_tab()

        # Таймер для периодической очистки памяти
        self.memory_cleanup_timer = QTimer(self)
        self.memory_cleanup_timer.timeout.connect(self.cleanup_memory)
        self.memory_cleanup_timer.start(30000)  # Каждые 30 секунд

    def cleanup_memory(self):
        QApplication.processEvents()
        if hasattr(self, 'tabs'):
            for i in range(self.tabs.count()):
                browser = self.tabs.widget(i)
                if browser:
                    browser.page().triggerAction(QWebEnginePage.Stop)

    def login_to_default_profile(self):
        users = self.db.get_users()
        if users:
            default_user = next((user for user in users if user[1] == 'Default'), users[0])
            self.current_user_id = default_user[0]
            self.update_history_table()
            self.update_downloads_table()
            self.update_extensions_list()
            self.update_passwords_list()

    def load_settings(self):
        self.block_trackers = self.settings.value("block_trackers", True, bool)
        self.force_https = self.settings.value("force_https", True, bool)
        self.phishing_protection = self.settings.value("phishing_protection", True, bool)
        self.cookie_policy = self.settings.value("cookie_policy", 1, int)
        self.cache_size = self.settings.value("cache_size", 100, int)
        self.preload_enabled = self.settings.value("preload_enabled", True, bool)
        self.memory_saver = self.settings.value("memory_saver", False, bool)
        self.theme = self.settings.value("theme", "dark", str)
        self.default_zoom = self.settings.value("default_zoom", 100, int)
        self.download_path = self.settings.value("download_path",
                                                 QStandardPaths.writableLocation(QStandardPaths.DownloadLocation), str)
        self.search_engine = self.settings.value("search_engine", "Yandex", str)
        self.home_page = self.settings.value("home_page", "https://ya.ru", str)
        self.open_new_tabs = self.settings.value("open_new_tabs", True, bool)
        self.block_ads = self.settings.value("block_ads", True, bool)
        self.interceptor.block_ads = self.block_ads
        self.sidebar_collapsed = self.settings.value("sidebar_collapsed", False, bool)

    def init_ui(self):
        # Основной виджет с градиентным фоном
        main_widget = GradientWidget()
        main_layout = QHBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Боковая панель с новым дизайном
        self.sidebar = QFrame()
        self.sidebar.setFixedWidth(280 if not self.sidebar_collapsed else 50)
        self.sidebar.setStyleSheet("""
            QFrame {
                background-color: #1e293b;
                border-right: 1px solid #334155;
            }
            QPushButton {
                color: #e2e8f0;
                text-align: left;
                padding: 12px 15px;
                border: none;
                background: transparent;
                font-size: 14px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #334155;
            }
            QPushButton:pressed {
                background-color: #475569;
            }
            QListWidget {
                background-color: transparent;
                border: none;
                color: #e2e8f0;
                font-size: 13px;
            }
            QListWidget::item {
                padding: 8px 10px;
                border-bottom: 1px solid #334155;
            }
            QListWidget::item:hover {
                background-color: #334155;
            }
            QListWidget::item:selected {
                background-color: #475569;
            }
        """)

        sidebar_layout = QVBoxLayout()
        sidebar_layout.setContentsMargins(10, 15, 10, 15)
        sidebar_layout.setSpacing(10)

        # Кнопка сворачивания/разворачивания боковой панели
        self.toggle_sidebar_btn = QPushButton()
        self.toggle_sidebar_btn.setIcon(QIcon.fromTheme("sidebar-collapse" if not self.sidebar_collapsed else "sidebar-expand"))
        self.toggle_sidebar_btn.setToolTip("Свернуть/развернуть боковую панель")
        self.toggle_sidebar_btn.clicked.connect(self.toggle_sidebar)
        self.toggle_sidebar_btn.setFixedSize(30, 30)
        self.toggle_sidebar_btn.setStyleSheet("""
            QPushButton {
                background-color: #3b82f6;
                border-radius: 15px;
                padding: 5px;
            }
            QPushButton:hover {
                background-color: #2563eb;
            }
        """)

        sidebar_layout.addWidget(self.toggle_sidebar_btn, 0, Qt.AlignLeft)

        if not self.sidebar_collapsed:
            # Заголовок боковой панели
            sidebar_header = QLabel("Secure Browser")
            sidebar_header.setStyleSheet("""
                QLabel {
                    color: #f8fafc;
                    font-size: 18px;
                    font-weight: bold;
                    padding: 10px 5px;
                    border-bottom: 1px solid #334155;
                }
            """)
            sidebar_layout.addWidget(sidebar_header)

            # Кнопки боковой панели с иконками
            self.profile_btn = QPushButton("Профиль")
            self.profile_btn.setIcon(QIcon.fromTheme("user-identity"))
            
            self.bookmarks_btn = QPushButton("Закладки")
            self.bookmarks_btn.setIcon(QIcon.fromTheme("bookmarks-organize"))
            
            self.history_btn = QPushButton("История")
            self.history_btn.setIcon(QIcon.fromTheme("view-history"))
            
            self.downloads_btn = QPushButton("Загрузки")
            self.downloads_btn.setIcon(QIcon.fromTheme("folder-download"))
            
            self.extensions_btn = QPushButton("Расширения")
            self.extensions_btn.setIcon(QIcon.fromTheme("preferences-other"))
            
            self.passwords_btn = QPushButton("Пароли")
            self.passwords_btn.setIcon(QIcon.fromTheme("dialog-password"))
            self.passwords_btn.clicked.connect(self.show_password_manager)

            for btn in [self.profile_btn, self.bookmarks_btn, self.history_btn,
                        self.downloads_btn, self.extensions_btn, self.passwords_btn]:
                btn.setFixedHeight(40)
                btn.setIconSize(QSize(20, 20))

            # Stacked widget для содержимого боковой панели
            self.sidebar_content = QStackedWidget()
            self.sidebar_content.setStyleSheet("""
                QStackedWidget {
                    background-color: transparent;
                }
                QLabel {
                    color: #e2e8f0;
                }
            """)

            # Профиль
            self.profile_widget = QWidget()
            profile_layout = QVBoxLayout()
            profile_layout.setContentsMargins(5, 5, 5, 5)
            
            self.profile_list = QListWidget()
            self.profile_list.itemClicked.connect(self.switch_profile)

            self.add_profile_btn = QPushButton("Добавить профиль")
            self.add_profile_btn.clicked.connect(self.add_profile)
            self.add_profile_btn.setStyleSheet("""
                QPushButton {
                    background-color: #3b82f6;
                    color: white;
                    padding: 8px;
                    border-radius: 6px;
                }
                QPushButton:hover {
                    background-color: #2563eb;
                }
            """)

            profile_layout.addWidget(QLabel("Профили:"))
            profile_layout.addWidget(self.profile_list)
            profile_layout.addWidget(self.add_profile_btn)
            profile_layout.setSpacing(10)
            self.profile_widget.setLayout(profile_layout)

            # Закладки
            self.bookmarks_widget = QWidget()
            bookmarks_layout = QVBoxLayout()
            bookmarks_layout.setContentsMargins(5, 5, 5, 5)
            
            self.bookmarks_list = QListWidget()
            bookmarks_layout.addWidget(QLabel("Закладки:"))
            bookmarks_layout.addWidget(self.bookmarks_list)
            bookmarks_layout.setSpacing(10)
            self.bookmarks_widget.setLayout(bookmarks_layout)

            # История
            self.history_widget = QWidget()
            history_layout = QVBoxLayout()
            history_layout.setContentsMargins(5, 5, 5, 5)
            
            self.history_table = QTableWidget()
            self.history_table.setColumnCount(3)
            self.history_table.setHorizontalHeaderLabels(["URL", "Название", "Время"])
            self.history_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
            self.history_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
            self.history_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
            self.history_table.setEditTriggers(QTableWidget.NoEditTriggers)
            self.history_table.setStyleSheet("""
                QTableWidget {
                    background-color: #1e293b;
                    color: #e2e8f0;
                    border: 1px solid #334155;
                    gridline-color: #334155;
                }
                QHeaderView::section {
                    background-color: #334155;
                    color: #e2e8f0;
                    padding: 5px;
                    border: none;
                }
            """)

            clear_history_btn = QPushButton("Очистить историю")
            clear_history_btn.clicked.connect(self.clear_history)
            clear_history_btn.setStyleSheet("""
                QPushButton {
                    background-color: #ef4444;
                    color: white;
                    padding: 8px;
                    border-radius: 6px;
                }
                QPushButton:hover {
                    background-color: #dc2626;
                }
            """)

            history_layout.addWidget(QLabel("История:"))
            history_layout.addWidget(self.history_table)
            history_layout.addWidget(clear_history_btn)
            history_layout.setSpacing(10)
            self.history_widget.setLayout(history_layout)

            # Загрузки
            self.downloads_widget = QWidget()
            downloads_layout = QVBoxLayout()
            downloads_layout.setContentsMargins(5, 5, 5, 5)
            
            self.downloads_table = QTableWidget()
            self.downloads_table.setColumnCount(4)
            self.downloads_table.setHorizontalHeaderLabels(["URL", "Файл", "Статус", "Время"])
            self.downloads_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
            self.downloads_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
            self.downloads_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
            self.downloads_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
            self.downloads_table.setEditTriggers(QTableWidget.NoEditTriggers)
            self.downloads_table.setStyleSheet("""
                QTableWidget {
                    background-color: #1e293b;
                    color: #e2e8f0;
                    border: 1px solid #334155;
                    gridline-color: #334155;
                }
                QHeaderView::section {
                    background-color: #334155;
                    color: #e2e8f0;
                    padding: 5px;
                    border: none;
                }
            """)

            open_downloads_btn = QPushButton("Открыть папку загрузок")
            open_downloads_btn.clicked.connect(self.open_downloads_folder)
            open_downloads_btn.setStyleSheet("""
                QPushButton {
                    background-color: #3b82f6;
                    color: white;
                    padding: 8px;
                    border-radius: 6px;
                }
                QPushButton:hover {
                    background-color: #2563eb;
                }
            """)

            downloads_layout.addWidget(QLabel("Загрузки:"))
            downloads_layout.addWidget(self.downloads_table)
            downloads_layout.addWidget(open_downloads_btn)
            downloads_layout.setSpacing(10)
            self.downloads_widget.setLayout(downloads_layout)

            # Расширения
            self.extensions_widget = QWidget()
            extensions_layout = QVBoxLayout()
            extensions_layout.setContentsMargins(5, 5, 5, 5)
            
            self.extensions_list = QListWidget()
            self.extensions_list.setStyleSheet("""
                QListWidget {
                    background-color: #1e293b;
                    color: #e2e8f0;
                    border: 1px solid #334155;
                }
                QListWidget::item {
                    padding: 10px;
                    border-bottom: 1px solid #334155;
                }
                QListWidget::item:hover {
                    background-color: #334155;
                }
            """)
            
            self.extensions_list.itemClicked.connect(self.on_extension_clicked)
            
            add_extension_btn = QPushButton("Добавить расширение")
            add_extension_btn.clicked.connect(self.add_extension)
            add_extension_btn.setStyleSheet("""
                QPushButton {
                    background-color: #3b82f6;
                    color: white;
                    padding: 8px;
                    border-radius: 6px;
                }
                QPushButton:hover {
                    background-color: #2563eb;
                }
            """)
            
            extensions_layout.addWidget(QLabel("Расширения:"))
            extensions_layout.addWidget(self.extensions_list)
            extensions_layout.addWidget(add_extension_btn)
            extensions_layout.setSpacing(10)
            self.extensions_widget.setLayout(extensions_layout)

            # Добавляем виджеты в stacked widget
            self.sidebar_content.addWidget(self.profile_widget)
            self.sidebar_content.addWidget(self.bookmarks_widget)
            self.sidebar_content.addWidget(self.history_widget)
            self.sidebar_content.addWidget(self.downloads_widget)
            self.sidebar_content.addWidget(self.extensions_widget)

            # Подключаем кнопки к переключению страниц
            self.profile_btn.clicked.connect(lambda: self.sidebar_content.setCurrentIndex(0))
            self.bookmarks_btn.clicked.connect(lambda: self.sidebar_content.setCurrentIndex(1))
            self.history_btn.clicked.connect(lambda: self.sidebar_content.setCurrentIndex(2))
            self.downloads_btn.clicked.connect(lambda: self.sidebar_content.setCurrentIndex(3))
            self.extensions_btn.clicked.connect(lambda: self.sidebar_content.setCurrentIndex(4))

            # Обновляем данные профилей
            self.update_profiles_list()

            sidebar_layout.addWidget(self.profile_btn)
            sidebar_layout.addWidget(self.bookmarks_btn)
            sidebar_layout.addWidget(self.history_btn)
            sidebar_layout.addWidget(self.downloads_btn)
            sidebar_layout.addWidget(self.extensions_btn)
            sidebar_layout.addWidget(self.passwords_btn)
            sidebar_layout.addWidget(self.sidebar_content)

        sidebar_layout.addStretch()
        self.sidebar.setLayout(sidebar_layout)

        # Основная область
        self.main_area = QWidget()
        main_area_layout = QVBoxLayout()
        main_area_layout.setContentsMargins(0, 0, 0, 0)
        main_area_layout.setSpacing(0)

        # Панель инструментов с новым дизайном
        self.toolbar = QToolBar()
        self.toolbar.setMovable(False)
        self.toolbar.setStyleSheet("""
            QToolBar {
                background-color: #1e293b;
                border-bottom: 1px solid #334155;
                padding: 5px;
            }
            QPushButton {
                background-color: transparent;
                border: none;
                padding: 5px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #334155;
            }
            QPushButton:pressed {
                background-color: #475569;
            }
            QLineEdit {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 15px;
                padding: 5px 10px;
                color: #e2e8f0;
                font-size: 14px;
            }
        """)

        # Кнопки навигации
        self.back_btn = QPushButton()
        self.back_btn.setIcon(QIcon.fromTheme("go-previous"))
        self.back_btn.setToolTip("Назад")
        self.back_btn.clicked.connect(self.navigate_back)

        self.forward_btn = QPushButton()
        self.forward_btn.setIcon(QIcon.fromTheme("go-next"))
        self.forward_btn.setToolTip("Вперед")
        self.forward_btn.clicked.connect(self.navigate_forward)

        self.refresh_btn = QPushButton()
        self.refresh_btn.setIcon(QIcon.fromTheme("view-refresh"))
        self.refresh_btn.setToolTip("Обновить")
        self.refresh_btn.clicked.connect(self.refresh_page)

        self.home_btn = QPushButton()
        self.home_btn.setIcon(QIcon.fromTheme("go-home"))
        self.home_btn.setToolTip("Домашняя страница")
        self.home_btn.clicked.connect(self.navigate_home)

        # Поле адреса
        self.url_bar = QLineEdit()
        self.url_bar.setPlaceholderText("Введите адрес или поисковый запрос")
        self.url_bar.returnPressed.connect(self.navigate_to_url)

        # Кнопка новой вкладки
        self.new_tab_btn = QPushButton()
        self.new_tab_btn.setIcon(QIcon.fromTheme("tab-new"))
        self.new_tab_btn.setToolTip("Новая вкладка")
        self.new_tab_btn.clicked.connect(lambda: self.create_tab())

        # Кнопка приватной вкладки
        self.private_tab_btn = QPushButton()
        self.private_tab_btn.setIcon(QIcon.fromTheme("security-high"))
        self.private_tab_btn.setToolTip("Новая приватная вкладка")
        self.private_tab_btn.clicked.connect(lambda: self.create_tab(is_private=True))

        # Добавляем элементы на панель инструментов
        for widget in [self.back_btn, self.forward_btn, self.refresh_btn,
                       self.home_btn, self.url_bar, self.new_tab_btn, self.private_tab_btn]:
            self.toolbar.addWidget(widget)

        # Виджет вкладок с новым дизайном
        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.tabs.currentChanged.connect(self.tab_changed)
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: none;
            }
            QTabBar::tab {
                background: #1e293b;
                color: #94a3b8;
                padding: 8px 15px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                border: 1px solid #334155;
                margin-right: 2px;
                font-size: 12px;
            }
            QTabBar::tab:selected {
                background: #334155;
                color: #f8fafc;
                border-bottom: 2px solid #3b82f6;
            }
            QTabBar::tab:hover {
                background: #334155;
                color: #f8fafc;
            }
            QTabBar::close-button {
                image: url(:/icons/close-tab);
                subcontrol-position: right;
                padding: 3px;
            }
            QTabBar::close-button:hover {
                background: #ef4444;
                border-radius: 4px;
            }
        """)

        # Добавляем элементы в основную область
        main_area_layout.addWidget(self.toolbar)
        main_area_layout.addWidget(self.tabs)

        self.main_area.setLayout(main_area_layout)

        # Собираем основной интерфейс
        main_layout.addWidget(self.sidebar)
        main_layout.addWidget(self.main_area)

        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)

        # Настройка меню
        self.init_menu()

        # Применяем тему
        self.apply_theme()

    def toggle_sidebar(self):
        self.sidebar_collapsed = not self.sidebar_collapsed
        self.sidebar.setFixedWidth(280 if not self.sidebar_collapsed else 50)
        self.toggle_sidebar_btn.setIcon(QIcon.fromTheme("sidebar-collapse" if not self.sidebar_collapsed else "sidebar-expand"))
        self.settings.setValue("sidebar_collapsed", self.sidebar_collapsed)

    def init_menu(self):
        menubar = self.menuBar()
        menubar.setStyleSheet("""
            QMenuBar {
                background-color: #1e293b;
                color: #e2e8f0;
                padding: 5px;
                border-bottom: 1px solid #334155;
            }
            QMenuBar::item {
                padding: 5px 10px;
                background: transparent;
            }
            QMenuBar::item:selected {
                background: #334155;
                border-radius: 4px;
            }
            QMenu {
                background-color: #1e293b;
                color: #e2e8f0;
                border: 1px solid #334155;
                padding: 5px;
            }
            QMenu::item {
                padding: 5px 25px 5px 20px;
            }
            QMenu::item:selected {
                background-color: #334155;
            }
            QMenu::separator {
                height: 1px;
                background: #334155;
                margin: 5px 0;
            }
        """)

        # Меню Файл
        file_menu = menubar.addMenu("Файл")

        new_tab_action = QAction("Новая вкладка", self)
        new_tab_action.setShortcut(QKeySequence("Ctrl+T"))
        new_tab_action.triggered.connect(lambda: self.create_tab())
        file_menu.addAction(new_tab_action)

        new_private_tab_action = QAction("Новая приватная вкладка", self)
        new_private_tab_action.setShortcut(QKeySequence("Ctrl+Shift+T"))
        new_private_tab_action.triggered.connect(lambda: self.create_tab(is_private=True))
        file_menu.addAction(new_private_tab_action)

        close_tab_action = QAction("Закрыть вкладку", self)
        close_tab_action.setShortcut(QKeySequence("Ctrl+W"))
        close_tab_action.triggered.connect(self.close_current_tab)
        file_menu.addAction(close_tab_action)

        file_menu.addSeparator()

        settings_action = QAction("Настройки", self)
        settings_action.setShortcut(QKeySequence("Ctrl+,"))
        settings_action.triggered.connect(self.show_settings)
        file_menu.addAction(settings_action)

        exit_action = QAction("Выход", self)
        exit_action.setShortcut(QKeySequence("Ctrl+Q"))
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Меню Настройки
        settings_menu = menubar.addMenu("Настройки")

        privacy_action = QAction("Приватность и безопасность", self)
        privacy_action.triggered.connect(self.show_privacy_settings)
        settings_menu.addAction(privacy_action)

        performance_action = QAction("Производительность", self)
        performance_action.triggered.connect(self.show_performance_settings)
        settings_menu.addAction(performance_action)

        appearance_action = QAction("Внешний вид", self)
        appearance_action.triggered.connect(self.show_appearance_settings)
        settings_menu.addAction(appearance_action)

        # Меню Справка
        help_menu = menubar.addMenu("Справка")

        about_action = QAction("О программе", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def apply_theme(self):
        palette = QPalette()

        if self.theme == "dark":
            palette.setColor(QPalette.Window, QColor(30, 41, 59))
            palette.setColor(QPalette.WindowText, QColor(226, 232, 240))
            palette.setColor(QPalette.Base, QColor(15, 23, 42))
            palette.setColor(QPalette.AlternateBase, QColor(30, 41, 59))
            palette.setColor(QPalette.ToolTipBase, QColor(226, 232, 240))
            palette.setColor(QPalette.ToolTipText, QColor(226, 232, 240))
            palette.setColor(QPalette.Text, QColor(226, 232, 240))
            palette.setColor(QPalette.Button, QColor(30, 41, 59))
            palette.setColor(QPalette.ButtonText, QColor(226, 232, 240))
            palette.setColor(QPalette.BrightText, QColor(239, 68, 68))
            palette.setColor(QPalette.Link, QColor(59, 130, 246))
            palette.setColor(QPalette.Highlight, QColor(59, 130, 246))
            palette.setColor(QPalette.HighlightedText, QColor(248, 250, 252))
        else:
            palette.setColor(QPalette.Window, QColor(240, 240, 240))
            palette.setColor(QPalette.WindowText, QColor(0, 0, 0))
            palette.setColor(QPalette.Base, QColor(255, 255, 255))
            palette.setColor(QPalette.AlternateBase, QColor(240, 240, 240))
            palette.setColor(QPalette.ToolTipBase, QColor(255, 255, 255))
            palette.setColor(QPalette.ToolTipText, QColor(0, 0, 0))
            palette.setColor(QPalette.Text, QColor(0, 0, 0))
            palette.setColor(QPalette.Button, QColor(240, 240, 240))
            palette.setColor(QPalette.ButtonText, QColor(0, 0, 0))
            palette.setColor(QPalette.BrightText, QColor(255, 0, 0))
            palette.setColor(QPalette.Link, QColor(0, 0, 255))
            palette.setColor(QPalette.Highlight, QColor(0, 120, 215))
            palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))

        self.setPalette(palette)
        
        # Обновляем стили для контрастности текста в настройках
        self.update_settings_style()

    def update_settings_style(self):
        contrast_color = "#000000" if self.theme == "light" else "#ffffff"
        contrast_style = f"""
            QLabel, QCheckBox, QRadioButton, QGroupBox {{
                color: {contrast_color};
            }}
        """
        QApplication.instance().setStyleSheet(contrast_style)

    def create_tab(self, url=None, is_private=False):
        if is_private:
            browser = BrowserTab(self.private_profile, is_private=True, parent=self)
        else:
            profile = QWebEngineProfile.defaultProfile()
            browser = BrowserTab(profile, is_private=False, parent=self)

        # Устанавливаем интерцептор для блокировки рекламы
        profile = browser.page().profile()
        profile.setUrlRequestInterceptor(self.interceptor)

        if url:
            browser.setUrl(QUrl(url))
        else:
            browser.setUrl(QUrl(self.home_page))

        tab_index = self.tabs.addTab(browser, "Новая вкладка")
        self.tabs.setCurrentIndex(tab_index)

        return browser

    def close_tab(self, index):
        if self.tabs.count() > 1:
            self.tabs.removeTab(index)

    def close_current_tab(self):
        self.close_tab(self.tabs.currentIndex())

    def tab_changed(self, index):
        if index >= 0:
            browser = self.tabs.widget(index)
            if browser:
                self.update_urlbar(browser.url(), browser)

    def update_urlbar(self, url, browser=None):
        if browser != self.tabs.currentWidget():
            return

        self.url_bar.setText(url.toString())
        self.url_bar.setCursorPosition(0)

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
        current_browser = self.tabs.currentWidget()
        if current_browser:
            current_browser.setUrl(QUrl(self.home_page))

    def navigate_to_url(self):
        url = self.url_bar.text()

        if not url.startswith(('http://', 'https://')):
            if '.' in url:
                url = 'http://' + url
            else:
                if self.search_engine == "Google":
                    url = f"https://www.google.com/search?q={url}"
                elif self.search_engine == "Yandex":
                    url = f"https://yandex.ru/search/?text={url}"
                elif self.search_engine == "DuckDuckGo":
                    url = f"https://duckduckgo.com/?q={url}"

        current_browser = self.tabs.currentWidget()
        if current_browser:
            current_browser.setUrl(QUrl(url))
        else:
            self.create_tab(url)

    def show_settings(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Настройки браузера")
        dialog.setMinimumSize(800, 600)
        dialog.setStyleSheet("""
            QDialog {
                background-color: #1e293b;
                color: #e2e8f0;
            }
            QGroupBox {
                border: 1px solid #334155;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 15px;
                color: #e2e8f0;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 3px;
                color: #e2e8f0;
            }
            QCheckBox, QRadioButton {
                color: #e2e8f0;
                padding: 5px;
            }
            QLabel {
                color: #e2e8f0;
                font-weight: bold;
            }
            QPushButton {
                background-color: #3b82f6;
                color: white;
                padding: 8px 16px;
                border-radius: 6px;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #2563eb;
            }
            QPushButton:pressed {
                background-color: #1d4ed8;
            }
            QLineEdit, QComboBox {
                background-color: #1e293b;
                border: 1px solid #334155;
                color: #e2e8f0;
                padding: 5px;
                border-radius: 4px;
            }
            QSlider::groove:horizontal {
                height: 6px;
                background: #334155;
                border-radius: 3px;
            }
            QSlider::handle:horizontal {
                width: 16px;
                height: 16px;
                margin: -5px 0;
                border-radius: 8px;
                background: #3b82f6;
            }
            QSlider::sub-page:horizontal {
                background: #3b82f6;
                border-radius: 3px;
            }
        """)

        tabs = QTabWidget()

        # Основные настройки
        basic_tab = QWidget()
        basic_layout = QVBoxLayout()

        # Группа поиска
        search_group = QGroupBox("Поиск")
        search_layout = QFormLayout()

        self.search_engine_combo = QComboBox()
        self.search_engine_combo.addItems(["Google", "Yandex", "DuckDuckGo"])
        self.search_engine_combo.setCurrentText(self.search_engine)

        search_layout.addRow("Поисковая система:", self.search_engine_combo)
        search_group.setLayout(search_layout)

        # Группа домашней страницы
        home_group = QGroupBox("Домашняя страница")
        home_layout = QFormLayout()

        self.home_page_edit = QLineEdit(self.home_page)
        home_layout.addRow("URL:", self.home_page_edit)
        home_group.setLayout(home_layout)

        # Группа вкладок
        tabs_group = QGroupBox("Вкладки")
        tabs_layout = QVBoxLayout()

        self.open_new_tabs_check = QCheckBox("Открывать ссылки в новой вкладке")
        self.open_new_tabs_check.setChecked(self.open_new_tabs)

        tabs_layout.addWidget(self.open_new_tabs_check)
        tabs_group.setLayout(tabs_layout)

        # Группа масштабирования
        zoom_group = QGroupBox("Масштабирование")
        zoom_layout = QFormLayout()

        self.zoom_slider = QSlider(Qt.Horizontal)
        self.zoom_slider.setRange(50, 200)  # 50% - 200%
        self.zoom_slider.setValue(self.default_zoom)
        self.zoom_slider.setTickInterval(25)
        self.zoom_slider.setTickPosition(QSlider.TicksBelow)

        self.zoom_label = QLabel(f"{self.default_zoom}%")
        self.zoom_slider.valueChanged.connect(
            lambda v: self.zoom_label.setText(f"{v}%"))

        zoom_layout.addRow("Масштаб по умолчанию:", self.zoom_slider)
        zoom_layout.addRow(self.zoom_label)
        zoom_group.setLayout(zoom_layout)

        basic_layout.addWidget(search_group)
        basic_layout.addWidget(home_group)
        basic_layout.addWidget(tabs_group)
        basic_layout.addWidget(zoom_group)
        basic_layout.addStretch()

        basic_tab.setLayout(basic_layout)

        # Вкладка приватности
        privacy_tab = QWidget()
        privacy_layout = QVBoxLayout()

        # Группа безопасности
        security_group = QGroupBox("Безопасность")
        security_layout = QFormLayout()

        self.block_trackers_check = QCheckBox("Блокировать трекеры")
        self.block_trackers_check.setChecked(self.block_trackers)

        self.force_https_check = QCheckBox("Принудительно использовать HTTPS")
        self.force_https_check.setChecked(self.force_https)

        self.phishing_protection_check = QCheckBox("Защита от фишинга")
        self.phishing_protection_check.setChecked(self.phishing_protection)

        self.block_ads_check = QCheckBox("Блокировать рекламу")
        self.block_ads_check.setChecked(self.block_ads)

        security_layout.addRow(self.block_trackers_check)
        security_layout.addRow(self.force_https_check)
        security_layout.addRow(self.phishing_protection_check)
        security_layout.addRow(self.block_ads_check)

        security_group.setLayout(security_layout)

        # Группа cookie
        cookie_group = QGroupBox("Настройки cookie")
        cookie_layout = QVBoxLayout()

        self.cookie_policy_group = QButtonGroup()

        cookie_all = QRadioButton("Принимать все cookie")
        cookie_visited = QRadioButton("Принимать только от посещаемых сайтов")
        cookie_none = QRadioButton("Блокировать все cookie")

        self.cookie_policy_group.addButton(cookie_all, 0)
        self.cookie_policy_group.addButton(cookie_visited, 1)
        self.cookie_policy_group.addButton(cookie_none, 2)

        self.cookie_policy_group.button(self.cookie_policy).setChecked(True)

        cookie_layout.addWidget(cookie_all)
        cookie_layout.addWidget(cookie_visited)
        cookie_layout.addWidget(cookie_none)
        cookie_group.setLayout(cookie_layout)

        privacy_layout.addWidget(security_group)
        privacy_layout.addWidget(cookie_group)
        privacy_layout.addStretch()

        privacy_tab.setLayout(privacy_layout)

        # Вкладка производительности
        performance_tab = QWidget()
        performance_layout = QVBoxLayout()

        # Группа кэша
        cache_group = QGroupBox("Кэширование")
        cache_layout = QFormLayout()

        self.cache_size_slider = QSlider(Qt.Horizontal)
        self.cache_size_slider.setRange(10, 1000)  # 10MB - 1GB
        self.cache_size_slider.setValue(self.cache_size)
        self.cache_size_slider.setTickInterval(50)
        self.cache_size_slider.setTickPosition(QSlider.TicksBelow)

        self.cache_size_label = QLabel(f"{self.cache_size} MB")
        self.cache_size_slider.valueChanged.connect(
            lambda v: self.cache_size_label.setText(f"{v} MB"))

        cache_layout.addRow("Размер кэша:", self.cache_size_slider)
        cache_layout.addRow(self.cache_size_label)

        self.preload_check = QCheckBox("Предварительная загрузка часто посещаемых сайтов")
        self.preload_check.setChecked(self.preload_enabled)
        cache_layout.addRow(self.preload_check)

        self.memory_saver_check = QCheckBox("Режим экономии памяти")
        self.memory_saver_check.setChecked(self.memory_saver)
        cache_layout.addRow(self.memory_saver_check)

        cache_group.setLayout(cache_layout)
        performance_layout.addWidget(cache_group)
        performance_layout.addStretch()

        performance_tab.setLayout(performance_layout)

        # Вкладка внешнего вида
        appearance_tab = QWidget()
        appearance_layout = QVBoxLayout()

        # Группа темы
        theme_group = QGroupBox("Тема оформления")
        theme_layout = QVBoxLayout()

        self.theme_group = QButtonGroup()

        theme_light = QRadioButton("Светлая")
        theme_dark = QRadioButton("Темная")

        self.theme_group.addButton(theme_light, 0)
        self.theme_group.addButton(theme_dark, 1)

        if self.theme == "dark":
            theme_dark.setChecked(True)
        else:
            theme_light.setChecked(True)

        theme_layout.addWidget(theme_light)
        theme_layout.addWidget(theme_dark)
        theme_group.setLayout(theme_layout)

        appearance_layout.addWidget(theme_group)
        appearance_layout.addStretch()

        appearance_tab.setLayout(appearance_layout)

        # Добавляем вкладки
        tabs.addTab(basic_tab, "Основные")
        tabs.addTab(privacy_tab, "Приватность")
        tabs.addTab(performance_tab, "Производительность")
        tabs.addTab(appearance_tab, "Внешний вид")

        # Кнопки сохранения/отмены
        button_box = QHBoxLayout()
        save_btn = QPushButton("Сохранить")
        save_btn.clicked.connect(lambda: self.save_settings(dialog))
        cancel_btn = QPushButton("Отмена")
        cancel_btn.clicked.connect(dialog.reject)

        button_box.addStretch()
        button_box.addWidget(save_btn)
        button_box.addWidget(cancel_btn)

        # Основной layout
        main_layout = QVBoxLayout()
        main_layout.addWidget(tabs)
        main_layout.addLayout(button_box)

        dialog.setLayout(main_layout)
        dialog.exec_()

    def save_settings(self, dialog):
        # Сохраняем основные настройки
        self.search_engine = self.search_engine_combo.currentText()
        self.home_page = self.home_page_edit.text()
        self.open_new_tabs = self.open_new_tabs_check.isChecked()
        self.default_zoom = self.zoom_slider.value()

        # Сохраняем настройки приватности
        self.block_trackers = self.block_trackers_check.isChecked()
        self.force_https = self.force_https_check.isChecked()
        self.phishing_protection = self.phishing_protection_check.isChecked()
        self.cookie_policy = self.cookie_policy_group.checkedId()
        self.block_ads = self.block_ads_check.isChecked()
        self.interceptor.block_ads = self.block_ads

        # Сохраняем настройки производительности
        self.cache_size = self.cache_size_slider.value()
        self.preload_enabled = self.preload_check.isChecked()
        self.memory_saver = self.memory_saver_check.isChecked()

        # Сохраняем настройки внешнего вида
        new_theme = "dark" if self.theme_group.checkedId() == 1 else "light"
        if new_theme != self.theme:
            self.theme = new_theme
            self.apply_theme()

        # Сохраняем в QSettings
        self.settings.setValue("search_engine", self.search_engine)
        self.settings.setValue("home_page", self.home_page)
        self.settings.setValue("open_new_tabs", self.open_new_tabs)
        self.settings.setValue("default_zoom", self.default_zoom)
        self.settings.setValue("block_trackers", self.block_trackers)
        self.settings.setValue("force_https", self.force_https)
        self.settings.setValue("phishing_protection", self.phishing_protection)
        self.settings.setValue("cookie_policy", self.cookie_policy)
        self.settings.setValue("cache_size", self.cache_size)
        self.settings.setValue("preload_enabled", self.preload_enabled)
        self.settings.setValue("memory_saver", self.memory_saver)
        self.settings.setValue("theme", self.theme)
        self.settings.setValue("block_ads", self.block_ads)

        dialog.accept()

    def show_privacy_settings(self):
        tabs = QTabWidget()
        tabs.setCurrentIndex(1)
        self.show_settings()

    def show_performance_settings(self):
        tabs = QTabWidget()
        tabs.setCurrentIndex(2)
        self.show_settings()

    def show_appearance_settings(self):
        tabs = QTabWidget()
        tabs.setCurrentIndex(3)
        self.show_settings()

    def show_about(self):
        about_text = """
        <h2>Secure Browser</h2>
        <p>Версия 1.0</p>
        <p>Современный безопасный браузер с поддержкой приватного режима</p>
        <p>Исходный код: <a href='https://github.com/exentixs/-'>GitHub</a></p>
        """

        msg = QMessageBox()
        msg.setWindowTitle("О программе")
        msg.setTextFormat(Qt.RichText)
        msg.setText(about_text)
        msg.setStyleSheet("""
            QMessageBox {
                background-color: #1e293b;
                color: #e2e8f0;
            }
            QLabel {
                color: #e2e8f0;
            }
            QPushButton {
                background-color: #3b82f6;
                color: white;
                padding: 5px 10px;
                border-radius: 4px;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #2563eb;
            }
        """)
        msg.exec_()

    def update_profiles_list(self):
        self.profile_list.clear()
        users = self.db.get_users()
        for user_id, name, password in users:
            item = QListWidgetItem(name)
            item.setData(Qt.UserRole, (user_id, password is not None))
            self.profile_list.addItem(item)

    def switch_profile(self, item):
        user_id, has_password = item.data(Qt.UserRole)
        name = item.text()

        if has_password:
            password, ok = QInputDialog.getText(self, "Вход в профиль",
                                                f"Введите пароль для профиля '{name}':",
                                                QLineEdit.Password)

            if not ok:
                return

            if not self.db.check_password(user_id, password):
                QMessageBox.warning(self, "Ошибка", "Неверный пароль")
                return
        else:
            pass

        self.current_user_id = user_id
        QMessageBox.information(self, "Успех", f"Вы вошли в профиль {name}")
        self.update_history_table()
        self.update_downloads_table()
        self.update_extensions_list()
        self.update_passwords_list()

    def add_profile(self):
        name, ok = QInputDialog.getText(self, "Новый профиль", "Введите имя профиля:")
        if ok and name:
            users = self.db.get_users()
            if any(name == existing_name for _, existing_name, _ in users):
                QMessageBox.warning(self, "Ошибка", "Профиль с таким именем уже существует")
                return

            password, ok = QInputDialog.getText(self, "Пароль",
                                                "Введите пароль (оставьте пустым, если не нужен):",
                                                QLineEdit.Password)
            if ok:
                user_id = self.db.add_user(name, password if password else None)
                if user_id:
                    self.update_profiles_list()
                    QMessageBox.information(self, "Успех", "Профиль создан")
                else:
                    QMessageBox.warning(self, "Ошибка", "Не удалось создать профиль")

    def update_history_table(self):
        if self.current_user_id == -1:
            return

        self.history_table.setRowCount(0)
        history = self.db.get_history(self.current_user_id)

        for row, (url, title, visit_time) in enumerate(history):
            self.history_table.insertRow(row)
            self.history_table.setItem(row, 0, QTableWidgetItem(url))
            self.history_table.setItem(row, 1, QTableWidgetItem(title))
            self.history_table.setItem(row, 2, QTableWidgetItem(visit_time))

    def clear_history(self):
        if self.current_user_id == -1:
            return

        reply = QMessageBox.question(self, "Очистка истории",
                                     "Вы уверены, что хотите очистить историю?",
                                     QMessageBox.Yes | QMessageBox.No)

        if reply == QMessageBox.Yes:
            if self.db.clear_history(self.current_user_id):
                self.update_history_table()
                QMessageBox.information(self, "Успех", "История очищена")
            else:
                QMessageBox.warning(self, "Ошибка", "Не удалось очистить историю")

    def update_downloads_table(self):
        if self.current_user_id == -1:
            return

        self.downloads_table.setRowCount(0)
        downloads = self.db.get_downloads(self.current_user_id)

        for row, (url, file_path, start_time, finish_time, status) in enumerate(downloads):
            self.downloads_table.insertRow(row)
            self.downloads_table.setItem(row, 0, QTableWidgetItem(url))
            self.downloads_table.setItem(row, 1, QTableWidgetItem(file_path))
            self.downloads_table.setItem(row, 2, QTableWidgetItem(status))

            time_str = finish_time if finish_time else start_time
            self.downloads_table.setItem(row, 3, QTableWidgetItem(time_str))

    def open_downloads_folder(self):
        path = self.download_path
        if not os.path.exists(path):
            os.makedirs(path)

        if sys.platform == "win32":
            os.startfile(path)
        elif sys.platform == "darwin":
            os.system(f'open "{path}"')
        else:
            os.system(f'xdg-open "{path}"')

    def update_extensions_list(self):
        if self.current_user_id == -1:
            return

        self.extensions_list.clear()
        extensions = self.db.get_extensions(self.current_user_id)

        for ext_id, name, version, enabled in extensions:
            item = QListWidgetItem(f"{name} v{version} {'✓' if enabled else '✗'}")
            item.setData(Qt.UserRole, ext_id)
            self.extensions_list.addItem(item)

    def on_extension_clicked(self, item):
        ext_id = item.data(Qt.UserRole)
        extensions = self.db.get_extensions(self.current_user_id)
        ext_info = next((ext for ext in extensions if ext[0] == ext_id), None)
        
        if ext_info:
            ext_id, name, version, enabled = ext_info
            
            menu = QMenu()
            toggle_action = QAction("Включить" if not enabled else "Выключить", self)
            remove_action = QAction("Удалить", self)
            
            toggle_action.triggered.connect(lambda: self.toggle_extension(ext_id, not enabled))
            remove_action.triggered.connect(lambda: self.remove_extension(ext_id))
            
            menu.addAction(toggle_action)
            menu.addAction(remove_action)
            menu.exec_(self.extensions_list.viewport().mapToGlobal(
                self.extensions_list.visualItemRect(item).bottomLeft()))

    def toggle_extension(self, ext_id, enabled):
        if self.db.toggle_extension(ext_id, enabled):
            self.update_extensions_list()
        else:
            QMessageBox.warning(self, "Ошибка", "Не удалось изменить состояние расширения")

    def remove_extension(self, ext_id):
        reply = QMessageBox.question(self, "Удаление расширения",
                                    "Вы уверены, что хотите удалить это расширение?",
                                    QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            if self.db.remove_extension(ext_id):
                self.update_extensions_list()
                QMessageBox.information(self, "Успех", "Расширение удалено")
            else:
                QMessageBox.warning(self, "Ошибка", "Не удалось удалить расширение")

    def add_extension(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Выберите файл расширения", 
                                                  "", "Расширения (*.crx *.zip)")
        if file_path:
            # Здесь должна быть логика установки расширения
            # Для примера просто добавляем запись в базу данных
            name = os.path.basename(file_path)
            version = "1.0"
            
            if self.db.add_extension(self.current_user_id, name, version, file_path):
                self.update_extensions_list()
                QMessageBox.information(self, "Успех", "Расширение добавлено")
            else:
                QMessageBox.warning(self, "Ошибка", "Не удалось добавить расширение")

    def update_passwords_list(self):
        if self.current_user_id == -1:
            return

        self.passwords_list.clear()
        passwords = self.db.get_passwords(self.current_user_id)

        for pwd_id, site, username, password in passwords:
            item = QListWidgetItem(f"{site} - {username}")
            item.setData(Qt.UserRole, pwd_id)
            self.passwords_list.addItem(item)

    def show_password_manager(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Менеджер паролей")
        dialog.setMinimumSize(600, 400)
        dialog.setStyleSheet("""
            QDialog {
                background-color: #1e293b;
                color: #e2e8f0;
            }
            QLabel {
                color: #e2e8f0;
                font-weight: bold;
            }
            QLineEdit, QPushButton {
                background-color: #334155;
                color: #e2e8f0;
                border: 1px solid #475569;
                padding: 5px;
                border-radius: 4px;
            }
            QPushButton {
                background-color: #3b82f6;
                padding: 8px;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #2563eb;
            }
            QListWidget {
                background-color: #1e293b;
                color: #e2e8f0;
                border: 1px solid #334155;
            }
            QListWidget::item {
                padding: 8px;
                border-bottom: 1px solid #334155;
            }
            QListWidget::item:hover {
                background-color: #334155;
            }
        """)

        layout = QVBoxLayout()

        # Список сохраненных паролей
        self.passwords_list = QListWidget()
        self.passwords_list.itemClicked.connect(self.show_password_details)
        layout.addWidget(QLabel("Сохраненные пароли:"))
        layout.addWidget(self.passwords_list)

        # Форма для добавления нового пароля
        form_group = QGroupBox("Добавить новый пароль")
        form_layout = QFormLayout()

        self.site_edit = QLineEdit()
        self.username_edit = QLineEdit()
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)

        form_layout.addRow("Сайт:", self.site_edit)
        form_layout.addRow("Имя пользователя:", self.username_edit)
        form_layout.addRow("Пароль:", self.password_edit)

        add_btn = QPushButton("Добавить")
        add_btn.clicked.connect(self.add_password)
        form_layout.addRow(add_btn)

        form_group.setLayout(form_layout)
        layout.addWidget(form_group)

        # Кнопки управления
        button_box = QHBoxLayout()
        show_btn = QPushButton("Показать пароль")
        show_btn.clicked.connect(lambda: self.password_edit.setEchoMode(
            QLineEdit.Normal if self.password_edit.echoMode() == QLineEdit.Password 
            else QLineEdit.Password))
        
        remove_btn = QPushButton("Удалить")
        remove_btn.clicked.connect(self.remove_password)
        
        close_btn = QPushButton("Закрыть")
        close_btn.clicked.connect(dialog.accept)

        button_box.addWidget(show_btn)
        button_box.addWidget(remove_btn)
        button_box.addWidget(close_btn)
        layout.addLayout(button_box)

        dialog.setLayout(layout)
        
        # Обновляем список паролей
        self.update_passwords_list()
        
        dialog.exec_()

    def show_password_details(self, item):
        pwd_id = item.data(Qt.UserRole)
        passwords = self.db.get_passwords(self.current_user_id)
        password_info = next((pwd for pwd in passwords if pwd[0] == pwd_id), None)
        
        if password_info:
            _, site, username, password = password_info
            self.site_edit.setText(site)
            self.username_edit.setText(username)
            self.password_edit.setText(password)

    def add_password(self):
        site = self.site_edit.text()
        username = self.username_edit.text()
        password = self.password_edit.text()
        
        if not site or not username or not password:
            QMessageBox.warning(self, "Ошибка", "Все поля должны быть заполнены")
            return
            
        if self.db.add_password(self.current_user_id, site, username, password):
            self.update_passwords_list()
            self.site_edit.clear()
            self.username_edit.clear()
            self.password_edit.clear()
            QMessageBox.information(self, "Успех", "Пароль добавлен")
        else:
            QMessageBox.warning(self, "Ошибка", "Не удалось добавить пароль")

    def remove_password(self):
        current_item = self.passwords_list.currentItem()
        if not current_item:
            QMessageBox.warning(self, "Ошибка", "Выберите пароль для удаления")
            return
            
        pwd_id = current_item.data(Qt.UserRole)
        
        reply = QMessageBox.question(self, "Удаление пароля",
                                    "Вы уверены, что хотите удалить этот пароль?",
                                    QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            if self.db.remove_password(pwd_id):
                self.update_passwords_list()
                self.site_edit.clear()
                self.username_edit.clear()
                self.password_edit.clear()
                QMessageBox.information(self, "Успех", "Пароль удален")
            else:
                QMessageBox.warning(self, "Ошибка", "Не удалось удалить пароль")


def main():
    # Настройки для корректной работы и аппаратного ускорения
    os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = (
        "--enable-media-stream "
        "--enable-usermedia-screen-capture "
        "--enable-gpu-rasterization "
        "--enable-accelerated-video-decode "
        "--enable-accelerated-video "
        "--enable-native-gpu-memory-buffers "
        "--disable-gpu-driver-bug-workarounds"
    )

    app = QApplication(sys.argv)
    app.setApplicationName("Secure Browser")
    app.setStyle('Fusion')

    try:
        browser = BrowserWindow()
        browser.show()
        sys.exit(app.exec_())
    except Exception as e:
        print(f"Application error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
