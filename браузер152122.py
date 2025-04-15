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
from PyQt5.QtGui import QIcon, QPixmap, QFont, QColor, QPalette, QKeySequence
from PyQt5.QtWebEngineCore import QWebEngineUrlRequestInterceptor, QWebEngineUrlRequestInfo


class PrivacyRequestInterceptor(QWebEngineUrlRequestInterceptor):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.block_trackers = True
        self.force_https = True
        self.phishing_protection = True
        self.cookie_policy = 1  # 0 - все, 1 - только посещаемые, 2 - none
        self.visited_domains = set()

    def interceptRequest(self, info):
        url = info.requestUrl().toString()

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
            domain = QUrl(url).host()
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

    def get_users(self):
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

        # Включение аппаратного ускорения
        self.page().settings().setAttribute(QWebEngineSettings.Accelerated2dCanvasEnabled, True)
        self.page().settings().setAttribute(QWebEngineSettings.WebGLEnabled, True)
        self.page().settings().setAttribute(QWebEngineSettings.PlaybackRequiresUserGesture, False)

        self.page().urlChanged.connect(self.on_url_changed)
        self.page().loadFinished.connect(self.on_load_finished)

    def apply_settings(self):
        settings = self.page().settings()

        # Безопасность
        settings.setAttribute(QWebEngineSettings.JavascriptEnabled, True)
        settings.setAttribute(QWebEngineSettings.LocalStorageEnabled, not self.is_private)
        settings.setAttribute(QWebEngineSettings.WebRTCPublicInterfacesOnly, True)

        # Производительность
        settings.setAttribute(QWebEngineSettings.Accelerated2dCanvasEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebGLEnabled, True)
        settings.setAttribute(QWebEngineSettings.AllowRunningInsecureContent, False)

        # Видео и медиа
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


class BrowserWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Browser")
        self.setMinimumSize(1024, 768)

        # Установка флагов для улучшения производительности
        QCoreApplication.setAttribute(Qt.AA_EnableHighDpiScaling)
        QCoreApplication.setAttribute(Qt.AA_UseHighDpiPixmaps)
        QCoreApplication.setAttribute(Qt.AA_ShareOpenGLContexts)

        # Инициализация компонентов
        self.db = BrowserDatabase()
        self.settings = QSettings("SecureBrowser", "Settings")
        self.current_user_id = -1
        self.private_profile = PrivateProfile()

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

        # Автоматически входим в дефолтный профиль
        self.login_to_default_profile()

        # Создаем первую вкладку
        self.create_tab()

        # Таймер для периодической очистки памяти
        self.memory_cleanup_timer = QTimer(self)
        self.memory_cleanup_timer.timeout.connect(self.cleanup_memory)
        self.memory_cleanup_timer.start(30000)  # Каждые 30 секунд

    def cleanup_memory(self):
        """Периодическая очистка памяти для улучшения производительности"""
        QApplication.processEvents()
        if hasattr(self, 'tabs'):
            for i in range(self.tabs.count()):
                browser = self.tabs.widget(i)
                if browser:
                    browser.page().triggerAction(QWebEnginePage.Stop)

    def login_to_default_profile(self):
        """Автоматически входит в дефолтный профиль при запуске"""
        users = self.db.get_users()
        if users:
            default_user = next((user for user in users if user[1] == 'Default'), users[0])
            self.current_user_id = default_user[0]
            self.update_history_table()
            self.update_downloads_table()

    def load_settings(self):
        # Загрузка сохраненных настроек с Яндексом по умолчанию
        self.block_trackers = self.settings.value("block_trackers", True, bool)
        self.force_https = self.settings.value("force_https", True, bool)
        self.phishing_protection = self.settings.value("phishing_protection", True, bool)
        self.cookie_policy = self.settings.value("cookie_policy", 1, int)
        self.cache_size = self.settings.value("cache_size", 100, int)  # MB
        self.preload_enabled = self.settings.value("preload_enabled", True, bool)
        self.memory_saver = self.settings.value("memory_saver", False, bool)
        self.theme = self.settings.value("theme", "dark", str)
        self.default_zoom = self.settings.value("default_zoom", 100, int)
        self.download_path = self.settings.value("download_path",
                                                 QStandardPaths.writableLocation(QStandardPaths.DownloadLocation), str)
        self.search_engine = self.settings.value("search_engine", "Yandex", str)  # Яндекс по умолчанию
        self.home_page = self.settings.value("home_page", "https://ya.ru", str)  # Яндекс по умолчанию
        self.open_new_tabs = self.settings.value("open_new_tabs", True, bool)

    def init_ui(self):
        # Основной виджет
        main_widget = QWidget()
        main_layout = QHBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Боковая панель
        self.sidebar = QFrame()
        self.sidebar.setFixedWidth(250)
        self.sidebar.setStyleSheet("background-color: #2c3e50;")

        sidebar_layout = QVBoxLayout()
        sidebar_layout.setContentsMargins(0, 0, 0, 0)

        # Кнопки боковой панели
        self.profile_btn = QPushButton("Профиль")
        self.bookmarks_btn = QPushButton("Закладки")
        self.history_btn = QPushButton("История")
        self.downloads_btn = QPushButton("Загрузки")
        self.extensions_btn = QPushButton("Расширения")

        for btn in [self.profile_btn, self.bookmarks_btn, self.history_btn,
                    self.downloads_btn, self.extensions_btn]:
            btn.setStyleSheet("""
                QPushButton {
                    color: white;
                    text-align: left;
                    padding: 10px;
                    border: none;
                    background: transparent;
                }
                QPushButton:hover {
                    background-color: #34495e;
                }
                QPushButton:pressed {
                    background-color: #2980b9;
                }
            """)
            btn.setFixedHeight(40)

        # Stacked widget для содержимого боковой панели
        self.sidebar_content = QStackedWidget()

        # Профиль
        self.profile_widget = QWidget()
        profile_layout = QVBoxLayout()

        self.profile_list = QListWidget()
        self.profile_list.itemClicked.connect(self.switch_profile)

        self.add_profile_btn = QPushButton("Добавить профиль")
        self.add_profile_btn.clicked.connect(self.add_profile)
        self.add_profile_btn.setStyleSheet("background-color: #3498db; color: white;")

        profile_layout.addWidget(QLabel("Профили:"))
        profile_layout.addWidget(self.profile_list)
        profile_layout.addWidget(self.add_profile_btn)
        self.profile_widget.setLayout(profile_layout)

        # Закладки
        self.bookmarks_widget = QWidget()
        bookmarks_layout = QVBoxLayout()
        self.bookmarks_list = QListWidget()
        bookmarks_layout.addWidget(QLabel("Закладки:"))
        bookmarks_layout.addWidget(self.bookmarks_list)
        self.bookmarks_widget.setLayout(bookmarks_layout)

        # История
        self.history_widget = QWidget()
        history_layout = QVBoxLayout()
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(3)
        self.history_table.setHorizontalHeaderLabels(["URL", "Название", "Время"])
        self.history_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.history_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.history_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.history_table.setEditTriggers(QTableWidget.NoEditTriggers)

        clear_history_btn = QPushButton("Очистить историю")
        clear_history_btn.clicked.connect(self.clear_history)
        clear_history_btn.setStyleSheet("background-color: #e74c3c; color: white;")

        history_layout.addWidget(QLabel("История:"))
        history_layout.addWidget(self.history_table)
        history_layout.addWidget(clear_history_btn)
        self.history_widget.setLayout(history_layout)

        # Загрузки
        self.downloads_widget = QWidget()
        downloads_layout = QVBoxLayout()
        self.downloads_table = QTableWidget()
        self.downloads_table.setColumnCount(4)
        self.downloads_table.setHorizontalHeaderLabels(["URL", "Файл", "Статус", "Время"])
        self.downloads_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.downloads_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.downloads_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.downloads_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.downloads_table.setEditTriggers(QTableWidget.NoEditTriggers)

        open_downloads_btn = QPushButton("Открыть папку загрузок")
        open_downloads_btn.clicked.connect(self.open_downloads_folder)
        open_downloads_btn.setStyleSheet("background-color: #3498db; color: white;")

        downloads_layout.addWidget(QLabel("Загрузки:"))
        downloads_layout.addWidget(self.downloads_table)
        downloads_layout.addWidget(open_downloads_btn)
        self.downloads_widget.setLayout(downloads_layout)

        # Расширения
        self.extensions_widget = QWebEngineView()
        self.extensions_widget.setUrl(QUrl("chrome://extensions"))

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
        sidebar_layout.addWidget(self.sidebar_content)

        self.sidebar.setLayout(sidebar_layout)

        # Основная область
        self.main_area = QWidget()
        main_area_layout = QVBoxLayout()
        main_area_layout.setContentsMargins(0, 0, 0, 0)
        main_area_layout.setSpacing(0)

        # Панель инструментов
        self.toolbar = QToolBar()
        self.toolbar.setMovable(False)
        self.toolbar.setStyleSheet("background-color: #34495e;")

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

        # Виджет вкладок
        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.tabs.currentChanged.connect(self.tab_changed)

        # Настройка стиля вкладок
        self.tabs.setStyleSheet("""
            QTabBar::tab {
                background: #34495e;
                color: white;
                padding: 8px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                border: 1px solid #2c3e50;
            }
            QTabBar::tab:selected {
                background: #2980b9;
            }
            QTabBar::tab:hover {
                background: #3498db;
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

    def init_menu(self):
        menubar = self.menuBar()

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
            palette.setColor(QPalette.Window, QColor(53, 53, 53))
            palette.setColor(QPalette.WindowText, Qt.white)
            palette.setColor(QPalette.Base, QColor(25, 25, 25))
            palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
            palette.setColor(QPalette.ToolTipBase, Qt.white)
            palette.setColor(QPalette.ToolTipText, Qt.white)
            palette.setColor(QPalette.Text, Qt.white)
            palette.setColor(QPalette.Button, QColor(53, 53, 53))
            palette.setColor(QPalette.ButtonText, Qt.white)
            palette.setColor(QPalette.BrightText, Qt.red)
            palette.setColor(QPalette.Link, QColor(42, 130, 218))
            palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
            palette.setColor(QPalette.HighlightedText, Qt.black)
        else:
            palette = QApplication.style().standardPalette()

        self.setPalette(palette)
        self.setStyleSheet("""
            QMenuBar {
                background-color: #2c3e50;
                color: white;
            }
            QMenuBar::item {
                background: transparent;
                padding: 5px 10px;
            }
            QMenuBar::item:selected {
                background: #34495e;
            }
            QMenu {
                background-color: #34495e;
                color: white;
                border: 1px solid #2c3e50;
            }
            QMenu::item:selected {
                background-color: #2980b9;
            }
        """)

    def create_tab(self, url=None, is_private=False):
        if is_private:
            browser = BrowserTab(self.private_profile, is_private=True, parent=self)
        else:
            profile = QWebEngineProfile.defaultProfile()
            browser = BrowserTab(profile, is_private=False, parent=self)

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

        security_layout.addRow(self.block_trackers_check)
        security_layout.addRow(self.force_https_check)
        security_layout.addRow(self.phishing_protection_check)

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

        # Сохраняем настройки производительности
        self.cache_size = self.cache_size_slider.value()
        self.preload_enabled = self.preload_check.isChecked()
        self.memory_saver = self.memory_saver_check.isChecked()

        # Сохраняем настройки внешнего вида
        self.theme = "dark" if self.theme_group.checkedId() == 1 else "light"

        # Применяем изменения
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
        Secure Browser
        Версия 1.0

        Современный безопасный браузер с поддержкой приватного режима

        Исходный код: 
        <a href='https://github.com/exentixs/-'>GitHub</a>
        """

        msg = QMessageBox()
        msg.setWindowTitle("О программе")
        msg.setTextFormat(Qt.RichText)
        msg.setText(about_text)
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

        # Если у профиля есть пароль, запрашиваем его
        if has_password:
            password, ok = QInputDialog.getText(self, "Вход в профиль",
                                                f"Введите пароль для профиля '{name}':",
                                                QLineEdit.Password)

            if not ok:
                return  # Пользователь отменил ввод

            if not self.db.check_password(user_id, password):
                QMessageBox.warning(self, "Ошибка", "Неверный пароль")
                return
        else:
            # Для профиля без пароля просто продолжаем
            pass

        self.current_user_id = user_id
        QMessageBox.information(self, "Успех", f"Вы вошли в профиль {name}")
        self.update_history_table()
        self.update_downloads_table()

    def add_profile(self):
        name, ok = QInputDialog.getText(self, "Новый профиль", "Введите имя профиля:")
        if ok and name:
            # Проверяем, не существует ли уже профиль с таким именем
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