браузер ипсытавался на основе Fedora и работа обеспечена на основе(Chromium Embedded Framework)
# -Основные зависимости:


pip install PyQt5==5.15.9           # Основной фреймворк для GUI
pip install PyQtWebEngine==5.15.6   # Для встроенного движка браузера (WebEngine)
pip install cryptography==41.0.7    # Для шифрования данных пользователей
Дополнительные зависимости (обычно устанавливаются автоматически):


pip install sip                     # Система интерфейсов для PyQt
pip install pyqt5-plugins           # Дополнительные плагины для PyQt5
pip install pyqt5-tools             # Инструменты для разработки (не обязательны для работы)
pip install cffi                    # Для работы cryptography
Для Linux (дополнительные системные зависимости):


# Для Debian/Ubuntu:
sudo apt install python3-pyqt5 python3-pyqt5.qtwebengine libqt5webkit5-dev

# Для Fedora/RHEL:
sudo dnf install python3-qt5 python3-qt5-webengine qt5-qtwebkit-devel

# Для Arch Linux:
sudo pacman -S python-pyqt5 python-pyqt5-webengine qt5-webengine
Для работы с видео (WebRTC):

# На Linux может потребоваться:
sudo apt install libavcodec-dev libavformat-dev libswscale-dev libvpx-dev

# Или явно указать флаги при запуске:
export QTWEBENGINE_CHROMIUM_FLAGS="--enable-media-stream --enable-usermedia-screen-capture"
Рекомендуемые версии (для стабильной работы):

PyQt5 >= 5.15.0
PyQtWebEngine >= 5.15.0
cryptography >= 3.4
Python >= 3.8
Полная команда для установки:

pip install PyQt5==5.15.9 PyQtWebEngine==5.15.6 cryptography==41.0.7
