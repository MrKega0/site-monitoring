# main.py

import sys
import logging
from db import create_tables
from auth import authenticate_user
from ui import UserInterface
from PyQt6.QtWidgets import QApplication


def main():
    # Настройка логирования
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s:%(message)s",
        filename="monitoring.log",
        filemode="a",
        encoding="utf-8",  # Указываем кодировку
    )

    logging.info("Запуск системы мониторинга.")

    # Инициализация базы данных
    create_tables()

    # Авторизация пользователя
    if not authenticate_user():
        logging.warning("Авторизация не удалась.")
        print("Авторизация не удалась.")
        return

    # Запуск приложения
    app = QApplication(sys.argv)
    ui = UserInterface()
    ui.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
