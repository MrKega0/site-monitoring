# main.py

import logging
from db import create_tables
from auth import authenticate_user
from ui import UserInterface
from dotenv import load_dotenv

load_dotenv()

def main():
    # Настройка логирования с указанием кодировки UTF-8
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s:%(message)s',
        filename='monitoring.log',
        filemode='a',
        encoding='utf-8'  # Указываем кодировку
    )

    logging.info('Запуск системы мониторинга.')

    # Инициализация базы данных
    create_tables()

    # Авторизация пользователя
    if not authenticate_user():
        logging.warning('Авторизация не удалась.')
        print('Авторизация не удалась.')
        return

    # Запуск пользовательского интерфейса после авторизации
    app = UserInterface()
    app.run()

if __name__ == '__main__':
    main()
