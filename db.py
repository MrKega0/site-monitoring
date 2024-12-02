# db.py
"""
Модуль для работы с базой данных SQLite.
Обеспечивает создание таблиц и безопасные операции с базой данных.
"""

import sqlite3
import hashlib
import os
import logging

DB_NAME = 'monitoring.db'

def create_tables():
    """
    Создает таблицы пользователей и записей мониторинга.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Таблица пользователей
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL
    )
    ''')

    # Таблица записей мониторинга
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS monitoring_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        site_url TEXT NOT NULL,
        response_time REAL,
        http_status INTEGER,
        check_datetime TEXT NOT NULL
    )
    ''')

    conn.commit()
    conn.close()
    logging.info('Таблицы созданы или уже существуют.')

def hash_password(password: str, salt: str = None) -> tuple:
    """
    Возвращает хешированный пароль и соль.
    """
    if not salt:
        salt = os.urandom(32).hex()
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
    return pwd_hash, salt

def add_user(username: str, password: str):
    """
    Добавляет нового пользователя в базу данных с хешированным паролем.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    pwd_hash, salt = hash_password(password)

    try:
        cursor.execute('INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)', (username, pwd_hash, salt))
        conn.commit()
        logging.info(f'Добавлен новый пользователь: {username}')
    except sqlite3.IntegrityError:
        logging.warning(f'Пользователь {username} уже существует.')
    finally:
        conn.close()

def validate_user(username: str, password: str) -> bool:
    """
    Проверяет соответствие логина и пароля пользователя.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute('SELECT password_hash, salt FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()

    conn.close()

    if result:
        stored_hash, salt = result
        pwd_hash, _ = hash_password(password, salt)
        if pwd_hash == stored_hash:
            logging.info(f'Пользователь {username} успешно авторизован.')
            return True
        else:
            logging.warning(f'Неверный пароль для пользователя {username}.')
            return False
    else:
        logging.warning(f'Пользователь {username} не найден.')
        return False

def insert_monitoring_record(site_url: str, response_time: float, http_status: int, check_datetime: str):
    """
    Вставляет запись мониторинга в базу данных.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute('''
    INSERT INTO monitoring_records (site_url, response_time, http_status, check_datetime)
    VALUES (?, ?, ?, ?)
    ''', (site_url, response_time, http_status, check_datetime))

    conn.commit()
    conn.close()
    logging.info(f'Запись мониторинга добавлена для {site_url} с статусом {http_status}.')

def get_latest_records(limit=10):
    """
    Возвращает последние записи мониторинга.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT site_url, response_time, http_status, check_datetime
        FROM monitoring_records
        ORDER BY id DESC
        LIMIT ?
    ''', (limit,))
    records = cursor.fetchall()
    conn.close()
    return records

def user_exists(username: str) -> bool:
    """
    Проверяет, существует ли пользователь с данным логином.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()

    conn.close()

    return result is not None
