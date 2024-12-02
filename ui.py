# ui.py

"""
Модуль для пользовательского интерфейса после авторизации.
Позволяет изменять настройки мониторинга, просматривать логи и состояние сервера.
"""

import logging
import re
import sqlite3
import threading
from datetime import datetime

import matplotlib
from PyQt6.QtCore import QTimer
from PyQt6.QtGui import QTextCursor
from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

matplotlib.use("QtAgg")  # Указываем бэкенд Matplotlib для PyQt6
# ui.py
import matplotlib
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

from db import DB_NAME
from monitor import monitor_sites

matplotlib.use("QtAgg")  # Указываем бэкенд Matplotlib для PyQt6


class UserInterface(QWidget):
    def __init__(self):
        super().__init__()  # Вызов конструктора базового класса

        self.setWindowTitle("Система мониторинга веб-сайтов")

        # Инициализация атрибутов
        self.sites = ["http://example.com", "http://example.org"]
        self.check_interval = 60
        self.admin_email = "admin@example.com"
        self.monitoring_thread = None
        self.monitoring_active = False
        self.stop_event = None

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # Поля для ввода настроек
        settings_layout = QHBoxLayout()

        # Сайты
        sites_layout = QVBoxLayout()
        sites_label = QLabel("Сайты для мониторинга (через запятую):")
        self.sites_input = QLineEdit(", ".join(self.sites))
        sites_layout.addWidget(sites_label)
        sites_layout.addWidget(self.sites_input)
        settings_layout.addLayout(sites_layout)

        # Интервал проверки
        interval_layout = QVBoxLayout()
        interval_label = QLabel("Интервал проверки (в секундах):")
        self.interval_input = QLineEdit(str(self.check_interval))
        interval_layout.addWidget(interval_label)
        interval_layout.addWidget(self.interval_input)
        settings_layout.addLayout(interval_layout)

        # Email администратора
        email_layout = QVBoxLayout()
        email_label = QLabel("Email администратора:")
        self.email_input = QLineEdit(self.admin_email)
        email_layout.addWidget(email_label)
        email_layout.addWidget(self.email_input)
        settings_layout.addLayout(email_layout)

        layout.addLayout(settings_layout)

        # Кнопки управления
        buttons_layout = QHBoxLayout()

        self.start_button = QPushButton("Запустить мониторинг")
        self.start_button.clicked.connect(self.start_monitoring)

        self.stop_button = QPushButton("Остановить мониторинг")
        self.stop_button.clicked.connect(self.stop_monitoring)
        self.stop_button.setEnabled(False)

        self.logs_button = QPushButton("Просмотреть логи")
        self.logs_button.clicked.connect(self.view_logs)

        buttons_layout.addWidget(self.start_button)
        buttons_layout.addWidget(self.stop_button)
        buttons_layout.addWidget(self.logs_button)

        layout.addLayout(buttons_layout)

        # Отображение состояния сервера
        status_label = QLabel("Состояние сервера:")
        self.status_table = QTableWidget()
        self.status_table.setColumnCount(4)
        self.status_table.setHorizontalHeaderLabels(
            ["Сайт", "Время ответа", "HTTP статус", "Дата и время"]
        )
        self.status_table.horizontalHeader().setStretchLastSection(True)

        layout.addWidget(status_label)
        layout.addWidget(self.status_table)

        # Кнопка для открытия графика
        self.graph_button = QPushButton("Показать график")
        self.graph_button.clicked.connect(self.show_graph)
        layout.addWidget(self.graph_button)

        # Устанавливаем основной макет для виджета
        self.setLayout(layout)

        # Таймер для обновления состояния
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_status)
        self.timer.start(5000)  # Обновление каждые 5 секунд

    def closeEvent(self, event):
        # Останавливаем мониторинг, если он активен
        if self.monitoring_active:
            self.stop_monitoring()
        event.accept()  # Продолжаем закрытие окна

    def show_graph(self):
        selected_items = self.status_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(
                self,
                "Ошибка",
                "Пожалуйста, выберите запись в таблице для отображения графика.",
            )
            return

        # Получаем URL сайта из первой колонки выбранной строки
        row = selected_items[0].row()
        site_url_item = self.status_table.item(row, 0)
        if site_url_item:
            site_url = site_url_item.text()
            graph_window = GraphWindow(site_url)
            graph_window.exec()

    def is_valid_email(self, email):
        """
        Проверяет корректность email-адреса.
        """
        # Простое регулярное выражение для проверки email
        pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
        return re.match(pattern, email) is not None

    def start_monitoring(self):
        if self.monitoring_active:
            QMessageBox.warning(self, "Внимание", "Мониторинг уже запущен.")
            return

        # Получение настроек
        input_sites = [site.strip() for site in self.sites_input.text().split(",")]
        try:
            self.check_interval = int(self.interval_input.text())
            if self.check_interval <= 0:
                raise ValueError
        except ValueError:
            QMessageBox.warning(
                self, "Ошибка", "Интервал проверки должен быть положительным числом."
            )
            return
        self.admin_email = self.email_input.text()

        # Проверка корректности email
        if not self.is_valid_email(self.admin_email):
            QMessageBox.warning(
                self, "Ошибка", f"Некорректный email-адрес: {self.admin_email}"
            )
            return

        # Создаём новый список для обработанных сайтов
        processed_sites = []
        for site in input_sites:
            if not site.startswith(("http://", "https://")):
                reply = QMessageBox.question(
                    self,
                    "Некорректный URL",
                    f'Сайт "{site}" не содержит "http://" или "https://". Хотите автоматически добавить "http://"?',
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                )
                if reply == QMessageBox.StandardButton.Yes:
                    site = "http://" + site
                    processed_sites.append(site)
                else:
                    QMessageBox.warning(self, "Ошибка", f"Некорректный URL: {site}")
                    return
            else:
                processed_sites.append(site)

        self.sites = processed_sites

        # Запуск мониторинга в отдельном потоке
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(target=self.run_monitoring)
        self.monitoring_thread.start()

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)

        logging.info("Мониторинг запущен.")

    def run_monitoring(self):
        self.stop_event = threading.Event()
        monitor_sites(
            self.sites, self.check_interval, self.admin_email, self.stop_event
        )

    def stop_monitoring(self):
        if not self.monitoring_active:
            return

        self.stop_event.set()
        self.monitoring_thread.join()  # Дождаться завершения потока
        self.monitoring_active = False

        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

        logging.info("Мониторинг остановлен.")

    def view_logs(self):
        try:
            with open("monitoring.log", "r", encoding="utf-8", errors="replace") as f:
                logs = f.read()
            log_window = LogWindow(logs)
            log_window.exec()
        except FileNotFoundError:
            QMessageBox.warning(self, "Ошибка", "Лог-файл не найден.")

    def update_status(self):
        # Подключение к базе данных и получение последних записей
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT site_url, response_time, http_status, check_datetime
            FROM monitoring_records
            ORDER BY id DESC
            LIMIT 10
        """)

        records = cursor.fetchall()
        conn.close()

        # Обновление таблицы
        self.status_table.setRowCount(len(records))
        for row_index, row_data in enumerate(records):
            for column_index, data in enumerate(row_data):
                if data is None:
                    data = "Ошибка"
                elif isinstance(data, float):
                    data = f"{data:.2f} с"
                self.status_table.setItem(
                    row_index, column_index, QTableWidgetItem(str(data))
                )


class LogWindow(QDialog):
    def __init__(self, logs):
        super().__init__()
        self.setWindowTitle("Логи системы")
        self.setMinimumWidth(600)
        self.setMinimumHeight(400)

        layout = QVBoxLayout()

        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(True)
        self.text_edit.setText(logs)
        self.text_edit.moveCursor(QTextCursor.MoveOperation.End)  # Прокручиваем к концу
        layout.addWidget(self.text_edit)

        self.close_button = QPushButton("Закрыть")
        self.close_button.clicked.connect(self.close)
        layout.addWidget(self.close_button)

        self.setLayout(layout)


class GraphWindow(QDialog):
    def __init__(self, site_url):
        super().__init__()
        self.setWindowTitle(f"График состояния сайта: {site_url}")
        self.setMinimumWidth(800)
        self.setMinimumHeight(600)

        layout = QVBoxLayout()

        self.figure = Figure()
        self.canvas = FigureCanvas(self.figure)
        layout.addWidget(self.canvas)

        self.load_data(site_url)

        self.setLayout(layout)

    def load_data(self, site_url):
        # Получаем данные из базы данных
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT check_datetime, response_time, http_status
            FROM monitoring_records
            WHERE site_url = ?
            ORDER BY id ASC
        """,
            (site_url,),
        )

        data = cursor.fetchall()
        conn.close()

        if not data:
            QMessageBox.warning(self, "Ошибка", "Нет данных для отображения.")
            return

        timestamps = [datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S") for row in data]
        response_times = [row[1] if row[1] is not None else 0 for row in data]
        http_statuses = [row[2] if row[2] is not None else 0 for row in data]

        # Построение графика
        ax = self.figure.add_subplot(111)
        ax.clear()

        # График времени ответа
        ax.plot(timestamps, response_times, label="Время ответа (с)")

        # Отображение HTTP статусов как точек
        for i, status in enumerate(http_statuses):
            color = "green" if status and status < 400 else "red"
            ax.scatter(timestamps[i], response_times[i], color=color)

        ax.set_xlabel("Время проверки")
        ax.set_ylabel("Время ответа (с)")
        ax.set_title(f"Состояние сайта: {site_url}")
        ax.legend()
        ax.grid(True)

        self.figure.autofmt_xdate()
        self.canvas.draw()


class LogWindow(QDialog):
    def __init__(self, logs):
        super().__init__()
        self.setWindowTitle("Логи системы")
        self.setMinimumWidth(600)
        self.setMinimumHeight(400)

        layout = QVBoxLayout()

        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(True)
        self.text_edit.setText(logs)
        self.text_edit.moveCursor(QTextCursor.MoveOperation.End)  # Прокручиваем к концу
        layout.addWidget(self.text_edit)

        self.close_button = QPushButton("Закрыть")
        self.close_button.clicked.connect(self.close)
        layout.addWidget(self.close_button)

        self.setLayout(layout)


class GraphWindow(QDialog):
    def __init__(self, site_url):
        super().__init__()
        self.setWindowTitle(f"График состояния сайта: {site_url}")
        self.setMinimumWidth(800)
        self.setMinimumHeight(600)

        layout = QVBoxLayout()

        self.figure = Figure()
        self.canvas = FigureCanvas(self.figure)
        layout.addWidget(self.canvas)

        self.load_data(site_url)

        self.setLayout(layout)

    def load_data(self, site_url):
        # Получаем данные из базы данных
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT check_datetime, response_time, http_status
            FROM monitoring_records
            WHERE site_url = ?
            ORDER BY id ASC
        """,
            (site_url,),
        )

        data = cursor.fetchall()
        conn.close()

        if not data:
            QMessageBox.warning(self, "Ошибка", "Нет данных для отображения.")
            return

        timestamps = [datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S") for row in data]
        response_times = [row[1] if row[1] is not None else 0 for row in data]
        http_statuses = [row[2] if row[2] is not None else 0 for row in data]

        # Построение графика
        ax = self.figure.add_subplot(111)
        ax.clear()

        # График времени ответа
        ax.plot(timestamps, response_times, label="Время ответа (с)")

        # Отображение HTTP статусов как точек
        for i, status in enumerate(http_statuses):
            color = "green" if status and status < 400 else "red"
            ax.scatter(timestamps[i], response_times[i], color=color)

        ax.set_xlabel("Время проверки")
        ax.set_ylabel("Время ответа (с)")
        ax.set_title(f"Состояние сайта: {site_url}")
        ax.legend()
        ax.grid(True)

        self.figure.autofmt_xdate()
        self.canvas.draw()
