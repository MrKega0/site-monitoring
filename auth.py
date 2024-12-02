# auth.py
"""
Модуль для авторизации и регистрации пользователей с использованием PyQt6.
"""

import sys
from PyQt6.QtWidgets import (
    QApplication,
    QWidget,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QMessageBox,
)
from db import validate_user, add_user, user_exists
import logging


class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Авторизация")

        self.layout = QVBoxLayout()

        self.username_label = QLabel("Логин:")
        self.username_input = QLineEdit()

        self.password_label = QLabel("Пароль:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.login_button = QPushButton("Войти")
        self.login_button.clicked.connect(self.handle_login)

        self.register_button = QPushButton("Регистрация")
        self.register_button.clicked.connect(self.handle_register)

        self.layout.addWidget(self.username_label)
        self.layout.addWidget(self.username_input)
        self.layout.addWidget(self.password_label)
        self.layout.addWidget(self.password_input)
        self.layout.addWidget(self.login_button)
        self.layout.addWidget(self.register_button)

        self.setLayout(self.layout)

        self.is_authenticated = False

    def handle_login(self):
        username = self.username_input.text()
        password = self.password_input.text()

        if not username or not password:
            QMessageBox.warning(self, "Ошибка", "Пожалуйста, введите логин и пароль.")
            return

        if validate_user(username, password):
            QMessageBox.information(self, "Успех", "Авторизация успешна!")
            self.is_authenticated = True
            self.close()
        else:
            QMessageBox.warning(self, "Ошибка", "Неверный логин или пароль.")

    def handle_register(self):
        username = self.username_input.text()
        password = self.password_input.text()

        if not username or not password:
            QMessageBox.warning(
                self, "Ошибка", "Введите логин и пароль для регистрации."
            )
            return

        if len(password) < 6:
            QMessageBox.warning(
                self, "Ошибка", "Пароль должен содержать не менее 6 символов."
            )
            return

        if user_exists(username):
            QMessageBox.warning(
                self, "Ошибка", "Пользователь с таким логином уже существует."
            )
            return

        add_user(username, password)
        QMessageBox.information(
            self, "Успех", "Регистрация успешна! Теперь вы можете войти."
        )
        logging.info(f"Новый пользователь зарегистрирован: {username}")


def authenticate_user():
    app = QApplication(sys.argv)
    login_window = LoginWindow()
    login_window.show()
    app.exec()

    return login_window.is_authenticated
