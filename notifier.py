# notifier.py

import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging


def send_email_notification(admin_email: str, site: str, error: str):
    """
    Отправляет уведомление администратору о сбое сайта.
    """
    sender_email = os.getenv("SENDER_EMAIL")
    sender_password = os.getenv("EMAIL_PASSWORD")
    receiver_email = admin_email

    # Проверяем, что переменные окружения загружены
    if not sender_email or not sender_password:
        logging.error(
            "Email отправителя или пароль не установлены в переменных окружения."
        )
        return

    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = f"Сбой мониторинга сайта: {site}"

    text = f"Обнаружена ошибка при мониторинге {site}. Ошибка: {error}"
    message.attach(MIMEText(text, "plain", "utf-8"))

    try:
        server = smtplib.SMTP_SSL("smtp.yandex.ru", 465)
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, receiver_email, message.as_string())
        server.quit()
        logging.info(
            f"Email-уведомление отправлено администратору о проблеме с сайтом {site}."
        )
    except Exception as e:
        logging.error(f"Не удалось отправить email: {e}")
