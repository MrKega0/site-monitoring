# monitor.py

import requests
import time
from datetime import datetime
from db import insert_monitoring_record
from notifier import send_email_notification
import logging

def monitor_sites(sites: list, check_interval: int, admin_email: str, stop_event):
    """
    Автоматически мониторит список сайтов с заданным интервалом.
    """
    logging.info('Начало мониторинга сайтов.')

    while not stop_event.is_set():
        for site in sites:
            if stop_event.is_set():
                break
            try:
                # Проверяем, является ли URL корректным
                if not site.startswith(('http://', 'https://')):
                    raise ValueError(f'Некорректный URL: {site}')

                start_time = time.time()
                response = requests.get(site, timeout=5)  # Уменьшили таймаут до 5 секунд
                response_time = time.time() - start_time
                http_status = response.status_code
                check_datetime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                insert_monitoring_record(site, response_time, http_status, check_datetime)

                if http_status >= 400:
                    send_email_notification(admin_email, site, f'HTTP {http_status}')
                    logging.warning(f'Сайт {site} вернул ошибку HTTP {http_status}.')

            except ValueError as ve:
                # Обрабатываем некорректный URL
                response_time = None
                http_status = None
                check_datetime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                insert_monitoring_record(site, response_time, http_status, check_datetime)
                send_email_notification(admin_email, site, str(ve))
                logging.error(f'Ошибка при проверке сайта {site}: {ve}')

            except requests.RequestException as e:
                # Обрабатываем ошибки запросов
                response_time = None
                http_status = None
                check_datetime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                insert_monitoring_record(site, response_time, http_status, check_datetime)
                send_email_notification(admin_email, site, 'Сайт недоступен')
                logging.error(f'Ошибка при доступе к сайту {site}: {e}')

            except Exception as e:
                # Обрабатываем другие возможные исключения
                response_time = None
                http_status = None
                check_datetime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                insert_monitoring_record(site, response_time, http_status, check_datetime)
                send_email_notification(admin_email, site, 'Неизвестная ошибка')
                logging.error(f'Неизвестная ошибка при проверке сайта {site}: {e}')

        # Используем stop_event.wait()
        if stop_event.wait(timeout=check_interval):
            # Если stop_event установлен, выходим из цикла
            break

    logging.info('Мониторинг сайтов остановлен.')
