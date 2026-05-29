#!/usr/bin/env python3

# ============================================================
#                     НАСТРОЙКИ СКРИПТА
# ============================================================

ORG_ID      = ""            # ID организации Яндекс 360
TOKEN       = ""       # OAuth токен
DATE_FROM   = "2026-05-18"         # Начало периода (YYYY-MM-DD)
DATE_TO     = "2026-05-22"         # Конец периода  (YYYY-MM-DD)
OUTPUT_FILE = "last_logins.csv"    # Имя выходного файла
PAGE_SIZE   = 100                  # Размер страницы (макс. 100)

# ============================================================

import csv
import requests
import sys
from datetime import datetime, timezone
from dateutil import parser as date_parser


# Типы событий которые считаем успешной авторизацией
LOGIN_EVENT_TYPES = {
    "id_account.login",
    "id_account.auth",
    "passport.login",
    "passport.auth",
    "login",
    "auth",
}


def get_audit_logs(date_from: datetime, date_to: datetime) -> list:
    url = f"https://cloud-api.yandex.net/v1/auditlog/organizations/{ORG_ID}/events"

    headers = {
        "Authorization": f"OAuth {TOKEN}",
        "Content-Type": "application/json",
    }

    params = {
        "count":      PAGE_SIZE,
        "started_at": date_from.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
        "ended_at":   date_to.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
    }

    all_logs = []
    page_num = 1

    print(f"\n📡 Начинаем получение логов...")
    print(f"   URL: {url}")
    print(f"   Период: {params['started_at']} → {params['ended_at']}")

    while True:
        print(f"   Загружаем страницу {page_num}...", end=" ")

        try:
            response = requests.get(url, headers=headers, params=params, timeout=30)
        except requests.exceptions.ConnectionError:
            print("\n❌ Ошибка подключения. Проверьте интернет-соединение.")
            sys.exit(1)
        except requests.exceptions.Timeout:
            print("\n❌ Превышено время ожидания ответа от сервера.")
            sys.exit(1)

        if response.status_code == 401:
            print("\n❌ Ошибка авторизации. Проверьте OAuth токен.")
            print(f"   Ответ сервера: {response.text}")
            sys.exit(1)
        elif response.status_code == 403:
            print("\n❌ Доступ запрещён. Проверьте права токена.")
            print(f"   Ответ сервера: {response.text}")
            sys.exit(1)
        elif response.status_code == 404:
            print("\n❌ Не найдено. Проверьте ORG_ID.")
            print(f"   Ответ сервера: {response.text}")
            sys.exit(1)
        elif response.status_code != 200:
            print(f"\n❌ Ошибка API: {response.status_code}")
            print(f"   Ответ: {response.text}")
            sys.exit(1)

        data   = response.json()
        events = data.get("items", [])
        all_logs.extend(events)

        print(f"получено записей: {len(events)} (всего: {len(all_logs)})")

        # Пагинация через iteration_key
        iteration_key = data.get("iteration_key", "")
        if not iteration_key or len(events) < PAGE_SIZE:
            break

        params["iteration_key"] = iteration_key
        page_num += 1

    print(f"\n✅ Загрузка завершена. Всего записей: {len(all_logs)}")
    return all_logs


def detect_platform(record: dict) -> str:
    event_type = record.get("event", {}).get("type", "").lower()

    if event_type == "id_cookie.set":
        return "Браузер"
    elif event_type == "id_nondevice_token.issued":
        return "OAuth-токен"
    elif event_type == "id_device_token.issued":
        return "Мобильное приложение"
    elif event_type == "id_app_password.login":
        return "Пароль приложения"
    elif event_type == "id_account.login":
        return "Браузер"
    elif event_type == "id_account.auth":
        return "Браузер"
    else:
        return event_type


def is_success_auth_event(record: dict) -> bool:
    event = record.get("event", {})

    event_type = event.get("type", "").lower()
    status     = event.get("status", "").lower()

    # Статус должен быть Success
    if status != "success":
        return False

    # Все типы событий которые считаем авторизацией
    AUTH_TYPES = {
        "id_account.login",
        "id_account.auth",
        "id_app_password.login",
        "id_cookie.set",
        "id_device_token.issued",
        "id_nondevice_token.issued",
        "passport.login",
        "passport.auth",
    }

    if event_type in AUTH_TYPES:
        return True

    return False



def extract_user(record: dict) -> str:
    """
    Извлекает логин пользователя из записи.
    """
    # Сначала пробуем верхний уровень
    user_login = record.get("user_login", "")
    if user_login:
        return user_login

    # Потом внутри event
    event = record.get("event", {})
    for field in ["user_login", "login", "email", "user_email"]:
        value = event.get(field, "")
        if value:
            return value

    return None


def extract_datetime(record: dict) -> datetime:
    event = record.get("event", {})

    timestamp_fields = ["occurred_at", "eventTime", "timestamp", "createdAt", "created_at"]

    for field in timestamp_fields:
        ts = event.get(field) or record.get(field)
        if ts:
            try:
                # Убираем конвертацию в UTC — оставляем время как есть
                dt = date_parser.parse(ts)
                return dt.replace(tzinfo=None)
            except (ValueError, TypeError):
                continue

    return None



def extract_ip(record: dict) -> str:
    event = record.get("event", {})
    ip = event.get("ip", "")
    # Игнорируем системный IP ::1
    if ip and ip != "::1":
        return ip
    return ""


def process_logs(logs: list) -> dict:
    print(f"\n🔍 Обрабатываем {len(logs)} записей...")

    # Показываем уникальные типы событий для информации
    event_types = set()
    for record in logs:
        et = record.get("event", {}).get("type", "")
        if et:
            event_types.add(et)
    print(f"\n   📋 Типы событий в выборке: {sorted(event_types)}")

    last_logins = {}
    success_count = 0
    skipped_count = 0

    for record in logs:
        if not is_success_auth_event(record):
            skipped_count += 1
            continue

        user = extract_user(record)
        if not user:
            skipped_count += 1
            continue

        event_dt = extract_datetime(record)
        if not event_dt:
            skipped_count += 1
            continue

        success_count += 1

        if user not in last_logins or event_dt > last_logins[user]["datetime"]:
            last_logins[user] = {
                "datetime":    event_dt,
                "platform":    detect_platform(record),
                "event_type":  record.get("event", {}).get("type", ""),
                "ip":          extract_ip(record),
                "user_name":   record.get("user_name", ""),
            }

    print(f"\n   ✓ Успешных авторизаций: {success_count}")
    print(f"   ✗ Пропущено: {skipped_count}")
    print(f"   👤 Уникальных пользователей: {len(last_logins)}")

    return last_logins


def save_csv(last_logins: dict) -> None:
    fieldnames = [
        "Пользователь",
        "Имя",
        "Дата последней авторизации",
        "Время последней авторизации",
        "Платформа",
        "IP адрес",
        "Тип события",
    ]

    rows = []
    for user, data in last_logins.items():
        rows.append({
            "Пользователь":                user,
            "Имя":                         data["user_name"],
            "Дата последней авторизации":  data["datetime"].strftime("%d.%m.%Y"),
            "Время последней авторизации": data["datetime"].strftime("%H:%M:%S"),
            "Платформа":                   data["platform"],
            "IP адрес":                    data["ip"],
            "Тип события":                 data["event_type"],
        })

    rows.sort(
        key=lambda x: datetime.strptime(
            f"{x['Дата последней авторизации']} {x['Время последней авторизации']}",
            "%d.%m.%Y %H:%M:%S"
        ),
        reverse=True
    )

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=";")
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n💾 Файл сохранён: {OUTPUT_FILE}")
    print(f"   Строк в файле: {len(rows)}")


def main():
    print("=" * 50)
    print("  Яндекс 360 — Сбор последних авторизаций")
    print("=" * 50)

    date_from = datetime.strptime(DATE_FROM, "%Y-%m-%d").replace(hour=0,  minute=0,  second=0)
    date_to   = datetime.strptime(DATE_TO,   "%Y-%m-%d").replace(hour=23, minute=59, second=59)

    if date_from > date_to:
        print("❌ Ошибка: DATE_FROM не может быть позже DATE_TO")
        sys.exit(1)

    logs = get_audit_logs(date_from, date_to)

    if not logs:
        print("\n⚠️  Логи за указанный период не найдены.")
        sys.exit(0)

    last_logins = process_logs(logs)

    if not last_logins:
        print("\n⚠️  Успешных авторизаций не найдено.")
        sys.exit(0)

    save_csv(last_logins)
    print("\n✅ Готово!")


if __name__ == "__main__":
    main()
