# Руководство по использованию

## Требования

- Python 3.9+
- Доступ к Audit Log API Яндекс 360
- OAuth токен с правами на чтение логов

## Установка

```bash
# Клонируй репозиторий
git clone https://github.com/твой-username/last-auth-users.git
cd last-auth-users

# Создай виртуальное окружение
python3 -m venv venv
source venv/bin/activate

# Установи зависимости
pip install -r requirements.txt

Настройка периода
Скрипт собирает данные за указанный период:

python
DATE_FROM = "2026-05-01"  # начало периода
DATE_TO   = "2026-05-31"  # конец периода

Частые ошибки

Ошибка	Причина	Решение
401 Unauthorized	Неверный токен	Проверь OAuth токен
403 Forbidden	Нет прав	Выдай права на Audit Log
404 Not Found	Неверный ORG_ID	Проверь ID организации
Нет записей	Нет событий за период	Измени период