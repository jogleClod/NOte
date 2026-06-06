# NoteVault

Веб-сервис для хранения личных заметок с возможностью прикреплять файлы.

## Стек

- Python 3 + Flask
- SQLite (файл `notevault.db` создаётся автоматически)
- Без Docker, без внешних зависимостей кроме Flask

## Запуск (< 2 минут)

```bash
# 1. Клонировать репозиторий
git clone <repo-url>
cd notevault

# 2. Установить зависимости
pip install -r requirements.txt

# 3. Запустить
python app.py
```

Приложение поднимется на http://localhost:5000

## Ветки

- `vulnerable` — исходная версия с уязвимостями
- `fixed` — исправленная версия

## Структура

```
notevault/
├── app.py              # Основное приложение
├── requirements.txt
├── uploads/            # Загружаемые файлы (создаётся автоматически)
├── templates/
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── new_note.html
│   └── view_note.html
└── static/css/style.css
```

## Функциональность

- Регистрация и вход
- Создание/просмотр/удаление заметок
- Поиск по заметкам
- Прикрепление файлов к заметкам
