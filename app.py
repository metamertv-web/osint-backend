import os
import re
import shutil
import subprocess
import tempfile
import time
from datetime import datetime

from flask import Flask, request, send_file, jsonify, after_this_request
from flask_cors import CORS

app = Flask(__name__)
# На проде замени "*" на домен своего Vercel-фронтенда
CORS(app, origins=os.environ.get("ALLOWED_ORIGIN", "*"))

EMAIL_RE = re.compile(r"^[^@\s,;<>\"'`|&$-][^@\s,;<>\"'`|&$]*@[^@\s,;<>\"'`|&$]+\.[A-Za-z]{2,}$")
PHONE_RE = re.compile(r"^\+?\d{7,15}$")
NICK_RE = re.compile(r"^[A-Za-z0-9_.\-]{2,40}$")

# Простейший rate limit в памяти: 1 запрос / 20 сек с одного IP
_last_hit = {}
RATE_SECONDS = 20


def client_ip():
    fwd = request.headers.get("X-Forwarded-For", "")
    return fwd.split(",")[0].strip() if fwd else request.remote_addr


def run(cmd, timeout=150):
    """Запуск консольной утилиты без shell (защита от инъекций)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (p.stdout or "") + (("\n[stderr]\n" + p.stderr) if p.stderr.strip() else "")
    except subprocess.TimeoutExpired:
        return f"[!] Таймаут: {' '.join(cmd[:2])} работал дольше {timeout} сек."
    except FileNotFoundError:
        return f"[!] Утилита не найдена: {cmd[0]}"


def scan_email(email):
    # "--" не нужен: EMAIL_RE запрещает ведущий дефис
    return run(["holehe", email, "--only-used", "--no-color"], timeout=150)


def scan_phone(phone):
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone

    out = []
    try:
        num = phonenumbers.parse(phone if phone.startswith("+") else "+" + phone)
        out.append(f"Валиден: {phonenumbers.is_valid_number(num)}")
        out.append(f"Международный формат: {phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.INTERNATIONAL)}")
        out.append(f"Регион: {geocoder.description_for_number(num, 'ru')}")
        out.append(f"Оператор: {carrier.name_for_number(num, 'ru') or 'н/д'}")
        out.append(f"Часовые пояса: {', '.join(timezone.time_zones_for_number(num))}")
    except Exception as e:
        out.append(f"[!] Ошибка разбора номера: {e}")

    # PhoneInfoga (Go-бинарник). Если установлен в образ — используем.
    # Утилиты "phonsint" не существует; ближайшая — phoneinfoga.
    if shutil.which("phoneinfoga"):
        out.append("\n--- phoneinfoga ---")
        out.append(run(["phoneinfoga", "scan", "-n", phone], timeout=90))
    return "\n".join(out)


def scan_username(username, workdir):
    out = run(
        ["maigret", username, "-J", "ndjson", "--folderoutput", workdir,
         "--top-sites", "300", "--timeout", "10", "--retries", "0",
         "--no-progressbar", "--no-color"],
        timeout=160,
    )
    # Добавляем найденные профили из ndjson-отчёта
    for name in sorted(os.listdir(workdir)):
        if name.endswith(".ndjson") or name.endswith(".json"):
            with open(os.path.join(workdir, name), encoding="utf-8", errors="ignore") as f:
                out += f"\n\n--- {name} ---\n" + f.read()
    return out


@app.get("/")
def health():
    return jsonify(status="ok")


@app.get("/api/search")
def search():
    q = (request.args.get("q") or "").strip()
    if not q or len(q) > 100:
        return jsonify(error="Пустой или слишком длинный запрос"), 400

    ip = client_ip()
    now = time.time()
    if now - _last_hit.get(ip, 0) < RATE_SECONDS:
        return jsonify(error="Слишком часто. Подожди немного."), 429
    _last_hit[ip] = now

    workdir = tempfile.mkdtemp(prefix="osint_")

    @after_this_request
    def cleanup(resp):
        # Сервер "забывает" запрос: удаляем всё после отправки
        shutil.rmtree(workdir, ignore_errors=True)
        return resp

    if "@" in q:
        if not EMAIL_RE.match(q):
            return jsonify(error="Некорректная почта"), 400
        kind, result = "email", scan_email(q)
    elif q.startswith("+") or q.isdigit():
        if not PHONE_RE.match(q):
            return jsonify(error="Некорректный номер"), 400
        kind, result = "phone", scan_phone(q)
    else:
        if not NICK_RE.match(q):
            return jsonify(error="Некорректный ник (буквы, цифры, _ . -)"), 400
        kind, result = "username", scan_username(q, workdir)

    path = os.path.join(workdir, "result.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"Тип: {kind}\nЗапрос: {q}\nДата: {datetime.utcnow().isoformat()}Z\n{'=' * 40}\n\n{result}\n")

    return send_file(path, as_attachment=True, download_name=f"result_{kind}.txt", mimetype="text/plain")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
