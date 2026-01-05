import os
import logging
import requests
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

# === ВСТАВЬ СЮДА СВОИ API-КЛЮЧИ ===
SHODAN_API_KEY = "SHODAN_API_KEY"
ABUSEIPDB_API_KEY = "ABUSEIPDB_API_KEY"
VT_API_KEY = "VT_API_KEY"

# === Функции запросов к API ===

def get_shodan_info(ip):
    url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            ports = data.get("ports", [])
            hostnames = data.get("hostnames", [])
            org = data.get("org", "N/A")
            country = data.get("country_name", "N/A")
            return (
                f"🌍 *Shodan*:\n"
                f"Организация: `{org}`\n"
                f"Страна: `{country}`\n"
                f"Хосты: `{', '.join(hostnames) if hostnames else '—'}`\n"
                f"Открытые порты: `{ports}`"
            )
        else:
            return "🌍 *Shodan*: Информация не найдена или ошибка запроса."
    except Exception as e:
        return f"🌍 *Shodan*: Ошибка — `{str(e)}`"

def get_abuseipdb_info(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    try:
        r = requests.get(url, headers=headers, params=params, timeout=10)
        if r.status_code == 200:
            data = r.json().get("data", {})
            score = data.get("abuseConfidenceScore", "N/A")
            total_reports = data.get("totalReports", 0)
            last_report = data.get("lastReportedAt", "N/A")
            return (
                f"🚨 *AbuseIPDB*:\n"
                f"Уверенность в злонамеренности: `{score}%`\n"
                f"Всего жалоб: `{total_reports}`\n"
                f"Последняя жалоба: `{last_report}`"
            )
        else:
            return "🚨 *AbuseIPDB*: Не удалось получить данные."
    except Exception as e:
        return f"🚨 *AbuseIPDB*: Ошибка — `{str(e)}`"

def get_virustotal_info(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "x-apikey": VT_API_KEY
    }
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json().get("data", {}).get("attributes", {})
            as_owner = data.get("as_owner", "N/A")
            country = data.get("country", "N/A")
            reputation = data.get("reputation", 0)
            last_analysis = data.get("last_analysis_stats", {})
            malicious = last_analysis.get("malicious", 0)
            return (
                f"🦠 *VirusTotal*:\n"
                f"AS Владелец: `{as_owner}`\n"
                f"Страна: `{country}`\n"
                f"Репутация: `{reputation}`\n"
                f"Помечено как вредоносный: `{malicious}` движками"
            )
        else:
            return "🦠 *VirusTotal*: Данные не найдены или ограничение API."
    except Exception as e:
        return f"🦠 *VirusTotal*: Ошибка — `{str(e)}`"

# === Обработчики Telegram ===

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Привет! Пришлите IP-адрес, и я покажу информацию о нём из Shodan, AbuseIPDB и VirusTotal."
    )

async def handle_ip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ip = update.message.text.strip()
    # Простая проверка IP (можно улучшить регуляркой)
    if not (4 <= len(ip.split('.')) <= 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in ip.split('.'))):
        await update.message.reply_text("Пожалуйста, пришлите корректный IPv4-адрес.")
        return

    msg = await update.message.reply_text("🔍 Запрашиваю информацию...")

    shodan = get_shodan_info(ip)
    abuse = get_abuseipdb_info(ip)
    vt = get_virustotal_info(ip)

    full_report = f"🔍 Отчёт по IP `{ip}`:\n\n{shodan}\n\n{abuse}\n\n{vt}"
    await msg.edit_text(full_report, parse_mode="Markdown")

# === Запуск бота ===

def main():
    logging.basicConfig(level=logging.INFO)
    # Замени 'YOUR_TELEGRAM_BOT_TOKEN' на токен от @BotFather
    app = Application.builder().token("TELEGRAM_TOKEN").build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_ip))

    print("Бот запущен...")
    app.run_polling()

if __name__ == "__main__":
    main()
    