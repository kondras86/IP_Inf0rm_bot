import re
import os
import logging
import requests
import base64
from datetime import datetime
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

# === Настройка логирования ===
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# === Получаем API-ключи из переменных окружения ===
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")

# === Проверка наличия всех ключей ===
if not all([TELEGRAM_TOKEN, SHODAN_API_KEY, ABUSEIPDB_API_KEY, VT_API_KEY]):
    missing = []
    if not TELEGRAM_TOKEN: missing.append("TELEGRAM_TOKEN")
    if not SHODAN_API_KEY: missing.append("SHODAN_API_KEY")
    if not ABUSEIPDB_API_KEY: missing.append("ABUSEIPDB_API_KEY")
    if not VT_API_KEY: missing.append("VT_API_KEY")
    raise RuntimeError(f"Отсутствуют переменные окружения: {', '.join(missing)}")

logger.info("Все переменные окружения найдены. Запуск...")

# === Health Check Server (для Render) ===
class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/healthz':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'OK')
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        pass  # Подавляем логи HTTP-запросов

def run_health_server():
    server = HTTPServer(('0.0.0.0', 8080), HealthHandler)
    logger.info("Health check server запущен на порту 8080")
    server.serve_forever()

# === Функции запросов к API ===

def get_shodan_info(ip):
    # Исправлено: убраны пробелы в URL
    url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            ports = data.get("ports", [])
            hostnames = data.get("hostnames", [])
            org = data.get("org", "N/A")
            country = data.get("country_name", "N/A")
            asn = data.get("asn", "Неизвестно")
            city = data.get("city", "—")
            isp = data.get("isp", "—")
            domain = data.get("domains", []) or ["—"]
            
            return (
                f"3️⃣ *Shodan*\n"
                f"*Host:* `{ip}`\n"
                f"*ISP:* `{isp}`\n"
                f"*Org:* `{org}`\n"
                f"*ASN:* `{asn}`\n"
                f"*Hostnames:* `{', '.join(hostnames) if hostnames else '—'}`\n"
                f"*Domain:* `{', '.join(domain) if domain else '—'}`\n"
                f"*Country:* {country}\n"
                f"*City:* `{city}`\n"
                f"*Ports:* `{ports}`\n"
                f"[🔍 Shodan Link](https://www.shodan.io/host/{ip})"
            )
        else:
            return (
                f"3️⃣ *Shodan*\n"
                f"*Host:* `{ip}`\n"
                f"*Result:* Not Found in database 😐\n"
                f"[🔍 Shodan Link](https://www.shodan.io/host/{ip})"
            )
    except Exception as e:
        logger.error(f"Shodan error: {e}")
        return f"3️⃣ *Shodan*: Ошибка — `{str(e)}`"

def get_abuseipdb_info(ip):
    # Исправлено: убраны пробелы в URL
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
            score = data.get("abuseConfidenceScore", 0)
            total_reports = data.get("totalReports", 0)
            distinct_users = data.get("numDistinctUsers", 0)
            last_report = data.get("lastReportedAt", "N/A")
            isp = data.get("isp", "N/A")
            usage_type = data.get("usageType", "N/A")
            domain = data.get("domain", "N/A")
            country = data.get("countryCode", "N/A")
            
            # Упрощенный флаг (можно расширить словарь при необходимости)
            country_flag = "🌍" 
            if country == "RU": country_flag = "🇷🇺"
            elif country == "US": country_flag = "🇺🇸"
            elif country == "DE": country_flag = "🇩"
            elif country == "CN": country_flag = "🇨🇳"
            
            score_emoji = "🔴" if score >= 80 else "🟠" if score >= 50 else "🟡" if score >= 20 else "🟢"
            
            return (
                f"1️⃣ *AbuseIPDB*\n"
                f"*IP:* `{ip}`\n"
                f"*ISP:* `{isp}`\n"
                f"*Usage Type:* `{usage_type}`\n"
                f"*Domain:* `{domain}`\n"
                f"*Country:* {country_flag} {country}\n"
                f"*Score:* {score_emoji} {score}%\n"
                f"*Reports:* `{total_reports}` (by `{distinct_users}` users)\n"
                f"*Last Report:* `{last_report}`\n"
                f"[🔗 AbuseIPDB Link](https://www.abuseipdb.com/check/{ip})"
            )
        else:
            return (
                f"1️⃣ *AbuseIPDB*\n"
                f"*IP:* `{ip}`\n"
                f"*Result:* Not Found 😐\n"
                f"[🔗 AbuseIPDB Link](https://www.abuseipdb.com/check/{ip})"
            )
    except Exception as e:
        logger.error(f"AbuseIPDB error: {e}")
        return f"1️⃣ *AbuseIPDB*: Ошибка — `{str(e)}`"

def get_virustotal_info(ip):
    # Исправлено: убраны пробелы в URL
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
            suspicious = last_analysis.get("suspicious", 0)
            total_engines = sum(last_analysis.values())
            community_score = data.get("community_reputation", 0)
            reg_iri = data.get("regional_internet_registry", "N/A")
            
            country_flag = "🌍"
            if country == "RU": country_flag = "🇷"
            elif country == "US": country_flag = "🇺🇸"
            elif country == "DE": country_flag = "🇩🇪"
            
            malicious_emoji = "❗️" if malicious > 0 else "✅"
            suspicious_emoji = "⚠️" if suspicious > 0 else "✅"
            
            return (
                f"2️⃣ *VirusTotal*\n"
                f"*IP:* `{ip}`\n"
                f"*Owner:* `{as_owner}`\n"
                f"*Registry:* `{reg_iri}`\n"
                f"*Country:* {country_flag} {country}\n"
                f"*Malicious:* {malicious_emoji} {malicious} / {total_engines}\n"
                f"*Suspicious:* {suspicious_emoji} {suspicious} / {total_engines}\n"
                f"*Reputation:* {reputation}\n"
                f"[🔗 VT Link](https://www.virustotal.com/gui/ip-address/{ip})"
            )
        else:
            return (
                f"2️⃣ *VirusTotal*\n"
                f"*IP:* `{ip}`\n"
                f"*Result:* Not Found 😐\n"
                f"[🔗 VT Link](https://www.virustotal.com/gui/ip-address/{ip})"
            )
    except Exception as e:
        logger.error(f"VirusTotal IP error: {e}")
        return f"2️⃣ *VirusTotal*: Ошибка — `{str(e)}`"

def get_virustotal_url_info(url):
    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    # Исправлено: убраны пробелы
    vt_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        r = requests.get(vt_url, headers=headers, timeout=15)
        if r.status_code == 200:
            data = r.json().get("data", {}).get("attributes", {})
            last_analysis = data.get("last_analysis_stats", {})
            malicious = last_analysis.get("malicious", 0)
            suspicious = last_analysis.get("suspicious", 0)
            harmless = last_analysis.get("harmless", 0)
            total = sum(last_analysis.values())
            reputation = data.get("reputation", 0)
            categories = data.get("categories", [])
            first_submission = data.get("first_submission_date")
            last_analysis_date = data.get("last_analysis_date")

            def fmt_ts(ts):
                return datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC") if ts else "N/A"

            malicious_emoji = "🔴" if malicious > 0 else "🟢"

            return (
                f"🌐 *VirusTotal (URL)*\n"
                f"*Ссылка:* `{url}`\n"
                f"*Репутация:* `{reputation}`\n"
                f"*Вредоносная:* {malicious_emoji} `{malicious}` / `{total}`\n"
                f"*Подозрительная:* ⚠️ `{suspicious}` / `{total}`\n"
                f"*Категории:* `{', '.join(categories) if categories else '—'}`\n"
                f"*First seen:* `{fmt_ts(first_submission)}`\n"
                f"*Last analysis:* `{fmt_ts(last_analysis_date)}`\n"
                f"[🔍 VT Link](https://www.virustotal.com/gui/url/{encoded_url})"
            )
        elif r.status_code == 404:
            scan_url = "https://www.virustotal.com/api/v3/urls"
            scan_headers = {"x-apikey": VT_API_KEY, "Content-Type": "application/x-www-form-urlencoded"}
            scan_data = {"url": url}
            scan_r = requests.post(scan_url, headers=scan_headers, data=scan_data, timeout=15)
            if scan_r.status_code == 200:
                scan_id = scan_r.json().get("data", {}).get("id")
                return (
                    f"🌐 *VirusTotal (URL)*\n"
                    f"*Ссылка:* `{url}`\n"
                    f"*Результат:* URL не найден в базе. Отправлен на анализ.\n"
                    f"Результат будет доступен через несколько минут.\n"
                    f"[🔍 VT Link](https://www.virustotal.com/gui/url/{scan_id})"
                )
            else:
                return f"🌐 *VirusTotal (URL)*: Ошибка отправки на анализ."
        else:
            return f"🌐 *VirusTotal (URL)*: Ошибка API ({r.status_code})"
    except Exception as e:
        logger.error(f"VirusTotal URL error: {e}")
        return f"🌐 *VirusTotal (URL)*: Ошибка — `{str(e)}`"

# === Обработчики Telegram ===

async def handle_ip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()

    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if ip_pattern.match(text):
        parts = text.split('.')
        if all(0 <= int(part) <= 255 for part in parts):
            msg = await update.message.reply_text("🔍 Запрашиваю информацию об IP...")
            try:
                shodan = get_shodan_info(text)
                abuse = get_abuseipdb_info(text)
                vt = get_virustotal_info(text)
                full_report = f"🔍 *Информация об IP `{text}`:*\n\n{abuse}\n\n{vt}\n\n{shodan}"
                await msg.edit_text(full_report, parse_mode="Markdown", disable_web_page_preview=True)
            except Exception as e:
                await msg.edit_text(f"❌ Произошла ошибка при обработке: {str(e)}")
            return

    url_pattern = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE)
    if url_pattern.match(text):
        msg = await update.message.reply_text("🔍 Проверяю URL в VirusTotal...")
        try:
            vt_url_report = get_virustotal_url_info(text)
            await msg.edit_text(vt_url_report, parse_mode="Markdown", disable_web_page_preview=True)
        except Exception as e:
            await msg.edit_text(f"❌ Произошла ошибка при обработке: {str(e)}")
        return

    await update.message.reply_text(
        "Пожалуйста, отправьте:\n"
        "• IPv4-адрес (например, `8.8.8.8`), или\n"
        "• Ссылку (например, `https://example.com`)"
    )

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Привет! Я бот для проверки IP и URL.\n"
        "Отправьте:\n"
        "• IPv4-адрес (например, `8.8.8.8`), или\n"
        "• Ссылку (например, `https://example.com`)"
    )

def main():
    # Запуск Health Check сервера в отдельном потоке
    threading.Thread(target=run_health_server, daemon=True).start()
    
    logger.info("Запуск Telegram бота...")
    app = Application.builder().token(TELEGRAM_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_ip))

    print("Бот запущен и готов к работе!")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
