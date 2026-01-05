import re
import os
import logging
import requests
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

# Получаем API-ключи из переменных окружения
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")

# Проверка, что все ключи заданы
if not all([TELEGRAM_TOKEN, SHODAN_API_KEY, ABUSEIPDB_API_KEY, VT_API_KEY]):
    raise RuntimeError("Одна или несколько переменных окружения не заданы!")

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
            asn = data.get("asn", "Неизвестно")
            city = data.get("city", "—")
            isp = data.get("isp", "—")
            domain = data.get("domains", []) or ["—"]
            
            return (
                f"3️⃣ *Shodan*\n"
                f"*Host:* `{ip}`\n"
                f"*ISP:* `{isp}`\n"
                f"*Тип использования:* `Дата-центр/Веб-хостинг/Транзит`\n"
                f"*ASN:* `{asn}`\n"
                f"*Имя хозяина(ы):* `{', '.join(hostnames) if hostnames else '—'}`\n"
                f"*Доменное имя:* `{', '.join(domain) if domain else '—'}`\n"
                f"*Кантри:* 🇩🇪 {country}\n"
                f"*Город:* `{city}`\n"
                f"*Открытые порты:* `{ports}`\n"
                f"[🔍 Просмотреть на Shodan](https://www.shodan.io/host/{ip})"
            )
        else:
            return (
                f"3️⃣ *Shodan*\n"
                f"*Host:* `{ip}`\n"
                f"*Result:* Not Found in database 😐\n"
                f"[🔍 Просмотреть на Shodan](https://www.shodan.io/host/{ip})"
            )
    except Exception as e:
        return f"3️⃣ *Shodan*: Ошибка — `{str(e)}`"

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
            score = data.get("abuseConfidenceScore", 0)
            total_reports = data.get("totalReports", 0)
            distinct_users = data.get("numDistinctUsers", 0)
            last_report = data.get("lastReportedAt", "N/A")
            isp = data.get("isp", "N/A")
            usage_type = data.get("usageType", "N/A")
            domain = data.get("domain", "N/A")
            country = data.get("countryCode", "N/A")
            country_flag = {
                "DE": "🇩🇪",
                "US": "🇺🇸",
                "RU": "🇷🇺",
                "CN": "🇨🇳",
                "FR": "🇫🇷",
                "GB": "🇬🇧",
                "JP": "🇯🇵",
                "BR": "🇧🇷",
                "IN": "🇮🇳",
                "CA": "🇨🇦",
                "AU": "🇦🇺",
                "IT": "🇮🇹",
                "ES": "🇪🇸",
                "NL": "🇳🇱",
                "CH": "🇨🇭",
                "SE": "🇸🇪",
                "NO": "🇳🇴",
                "PL": "🇵🇱",
                "TR": "🇹🇷",
                "KR": "🇰🇷",
                "SG": "🇸🇬",
                "MX": "🇲🇽",
                "ZA": "🇿🇦",
                "AR": "🇦🇷",
                "PT": "🇵🇹",
                "BE": "🇧🇪",
                "AT": "🇦🇹",
                "DK": "🇩🇰",
                "FI": "🇫🇮",
                "GR": "🇬🇷",
                "HU": "🇭🇺",
                "CZ": "🇨🇿",
                "RO": "🇷🇴",
                "IL": "🇮🇱",
                "CL": "🇨🇱",
                "CO": "🇨🇴",
                "PE": "🇵🇪",
                "VE": "🇻🇪",
                "EC": "🇪🇨",
                "UY": "🇺🇾",
                "PY": "🇵🇾",
                "BO": "🇧🇴",
                "SV": "🇸🇻",
                "GT": "🇬🇹",
                "HN": "🇭🇳",
                "NI": "🇳🇮",
                "CR": "🇨🇷",
                "PA": "🇵🇦",
                "DO": "🇩🇴",
                "JM": "🇯🇲",
                "BS": "🇧🇸",
                "BB": "🇧🇧",
                "TT": "🇹🇹",
                "KN": "🇰🇳",
                "LC": "🇱🇨",
                "VC": "🇻🇨",
                "AG": "🇦🇬",
                "DM": "🇩🇲",
                "MS": "🇲🇸",
                "AI": "🇦🇮",
                "VG": "🇻🇬",
                "KY": "🇰🇾",
                "BM": "🇧🇲",
                "TC": "🇹🇨",
                "MP": "🇲🇵",
                "GU": "🇬🇺",
                "AS": "🇦🇸",
                "FM": "🇫🇲",
                "MH": "🇲🇭",
                "PW": "🇵🇼",
                "KI": "🇰🇮",
                "NR": "🇳🇷",
                "TV": "🇹🇻",
                "TO": "🇹🇴",
                "WS": "🇼🇸",
                "FJ": "🇫🇯",
                "VU": "🇻🇺",
                "PG": "🇵🇬",
                "SB": "🇸🇧",
                " Solomon Islands": "🇸🇧",
                "TL": "🇹🇱",
                "ID": "🇮🇩",
                "MY": "🇲🇾",
                "TH": "🇹🇭",
                "VN": "🇻🇳",
                "PH": "🇵🇭",
                "LK": "🇱🇰",
                "BD": "🇧🇩",
                "NP": "🇳🇵",
                "PK": "🇵🇰",
                "AF": "🇦🇫",
                "IR": "🇮🇷",
                "IQ": "🇮🇶",
                "SA": "🇸🇦",
                "AE": "🇦🇪",
                "QA": "🇶🇦",
                "BH": "🇧🇭",
                "KW": "🇰🇼",
                "OM": "🇴🇲",
                "JO": "🇯🇴",
                "LB": "🇱🇧",
                "SY": "🇸🇾",
                "YE": "🇾🇪",
                "DZ": "🇩🇿",
                "MA": "🇲🇦",
                "TN": "🇹🇳",
                "LY": "🇱🇾",
                "EG": "🇪🇬",
                "SD": "🇸🇩",
                "ET": "🇪🇹",
                "KE": "🇰🇪",
                "UG": "🇺🇬",
                "TZ": "🇹🇿",
                "RW": "🇷🇼",
                "BI": "🇧🇮",
                "MZ": "🇲🇿",
                "ZW": "🇿🇼",
                "NA": "🇳🇦",
                "BW": "🇧🇼",
                "ZA": "🇿🇦",
                "LS": "🇱🇸",
                "SZ": "🇸🇿",
                "MU": "🇲🇺",
                "MG": "🇲🇬",
                "KM": "🇰🇲",
                "SC": "🇸🇨",
                "MV": "🇲🇻",
                "IO": "🇮🇴",
                "CX": "🇨🇽",
                "CC": "🇨🇨",
                "HM": "🇭🇲",
                "NF": "🇳🇫",
                "AC": "🇦🇨",
                "TA": "🇹🇦",
                "GS": "🇬🇸",
                "FK": "🇫🇰",
                "BV": "🇧🇻",
                "SJ": "🇸🇯",
                "GL": "🇬🇱",
                "AQ": "🇦🇶",
                "UM": "🇺🇲",
                "VI": "🇻🇮",
                "PR": "🇵🇷",
                "MP": "🇲🇵",
                "GU": "🇬🇺",
                "AS": "🇦🇸",
                "FM": "🇫🇲",
                "MH": "🇲🇭",
                "PW": "🇵🇼",
                "KI": "🇰🇮",
                "NR": "🇳🇷",
                "TV": "🇹🇻",
                "TO": "🇹🇴",
                "WS": "🇼🇸",
                "FJ": "🇫🇯",
                "VU": "🇻🇺",
                "PG": "🇵🇬",
                "SB": "🇸🇧",
                "TL": "🇹🇱",
                "ID": "🇮🇩",
                "MY": "🇲🇾",
                "TH": "🇹🇭",
                "VN": "🇻🇳",
                "PH": "🇵🇭",
                "LK": "🇱🇰",
                "BD": "🇧🇩",
                "NP": "🇳🇵",
                "PK": "🇵🇰",
                "AF": "🇦🇫",
                "IR": "🇮🇷",
                "IQ": "🇮🇶",
                "SA": "🇸🇦",
                "AE": "🇦🇪",
                "QA": "🇶🇦",
                "BH": "🇧🇭",
                "KW": "🇰🇼",
                "OM": "🇴🇲",
                "JO": "🇯🇴",
                "LB": "🇱🇧",
                "SY": "🇸🇾",
                "YE": "🇾🇪",
                "DZ": "🇩🇿",
                "MA": "🇲🇦",
                "TN": "🇹🇳",
                "LY": "🇱🇾",
                "EG": "🇪🇬",
                "SD": "🇸🇩",
                "ET": "🇪🇹",
                "KE": "🇰🇪",
                "UG": "🇺🇬",
                "TZ": "🇹🇿",
                "RW": "🇷🇼",
                "BI": "🇧🇮",
                "MZ": "🇲🇿",
                "ZW": "🇿🇼",
                "NA": "🇳🇦",
                "BW": "🇧🇼",
                "ZA": "🇿🇦",
                "LS": "🇱🇸",
                "SZ": "🇸🇿",
                "MU": "🇲🇺",
                "MG": "🇲🇬",
                "KM": "🇰🇲",
                "SC": "🇸🇨",
                "MV": "🇲🇻",
                "IO": "🇮🇴",
                "CX": "🇨🇽",
                "CC": "🇨🇨",
                "HM": "🇭🇲",
                "NF": "🇳🇫",
                "AC": "🇦🇨",
                "TA": "🇹🇦",
                "GS": "🇬🇸",
                "FK": "🇫🇰",
                "BV": "🇧🇻",
                "SJ": "🇸🇯",
                "GL": "🇬🇱",
                "AQ": "🇦🇶",
                "UM": "🇺🇲",
                "VI": "🇻🇮",
                "PR": "🇵🇷",
            }.get(country, "🌍")
            score_emoji = "🔴" if score >= 80 else "🟠" if score >= 50 else "🟡" if score >= 20 else "🟢"
            
            return (
                f"1️⃣ *AbuseIPDB*\n"
                f"*IP:* `{ip}`\n"
                f"*ISP:* `{isp}`\n"
                f"*Usage Type:* `{usage_type}`\n"
                f"*Domain Name:* `{domain}`\n"
                f"*Country:* {country_flag} {country}\n"
                f"*Score:* {score_emoji} {score}\n"
                f"*Total Reports:* `{total_reports}`\n"
                f"*Count Distinct Users:* `{distinct_users}`\n"
                f"*Last Report:* `{last_report}`\n"
                f"[🔗 Check on AbuseIPDB](https://www.abuseipdb.com/check/{ip})"
            )
        else:
            return (
                f"1️⃣ *AbuseIPDB*\n"
                f"*IP:* `{ip}`\n"
                f"*Result:* Not Found 😐\n"
                f"[🔗 Check on AbuseIPDB](https://www.abuseipdb.com/check/{ip})"
            )
    except Exception as e:
        return f"1️⃣ *AbuseIPDB*: Ошибка — `{str(e)}`"

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
            suspicious = last_analysis.get("suspicious", 0)
            total_engines = sum(last_analysis.values())
            community_score = data.get("community_reputation", 0)
            reg_iri = data.get("regional_internet_registry", "N/A")
            country_flag = {
                "US": "🇺🇸",
                "DE": "🇩🇪",
                "RU": "🇷🇺",
                "CN": "🇨🇳",
                "FR": "🇫🇷",
                "GB": "🇬🇧",
                "JP": "🇯🇵",
                "BR": "🇧🇷",
                "IN": "🇮🇳",
                "CA": "🇨🇦",
                "AU": "🇦🇺",
                "IT": "🇮🇹",
                "ES": "🇪🇸",
                "NL": "🇳🇱",
                "CH": "🇨🇭",
                "SE": "🇸🇪",
                "NO": "🇳🇴",
                "PL": "🇵🇱",
                "TR": "🇹🇷",
                "KR": "🇰🇷",
                "SG": "🇸🇬",
                "MX": "🇲🇽",
                "ZA": "🇿🇦",
                "AR": "🇦🇷",
                "PT": "🇵🇹",
                "BE": "🇧🇪",
                "AT": "🇦🇹",
                "DK": "🇩🇰",
                "FI": "🇫🇮",
                "GR": "🇬🇷",
                "HU": "🇭🇺",
                "CZ": "🇨🇿",
                "RO": "🇷🇴",
                "IL": "🇮🇱",
                "CL": "🇨🇱",
                "CO": "🇨🇴",
                "PE": "🇵🇪",
                "VE": "🇻🇪",
                "EC": "🇪🇨",
                "UY": "🇺🇾",
                "PY": "🇵🇾",
                "BO": "🇧🇴",
                "SV": "🇸🇻",
                "GT": "🇬🇹",
                "HN": "🇭🇳",
                "NI": "🇳🇮",
                "CR": "🇨🇷",
                "PA": "🇵🇦",
                "DO": "🇩🇴",
                "JM": "🇯🇲",
                "BS": "🇧🇸",
                "BB": "🇧🇧",
                "TT": "🇹🇹",
                "KN": "🇰🇳",
                "LC": "🇱🇨",
                "VC": "🇻🇨",
                "AG": "🇦🇬",
                "DM": "🇩🇲",
                "MS": "🇲🇸",
                "AI": "🇦🇮",
                "VG": "🇻🇬",
                "KY": "🇰🇾",
                "BM": "🇧🇲",
                "TC": "🇹🇨",
                "MP": "🇲🇵",
                "GU": "🇬🇺",
                "AS": "🇦🇸",
                "FM": "🇫🇲",
                "MH": "🇲🇭",
                "PW": "🇵🇼",
                "KI": "🇰🇮",
                "NR": "🇳🇷",
                "TV": "🇹🇻",
                "TO": "🇹🇴",
                "WS": "🇼🇸",
                "FJ": "🇫🇯",
                "VU": "🇻🇺",
                "PG": "🇵🇬",
                "SB": "🇸🇧",
                "TL": "🇹🇱",
                "ID": "🇮🇩",
                "MY": "🇲🇾",
                "TH": "🇹🇭",
                "VN": "🇻🇳",
                "PH": "🇵🇭",
                "LK": "🇱🇰",
                "BD": "🇧🇩",
                "NP": "🇳🇵",
                "PK": "🇵🇰",
                "AF": "🇦🇫",
                "IR": "🇮🇷",
                "IQ": "🇮🇶",
                "SA": "🇸🇦",
                "AE": "🇦🇪",
                "QA": "🇶🇦",
                "BH": "🇧🇭",
                "KW": "🇰🇼",
                "OM": "🇴🇲",
                "JO": "🇯🇴",
                "LB": "🇱🇧",
                "SY": "🇸🇾",
                "YE": "🇾🇪",
                "DZ": "🇩🇿",
                "MA": "🇲🇦",
                "TN": "🇹🇳",
                "LY": "🇱🇾",
                "EG": "🇪🇬",
                "SD": "🇸🇩",
                "ET": "🇪🇹",
                "KE": "🇰🇪",
                "UG": "🇺🇬",
                "TZ": "🇹🇿",
                "RW": "🇷🇼",
                "BI": "🇧🇮",
                "MZ": "🇲🇿",
                "ZW": "🇿🇼",
                "NA": "🇳🇦",
                "BW": "🇧🇼",
                "ZA": "🇿🇦",
                "LS": "🇱🇸",
                "SZ": "🇸🇿",
                "MU": "🇲🇺",
                "MG": "🇲🇬",
                "KM": "🇰🇲",
                "SC": "🇸🇨",
                "MV": "🇲🇻",
                "IO": "🇮🇴",
                "CX": "🇨🇽",
                "CC": "🇨🇨",
                "HM": "🇭🇲",
                "NF": "🇳🇫",
                "AC": "🇦🇨",
                "TA": "🇹🇦",
                "GS": "🇬🇸",
                "FK": "🇫🇰",
                "BV": "🇧🇻",
                "SJ": "🇸🇯",
                "GL": "🇬🇱",
                "AQ": "🇦🇶",
                "UM": "🇺🇲",
                "VI": "🇻🇮",
                "PR": "🇵🇷",
            }.get(country, "🌍")
            malicious_emoji = "❗️" if malicious > 0 else "✅"
            suspicious_emoji = "⚠️" if suspicious > 0 else "✅"
            community_score_emoji = "⚪️" if community_score <= 0 else "🟡" if community_score < 50 else "🟠" if community_score < 80 else "🔴"
            
            return (
                f"2️⃣ *VirusTotal*\n"
                f"*ip_address:* `{ip}`\n"
                f"*Community Score:* {community_score_emoji} {community_score}\n"
                f"*Regional Internet Registry:* `{reg_iri}`\n"
                f"*Country:* {country_flag} {country}\n"
                f"*Malicious:* {malicious_emoji} {malicious} / {total_engines}\n"
                f"*Suspicious:* {suspicious_emoji} {suspicious} / {total_engines}\n"
                f"[🔗 Check on VirusTotal](https://www.virustotal.com/gui/ip-address/{ip})"
            )
        else:
            return (
                f"2️⃣ *VirusTotal*\n"
                f"*ip_address:* `{ip}`\n"
                f"*Result:* Not Found 😐\n"
                f"[🔗 Check on VirusTotal](https://www.virustotal.com/gui/ip-address/{ip})"
            )
    except Exception as e:
        return f"2️⃣ *VirusTotal*: Ошибка — `{str(e)}`"

def get_virustotal_url_info(url):
    # VirusTotal требует, чтобы URL был закодирован в base64 (без padding)
    import base64
    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

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

            # Форматируем даты
            from datetime import datetime
            def fmt_ts(ts):
                return datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC") if ts else "N/A"

            malicious_emoji = "🔴" if malicious > 0 else "🟢"

            return (
                f"🌐 *VirusTotal (URL)*\n"
                f"*Ссылка:* `{url}`\n"
                f"*Репутация:* `{reputation}`\n"
                f"*Вредоносная:* {malicious_emoji} `{malicious}` / `{total}`\n"
                f"*Подозрительная:* ⚠️ `{suspicious}` / `{total}`\n"
                f"*Безвредная:* ✅ `{harmless}` / `{total}`\n"
                f"*Категории:* `{', '.join(categories) if categories else '—'}`\n"
                f"*Первая проверка:* `{fmt_ts(first_submission)}`\n"
                f"*Последняя проверка:* `{fmt_ts(last_analysis_date)}`\n"
                f"[🔍 Посмотреть на VirusTotal](https://www.virustotal.com/gui/url/{encoded_url})"
            )
        elif r.status_code == 404:
            # URL не найден — можно отправить на анализ
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
                    f"[🔍 Посмотреть позже на VirusTotal](https://www.virustotal.com/gui/url/{scan_id})"
                )
            else:
                return (
                    f"🌐 *VirusTotal (URL)*\n"
                    f"*Ссылка:* `{url}`\n"
                    f"*Результат:* URL не найден и не удалось отправить на анализ."
                )
        else:
            return (
                f"🌐 *VirusTotal (URL)*\n"
                f"*Ссылка:* `{url}`\n"
                f"*Результат:* Ошибка API ({r.status_code})"
            )
    except Exception as e:
        return f"🌐 *VirusTotal (URL)*: Ошибка — `{str(e)}`"

# === Обработчики Telegram ===

async def handle_ip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()

    # Проверка на IP-адрес
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if ip_pattern.match(text):
        parts = text.split('.')
        if all(0 <= int(part) <= 255 for part in parts):
            msg = await update.message.reply_text("🔍 Запрашиваю информацию об IP...")
            shodan = get_shodan_info(text)
            abuse = get_abuseipdb_info(text)
            vt = get_virustotal_info(text)
            full_report = f"🔍 *Информация об IP `{text}`:*\n\n{abuse}\n\n{vt}\n\n{shodan}"
            await msg.edit_text(full_report, parse_mode="Markdown", disable_web_page_preview=True)
            return

    # Проверка на URL
    url_pattern = re.compile(
        r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE
    )
    if url_pattern.match(text):
        msg = await update.message.reply_text("🔍 Проверяю URL в VirusTotal...")
        vt_url_report = get_virustotal_url_info(text)
        await msg.edit_text(vt_url_report, parse_mode="Markdown", disable_web_page_preview=True)
        return

    # Если ни IP, ни URL
    await update.message.reply_text(
        "Пожалуйста, отправьте:\n"
        "• IPv4-адрес (например, `8.8.8.8`), или\n"
        "• Ссылку (например, `https://example.com`)"
    )

# === Запуск бота ===

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Привет! Отправьте:\n"
        "• IPv4-адрес (например, `8.8.8.8`), или\n"
        "• Ссылку (например, `https://example.com`)"
    )

def main():
    logging.basicConfig(level=logging.INFO)
    app = Application.builder().token(TELEGRAM_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_ip))

    print("Бот запущен...")
    app.run_polling()

if __name__ == "__main__":
    main()