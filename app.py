from flask import Flask, render_template, request
import tldextract
import urllib.parse
import whois
import requests
import math
import warnings
import base64
import re

# Desabilita avisos de certificados inseguros (comum em sites de phishing)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

app = Flask(__name__)

# --- CONFIGURAÇÕES E CHAVES ---
VT_API_KEY = "6e4b4ad2b96919dd87344e20097a3ae84289057493326f8a5eeab8342eb1d359"
DOMINIOS_LEGITIMOS = ["google", "microsoft", "apple", "netflix", "paypal", "itau", "amazon", "facebook", "twitter", "instagram", "linkedin"]
PALAVRAS_SUSPEITAS = ["login", "secure", "update", "verify", "account", "bank", "confirm", "payment", "password", "auth", "webscr", "transfer", "bradesco", "caixa", "santander"]
URL_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly"]
SUSPICIOUS_TLDS = [".xyz", ".top", ".tk", ".cf", ".ga", ".ml", ".gq", ".bid", ".win", ".icu", ".fun", ".loan"]
EXTENSOES_PERIGOSAS = [".exe", ".msi", ".bat", ".cmd", ".scr", ".vbs", ".js", ".jar", ".zip", ".rar", ".7z"]

# --- FUNÇÕES DE ANÁLISE ---

def check_virustotal(url):
    try:
        # A API v3 exige o ID da URL em base64 sem preenchimento
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(api_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            if malicious > 0:
                return f"🚨 <b>VirusTotal:</b> {malicious} antivírus detectaram ameaças neste link."
        elif response.status_code == 404:
            return "ℹ️ VirusTotal: URL ainda não analisada globalmente."
    except:
        return "⚠️ Erro ao consultar VirusTotal."
    return None

def analyze_malware_indicators(url):
    indicators = []
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.lower()
    hostname = parsed.netloc

    for ext in EXTENSOES_PERIGOSAS:
        if path.endswith(ext):
            indicators.append(f"🚩 Link aponta para arquivo executável (<b>{ext}</b>).")

    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname.split(':')[0]):
        indicators.append("🚩 URL utiliza um <b>IP direto</b> (comum em ataques).")
    return indicators

def levenshtein_distance(s1, s2):
    if len(s1) < len(s2): return levenshtein_distance(s2, s1)
    if len(s2) == 0: return len(s1)
    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def get_whois_data(url):
    try:
        ext = tldextract.extract(url)
        w = whois.whois(f"{ext.domain}.{ext.suffix}")
        creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        return {
            "registrar": w.registrar or "N/A",
            "creation_date": creation.strftime('%d/%m/%Y') if creation else "N/A",
            "country": w.country or "N/A"
        }
    except: return None

def is_suspicious_heuristics(url):
    reasons = []
    url_proc = url if url.startswith(("http://", "https://")) else "https://" + url
    try:
        parsed = urllib.parse.urlparse(url_proc)
        netloc = parsed.netloc.lower()
        ext = tldextract.extract(url_proc)
        domain = ext.domain.lower()

        if any(s in netloc for s in URL_SHORTENERS):
            reasons.append("Uso de encurtador de URL detected.")
        if f".{ext.suffix}" in SUSPICIOUS_TLDS:
            reasons.append(f"Extensão suspeita (<b>{ext.suffix}</b>).")
        if not url.startswith("https://"):
            reasons.append("Conexão sem criptografia (HTTP).")
        for legit in DOMINIOS_LEGITIMOS:
            dist = levenshtein_distance(domain, legit)
            if 0 < dist <= 2:
                reasons.append(f"Possível Typosquatting (similar a {legit.capitalize()}).")
        for palavra in PALAVRAS_SUSPEITAS:
            if palavra in url.lower() and palavra != domain:
                reasons.append(f"Termo sensível detectado: <b>{palavra}</b>.")
    except:
        reasons.append("Erro na análise da estrutura da URL.")
    return reasons

@app.route("/", methods=["GET", "POST"])
def index():
    result, reasons, whois_info, url_digitada = None, [], None, ""
    if request.method == "POST":
        url_digitada = request.form.get("url", "").strip()
        if url_digitada:
            full_url = url_digitada if url_digitada.startswith(("http://", "https://")) else "http://" + url_digitada
            
            vt = check_virustotal(full_url)
            if vt: reasons.append(vt)
            
            reasons.extend(analyze_malware_indicators(full_url))
            reasons.extend(is_suspicious_heuristics(url_digitada))
            whois_info = get_whois_data(full_url)
            
            result = "🚨 Riscos Detectados!" if reasons else "✅ URL parece Segura."
                
    return render_template("index.html", result=result, reasons=reasons, whois_info=whois_info, url_digitada=url_digitada)

if __name__ == "__main__":
    app.run(debug=True)
