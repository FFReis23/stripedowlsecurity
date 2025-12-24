from flask import Flask, render_template, request
import tldextract
import urllib.parse
import whois
import requests

app = Flask(__name__)

# --- Configurações de Segurança ---
DOMINIOS_LEGITIMOS = ["google", "microsoft", "apple", "netflix", "paypal", "itau", "amazon", "facebook", "twitter", "instagram", "linkedin"]
PALAVRAS_SUSPEITAS = ["login", "secure", "update", "verify", "account", "bank", "confirm", "payment", "password", "auth", "webscr", "transfer"]
URL_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly"]
SUSPICIOUS_TLDS = [".xyz", ".top", ".tk", ".cf", ".ga", ".ml", ".gq", ".bid", ".win", ".icu", ".fun"]

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

def analyze_security_headers(url):
    headers_info = []
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        security_headers = {
            'Strict-Transport-Security': 'Presente (Força uso de HTTPS)',
            'Content-Security-Policy': 'Presente (Previne injeção de scripts)',
            'X-Frame-Options': 'Presente (Previne ataques de Clickjacking)'
        }
        for header, desc in security_headers.items():
            if header in headers:
                headers_info.append(f"✅ {header}: {desc}")
            else:
                headers_info.append(f"❌ {header}: Ausente (Risco de segurança)")
    except:
        headers_info.append("⚠️ Não foi possível analisar os cabeçalhos HTTP.")
    return headers_info

def get_whois_data(url):
    try:
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"
        w = whois.whois(domain)
        return {
            "registrar": w.registrar if w.registrar else "N/A",
            "creation_date": w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date,
            "country": w.country if w.country else "N/A"
        }
    except:
        return None

def is_suspicious(url):
    reasons = []
    if not url.startswith(("http://", "https://")):
        processed_url = "https://" + url
    else:
        processed_url = url
    try:
        parsed_url = urllib.parse.urlparse(processed_url)
        netloc = parsed_url.netloc.lower()
        ext = tldextract.extract(processed_url)
        domain = ext.domain.lower()
        if any(shortener in netloc for shortener in URL_SHORTENERS):
            reasons.append("Uso de **encurtador de URL** detectado.")
        if f".{ext.suffix}" in SUSPICIOUS_TLDS:
            reasons.append(f"Extensão suspeita (**{ext.suffix}**).")
        if not url.startswith("https://"):
            reasons.append("Conexão **não segura** (sem HTTPS).")
        for legit in DOMINIOS_LEGITIMOS:
            dist = levenshtein_distance(domain, legit)
            if 0 < dist <= 2:
                reasons.append(f"Possível **Typosquatting** (similar a {legit.capitalize()}).")
                break
    except:
        reasons.append("Erro ao processar a estrutura da URL.")
    return reasons

@app.route("/", methods=["GET", "POST"])
def index():
    result, reasons, whois_info, headers_info, url_digitada = None, [], None, [], ""
    if request.method == "POST":
        url_digitada = request.form.get("url")
        if url_digitada:
            full_url = url_digitada if url_digitada.startswith(("http://", "https://")) else "https://" + url_digitada
            reasons = is_suspicious(url_digitada)
            whois_info = get_whois_data(full_url)
            headers_info = analyze_security_headers(full_url)
            result = "Alerta: Riscos detectados!" if reasons else "URL parece ser segura."
    return render_template("index.html", result=result, reasons=reasons, whois_info=whois_info, headers_info=headers_info, url_digitada=url_digitada)

if __name__ == "__main__":
    app.run(debug=True)
