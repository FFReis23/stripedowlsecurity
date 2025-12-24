from flask import Flask, render_template, request, url_for
import tldextract
from collections import Counter
import math
import urllib.parse

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

def is_suspicious(url):
    reasons = []
    
    # Normalização básica
    if not url.startswith(("http://", "https://")):
        processed_url = "https://" + url
    else:
        processed_url = url
    
    try:
        parsed_url = urllib.parse.urlparse(processed_url)
        netloc = parsed_url.netloc.lower()
        ext = tldextract.extract(processed_url)
        domain = ext.domain.lower()

        # 1. Verificar Encurtadores
        if any(shortener in netloc for shortener in URL_SHORTENERS):
            reasons.append("Uso de **encurtador de URL** (comum em phishing).")

        # 2. Verificar TLD (Extensão)
        if f".{ext.suffix}" in SUSPICIOUS_TLDS:
            reasons.append(f"Domínio com extensão suspeita (**{ext.suffix}**).")

        # 3. Verificar HTTPS
        if not url.startswith("https://"):
            reasons.append("A conexão **não é segura** (falta HTTPS).")

        # 4. Typosquatting (Simular domínios famosos)
        for legit in DOMINIOS_LEGITIMOS:
            dist = levenshtein_distance(domain, legit)
            if dist > 0 and dist <= 2:
                reasons.append(f"O nome assemelha-se muito ao site oficial da **{legit.capitalize()}**.")
                break

        # 5. Palavras suspeitas no caminho
        if any(word in processed_url.lower() for word in PALAVRAS_SUSPEITAS):
            reasons.append("Contém palavras-chave frequentemente usadas em golpes de roubo de conta.")

    except Exception as e:
        return [f"Erro na análise: {str(e)}"]

    return reasons

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    reasons = []
    url_digitada = ""
    
    if request.method == "POST":
        url_digitada = request.form.get("url")
        if url_digitada:
            reasons = is_suspicious(url_digitada)
            if not reasons:
                result = "✅ Esta URL parece ser segura para navegar."
            else:
                result = "⚠️ Alerta: Detectamos riscos nesta URL!"
    
    return render_template("index.html", result=result, reasons=reasons, url_digitada=url_digitada)

if __name__ == "__main__":
    app.run(debug=True)
