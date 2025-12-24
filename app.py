from flask import Flask, render_template, request, url_for
import re
import tldextract
import requests
import socket
import ssl
from datetime import datetime
from collections import Counter
import math
import urllib.parse
import idna
import html

app = Flask(__name__)

# --- Configurações ---
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

def shannon_entropy(data):
    if not data: return 0
    data = data.encode('utf-8', 'ignore').decode('utf-8')
    probabilities = [float(c) / len(data) for c in Counter(data).values()]
    return -sum(p * math.log(p, 2) for p in probabilities if p > 0)

def is_suspicious(url):
    reasons = []
    details = []
    
    if not url.startswith(("http://", "https://")):
        processed_url = "https://" + url
    else:
        processed_url = url
    
    try:
        parsed_url = urllib.parse.urlparse(processed_url)
        safe_netloc = parsed_url.netloc.split('@')[-1]
        ext = tldextract.extract(processed_url)
        hostname = ext.domain + "." + ext.suffix

        if any(shortener in safe_netloc for shortener in URL_SHORTENERS):
            reasons.append("Uso de **encurtador de URL**")

        if ext.suffix in SUSPICIOUS_TLDS:
            reasons.append(f"TLD suspeito ({ext.suffix})")

        if not processed_url.startswith("https://"):
            reasons.append("Não utiliza **HTTPS**")

        # Typosquatting
        for legit in DOMINIOS_LEGITIMOS:
            if levenshtein_distance(ext.domain, legit) in [1, 2]:
                reasons.append(f"Semelhante a '{legit}' (Typosquatting)")
                break

    except Exception as e:
        return f"Erro na análise: {str(e)}", []

    return (reasons, details)

# --- ROTAS CORRIGIDAS ---

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    reasons = []
    if request.method == "POST":
        url = request.form.get("url")
        if url:
            reasons, details = is_suspicious(url)
            if not reasons:
                result = "✅ URL parece segura."
            else:
                result = "⚠️ URL suspeita detectada!"
    
    return render_template("index.html", result=result, reasons=reasons)

@app.route("/ataque")
def ataque():
    # Renderiza o arquivo ataque.html que está na pasta templates
    return render_template("ataque.html")

if __name__ == "__main__":
    app.run(debug=True)
