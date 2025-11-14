from flask import Flask, render_template, request
import re
import tldextract
import requests
import socket
import ssl
from datetime import datetime

app = Flask(__name__)

def index():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)

# Função principal de verificação
def is_suspicious(url):
    reasons = []
    details = []

    # Extrair domínio, subdomínio e sufixo
    ext = tldextract.extract(url)
    hostname = ext.domain + "." + ext.suffix

    # HTTPS
    if not url.startswith("https://"):
        reasons.append("URL não utiliza HTTPS")
    else:
        try:
            ctx = ssl.create_default_context()

            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(3)
                s.connect((hostname, 443))
                cert = s.getpeercert()

                exp_date = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                if exp_date < datetime.utcnow():
                    reasons.append("Certificado SSL expirado")

        except Exception:
            reasons.append("Erro ao verificar SSL/TLS")

    # Uso de IP
    if re.match(r"^https?:\/\/\d+\.\d+\.\d+\.\d+", url):
        reasons.append("Uso de IP no lugar de domínio")

    # Subdomínios
    if len(ext.subdomain.split(".")) > 2:
        reasons.append("Muitos subdomínios")

    # Palavras suspeitas
    palavras_suspeitas = [
        "login", "secure", "update", "verify",
        "account", "bank", "confirm", "payment"
    ]

    if any(p in url.lower() for p in palavras_suspeitas):
        reasons.append("Contém palavras suspeitas")

    # Lista negra simples
    blacklist = ["malicious-site.com", "phishing-domain.net"]
    if ext.domain in blacklist:
        reasons.append(f"Domínio na lista negra: {ext.domain}")

    # WHOIS (via API gratuita)
    try:
        api_url = f"https://api.whoisfreaks.com/v1.0/whois?apiKey=free&whois=live&domainName={hostname}"
        whois_data = requests.get(api_url, timeout=5).json()

        if "creation_date" in whois_data:
            creation_date_str = whois_data["creation_date"]
            creation_date = datetime.strptime(creation_date_str[:10], "%Y-%m-%d")
            age_days = (datetime.now() - creation_date).days

            if age_days < 30:
                reasons.append("Domínio muito recente")

            details.append(f"Idade do domínio: {age_days} dias")

        else:
            details.append("WHOIS disponível, mas sem data de criação registrada")

    except Exception:
        details.append("Não foi possível obter informações WHOIS")

    # Redirecionamentos
    try:
        resp = requests.head(url, allow_redirects=True, timeout=4)
        if len(resp.history) > 0:
            details.append(f"Redirecionamentos detectados: {len(resp.history)}")
    except Exception:
        details.append("Não foi possível verificar redirecionamentos")

    # Resultado final
    if reasons:
        result_text = "⚠️ <strong>URL suspeita:</strong> " + ", ".join(reasons)
    else:
        result_text = "✅ <strong>URL parece segura.</strong>"

    # Detalhes adicionais
    if details:
        result_text += "<br><br>" + "<br>".join(details)

    return result_text


# Página extra
@app.route("/ataques")
def ataques():
    return render_template("ataques.html")


# Página principal
@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        url = request.form.get("url")

        if url:
            result = is_suspicious(url)

    return render_template("index.html", result=result)


# Iniciar localmente
if __name__ == "__main__":
    app.run(debug=True)
