from flask import Flask, render_template, request
import re
import tldextract
import requests
import socket
import ssl
from datetime import datetime
import whois

app = Flask(__name__)

def is_suspicious(url):
    reasons = []
    details = []
    ext = tldextract.extract(url)

    # HTTPS
    if not url.startswith("https://"):
        reasons.append("URL não utiliza HTTPS")
    else:
        try:
            hostname = ext.domain + "." + ext.suffix
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(3)
                s.connect((hostname, 443))
                cert = s.getpeercert()
                exp_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                if exp_date < datetime.utcnow():
                    reasons.append("Certificado SSL expirado")
        except Exception:
            reasons.append("Erro ao verificar SSL/TLS")

    # IP na URL
    if re.match(r"^https?:\/\/\d+\.\d+\.\d+\.\d+", url):
        reasons.append("Uso de IP no lugar de domínio")

    # Subdomínios
    if len(ext.subdomain.split('.')) > 2:
        reasons.append("Muitos subdomínios")

    palavras_suspeitas = ["login", "secure", "update", "verify", "account", "bank", "confirm", "payment"]
    if any(p in url.lower() for p in palavras_suspeitas):
        reasons.append("Contém palavras suspeitas")

    blacklist = ["malicious-site.com", "phishing-domain.net"]
    if ext.domain in blacklist:
        reasons.append(f"Domínio na lista negra: {ext.domain}")

    try:
        w = whois.whois(ext.domain + "." + ext.suffix)
        if hasattr(w, "creation_date") and w._
