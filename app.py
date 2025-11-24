from flask import Flask, render_template, request
import re
import tldextract
import requests
import socket
import ssl
from datetime import datetime
from collections import Counter
import math
# Importações existentes: flask, re, tldextract, requests, socket, ssl, datetime

app = Flask(__name__)

# --- Funções Auxiliares Adicionadas ---

def levenshtein_distance(s1, s2):
    """Calcula a distância de Levenshtein entre duas strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

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
    """Calcula a Entropia de Shannon para uma string."""
    if not data:
        return 0
    entropy = 0
    # Calcula a frequência de cada caractere
    probabilities = [float(c) / len(data) for c in Counter(data).values()]
    # Calcula a entropia
    for prob in probabilities:
        if prob > 0:
            entropy -= prob * math.log(prob, 2)
    return entropy

# Domínios conhecidos para checagem de spoofing (apenas o nome do domínio)
DOMINIOS_LEGITIMOS = ["google", "microsoft", "apple", "netflix", "paypal", "itau", "amazon", "facebook"] 

# --- Função Principal de Verificação ---

def is_suspicious(url):
    reasons = []
    details = []

    # 0. Preparação da URL
    if not url.startswith(("http://", "https://")):
        processed_url = "https://" + url
    else:
        processed_url = url
        
    ext = tldextract.extract(processed_url)
    hostname = ext.domain + "." + ext.suffix
    
    # 1. HTTPS e Certificado (Mantido)
    # ... (Bloco de código 1 original) ...
    
    if not processed_url.startswith("https://"):
        reasons.append("URL não utiliza HTTPS")
    else:
        try:
            ctx = ssl.create_default_context()
            host_for_ssl = hostname
            
            if ext.subdomain:
                host_for_ssl = ext.subdomain + "." + hostname

            # ATENÇÃO: A CONEXÃO SSL É MELHOR FEITA COM O HOSTNAME PURO PARA A PORTA 443
            with ctx.wrap_socket(socket.socket(), server_hostname=host_for_ssl) as s:
                s.settimeout(3)
                s.connect((hostname, 443))
                cert = s.getpeercert()

                # Verifica expiração
                exp_date_str = cert.get("notAfter", "")
                
                try:
                    exp_date = datetime.strptime(exp_date_str, "%b %d %H:%M:%S %Y %Z")
                except ValueError:
                    exp_date = datetime(2099, 12, 31) 
                    
                if exp_date < datetime.utcnow():
                    reasons.append("Certificado SSL expirado")
                
                # Detalhes do Certificado
                subject_info = cert.get('subject', [[]])
                cn = [item[1] for item in subject_info[0] if item[0] == 'commonName']
                details.append(f"Emissor do Certificado: {cn[0] if cn else 'Desconhecido'}")

        except Exception:
            reasons.append("Erro ao verificar SSL/TLS (host pode estar inacessível ou certificado inválido)")

    # 2. Uso de IP (Mantido)
    if re.match(r"^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
        reasons.append("Uso de IP no lugar de domínio")

    # 3. Subdomínios excessivos (Mantido)
    if len(ext.subdomain.split(".")) > 2:
        reasons.append("Muitos subdomínios (potencial ofuscamento)")

    # 4. Palavras suspeitas (Mantido)
    palavras_suspeitas = [
        "login", "secure", "update", "verify",
        "account", "bank", "confirm", "payment"
    ]

    if any(p in processed_url.lower() for p in palavras_suspeitas):
        reasons.append("Contém palavras suspeitas na URL")

    # 5. Lista negra simples (Mantido)
    blacklist = ["malicious-site.com", "phishing-domain.net"]
    if ext.domain in blacklist:
        reasons.append(f"Domínio na lista negra: {ext.domain}")

    # 6. WHOIS (Idade do domínio) - (Mantido, com melhoria no detalhe)
    try:
        api_url = f"https://api.whoisfreaks.com/v1.0/whois?apiKey=free&whois=live&domainName={hostname}"
        resp = requests.get(api_url, timeout=5)
        resp.raise_for_status()
        whois_data = resp.json()

        if (whois_data.get("whoisRecord") and 
            "creation_date" in whois_data["whoisRecord"] and
            whois_data["whoisRecord"]["creation_date"]):
            
            creation_date_str = whois_data["whoisRecord"]["creation_date"]
            
            try:
                creation_date = datetime.strptime(creation_date_str[:10], "%Y-%m-%d")
            except:
                creation_date = datetime(2000, 1, 1)
                details.append("Aviso: Falha ao parsear data WHOIS, usando fallback.")
                
            age_days = (datetime.now() - creation_date).days

            if age_days < 90:
                reasons.append("Domínio muito recente (menos de 90 dias)")

            details.append(f"Idade do domínio: {age_days} dias")

        else:
              details.append("Não foi possível obter a data de criação WHOIS")

    except requests.exceptions.RequestException:
        details.append("Não foi possível obter informações WHOIS (timeout ou erro de API externa)")
    except Exception:
        details.append("Não foi possível obter informações WHOIS (erro geral)")

        
    # --- 8. NOVA: Entropia de Shannon (Aleatoriedade) ---
    domain_part = ext.subdomain + ext.domain
    entropy_value = shannon_entropy(domain_part)
    
    if entropy_value > 3.5 and len(domain_part) > 10:
        reasons.append("Alta entropia no nome do domínio (potencial DGA)")
        
    details.append(f"Entropia do Domínio: {entropy_value:.2f}")


    # --- 9. NOVA: Distância de Levenshtein (Spoofing) ---
    min_distance = float('inf')
    closest_legit_domain = ""

    for legit_name in DOMINIOS_LEGITIMOS:
        dist = levenshtein_distance(ext.domain, legit_name)
        
        if dist < min_distance:
            min_distance = dist
            closest_legit_domain = legit_name

    # Heurística: Se a distância for 1 ou 2, é suspeito
    if min_distance in [1, 2]:
        reasons.append(f"Alta semelhança com '{closest_legit_domain}' (distância {min_distance})")


    # --- 10. NOVA: Análise de Conteúdo e Redirecionamentos ---
    try:
        # Usamos requests.get para obter o conteúdo para análise
        resp = requests.get(processed_url, allow_redirects=True, timeout=5)
        
        # Redirecionamentos excessivos
        if len(resp.history) > 3: 
            reasons.append(f"Muitos redirecionamentos ({len(resp.history)})")
        
        details.append(f"Redirecionamentos detectados: {len(resp.history)}")

        # Análise de Formulário de Login (phishing)
        # Busca por campos de senha e o texto "login" no corpo
        if "<input type=\"password\"" in resp.text.lower() and "login" in resp.text.lower():
             reasons.append("Página contém formulário de login (Alto Risco)")
             
    except requests.exceptions.Timeout:
        details.append("Não foi possível acessar a URL (Timeout)")
    except Exception:
        details.append("Não foi possível realizar análise de conteúdo/redirecionamentos")

    # Resultado final
    if reasons:
        result_text = "⚠️ <strong>URL suspeita:</strong> " + ", ".join(reasons)
    else:
        result_text = "✅ <strong>URL parece segura.</strong>"

    # Detalhes adicionais
    if details:
        result_text += "<br><br><strong>Detalhes da Análise:</strong><br>" + "<br>".join(details)

    return result_text


# Página extra (Mantido)
@app.route("/ataques")
def ataques():
    return render_template("ataques.html")


# Página principal (Rota correta com POST/GET) (Mantido)
@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        url = request.form.get("url")

        if url:
            result = is_suspicious(url)

    return render_template("index.html", result=result)


# Iniciar localmente (Mantido)
if __name__ == "__main__":
    app.run(debug=True)
