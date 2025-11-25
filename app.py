from flask import Flask, render_template, request
import re
import tldextract
import requests
import socket
import ssl
from datetime import datetime
from collections import Counter
import math
import urllib.parse
import idna # Novo: Para checagem de Homograph Attacks

app = Flask(__name__)

# --- Constantes e Configuração ---

# Domínios conhecidos para checagem de spoofing (expandidos)
DOMINIOS_LEGITIMOS = ["google", "microsoft", "apple", "netflix", "paypal", "itau", "amazon", "facebook", "twitter", "instagram", "linkedin"]
# Palavras-chave de alto risco
PALAVRAS_SUSPEITAS = [
    "login", "secure", "update", "verify",
    "account", "bank", "confirm", "payment",
    "password", "auth", "webscr", "transfer"
]
# Limite de dias para domínio "jovem"
IDADE_MINIMA_DIAS = 90
# Limite de comprimento da URL
COMPRIMENTO_MAXIMO = 150

# --- Funções Auxiliares (Mantidas) ---

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
    probabilities = [float(c) / len(data) for c in Counter(data).values()]
    for prob in probabilities:
        if prob > 0:
            # log na base 2 para bits
            entropy -= prob * math.log(prob, 2)
    return entropy

# --- Função Principal de Verificação (Atualizada) ---

def is_suspicious(url):
    reasons = []
    details = []

    # 0. Preparação da URL e Extração de Componentes
    if not url.startswith(("http://", "https://")):
        processed_url = "https://" + url
    else:
        processed_url = url
    
    # Adiciona tratamento para que tldextract não falhe em URLs com @
    try:
        parsed_url = urllib.parse.urlparse(processed_url)
        # Use o netloc para extração, excluindo a parte 'user:pass@' se houver
        safe_netloc = parsed_url.netloc.split('@')[-1]
        ext = tldextract.extract(parsed_url.scheme + '://' + safe_netloc + parsed_url.path)
        hostname = ext.domain + "." + ext.suffix
    except Exception as e:
        reasons.append(f"Falha na análise da URL (Erro: {type(e).__name__})")
        details.append(f"URL original: {url}")
        return "⚠️ <strong>URL suspeita:</strong> Falha na análise de componentes.", reasons

    # 1. HTTPS e Certificado (Mantido)
    if not processed_url.startswith("https://"):
        reasons.append("URL não utiliza **HTTPS**")
    else:
        try:
            ctx = ssl.create_default_context()
            host_for_ssl = hostname
            if ext.subdomain:
                host_for_ssl = ext.subdomain + "." + hostname

            with ctx.wrap_socket(socket.socket(), server_hostname=host_for_ssl) as s:
                s.settimeout(3)
                s.connect((hostname, 443))
                cert = s.getpeercert()

                exp_date_str = cert.get("notAfter", "")
                try:
                    exp_date = datetime.strptime(exp_date_str, "%b %d %H:%M:%S %Y %Z")
                except ValueError:
                    exp_date = datetime(2099, 12, 31) # Fallback seguro
                    details.append("Aviso: Falha ao parsear data de expiração SSL.")
                        
                if exp_date < datetime.utcnow():
                    reasons.append("Certificado SSL **expirado**")
                
                subject_info = cert.get('subject', [[]])
                cn = [item[1] for item in subject_info[0] if item[0] == 'commonName']
                details.append(f"Emissor do Certificado: {cn[0] if cn else 'Desconhecido'}")

        except Exception:
            reasons.append("Erro ao verificar SSL/TLS (host pode estar inacessível ou certificado inválido)")

    # 2. Uso de IP ou Codificação Numérica/Hex (APRIMORADO)
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", safe_netloc):
        reasons.append("Uso de **Endereço IP** no lugar de domínio")
    
    # Detecção de IP codificado (ex: 0x52.0x10.0x10.0x01)
    if re.search(r'(0x[0-9a-fA-F]+)', parsed_url.netloc):
        reasons.append("Uso de codificação **Hexadecimal/Numérica** no host")


    # 3. Subdomínios excessivos (Mantido)
    if len(ext.subdomain.split(".")) > 2:
        reasons.append("Muitos **subdomínios** (potencial ofuscamento)")

    # 4. Palavras suspeitas (APRIMORADO: Checa path/query)
    url_path_query = parsed_url.path + parsed_url.query
    if any(p in url_path_query.lower() for p in PALAVRAS_SUSPEITAS):
        reasons.append("Palavras de alto risco (**Login/Bank/Update**) no caminho/query")
    elif any(p in ext.subdomain.lower() for p in PALAVRAS_SUSPEITAS):
         reasons.append("Palavras de alto risco no **subdomínio**")

    # 5. Lista negra simples (Mantido)
    blacklist = ["malicious-site.com", "phishing-domain.net"]
    if ext.domain in blacklist:
        reasons.append(f"Domínio na **lista negra** simples")

    # 6. WHOIS (Idade do domínio)
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

            if age_days < IDADE_MINIMA_DIAS:
                reasons.append(f"Domínio muito **recente** (menos de {IDADE_MINIMA_DIAS} dias)")

            details.append(f"Idade do domínio: {age_days} dias")

        else:
            details.append("Não foi possível obter a data de criação WHOIS")

    except requests.exceptions.RequestException:
        details.append("Não foi possível obter informações WHOIS (timeout/erro de API)")
    except Exception:
        details.append("Não foi possível obter informações WHOIS (erro geral)")

    # 7. Entropia de Shannon (Mantido)
    domain_part = ext.subdomain + ext.domain
    entropy_value = shannon_entropy(domain_part)
    
    if entropy_value > 3.5 and len(domain_part) > 10:
        reasons.append("Alta **entropia** no nome (Potencial DGA)")
        
    details.append(f"Entropia do Domínio: {entropy_value:.2f}")


    # 8. Distância de Levenshtein (Mantido)
    min_distance = float('inf')
    closest_legit_domain = ""

    for legit_name in DOMINIOS_LEGITIMOS:
        dist = levenshtein_distance(ext.domain, legit_name)
        
        if dist < min_distance:
            min_distance = dist
            closest_legit_domain = legit_name

    if min_distance in [1, 2]:
        reasons.append(f"Alta semelhança com '{closest_legit_domain}' (distância {min_distance}) - **Typosquatting**")

    # 9. Símbolo '@' (Phishing por Credencial)
    if "@" in parsed_url.netloc:
        reasons.append("Presença de **'@' na URL** (Tentativa de esconder o host real)")

    # 10. Ofuscamento (Codificação)
    encoded_count = processed_url.count('%')
    if encoded_count > 5:
        reasons.append(f"Excesso de **codificação** na URL ({encoded_count}x '%')")

    # 11. Homograph Attack (Punycode/Unicode) (NOVO)
    try:
        # Se o domínio real difere da versão Punycode, é porque continha caracteres especiais
        # A codificação IDNA (usada para Punycode) falha ou é diferente para caracteres homógrafos
        domain_without_tld = ext.domain
        punycode_domain = domain_without_tld.encode('idna').decode('ascii')
        
        if domain_without_tld != punycode_domain and any(ord(c) > 127 for c in domain_without_tld):
            reasons.append("Uso de **caracteres Unicode/Punycode** no domínio (Homograph Attack)")
    except idna.IDNAError:
        reasons.append("Erro na codificação do domínio (Suspeita de caracteres inválidos/maliciosos)")
        
    # 12. Comprimento da URL (NOVO)
    if len(url) > COMPRIMENTO_MAXIMO:
        reasons.append(f"URL muito **longa** ({len(url)} chars) - Potencial ofuscamento")


    # 13. Redirecionamentos e Análise de Conteúdo (Final)
    try:
        resp = requests.get(processed_url, allow_redirects=True, timeout=5)
        
        # Redirecionamentos excessivos
        if len(resp.history) > 3:
            reasons.append(f"Muitos **redirecionamentos** ({len(resp.history)})")
        
        details.append(f"Redirecionamentos detectados: {len(resp.history)}")

        # Análise de Formulário de Login (phishing)
        if re.search(r'<input\s+type=["\']password["\']', resp.text, re.IGNORECASE):
             reasons.append("Página contém **formulário de senha** (Alto Risco)")
            
        # Análise de Redirecionamento por Meta Tag
        if re.search(r'<meta\s+http-equiv=["\']refresh["\'].*url=', resp.text, re.IGNORECASE):
             reasons.append("Página usa **meta tag refresh** (Potencial redirecionamento furtivo)")
            
    except requests.exceptions.Timeout:
        details.append("Não foi possível acessar a URL (Timeout)")
    except Exception as e:
        details.append(f"Não foi possível realizar análise de conteúdo/redirecionamentos: {type(e).__name__}")


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
    # Nota: Você precisa de um arquivo 'ataques.html' no diretório 'templates'
    return render_template("ataques.html")


# Página principal (Rota correta com POST/GET) (Mantido)
@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        url = request.form.get("url")

        if url:
            result = is_suspicious(url)

    # Nota: Você precisa de um arquivo 'index.html' no diretório 'templates'
    return render_template("index.html", result=result)


# Iniciar localmente (Mantido)
if __name__ == "__main__":
    app.run(debug=True)
