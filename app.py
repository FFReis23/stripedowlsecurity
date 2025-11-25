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
import idna # Para checagem de Homograph Attacks
import html # Para remover entidades HTML (opcional, mas bom para limpeza)

app = Flask(__name__)

# --- Constantes e Configuração ---

# Domínios conhecidos para checagem de spoofing
DOMINIOS_LEGITIMOS = ["google", "microsoft", "apple", "netflix", "paypal", "itau", "amazon", "facebook", "twitter", "instagram", "linkedin"]
# Palavras-chave de alto risco
PALAVRAS_SUSPEITAS = [
    "login", "secure", "update", "verify",
    "account", "bank", "confirm", "payment",
    "password", "auth", "webscr", "transfer"
]
# Encurtadores de URL comuns
URL_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly"]
# TLDs (Top Level Domains) com histórico de abuso/spam
SUSPICIOUS_TLDS = [".xyz", ".top", ".tk", ".cf", ".ga", ".ml", ".gq", ".bid", ".win", ".icu", ".fun"]

# Limites de Heurística
IDADE_MINIMA_DIAS = 90
COMPRIMENTO_MAXIMO = 150
MAX_DOTS_ALLOWED = 4 # Máximo de pontos permitidos no hostname

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
    # Normaliza a string para evitar erro em caracteres não-ASCII se houver.
    data = data.encode('utf-8', 'ignore').decode('utf-8')
    probabilities = [float(c) / len(data) for c in Counter(data).values()]
    for prob in probabilities:
        if prob > 0:
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
    
    try:
        parsed_url = urllib.parse.urlparse(processed_url)
        # Usa o netloc para extração, excluindo a parte 'user:pass@' se houver
        safe_netloc = parsed_url.netloc.split('@')[-1]
        
        # Se a URL começar com um encurtador, penalizamos
        if any(shortener in safe_netloc for shortener in URL_SHORTENERS):
            reasons.append("Uso de **encurtador de URL** (Ocultação de destino)")
            
        ext = tldextract.extract(processed_url)
        hostname = ext.domain + "." + ext.suffix
        
    except Exception as e:
        reasons.append(f"Falha na análise da URL (Erro: {type(e).__name__})")
        return "⚠️ <strong>URL suspeita:</strong> Falha na análise de componentes.", reasons

    # 1. Checagem de TLD Suspeito
    if ext.suffix in SUSPICIOUS_TLDS:
        reasons.append(f"Uso de **TLD suspeito** ({ext.suffix})")

    # 2. Contagem de Pontos no Hostname (NOVO)
    dot_count = safe_netloc.count('.')
    if dot_count > MAX_DOTS_ALLOWED:
        reasons.append(f"Excesso de pontos ({dot_count}) no hostname (Potencial ofuscamento)")

    # 3. HTTPS e Certificado (Mantido)
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
                    exp_date = datetime(2099, 12, 31) 
                    
                if exp_date < datetime.utcnow():
                    reasons.append("Certificado SSL **expirado**")
                
                subject_info = cert.get('subject', [[]])
                cn = [item[1] for item in subject_info[0] if item[0] == 'commonName']
                details.append(f"Emissor do Certificado: {cn[0] if cn else 'Desconhecido'}")

        except Exception:
            reasons.append("Erro ao verificar SSL/TLS (host pode estar inacessível ou certificado inválido)")

    # 4. Uso de IP ou Codificação Numérica/Hex
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", safe_netloc):
        reasons.append("Uso de **Endereço IP** no lugar de domínio")
    if re.search(r'(0x[0-9a-fA-F]+)', parsed_url.netloc):
        reasons.append("Uso de codificação **Hexadecimal/Numérica** no host")


    # 5. Subdomínios excessivos
    if len(ext.subdomain.split(".")) > 2:
        reasons.append("Muitos **subdomínios** (potencial ofuscamento)")

    # 6. Palavras suspeitas (Checa path/query)
    url_path_query = parsed_url.path + parsed_url.query
    if any(p in url_path_query.lower() for p in PALAVRAS_SUSPEITAS):
        reasons.append("Palavras de alto risco (**Login/Bank**) no caminho/query")
    elif any(p in ext.subdomain.lower() for p in PALAVRAS_SUSPEITAS):
         reasons.append("Palavras de alto risco no **subdomínio**")

    # 7. Idade do domínio (WHOIS)
    try:
        api_url = f"https://api.whoisfreaks.com/v1.0/whois?apiKey=free&whois=live&domainName={hostname}"
        resp_whois = requests.get(api_url, timeout=5)
        resp_whois.raise_for_status()
        whois_data = resp_whois.json()

        if (whois_data.get("whoisRecord") and 
            "creation_date" in whois_data["whoisRecord"] and
            whois_data["whoisRecord"]["creation_date"]):
            
            creation_date_str = whois_data["whoisRecord"]["creation_date"]
            creation_date = datetime.strptime(creation_date_str[:10], "%Y-%m-%d")
            age_days = (datetime.now() - creation_date).days

            if age_days < IDADE_MINIMA_DIAS:
                reasons.append(f"Domínio muito **recente** (menos de {IDADE_MINIMA_DIAS} dias)")
            details.append(f"Idade do domínio: {age_days} dias")
        else:
            details.append("Não foi possível obter a data de criação WHOIS")
    except Exception:
        details.append("Não foi possível obter informações WHOIS (erro ou timeout)")

    # 8. Entropia de Shannon
    domain_part = ext.subdomain + ext.domain
    entropy_value = shannon_entropy(domain_part)
    
    if entropy_value > 3.5 and len(domain_part) > 10:
        reasons.append("Alta **entropia** no nome (Potencial DGA)")
        
    details.append(f"Entropia do Domínio: {entropy_value:.2f}")

    # 9. Distância de Levenshtein (Typosquatting)
    min_distance = float('inf')
    closest_legit_domain = ""

    for legit_name in DOMINIOS_LEGITIMOS:
        dist = levenshtein_distance(ext.domain, legit_name)
        
        if dist < min_distance:
            min_distance = dist
            closest_legit_domain = legit_name

    if min_distance in [1, 2]:
        reasons.append(f"Alta semelhança com '{closest_legit_domain}' (distância {min_distance}) - **Typosquatting**")

    # 10. Símbolo '@'
    if "@" in parsed_url.netloc:
        reasons.append("Presença de **'@' na URL** (Tentativa de esconder o host real)")

    # 11. Ofuscamento (Codificação)
    encoded_count = processed_url.count('%')
    if encoded_count > 5:
        reasons.append(f"Excesso de **codificação** na URL ({encoded_count}x '%')")

    # 12. Homograph Attack (Punycode/Unicode)
    try:
        domain_without_tld = ext.domain
        punycode_domain = domain_without_tld.encode('idna').decode('ascii')
        
        if domain_without_tld != punycode_domain and any(ord(c) > 127 for c in domain_without_tld):
            reasons.append("Uso de **caracteres Unicode/Punycode** no domínio (Homograph Attack)")
    except idna.IDNAError:
        reasons.append("Erro na codificação do domínio (Suspeita de caracteres inválidos/maliciosos)")
        
    # 13. Comprimento da URL
    if len(url) > COMPRIMENTO_MAXIMO:
        reasons.append(f"URL muito **longa** ({len(url)} chars) - Potencial ofuscamento")


    # 14. Redirecionamentos e Análise de Conteúdo (Final)
    try:
        # Permite redirecionamentos para obter a página final
        resp = requests.get(processed_url, allow_redirects=True, timeout=5)
        html_content = resp.text.lower()
        
        # Redirecionamentos excessivos
        if len(resp.history) > 3:
            reasons.append(f"Muitos **redirecionamentos** ({len(resp.history)})")
        
        details.append(f"Redirecionamentos detectados: {len(resp.history)}")
        
        # Obtém o domínio final
        current_domain_final = tldextract.extract(resp.url).registered_domain

        # A. Análise de Formulário de Senha (e C2 Externo) (NOVO)
        if re.search(r'<input\s+type=["\']password["\']', html_content):
             reasons.append("Página contém **formulário de senha** (Alto Risco)")
             
             # Procura por <form action="URL_EXTERNA">
             form_actions = re.findall(r'<form[^>]+action=["\'](http[s]?://[^"\']*)["\']', html_content)
             
             for action_url in form_actions:
                 # Usa tldextract no action_url
                 action_netloc = tldextract.extract(action_url).registered_domain
                 
                 # Se a ação do formulário de senha aponta para outro domínio (C2)
                 if action_netloc and action_netloc != current_domain_final:
                     reasons.append(f"Formulário envia dados para **domínio externo** ({action_netloc})")
                     break

        # B. Detecção de Iframe (NOVO)
        if re.search(r'<iframe', html_content):
            reasons.append("Página contém **iframe** (Potencial ocultação de conteúdo)")

        # C. Análise de Redirecionamento por Meta Tag
        if re.search(r'<meta\s+http-equiv=["\']refresh["\'].*url=', html_content):
             reasons.append("Página usa **meta tag refresh** (Potencial redirecionamento furtivo)")
        
        # D. Baixa Contagem de Links Externos
        # Conta tags <a> que linkam para domínios DFERENTES do analisado
        external_links = len(re.findall(f'<a[^>]+href=["\'](http[s]?://(?!.*{current_domain_final}))', html_content))
        
        if external_links < 3 and len(html_content) > 1000:
             reasons.append(f"Baixa contagem de links externos ({external_links})")
        
        # E. Entropia em Blocos JavaScript (NOVO)
        script_content = re.findall(r'<script[^>]*>(.*?)</script>', resp.text, re.DOTALL | re.IGNORECASE)
        high_entropy_script_count = 0
        
        for script in script_content:
            # Remove entidades HTML (ex: &#xNN;) e ignora scripts muito pequenos
            clean_script = html.unescape(script)
            if len(clean_script) > 100 and shannon_entropy(clean_script) > 6.0: 
                high_entropy_script_count += 1
                
        if high_entropy_script_count > 0:
            reasons.append(f"Conteúdo JS com **alta entropia** ({high_entropy_script_count} bloco(s))")

            
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
