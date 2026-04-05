from flask import Flask, render_template, request
import tldextract
import urllib.parse
import whois
import requests
import math
import warnings

# Desabilita avisos de certificados inseguros (comum ao analisar sites de phishing)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

app = Flask(__name__)

# --- Configurações de Segurança ---
DOMINIOS_LEGITIMOS = ["google", "microsoft", "apple", "netflix", "paypal", "itau", "amazon", "facebook", "twitter", "instagram", "linkedin"]
PALAVRAS_SUSPEITAS = ["login", "secure", "update", "verify", "account", "bank", "confirm", "payment", "password", "auth", "webscr", "transfer", "bradesco", "caixa", "santander"]
URL_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly"]
SUSPICIOUS_TLDS = [".xyz", ".top", ".tk", ".cf", ".ga", ".ml", ".gq", ".bid", ".win", ".icu", ".fun", ".loan"]

def calculate_entropy(s):
    """Calcula a entropia de Shannon para detectar domínios gerados aleatoriamente."""
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy

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
        # verify=False permite analisar sites com problemas de SSL
        response = requests.get(url, timeout=5, verify=False, allow_redirects=True)
        headers = response.headers
        
        checks = {
            'Strict-Transport-Security': ('✅ HTTPS Forçado', '❌ Falta HSTS (Risco de Interceptação)'),
            'Content-Security-Policy': ('✅ CSP Ativo', '❌ Falta CSP (Risco de Injeção XSS)'),
            'X-Frame-Options': ('✅ Proteção Anti-Clickjacking', '❌ Falta X-Frame-Options')
        }
        
        for header, (pos, neg) in checks.items():
            headers_info.append(pos if header in headers else neg)
            
        if response.history:
            headers_info.append(f"ℹ️ O link redirecionou {len(response.history)} vez(es).")
            
    except Exception as e:
        headers_info.append(f"⚠️ Erro ao conectar: Site pode estar offline ou bloqueando acesso.")
    return headers_info

def get_whois_data(url):
    try:
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"
        w = whois.whois(domain)
        # Verifica se o domínio é muito recente (comum em phishing)
        creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        return {
            "registrar": w.registrar if w.registrar else "N/A",
            "creation_date": creation.strftime('%d/%m/%Y') if creation else "N/A",
            "country": w.country if w.country else "N/A"
        }
    except:
        return None

def is_suspicious(url):
    reasons = []
    # Normalização básica
    if not url.startswith(("http://", "https://")):
        url_to_parse = "https://" + url
    else:
        url_to_parse = url
        
    try:
        parsed_url = urllib.parse.urlparse(url_to_parse)
        netloc = parsed_url.netloc.lower()
        ext = tldextract.extract(url_to_parse)
        domain = ext.domain.lower()
        full_path = url.lower()

        # 1. Encurtadores
        if any(shortener in netloc for shortener in URL_SHORTENERS):
            reasons.append("Uso de **encurtador de URL** (comum para ocultar o destino real).")

        # 2. TLDs Suspeitas
        if f".{ext.suffix}" in SUSPICIOUS_TLDS:
            reasons.append(f"Extensão de domínio suspeita (**{ext.suffix}**).")

        # 3. HTTPS
        if not url.startswith("https://"):
            reasons.append("Conexão **não criptografada** (HTTP).")

        # 4. Typosquatting (Levenshtein)
        for legit in DOMINIOS_LEGITIMOS:
            dist = levenshtein_distance(domain, legit)
            if 0 < dist <= 2:
                reasons.append(f"Possível **Typosquatting** (se passa por {legit.capitalize()}).")
                break

        # 5. Palavras Suspeitas (Implementado agora)
        for palavra in PALAVRAS_SUSPEITAS:
            if palavra in full_path and palavra != domain:
                reasons.append(f"Contém termo sensível no caminho: **{palavra}**.")
                break

        # 6. Entropia Alta (Nomes aleatórios)
        if calculate_entropy(domain) > 3.8:
            reasons.append("Nome de domínio parece ser **gerado aleatoriamente**.")

        # 7. Excesso de Subdomínios
        if netloc.count('.') > 3:
            reasons.append("Excesso de subdomínios (técnica de camuflagem).")

    except:
        reasons.append("Erro ao processar a estrutura da URL.")
        
    return reasons

@app.route("/", methods=["GET", "POST"])
def index():
    result, reasons, whois_info, headers_info, url_digitada = None, [], None, [], ""
    if request.method == "POST":
        url_digitada = request.form.get("url", "").strip()
        if url_digitada:
            # Garante prefixo para análise técnica
            full_url = url_digitada if url_digitada.startswith(("http://", "https://")) else "http://" + url_digitada
            
            reasons = is_suspicious(url_digitada)
            whois_info = get_whois_data(full_url)
            headers_info = analyze_security_headers(full_url)
            
            if reasons:
                result = f"⚠️ Alerta: Encontramos {len(reasons)} indicadores de risco!"
            else:
                result = "✅ Esta URL parece seguir padrões normais."
                
    return render_template("index.html", result=result, reasons=reasons, whois_info=whois_info, headers_info=headers_info, url_digitada=url_digitada)

if __name__ == "__main__":
    app.run(debug=True)
