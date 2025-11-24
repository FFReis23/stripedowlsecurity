from flask import Flask, render_template, request
import re
import tldextract
import requests
import socket
import ssl
from datetime import datetime
# Import whois foi removido, pois usaremos requests novamente

app = Flask(__name__)

# Função principal de verificação
def is_suspicious(url):
    reasons = []
    details = []

    # Se a URL não começar com esquema, adicionamos um esquema padrão para processamento.
    if not url.startswith(("http://", "https://")):
        processed_url = "https://" + url # Assume https por padrão
    else:
        processed_url = url
        
    ext = tldextract.extract(processed_url)
    hostname = ext.domain + "." + ext.suffix
    
    # 1. HTTPS e Certificado
    if not processed_url.startswith("https://"):
        reasons.append("URL não utiliza HTTPS")
    else:
        try:
            # Tenta verificar o SSL/TLS
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

        except Exception:
            reasons.append("Erro ao verificar SSL/TLS (host pode estar inacessível ou certificado inválido)")

    # 2. Uso de IP
    if re.match(r"^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
        reasons.append("Uso de IP no lugar de domínio")

    # 3. Subdomínios excessivos
    if len(ext.subdomain.split(".")) > 2:
        reasons.append("Muitos subdomínios (potencial ofuscamento)")

    # 4. Palavras suspeitas
    palavras_suspeitas = [
        "login", "secure", "update", "verify",
        "account", "bank", "confirm", "payment"
    ]

    if any(p in processed_url.lower() for p in palavras_suspeitas):
        reasons.append("Contém palavras suspeitas na URL")

    # 5. Lista negra simples
    blacklist = ["malicious-site.com", "phishing-domain.net"]
    if ext.domain in blacklist:
        reasons.append(f"Domínio na lista negra: {ext.domain}")

    # 6. WHOIS (Idade do domínio) - USANDO API EXTERNA (WhoisFreaks)
    try:
        # ATENÇÃO: É NECESSÁRIO QUE ESTA API ESTEJA FUNCIONANDO E QUE A CHAVE SEJA VÁLIDA.
        api_url = f"https://api.whoisfreaks.com/v1.0/whois?apiKey=free&whois=live&domainName={hostname}"
        
        # Ajustei o timeout e adicionei verificação do status code
        resp = requests.get(api_url, timeout=5)
        resp.raise_for_status() # Lança erro para status 4xx/5xx
        whois_data = resp.json()

        # Verifica se o registro WHOIS existe e se tem a data de criação
        if (whois_data.get("whoisRecord") and 
            "creation_date" in whois_data["whoisRecord"] and
            whois_data["whoisRecord"]["creation_date"]):
            
            creation_date_str = whois_data["whoisRecord"]["creation_date"]
            
            # Tenta parsear o formato YYYY-MM-DD (a API WhoisFreaks costuma retornar assim)
            try:
                 # Pega apenas os primeiros 10 caracteres (YYYY-MM-DD)
                 creation_date = datetime.strptime(creation_date_str[:10], "%Y-%m-%d")
            except:
                 # Se falhar, tenta formatos mais comuns ou usa fallback
                 creation_date = datetime(2000, 1, 1) # Fallback seguro
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

        
    # 7. Redirecionamentos
    try:
        resp = requests.head(processed_url, allow_redirects=True, timeout=4)
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
        result_text += "<br><br><strong>Detalhes da Análise:</strong><br>" + "<br>".join(details)

    return result_text


# Página extra
@app.route("/ataques")
def ataques():
    return render_template("ataques.html")


# Página principal (Rota correta com POST/GET)
@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        url = request.form.get("url")

        if url:
            # Chama a função de verificação
            result = is_suspicious(url)

    # Passa o resultado para o template
    return render_template("index.html", result=result)


# Iniciar localmente
if __name__ == "__main__":
    app.run(debug=True)
