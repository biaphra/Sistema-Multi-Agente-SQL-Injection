"""
Exemplos de uso do Sistema Multi-Agente SQL Injection
"""
from multiagent_sqli_tester import MultiAgentSQLITester
import os

def example_basic_test():
    """Exemplo básico de teste"""
    print("=== EXEMPLO 1: Teste Básico ===")
    
    # Verificar se API key está configurada
    if not os.getenv('OPENAI_API_KEY'):
        print("⚠️  Configure OPENAI_API_KEY no arquivo .env primeiro")
        return
    
    # Inicializar tester
    tester = MultiAgentSQLITester()
    
    # Executar teste
    target_url = "https://httpbin.org/get"  # URL segura para teste
    parameter = "query"
    
    print(f"Testando: {target_url}")
    print(f"Parâmetro: {parameter}")
    
    # Executar teste completo
    report = tester.run_comprehensive_test(target_url, parameter, max_payloads=10)
    
    if report:
        # Salvar relatório
        filename = tester.save_report(report, "exemplo_basico.json")
        print(f"✅ Relatório salvo: {filename}")

def example_advanced_test():
    """Exemplo avançado com configurações personalizadas"""
    print("=== EXEMPLO 2: Teste Avançado ===")
    
    if not os.getenv('OPENAI_API_KEY'):
        print("⚠️  Configure OPENAI_API_KEY no arquivo .env primeiro")
        return
    
    tester = MultiAgentSQLITester()
    
    # Configurações avançadas
    target_url = "https://httpbin.org/post"
    parameter = "search"
    max_payloads = 25
    
    print(f"Teste avançado em: {target_url}")
    
    # Executar com mais payloads
    report = tester.run_comprehensive_test(target_url, parameter, max_payloads)
    
    if report:
        # Salvar em múltiplos formatos
        tester.save_report(report, "exemplo_avancado.json", "json")
        tester.save_report(report, "exemplo_avancado.html", "html")
        tester.save_report(report, "exemplo_avancado.md", "markdown")
        print("✅ Relatórios salvos em múltiplos formatos")

def example_reconnaissance_only():
    """Exemplo apenas de reconhecimento"""
    print("=== EXEMPLO 3: Apenas Reconhecimento ===")
    
    if not os.getenv('OPENAI_API_KEY'):
        print("⚠️  Configure OPENAI_API_KEY no arquivo .env primeiro")
        return
    
    from agents.reconnaissance import ReconnaissanceAgent
    
    recon_agent = ReconnaissanceAgent()
    
    # Fazer apenas reconhecimento
    target_url = "https://httpbin.org/get"
    recon_data = recon_agent.quick_scan(target_url)
    
    print("Dados de reconhecimento:")
    for key, value in recon_data.items():
        print(f"  {key}: {value}")

def example_payload_generation():
    """Exemplo de geração de payloads"""
    print("=== EXEMPLO 4: Geração de Payloads ===")
    
    if not os.getenv('OPENAI_API_KEY'):
        print("⚠️  Configure OPENAI_API_KEY no arquivo .env primeiro")
        return
    
    from agents.payload_generator import PayloadGeneratorAgent
    
    payload_agent = PayloadGeneratorAgent()
    
    # Gerar diferentes tipos de payloads
    print("Payloads básicos:")
    basic = payload_agent.generate_basic_payloads()
    for payload in basic[:5]:
        print(f"  {payload}")
    
    print("\nPayloads específicos MySQL:")
    mysql = payload_agent.generate_database_specific_payloads('mysql')
    for payload in mysql[:5]:
        print(f"  {payload}")
    
    print("\nPayloads para bypass WAF:")
    waf_bypass = payload_agent.generate_waf_bypass_payloads()
    for payload in waf_bypass[:5]:
        print(f"  {payload}")

def example_custom_analysis():
    """Exemplo de análise customizada"""
    print("=== EXEMPLO 5: Análise Customizada ===")
    
    if not os.getenv('OPENAI_API_KEY'):
        print("⚠️  Configure OPENAI_API_KEY no arquivo .env primeiro")
        return
    
    from agents.response_analyzer import ResponseAnalyzerAgent
    from tools.web_tools import WebTools
    
    analyzer = ResponseAnalyzerAgent()
    web_tools = WebTools()
    
    # Simular resposta
    test_url = "https://httpbin.org/get"
    response = web_tools.make_request(test_url, {'test': 'value'})
    
    if response:
        response_data = web_tools.analyze_response(response)
        analysis = analyzer.analyze_response(response_data, "' OR 1=1--")
        
        print("Análise da resposta:")
        print(f"  Vulnerável: {analysis['vulnerable']}")
        print(f"  Confiança: {analysis['confidence']:.2f}")
        print(f"  Tipo: {analysis['vulnerability_type']}")
        print(f"  Indicadores: {analysis['indicators']}")

def main():
    """Menu principal de exemplos"""
    print("🤖 Exemplos do Sistema Multi-Agente SQL Injection")
    print("=" * 50)
    
    examples = [
        ("Teste Básico", example_basic_test),
        ("Teste Avançado", example_advanced_test),
        ("Apenas Reconhecimento", example_reconnaissance_only),
        ("Geração de Payloads", example_payload_generation),
        ("Análise Customizada", example_custom_analysis)
    ]
    
    print("Escolha um exemplo:")
    for i, (name, _) in enumerate(examples, 1):
        print(f"  {i}. {name}")
    
    try:
        choice = int(input("\nDigite o número do exemplo (1-5): "))
        if 1 <= choice <= len(examples):
            print()
            examples[choice-1][1]()
        else:
            print("❌ Opção inválida")
    except ValueError:
        print("❌ Digite um número válido")
    except KeyboardInterrupt:
        print("\n👋 Saindo...")

if __name__ == "__main__":
    main()
