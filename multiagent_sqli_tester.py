"""
Sistema Multi-Agente de Teste SQL Injection
Coordenador principal que orquestra todos os agentes especializados
"""
import os
import sys
import time
from typing import Dict, List, Optional
from datetime import datetime
from rich.console import Console
from rich.progress import Progress, TaskID
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

# Importar agentes
from agents.payload_generator import PayloadGeneratorAgent
from agents.response_analyzer import ResponseAnalyzerAgent
from agents.reconnaissance import ReconnaissanceAgent
from agents.evasion_specialist import EvasionSpecialistAgent
from agents.report_generator import ReportGeneratorAgent
from tools.web_tools import WebTools
from config import Config

class MultiAgentSQLITester:
    def __init__(self):
        self.console = Console()
        self.web_tools = WebTools()
        
        # Inicializar agentes
        self.payload_agent = PayloadGeneratorAgent()
        self.analyzer_agent = ResponseAnalyzerAgent()
        self.recon_agent = ReconnaissanceAgent()
        self.evasion_agent = EvasionSpecialistAgent()
        self.report_agent = ReportGeneratorAgent()
        
        # Dados de teste
        self.test_results = []
        self.recon_data = {}
        self.failed_payloads = []
        
    def run_comprehensive_test(self, target_url: str, parameter: str = 'query', 
                             max_payloads: int = 50) -> Dict:
        """Executa teste completo com todos os agentes"""
        
        self.console.print(Panel.fit(
            "[bold blue]🤖 Sistema Multi-Agente de Teste SQL Injection[/bold blue]\n"
            f"[yellow]Alvo:[/yellow] {target_url}\n"
            f"[yellow]Parâmetro:[/yellow] {parameter}",
            title="Iniciando Teste"
        ))
        
        start_time = time.time()
        
        try:
            # Fase 1: Reconhecimento
            self.console.print("\n[bold green]📡 Fase 1: Reconhecimento[/bold green]")
            self.recon_data = self.recon_agent.full_reconnaissance(target_url, parameter)
            self._print_recon_summary()
            
            # Fase 2: Geração de Payloads
            self.console.print("\n[bold green]🎯 Fase 2: Geração de Payloads[/bold green]")
            payloads = self._generate_comprehensive_payloads(max_payloads)
            self.console.print(f"[cyan]Total de payloads gerados:[/cyan] {len(payloads)}")
            
            # Fase 3: Execução de Testes
            self.console.print("\n[bold green]🔍 Fase 3: Execução de Testes[/bold green]")
            self._execute_tests(target_url, parameter, payloads)
            
            # Fase 4: Geração de Relatório
            self.console.print("\n[bold green]📊 Fase 4: Geração de Relatório[/bold green]")
            report = self._generate_final_report(target_url, parameter, start_time)
            
            # Exibir resultados
            self._display_results()
            
            return report
            
        except Exception as e:
            self.console.print(f"[bold red]❌ Erro durante o teste:[/bold red] {str(e)}")
            return {}
    
    def _generate_comprehensive_payloads(self, max_payloads: int) -> List[str]:
        """Gera payloads usando múltiplas estratégias"""
        all_payloads = []
        
        # Payloads básicos
        basic_payloads = self.payload_agent.generate_basic_payloads()
        all_payloads.extend(basic_payloads)
        
        # Payloads específicos do banco
        db_type = self.recon_data.get('database_type')
        if db_type:
            db_payloads = self.payload_agent.generate_database_specific_payloads(db_type)
            all_payloads.extend(db_payloads)
        
        # Payloads para bypass de WAF
        if self.recon_data.get('waf_detected'):
            waf_payloads = self.payload_agent.generate_waf_bypass_payloads(
                self.recon_data.get('waf_type')
            )
            all_payloads.extend(waf_payloads)
        
        # Payloads contextuais
        context = {
            'database_type': db_type,
            'waf_detected': self.recon_data.get('waf_detected', False),
            'parameter_type': self.recon_data.get('parameter_analysis', {}).get('type', 'string')
        }
        contextual_payloads = self.payload_agent.generate_contextual_payloads(context)
        all_payloads.extend(contextual_payloads)
        
        # Payloads gerados por IA
        ai_payloads = self.payload_agent.generate_ai_payloads(self.recon_data)
        all_payloads.extend(ai_payloads)
        
        # Remover duplicatas e limitar
        unique_payloads = list(set(all_payloads))
        return unique_payloads[:max_payloads]
    
    def _execute_tests(self, target_url: str, parameter: str, payloads: List[str]):
        """Executa testes com todos os payloads"""
        
        # Estabelecer baseline
        baseline_response = self.web_tools.make_request(target_url, {parameter: 'baseline_test'})
        if baseline_response:
            baseline_data = self.web_tools.analyze_response(baseline_response)
            self.analyzer_agent.set_baseline(baseline_data)
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Testando payloads...", total=len(payloads))
            
            for i, payload in enumerate(payloads):
                progress.update(task, advance=1)
                
                # Fazer requisição
                response = self.web_tools.make_request(target_url, {parameter: payload})
                
                if response:
                    # Analisar resposta
                    response_data = self.web_tools.analyze_response(response)
                    analysis = self.analyzer_agent.analyze_response(response_data, payload)
                    
                    # Salvar resultado
                    self.test_results.append(analysis)
                    
                    # Se não vulnerável, tentar evasão
                    if not analysis['vulnerable'] and self.recon_data.get('waf_detected'):
                        self._try_evasion_techniques(target_url, parameter, payload)
                    
                    # Feedback em tempo real
                    if analysis['vulnerable']:
                        self.console.print(f"[green]✅ Vulnerabilidade detectada:[/green] {payload[:50]}...")
                else:
                    # Registrar falha
                    self.test_results.append({
                        'payload': payload,
                        'vulnerable': False,
                        'confidence': 0.0,
                        'error': 'Request failed'
                    })
                
                # Delay para evitar rate limiting
                time.sleep(0.1)
    
    def _try_evasion_techniques(self, target_url: str, parameter: str, original_payload: str):
        """Tenta técnicas de evasão para payloads que falharam"""
        waf_info = {
            'type': self.recon_data.get('waf_type'),
            'detected': self.recon_data.get('waf_detected')
        }
        
        # Gerar payloads de evasão
        evasion_payloads = self.evasion_agent.generate_evasion_payloads(
            original_payload, waf_info.get('type')
        )
        
        # Testar alguns payloads de evasão (limitado para não sobrecarregar)
        for evasion_payload in evasion_payloads[:5]:
            response = self.web_tools.make_request(target_url, {parameter: evasion_payload})
            
            if response:
                response_data = self.web_tools.analyze_response(response)
                analysis = self.analyzer_agent.analyze_response(response_data, evasion_payload)
                
                # Marcar como evasão
                analysis['evasion_attempt'] = True
                analysis['original_payload'] = original_payload
                
                self.test_results.append(analysis)
                
                if analysis['vulnerable']:
                    self.console.print(f"[yellow]🔓 Evasão bem-sucedida:[/yellow] {evasion_payload[:50]}...")
                    break
    
    def _generate_final_report(self, target_url: str, parameter: str, start_time: float) -> Dict:
        """Gera relatório final"""
        target_info = {
            'url': target_url,
            'parameter': parameter,
            'duration': f"{time.time() - start_time:.2f}s",
            'total_payloads': len(self.test_results)
        }
        
        report = self.report_agent.generate_comprehensive_report(
            self.test_results, self.recon_data, target_info
        )
        
        return report
    
    def _print_recon_summary(self):
        """Exibe resumo do reconhecimento"""
        table = Table(title="Resumo do Reconhecimento")
        table.add_column("Categoria", style="cyan")
        table.add_column("Informação", style="white")
        
        table.add_row("Tecnologias", ", ".join(self.recon_data.get('technologies', ['Não detectadas'])))
        table.add_row("Banco de Dados", self.recon_data.get('database_type', 'Desconhecido'))
        table.add_row("WAF Detectado", "Sim" if self.recon_data.get('waf_detected') else "Não")
        
        if self.recon_data.get('waf_detected'):
            table.add_row("Tipo de WAF", self.recon_data.get('waf_type', 'Desconhecido'))
        
        table.add_row("Headers de Segurança", str(len(self.recon_data.get('security_headers', {}))))
        table.add_row("Formulários", str(len(self.recon_data.get('forms', []))))
        
        self.console.print(table)
    
    def _display_results(self):
        """Exibe resultados finais"""
        vulnerable_tests = [r for r in self.test_results if r.get('vulnerable', False)]
        
        # Resumo geral
        summary_table = Table(title="Resumo dos Resultados")
        summary_table.add_column("Métrica", style="cyan")
        summary_table.add_column("Valor", style="white")
        
        summary_table.add_row("Total de Testes", str(len(self.test_results)))
        summary_table.add_row("Vulnerabilidades Encontradas", str(len(vulnerable_tests)))
        summary_table.add_row("Taxa de Sucesso", f"{(len(vulnerable_tests)/len(self.test_results))*100:.1f}%" if self.test_results else "0%")
        
        self.console.print(summary_table)
        
        # Vulnerabilidades por severidade
        if vulnerable_tests:
            severity_table = Table(title="Vulnerabilidades por Severidade")
            severity_table.add_column("Severidade", style="cyan")
            severity_table.add_column("Quantidade", style="white")
            
            severities = {}
            for test in vulnerable_tests:
                sev = test.get('severity', 'unknown')
                severities[sev] = severities.get(sev, 0) + 1
            
            for severity, count in severities.items():
                color = {
                    'critical': 'red',
                    'high': 'orange1',
                    'medium': 'yellow',
                    'low': 'green'
                }.get(severity, 'white')
                
                severity_table.add_row(
                    f"[{color}]{severity.upper()}[/{color}]",
                    str(count)
                )
            
            self.console.print(severity_table)
            
            # Top payloads vulneráveis
            top_payloads = Table(title="Top 5 Payloads Vulneráveis")
            top_payloads.add_column("Payload", style="cyan", max_width=50)
            top_payloads.add_column("Tipo", style="white")
            top_payloads.add_column("Confiança", style="green")
            
            sorted_vulns = sorted(vulnerable_tests, key=lambda x: x.get('confidence', 0), reverse=True)
            
            for vuln in sorted_vulns[:5]:
                top_payloads.add_row(
                    vuln.get('payload', '')[:47] + "..." if len(vuln.get('payload', '')) > 50 else vuln.get('payload', ''),
                    vuln.get('vulnerability_type', 'unknown'),
                    f"{vuln.get('confidence', 0)*100:.1f}%"
                )
            
            self.console.print(top_payloads)
    
    def save_report(self, report: Dict, filename: str = None, format_type: str = 'json'):
        """Salva relatório em arquivo"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"sqli_report_{timestamp}.{format_type}"
        
        report_content = self.report_agent.export_report(report, format_type)
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        self.console.print(f"[green]📄 Relatório salvo:[/green] {filename}")
        return filename

def main():
    """Função principal para execução via linha de comando"""
    if len(sys.argv) < 2:
        print("Uso: python multiagent_sqli_tester.py <URL> [parâmetro] [max_payloads]")
        print("Exemplo: python multiagent_sqli_tester.py https://example.com/search.php query 50")
        sys.exit(1)
    
    target_url = sys.argv[1]
    parameter = sys.argv[2] if len(sys.argv) > 2 else 'query'
    max_payloads = int(sys.argv[3]) if len(sys.argv) > 3 else 50
    
    # Verificar se API key está configurada
    if not Config.OPENAI_API_KEY:
        print("❌ OPENAI_API_KEY não configurada. Configure no arquivo .env")
        sys.exit(1)
    
    # Executar teste
    tester = MultiAgentSQLITester()
    report = tester.run_comprehensive_test(target_url, parameter, max_payloads)
    
    if report:
        # Salvar relatórios em múltiplos formatos
        tester.save_report(report, format_type='json')
        tester.save_report(report, format_type='html')
        tester.save_report(report, format_type='markdown')
        
        print("\n✅ Teste completo! Verifique os relatórios gerados.")
    else:
        print("\n❌ Erro durante a execução do teste.")

if __name__ == "__main__":
    main()
