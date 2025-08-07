"""
Demonstração do Sistema Multi-Agente SQL Injection
Script para testar o sistema sem necessidade de API key real
"""
import time
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress

class SQLIDemo:
    def __init__(self):
        self.console = Console()
    
    def run_demo(self):
        """Executa demonstração completa do sistema"""
        
        self.console.print(Panel.fit(
            "[bold blue]🤖 DEMONSTRAÇÃO: Sistema Multi-Agente SQL Injection[/bold blue]\n"
            "[yellow]Simulando teste em ambiente controlado[/yellow]",
            title="Demo Mode"
        ))
        
        # Simular fases do teste
        self._demo_reconnaissance()
        self._demo_payload_generation()
        self._demo_testing_execution()
        self._demo_evasion_techniques()
        self._demo_report_generation()
        
        self.console.print(Panel.fit(
            "[bold green]✅ Demonstração Concluída![/bold green]\n"
            "[cyan]O sistema está pronto para uso com alvos reais[/cyan]",
            title="Demo Completa"
        ))
    
    def _demo_reconnaissance(self):
        """Demonstra fase de reconhecimento"""
        self.console.print("\n[bold green]📡 FASE 1: Reconhecimento Inteligente[/bold green]")
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Coletando informações do alvo...", total=100)
            
            steps = [
                ("Analisando headers HTTP", 20),
                ("Detectando tecnologias", 25),
                ("Identificando WAF", 15),
                ("Fingerprinting de banco", 20),
                ("Analisando formulários", 10),
                ("Gerando insights com IA", 10)
            ]
            
            for step, advance in steps:
                time.sleep(0.5)
                progress.update(task, advance=advance)
                self.console.print(f"  [yellow]→[/yellow] {step}")
        
        # Resultados simulados
        recon_table = Table(title="Resultados do Reconhecimento")
        recon_table.add_column("Categoria", style="cyan")
        recon_table.add_column("Resultado", style="white")
        
        recon_table.add_row("Servidor", "Apache/2.4.41 (Ubuntu)")
        recon_table.add_row("Tecnologias", "PHP 7.4, MySQL 8.0")
        recon_table.add_row("WAF Detectado", "[red]Cloudflare[/red]")
        recon_table.add_row("Banco de Dados", "[green]MySQL[/green]")
        recon_table.add_row("Headers de Segurança", "2/7 implementados")
        recon_table.add_row("Formulários", "3 encontrados")
        recon_table.add_row("Nível de Segurança", "[yellow]6/10[/yellow]")
        
        self.console.print(recon_table)
    
    def _demo_payload_generation(self):
        """Demonstra geração de payloads"""
        self.console.print("\n[bold green]🎯 FASE 2: Geração Inteligente de Payloads[/bold green]")
        
        payload_types = [
            ("Payloads Básicos", 15, "green"),
            ("Específicos MySQL", 12, "blue"),
            ("Bypass Cloudflare", 8, "yellow"),
            ("Time-based Blind", 6, "orange1"),
            ("Union-based", 10, "purple"),
            ("Gerados por IA", 5, "red")
        ]
        
        generation_table = Table(title="Payloads Gerados por Categoria")
        generation_table.add_column("Categoria", style="cyan")
        generation_table.add_column("Quantidade", style="white")
        generation_table.add_column("Exemplo", style="dim")
        
        examples = [
            "' OR 1=1--",
            "' UNION SELECT @@version--",
            "' /**/OR/**/1=1--",
            "' AND SLEEP(5)--",
            "' UNION SELECT 1,2,3--",
            "' OR (SELECT COUNT(*) FROM users)>0--"
        ]
        
        for i, (category, count, color) in enumerate(payload_types):
            generation_table.add_row(
                f"[{color}]{category}[/{color}]",
                str(count),
                examples[i][:30] + "..."
            )
        
        self.console.print(generation_table)
        self.console.print(f"[cyan]Total de payloads únicos gerados:[/cyan] [bold]56[/bold]")
    
    def _demo_testing_execution(self):
        """Demonstra execução dos testes"""
        self.console.print("\n[bold green]🔍 FASE 3: Execução Inteligente de Testes[/bold green]")
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Testando payloads...", total=56)
            
            vulnerabilities_found = []
            
            for i in range(56):
                time.sleep(0.05)  # Simular tempo de teste
                progress.update(task, advance=1)
                
                # Simular descoberta de vulnerabilidades
                if i in [12, 23, 34, 45]:  # Simular 4 vulnerabilidades
                    vuln_type = ["Error-based", "Time-based", "Union-based", "Boolean-based"][len(vulnerabilities_found)]
                    vulnerabilities_found.append(vuln_type)
                    self.console.print(f"  [green]✅ Vulnerabilidade {vuln_type} detectada![/green]")
        
        # Resultados dos testes
        results_table = Table(title="Resultados dos Testes")
        results_table.add_column("Métrica", style="cyan")
        results_table.add_column("Valor", style="white")
        
        results_table.add_row("Payloads Testados", "56")
        results_table.add_row("Vulnerabilidades Encontradas", "[red]4[/red]")
        results_table.add_row("Taxa de Sucesso", "[green]7.1%[/green]")
        results_table.add_row("Tempo Total", "2.8s")
        results_table.add_row("Falsos Positivos", "[green]0[/green]")
        
        self.console.print(results_table)
    
    def _demo_evasion_techniques(self):
        """Demonstra técnicas de evasão"""
        self.console.print("\n[bold green]🔓 FASE 4: Técnicas de Evasão Avançadas[/bold green]")
        
        evasion_table = Table(title="Técnicas de Evasão Aplicadas")
        evasion_table.add_column("Técnica", style="cyan")
        evasion_table.add_column("Payload Original", style="dim")
        evasion_table.add_column("Payload Modificado", style="yellow")
        evasion_table.add_column("Status", style="white")
        
        evasion_examples = [
            ("Comment Insertion", "' OR 1=1--", "' /**/OR/**/1=1--", "[green]Sucesso[/green]"),
            ("Case Variation", "' UNION SELECT", "' UnIoN sElEcT", "[red]Bloqueado[/red]"),
            ("URL Encoding", "' OR 1=1--", "'%20OR%201=1--", "[green]Sucesso[/green]"),
            ("Keyword Replacement", "' OR 1=1--", "' || 1=1--", "[yellow]Parcial[/yellow]")
        ]
        
        for technique, original, modified, status in evasion_examples:
            evasion_table.add_row(technique, original, modified, status)
        
        self.console.print(evasion_table)
        self.console.print("[cyan]2 técnicas de evasão bem-sucedidas contra Cloudflare[/cyan]")
    
    def _demo_report_generation(self):
        """Demonstra geração de relatórios"""
        self.console.print("\n[bold green]📊 FASE 5: Relatório Inteligente[/bold green]")
        
        # Análise de risco
        risk_table = Table(title="Análise de Risco")
        risk_table.add_column("Categoria", style="cyan")
        risk_table.add_column("Nível", style="white")
        risk_table.add_column("Detalhes", style="dim")
        
        risk_table.add_row("Risco Geral", "[red]ALTO[/red]", "4 vulnerabilidades críticas")
        risk_table.add_row("Impacto no Negócio", "[red]CRÍTICO[/red]", "Possível vazamento de dados")
        risk_table.add_row("Facilidade de Exploração", "[yellow]MODERADA[/yellow]", "WAF presente mas contornável")
        risk_table.add_row("Conformidade", "[red]NÃO CONFORME[/red]", "LGPD, PCI DSS afetados")
        
        self.console.print(risk_table)
        
        # Recomendações
        self.console.print("\n[bold yellow]🔧 Principais Recomendações:[/bold yellow]")
        recommendations = [
            "Implementar prepared statements em todos os queries",
            "Configurar WAF com regras mais restritivas",
            "Aplicar validação rigorosa de entrada",
            "Implementar logging de tentativas de SQL Injection",
            "Realizar auditoria completa do código"
        ]
        
        for i, rec in enumerate(recommendations, 1):
            self.console.print(f"  {i}. [cyan]{rec}[/cyan]")
        
        # Formatos de relatório
        self.console.print(f"\n[green]📄 Relatórios gerados:[/green]")
        formats = ["JSON (detalhado)", "HTML (executivo)", "Markdown (técnico)"]
        for fmt in formats:
            self.console.print(f"  [yellow]→[/yellow] {fmt}")

def main():
    """Executa demonstração"""
    demo = SQLIDemo()
    demo.run_demo()
    
    print("\n" + "="*60)
    print("🚀 SISTEMA PRONTO PARA USO!")
    print("="*60)
    print("\nPara usar com alvos reais:")
    print("1. Configure sua OPENAI_API_KEY no arquivo .env")
    print("2. Execute: python multiagent_sqli_tester.py <URL> <parâmetro>")
    print("\nExemplo:")
    print("python multiagent_sqli_tester.py https://example.com/search.php query")
    print("\n⚠️  Use apenas em sistemas que você possui autorização para testar!")

if __name__ == "__main__":
    main()
