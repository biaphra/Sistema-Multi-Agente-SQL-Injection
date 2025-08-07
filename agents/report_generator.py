"""
Agent Report Generator - Geração de relatórios inteligentes
"""
from crewai import Agent
from langchain_openai import ChatOpenAI
from typing import Dict, List, Optional
import json
from datetime import datetime
from config import Config

class ReportGeneratorAgent:
    def __init__(self):
        self.llm = ChatOpenAI(
            model=Config.OPENAI_MODEL,
            temperature=Config.TEMPERATURE,
            max_tokens=Config.MAX_TOKENS,
            api_key=Config.OPENAI_API_KEY
        )
        
        self.agent = Agent(
            role="Security Report Specialist",
            goal="Gerar relatórios detalhados e acionáveis sobre vulnerabilidades de SQL Injection",
            backstory="""Você é um especialista em documentação de segurança com experiência
            em análise de riscos e comunicação técnica. Seus relatórios são precisos, detalhados
            e fornecem recomendações práticas para correção de vulnerabilidades.""",
            verbose=True,
            allow_delegation=False,
            llm=self.llm
        )
    
    def generate_comprehensive_report(self, test_results: List[Dict], 
                                    recon_data: Dict, 
                                    target_info: Dict) -> Dict:
        """Gera relatório completo dos testes"""
        report = {
            'metadata': self._generate_metadata(target_info),
            'executive_summary': self._generate_executive_summary(test_results),
            'technical_details': self._generate_technical_details(test_results, recon_data),
            'vulnerability_analysis': self._analyze_vulnerabilities(test_results),
            'risk_assessment': self._assess_risk(test_results, recon_data),
            'recommendations': self._generate_recommendations(test_results, recon_data),
            'appendix': self._generate_appendix(test_results, recon_data)
        }
        
        return report
    
    def _generate_metadata(self, target_info: Dict) -> Dict:
        """Gera metadados do relatório"""
        return {
            'report_id': f"SQLI-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            'generation_date': datetime.now().isoformat(),
            'target_url': target_info.get('url', 'N/A'),
            'target_parameter': target_info.get('parameter', 'N/A'),
            'test_duration': target_info.get('duration', 'N/A'),
            'total_payloads_tested': target_info.get('total_payloads', 0),
            'report_version': '1.0',
            'generated_by': 'Multi-Agent SQL Injection Testing System'
        }
    
    def _generate_executive_summary(self, test_results: List[Dict]) -> Dict:
        """Gera resumo executivo"""
        vulnerable_tests = [r for r in test_results if r.get('vulnerable', False)]
        total_tests = len(test_results)
        vulnerability_count = len(vulnerable_tests)
        
        # Classificar severidades
        severity_counts = {
            'critical': len([r for r in vulnerable_tests if r.get('severity') == 'critical']),
            'high': len([r for r in vulnerable_tests if r.get('severity') == 'high']),
            'medium': len([r for r in vulnerable_tests if r.get('severity') == 'medium']),
            'low': len([r for r in vulnerable_tests if r.get('severity') == 'low'])
        }
        
        # Determinar status geral
        if severity_counts['critical'] > 0:
            overall_risk = 'CRITICAL'
        elif severity_counts['high'] > 0:
            overall_risk = 'HIGH'
        elif severity_counts['medium'] > 0:
            overall_risk = 'MEDIUM'
        elif severity_counts['low'] > 0:
            overall_risk = 'LOW'
        else:
            overall_risk = 'NONE'
        
        return {
            'overall_risk_level': overall_risk,
            'vulnerabilities_found': vulnerability_count,
            'total_tests_performed': total_tests,
            'success_rate': f"{(vulnerability_count/total_tests)*100:.1f}%" if total_tests > 0 else "0%",
            'severity_breakdown': severity_counts,
            'key_findings': self._extract_key_findings(vulnerable_tests),
            'immediate_actions_required': vulnerability_count > 0
        }
    
    def _generate_technical_details(self, test_results: List[Dict], recon_data: Dict) -> Dict:
        """Gera detalhes técnicos"""
        return {
            'target_analysis': {
                'technologies_detected': recon_data.get('technologies', []),
                'database_type': recon_data.get('database_type', 'Unknown'),
                'waf_protection': {
                    'detected': recon_data.get('waf_detected', False),
                    'type': recon_data.get('waf_type', 'N/A')
                },
                'security_headers': recon_data.get('security_headers', {}),
                'server_info': recon_data.get('server_info', {})
            },
            'testing_methodology': {
                'payload_categories_used': self._categorize_payloads(test_results),
                'evasion_techniques_applied': self._extract_evasion_techniques(test_results),
                'detection_methods': ['Error-based', 'Time-based', 'Union-based', 'Boolean-based']
            },
            'successful_attacks': self._format_successful_attacks(test_results)
        }
    
    def _analyze_vulnerabilities(self, test_results: List[Dict]) -> List[Dict]:
        """Analisa vulnerabilidades encontradas"""
        vulnerabilities = []
        vulnerable_tests = [r for r in test_results if r.get('vulnerable', False)]
        
        # Agrupar por tipo de vulnerabilidade
        vuln_types = {}
        for test in vulnerable_tests:
            vuln_type = test.get('vulnerability_type', 'unknown')
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = []
            vuln_types[vuln_type].append(test)
        
        for vuln_type, tests in vuln_types.items():
            vulnerability = {
                'type': vuln_type,
                'count': len(tests),
                'severity': self._calculate_max_severity(tests),
                'confidence': max([t.get('confidence', 0) for t in tests]),
                'payloads': [t.get('payload', '') for t in tests[:5]],  # Top 5
                'indicators': list(set([ind for t in tests for ind in t.get('indicators', [])])),
                'description': self._get_vulnerability_description(vuln_type),
                'impact': self._get_vulnerability_impact(vuln_type),
                'exploitation_difficulty': self._assess_exploitation_difficulty(tests)
            }
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _assess_risk(self, test_results: List[Dict], recon_data: Dict) -> Dict:
        """Avalia o risco geral"""
        vulnerable_tests = [r for r in test_results if r.get('vulnerable', False)]
        
        # Fatores de risco
        risk_factors = {
            'vulnerability_presence': len(vulnerable_tests) > 0,
            'high_confidence_vulns': len([r for r in vulnerable_tests if r.get('confidence', 0) > 0.8]) > 0,
            'multiple_attack_vectors': len(set([r.get('vulnerability_type') for r in vulnerable_tests])) > 1,
            'waf_bypass_successful': any('bypass' in str(r.get('indicators', [])) for r in vulnerable_tests),
            'database_exposure': any('data exposure' in str(r.get('indicators', [])) for r in vulnerable_tests),
            'no_waf_protection': not recon_data.get('waf_detected', False),
            'weak_security_headers': len(recon_data.get('security_headers', {})) < 3
        }
        
        # Calcular score de risco
        risk_score = sum(risk_factors.values()) / len(risk_factors)
        
        if risk_score >= 0.7:
            risk_level = 'CRITICAL'
        elif risk_score >= 0.5:
            risk_level = 'HIGH'
        elif risk_score >= 0.3:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'overall_risk_level': risk_level,
            'risk_score': f"{risk_score*100:.1f}%",
            'risk_factors': risk_factors,
            'business_impact': self._assess_business_impact(risk_level),
            'compliance_impact': self._assess_compliance_impact(vulnerable_tests)
        }
    
    def _generate_recommendations(self, test_results: List[Dict], recon_data: Dict) -> Dict:
        """Gera recomendações de correção"""
        vulnerable_tests = [r for r in test_results if r.get('vulnerable', False)]
        
        recommendations = {
            'immediate_actions': [],
            'short_term_fixes': [],
            'long_term_improvements': [],
            'preventive_measures': []
        }
        
        if vulnerable_tests:
            # Ações imediatas
            recommendations['immediate_actions'].extend([
                'Implementar validação rigorosa de entrada em todos os parâmetros',
                'Usar prepared statements/parameterized queries',
                'Aplicar princípio do menor privilégio para usuários de banco',
                'Implementar logging detalhado de tentativas de SQL Injection'
            ])
            
            # Correções de curto prazo
            recommendations['short_term_fixes'].extend([
                'Implementar WAF (Web Application Firewall) se não existir',
                'Configurar rate limiting para prevenir ataques automatizados',
                'Implementar sanitização adequada de dados de entrada',
                'Configurar alertas de segurança para tentativas de SQL Injection'
            ])
            
            # Melhorias de longo prazo
            recommendations['long_term_improvements'].extend([
                'Implementar arquitetura de segurança em camadas',
                'Realizar auditorias de segurança regulares',
                'Implementar programa de bug bounty',
                'Treinar equipe de desenvolvimento em secure coding'
            ])
        
        # Medidas preventivas gerais
        recommendations['preventive_measures'].extend([
            'Implementar testes de segurança automatizados no CI/CD',
            'Usar ferramentas de análise estática de código (SAST)',
            'Implementar testes de penetração regulares',
            'Manter frameworks e dependências atualizados'
        ])
        
        return recommendations
    
    def _generate_appendix(self, test_results: List[Dict], recon_data: Dict) -> Dict:
        """Gera apêndice com informações adicionais"""
        return {
            'all_payloads_tested': [r.get('payload', '') for r in test_results],
            'detailed_responses': [
                {
                    'payload': r.get('payload', ''),
                    'response_analysis': r.get('details', {}),
                    'confidence': r.get('confidence', 0),
                    'indicators': r.get('indicators', [])
                }
                for r in test_results if r.get('vulnerable', False)
            ],
            'reconnaissance_data': recon_data,
            'references': [
                'OWASP Top 10 - A03:2021 Injection',
                'CWE-89: Improper Neutralization of Special Elements used in an SQL Command',
                'NIST SP 800-53 - Security Controls for Federal Information Systems',
                'ISO/IEC 27001:2013 - Information Security Management'
            ],
            'tools_used': [
                'Multi-Agent SQL Injection Testing System',
                'LangChain AI Framework',
                'CrewAI Multi-Agent System',
                'Custom Web Analysis Tools'
            ]
        }
    
    def _extract_key_findings(self, vulnerable_tests: List[Dict]) -> List[str]:
        """Extrai principais descobertas"""
        findings = []
        
        if not vulnerable_tests:
            return ['Nenhuma vulnerabilidade de SQL Injection detectada']
        
        # Tipos de vulnerabilidade encontrados
        vuln_types = set([t.get('vulnerability_type') for t in vulnerable_tests])
        for vuln_type in vuln_types:
            findings.append(f"Vulnerabilidade {vuln_type} detectada")
        
        # Payloads de alta confiança
        high_conf = [t for t in vulnerable_tests if t.get('confidence', 0) > 0.8]
        if high_conf:
            findings.append(f"{len(high_conf)} vulnerabilidades de alta confiança encontradas")
        
        return findings
    
    def _categorize_payloads(self, test_results: List[Dict]) -> List[str]:
        """Categoriza payloads utilizados"""
        categories = set()
        for result in test_results:
            payload = result.get('payload', '').upper()
            if 'UNION' in payload:
                categories.add('Union-based')
            if 'SLEEP' in payload or 'WAITFOR' in payload:
                categories.add('Time-based')
            if any(error in payload for error in ['OR 1=1', 'AND 1=1']):
                categories.add('Boolean-based')
            if "'" in payload or '"' in payload:
                categories.add('Error-based')
        
        return list(categories)
    
    def _extract_evasion_techniques(self, test_results: List[Dict]) -> List[str]:
        """Extrai técnicas de evasão utilizadas"""
        techniques = set()
        for result in test_results:
            payload = result.get('payload', '')
            if '/**/' in payload:
                techniques.add('Comment insertion')
            if '%' in payload:
                techniques.add('URL encoding')
            if payload != payload.lower() and payload != payload.upper():
                techniques.add('Case variation')
            if '\\x' in payload:
                techniques.add('Hex encoding')
        
        return list(techniques)
    
    def _format_successful_attacks(self, test_results: List[Dict]) -> List[Dict]:
        """Formata ataques bem-sucedidos"""
        successful = []
        vulnerable_tests = [r for r in test_results if r.get('vulnerable', False)]
        
        for test in vulnerable_tests[:10]:  # Top 10
            successful.append({
                'payload': test.get('payload', ''),
                'type': test.get('vulnerability_type', 'unknown'),
                'confidence': f"{test.get('confidence', 0)*100:.1f}%",
                'severity': test.get('severity', 'unknown'),
                'indicators': test.get('indicators', [])[:3]  # Top 3 indicators
            })
        
        return successful
    
    def _calculate_max_severity(self, tests: List[Dict]) -> str:
        """Calcula severidade máxima"""
        severities = [t.get('severity', 'low') for t in tests]
        if 'critical' in severities:
            return 'critical'
        elif 'high' in severities:
            return 'high'
        elif 'medium' in severities:
            return 'medium'
        else:
            return 'low'
    
    def _get_vulnerability_description(self, vuln_type: str) -> str:
        """Retorna descrição da vulnerabilidade"""
        descriptions = {
            'error_based': 'SQL Injection baseada em mensagens de erro do banco de dados',
            'time_based': 'SQL Injection cega baseada em delays temporais',
            'union_based': 'SQL Injection usando UNION SELECT para extrair dados',
            'boolean_based': 'SQL Injection cega baseada em respostas verdadeiro/falso'
        }
        return descriptions.get(vuln_type, 'Tipo de SQL Injection não especificado')
    
    def _get_vulnerability_impact(self, vuln_type: str) -> str:
        """Retorna impacto da vulnerabilidade"""
        impacts = {
            'error_based': 'Exposição de estrutura do banco e possível extração de dados',
            'time_based': 'Extração de dados sensíveis através de inferência temporal',
            'union_based': 'Extração direta de dados do banco de dados',
            'boolean_based': 'Extração de dados através de inferência lógica'
        }
        return impacts.get(vuln_type, 'Impacto variável dependendo da exploração')
    
    def _assess_exploitation_difficulty(self, tests: List[Dict]) -> str:
        """Avalia dificuldade de exploração"""
        avg_confidence = sum([t.get('confidence', 0) for t in tests]) / len(tests)
        
        if avg_confidence > 0.8:
            return 'Fácil'
        elif avg_confidence > 0.6:
            return 'Moderada'
        else:
            return 'Difícil'
    
    def _assess_business_impact(self, risk_level: str) -> str:
        """Avalia impacto no negócio"""
        impacts = {
            'CRITICAL': 'Impacto crítico - Possível vazamento de dados, perda de confiança, multas regulatórias',
            'HIGH': 'Alto impacto - Risco de exposição de dados, danos à reputação',
            'MEDIUM': 'Impacto moderado - Possível comprometimento de dados não críticos',
            'LOW': 'Baixo impacto - Risco limitado de exposição de informações'
        }
        return impacts.get(risk_level, 'Impacto não determinado')
    
    def _assess_compliance_impact(self, vulnerable_tests: List[Dict]) -> List[str]:
        """Avalia impacto em conformidade"""
        if not vulnerable_tests:
            return []
        
        return [
            'LGPD - Lei Geral de Proteção de Dados',
            'PCI DSS - Payment Card Industry Data Security Standard',
            'ISO 27001 - Information Security Management',
            'OWASP Top 10 - A03:2021 Injection'
        ]
    
    def export_report(self, report: Dict, format_type: str = 'json') -> str:
        """Exporta relatório em diferentes formatos"""
        if format_type == 'json':
            return json.dumps(report, indent=2, ensure_ascii=False)
        elif format_type == 'html':
            return self._generate_html_report(report)
        elif format_type == 'markdown':
            return self._generate_markdown_report(report)
        else:
            return json.dumps(report, indent=2, ensure_ascii=False)
    
    def _generate_html_report(self, report: Dict) -> str:
        """Gera relatório em HTML"""
        # Implementação básica - pode ser expandida
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Relatório de SQL Injection - {report['metadata']['report_id']}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background: #f4f4f4; padding: 20px; border-radius: 5px; }}
                .critical {{ color: #d32f2f; }}
                .high {{ color: #f57c00; }}
                .medium {{ color: #fbc02d; }}
                .low {{ color: #388e3c; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Relatório de Teste SQL Injection</h1>
                <p>ID: {report['metadata']['report_id']}</p>
                <p>Data: {report['metadata']['generation_date']}</p>
                <p>Alvo: {report['metadata']['target_url']}</p>
            </div>
            
            <h2>Resumo Executivo</h2>
            <p>Nível de Risco: <span class="{report['executive_summary']['overall_risk_level'].lower()}">{report['executive_summary']['overall_risk_level']}</span></p>
            <p>Vulnerabilidades Encontradas: {report['executive_summary']['vulnerabilities_found']}</p>
            
            <!-- Adicionar mais seções conforme necessário -->
        </body>
        </html>
        """
        return html
    
    def _generate_markdown_report(self, report: Dict) -> str:
        """Gera relatório em Markdown"""
        md = f"""# Relatório de Teste SQL Injection

## Metadados
- **ID do Relatório:** {report['metadata']['report_id']}
- **Data de Geração:** {report['metadata']['generation_date']}
- **URL Alvo:** {report['metadata']['target_url']}
- **Parâmetro Testado:** {report['metadata']['target_parameter']}

## Resumo Executivo
- **Nível de Risco:** {report['executive_summary']['overall_risk_level']}
- **Vulnerabilidades Encontradas:** {report['executive_summary']['vulnerabilities_found']}
- **Total de Testes:** {report['executive_summary']['total_tests_performed']}
- **Taxa de Sucesso:** {report['executive_summary']['success_rate']}

## Principais Descobertas
"""
        for finding in report['executive_summary']['key_findings']:
            md += f"- {finding}\n"
        
        return md
