"""
Agent Reconnaissance - Coleta inteligente de informações sobre o alvo
"""
from crewai import Agent
from langchain_openai import ChatOpenAI
from typing import Dict, List, Optional
import requests
from urllib.parse import urlparse, urljoin
from tools.web_tools import WebTools
from config import Config

class ReconnaissanceAgent:
    def __init__(self):
        self.llm = ChatOpenAI(
            model=Config.OPENAI_MODEL,
            temperature=Config.TEMPERATURE,
            max_tokens=Config.MAX_TOKENS,
            api_key=Config.OPENAI_API_KEY
        )
        
        self.agent = Agent(
            role="Web Reconnaissance Specialist",
            goal="Coletar informações detalhadas sobre o alvo para otimizar os testes de SQL Injection",
            backstory="""Você é um especialista em reconhecimento web com foco em identificação
            de tecnologias, arquiteturas e possíveis vetores de ataque. Sua análise detalhada
            permite que outros agentes realizem testes mais precisos e eficazes.""",
            verbose=True,
            allow_delegation=False,
            llm=self.llm
        )
        
        self.web_tools = WebTools()
    
    def full_reconnaissance(self, target_url: str, parameter: str) -> Dict:
        """Realiza reconhecimento completo do alvo"""
        recon_data = {
            'target_url': target_url,
            'parameter': parameter,
            'technologies': [],
            'database_type': None,
            'waf_detected': False,
            'waf_type': None,
            'server_info': {},
            'forms': [],
            'endpoints': [],
            'parameter_analysis': {},
            'security_headers': {},
            'cookies': {},
            'error_pages': []
        }
        
        print(f"[RECON] Iniciando reconhecimento de {target_url}")
        
        # Análise básica da resposta
        response = self.web_tools.make_request(target_url)
        if response:
            recon_data['server_info'] = self.web_tools.analyze_response(response)
            recon_data['technologies'] = self.web_tools.detect_technologies(response)
            
            # Detecção de WAF
            waf_detected, waf_type = self.web_tools.detect_waf(response)
            recon_data['waf_detected'] = waf_detected
            recon_data['waf_type'] = waf_type
            
            # Análise de formulários
            recon_data['forms'] = self.web_tools.extract_forms(response)
            
            # Fingerprinting de banco de dados
            recon_data['database_type'] = self.web_tools.fingerprint_database(response)
            
            # Headers de segurança
            recon_data['security_headers'] = self._analyze_security_headers(response)
            
            # Cookies
            recon_data['cookies'] = dict(response.cookies)
        
        # Análise do parâmetro
        recon_data['parameter_analysis'] = self._analyze_parameter(target_url, parameter)
        
        # Descoberta de endpoints
        recon_data['endpoints'] = self._discover_endpoints(target_url)
        
        # Teste de páginas de erro
        recon_data['error_pages'] = self._test_error_pages(target_url)
        
        # Análise com IA
        ai_analysis = self._ai_analysis(recon_data)
        recon_data['ai_insights'] = ai_analysis
        
        return recon_data
    
    def _analyze_security_headers(self, response: requests.Response) -> Dict:
        """Analisa headers de segurança"""
        security_headers = {
            'x-frame-options': response.headers.get('x-frame-options'),
            'x-content-type-options': response.headers.get('x-content-type-options'),
            'x-xss-protection': response.headers.get('x-xss-protection'),
            'strict-transport-security': response.headers.get('strict-transport-security'),
            'content-security-policy': response.headers.get('content-security-policy'),
            'x-powered-by': response.headers.get('x-powered-by'),
            'server': response.headers.get('server')
        }
        
        return {k: v for k, v in security_headers.items() if v is not None}
    
    def _analyze_parameter(self, url: str, parameter: str) -> Dict:
        """Analisa o comportamento do parâmetro"""
        analysis = {
            'type': 'unknown',
            'required': False,
            'validation': 'none',
            'encoding': 'none',
            'behavior': {}
        }
        
        # Teste com diferentes tipos de entrada
        test_values = {
            'numeric': '123',
            'string': 'test',
            'special_chars': "test'\"<>&",
            'empty': '',
            'null': None
        }
        
        baseline_response = self.web_tools.make_request(url, {parameter: 'baseline'})
        if not baseline_response:
            return analysis
            
        for test_type, test_value in test_values.items():
            if test_value is None:
                continue
                
            test_response = self.web_tools.make_request(url, {parameter: test_value})
            if test_response:
                # Comparar respostas
                if test_response.text != baseline_response.text:
                    analysis['behavior'][test_type] = 'different_response'
                elif test_response.status_code != baseline_response.status_code:
                    analysis['behavior'][test_type] = 'different_status'
                else:
                    analysis['behavior'][test_type] = 'same_response'
        
        # Determinar tipo do parâmetro
        if analysis['behavior'].get('numeric') == 'different_response':
            analysis['type'] = 'numeric'
        elif analysis['behavior'].get('string') == 'different_response':
            analysis['type'] = 'string'
        
        # Verificar validação
        if analysis['behavior'].get('special_chars') == 'different_status':
            analysis['validation'] = 'input_validation'
        elif 'error' in test_response.text.lower():
            analysis['validation'] = 'error_prone'
        
        return analysis
    
    def _discover_endpoints(self, base_url: str) -> List[str]:
        """Descobre endpoints relacionados"""
        parsed_url = urlparse(base_url)
        base_path = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        common_endpoints = [
            '/admin',
            '/login',
            '/search',
            '/api',
            '/database',
            '/db',
            '/phpmyadmin',
            '/mysql',
            '/sql',
            '/query'
        ]
        
        discovered = []
        for endpoint in common_endpoints:
            test_url = urljoin(base_path, endpoint)
            response = self.web_tools.make_request(test_url)
            if response and response.status_code not in [404, 403]:
                discovered.append(test_url)
        
        return discovered
    
    def _test_error_pages(self, url: str) -> List[Dict]:
        """Testa páginas de erro para obter informações"""
        error_tests = [
            {'payload': "'", 'description': 'Single quote test'},
            {'payload': '"', 'description': 'Double quote test'},
            {'payload': '\\', 'description': 'Backslash test'},
            {'payload': ';', 'description': 'Semicolon test'},
            {'payload': '--', 'description': 'Comment test'}
        ]
        
        error_pages = []
        for test in error_tests:
            # Assumindo que o parâmetro é 'query' por padrão
            response = self.web_tools.make_request(url, {'query': test['payload']})
            if response:
                errors = self.web_tools.detect_database_errors(response)
                if errors:
                    error_pages.append({
                        'payload': test['payload'],
                        'description': test['description'],
                        'errors_detected': errors,
                        'status_code': response.status_code,
                        'response_snippet': response.text[:500]
                    })
        
        return error_pages
    
    def _ai_analysis(self, recon_data: Dict) -> Dict:
        """Análise com IA dos dados coletados"""
        prompt = f"""
        Como especialista em segurança web, analise os dados de reconhecimento e forneça insights:
        
        Alvo: {recon_data['target_url']}
        Tecnologias detectadas: {recon_data['technologies']}
        Tipo de banco: {recon_data.get('database_type', 'Desconhecido')}
        WAF detectado: {recon_data['waf_detected']}
        Headers de segurança: {list(recon_data['security_headers'].keys())}
        Formulários encontrados: {len(recon_data['forms'])}
        
        Forneça:
        1. Avaliação do nível de segurança (1-10)
        2. Principais vetores de ataque recomendados
        3. Técnicas específicas para este alvo
        4. Probabilidade de sucesso de SQL Injection (0-100%)
        5. Recomendações para os testes
        
        Responda em formato JSON:
        {{
            "security_level": 1-10,
            "attack_vectors": ["vector1", "vector2"],
            "recommended_techniques": ["technique1", "technique2"],
            "sqli_probability": 0-100,
            "recommendations": ["rec1", "rec2"],
            "risk_assessment": "low|medium|high|critical"
        }}
        """
        
        try:
            response = self.llm.invoke(prompt)
            import json
            result = json.loads(response.content)
            return result
        except Exception as e:
            print(f"Erro na análise com IA: {e}")
            return {
                "security_level": 5,
                "attack_vectors": ["unknown"],
                "recommended_techniques": ["basic_payloads"],
                "sqli_probability": 50,
                "recommendations": ["standard_testing"],
                "risk_assessment": "medium"
            }
    
    def quick_scan(self, target_url: str) -> Dict:
        """Scan rápido para informações básicas"""
        response = self.web_tools.make_request(target_url)
        if not response:
            return {}
            
        return {
            'status_code': response.status_code,
            'technologies': self.web_tools.detect_technologies(response),
            'database_type': self.web_tools.fingerprint_database(response),
            'waf_detected': self.web_tools.detect_waf(response)[0],
            'server': response.headers.get('server', 'Unknown')
        }
