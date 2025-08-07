"""
Agent Response Analyzer - Análise inteligente das respostas HTTP
"""
from crewai import Agent
from langchain_openai import ChatOpenAI
from typing import Dict, List, Tuple, Optional
import re
import difflib
from config import Config

class ResponseAnalyzerAgent:
    def __init__(self):
        self.llm = ChatOpenAI(
            model=Config.OPENAI_MODEL,
            temperature=Config.TEMPERATURE,
            max_tokens=Config.MAX_TOKENS,
            api_key=Config.OPENAI_API_KEY
        )
        
        self.agent = Agent(
            role="Response Analysis Specialist",
            goal="Analisar respostas HTTP para identificar vulnerabilidades de SQL Injection",
            backstory="""Você é um especialista em análise de respostas web com foco em detecção
            de vulnerabilidades de SQL Injection. Você possui conhecimento profundo sobre padrões
            de erro, comportamentos anômalos e indicadores sutis de vulnerabilidades em aplicações web.
            Sua análise é precisa e minimiza falsos positivos.""",
            verbose=True,
            allow_delegation=False,
            llm=self.llm
        )
        
        self.baseline_response = None
    
    def set_baseline(self, response_data: Dict):
        """Define a resposta baseline para comparações"""
        self.baseline_response = response_data
    
    def analyze_response(self, response_data: Dict, payload: str) -> Dict:
        """Análise completa da resposta"""
        analysis = {
            'payload': payload,
            'vulnerable': False,
            'confidence': 0.0,
            'vulnerability_type': None,
            'indicators': [],
            'severity': 'low',
            'details': {}
        }
        
        # Análises específicas
        error_analysis = self._analyze_error_patterns(response_data)
        timing_analysis = self._analyze_timing(response_data)
        content_analysis = self._analyze_content_changes(response_data)
        status_analysis = self._analyze_status_changes(response_data)
        
        # Combinar resultados
        all_indicators = []
        total_confidence = 0.0
        
        if error_analysis['detected']:
            all_indicators.extend(error_analysis['indicators'])
            total_confidence += error_analysis['confidence']
            analysis['vulnerability_type'] = 'error_based'
            
        if timing_analysis['detected']:
            all_indicators.extend(timing_analysis['indicators'])
            total_confidence += timing_analysis['confidence']
            if not analysis['vulnerability_type']:
                analysis['vulnerability_type'] = 'time_based'
                
        if content_analysis['detected']:
            all_indicators.extend(content_analysis['indicators'])
            total_confidence += content_analysis['confidence']
            if not analysis['vulnerability_type']:
                analysis['vulnerability_type'] = 'union_based'
                
        if status_analysis['detected']:
            all_indicators.extend(status_analysis['indicators'])
            total_confidence += status_analysis['confidence']
            
        # Determinar vulnerabilidade
        analysis['indicators'] = all_indicators
        analysis['confidence'] = min(total_confidence, 1.0)
        analysis['vulnerable'] = analysis['confidence'] > 0.3
        analysis['severity'] = self._calculate_severity(analysis['confidence'], all_indicators)
        
        # Detalhes adicionais
        analysis['details'] = {
            'error_analysis': error_analysis,
            'timing_analysis': timing_analysis,
            'content_analysis': content_analysis,
            'status_analysis': status_analysis
        }
        
        return analysis
    
    def _analyze_error_patterns(self, response_data: Dict) -> Dict:
        """Analisa padrões de erro SQL"""
        analysis = {
            'detected': False,
            'confidence': 0.0,
            'indicators': [],
            'error_types': []
        }
        
        content = response_data.get('text_content', '').lower()
        
        # Padrões de erro específicos
        error_patterns = {
            'mysql': [
                r'mysql_fetch_array\(\)',
                r'you have an error in your sql syntax',
                r'warning: mysql_',
                r'mysql_num_rows\(\)',
                r'mysql_query\(\)'
            ],
            'postgresql': [
                r'postgresql query failed',
                r'pg_query\(\)',
                r'pg_exec\(\)',
                r'postgresql error'
            ],
            'mssql': [
                r'microsoft ole db provider',
                r'odbc sql server driver',
                r'microsoft jet database',
                r'sql server'
            ],
            'oracle': [
                r'ora-\d{5}',
                r'oracle error',
                r'oracle driver'
            ],
            'generic': [
                r'sql syntax',
                r'database error',
                r'query failed',
                r'invalid query'
            ]
        }
        
        for db_type, patterns in error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content):
                    analysis['detected'] = True
                    analysis['confidence'] += 0.3
                    analysis['indicators'].append(f"SQL error pattern detected: {pattern}")
                    analysis['error_types'].append(db_type)
        
        # Padrões de stack trace
        stack_patterns = [
            r'stack trace',
            r'exception',
            r'fatal error',
            r'warning.*line \d+',
            r'error.*line \d+'
        ]
        
        for pattern in stack_patterns:
            if re.search(pattern, content):
                analysis['confidence'] += 0.2
                analysis['indicators'].append(f"Stack trace pattern: {pattern}")
        
        analysis['confidence'] = min(analysis['confidence'], 1.0)
        return analysis
    
    def _analyze_timing(self, response_data: Dict) -> Dict:
        """Analisa tempo de resposta para blind SQL injection"""
        analysis = {
            'detected': False,
            'confidence': 0.0,
            'indicators': []
        }
        
        response_time = response_data.get('response_time', 0)
        
        # Baseline comparison
        if self.baseline_response:
            baseline_time = self.baseline_response.get('response_time', 0)
            time_diff = response_time - baseline_time
            
            # Delay significativo (>3 segundos)
            if time_diff > 3.0:
                analysis['detected'] = True
                analysis['confidence'] = min(time_diff / 10.0, 0.9)
                analysis['indicators'].append(f"Significant delay detected: {time_diff:.2f}s")
            
            # Delay moderado (>1 segundo)
            elif time_diff > 1.0:
                analysis['confidence'] = 0.3
                analysis['indicators'].append(f"Moderate delay detected: {time_diff:.2f}s")
        
        # Tempo absoluto muito alto
        if response_time > 5.0:
            analysis['detected'] = True
            analysis['confidence'] = max(analysis['confidence'], 0.6)
            analysis['indicators'].append(f"High response time: {response_time:.2f}s")
        
        return analysis
    
    def _analyze_content_changes(self, response_data: Dict) -> Dict:
        """Analisa mudanças no conteúdo da resposta"""
        analysis = {
            'detected': False,
            'confidence': 0.0,
            'indicators': []
        }
        
        if not self.baseline_response:
            return analysis
        
        current_content = response_data.get('text_content', '')
        baseline_content = self.baseline_response.get('text_content', '')
        
        # Comparação de similaridade
        similarity = difflib.SequenceMatcher(None, baseline_content, current_content).ratio()
        
        if similarity < 0.5:  # Mudança significativa
            analysis['detected'] = True
            analysis['confidence'] = 1.0 - similarity
            analysis['indicators'].append(f"Significant content change: {(1-similarity)*100:.1f}%")
        
        # Procurar por dados expostos (UNION SELECT)
        union_patterns = [
            r'\b\d+\b.*\b\d+\b.*\b\d+\b',  # Padrão numérico típico de UNION
            r'root@localhost',
            r'information_schema',
            r'mysql\.user',
            r'version\(\)',
            r'@@version'
        ]
        
        for pattern in union_patterns:
            if re.search(pattern, current_content.lower()):
                analysis['detected'] = True
                analysis['confidence'] = max(analysis['confidence'], 0.8)
                analysis['indicators'].append(f"Data exposure pattern: {pattern}")
        
        # Mudanças no tamanho da resposta
        current_size = response_data.get('content_length', 0)
        baseline_size = self.baseline_response.get('content_length', 0)
        
        if baseline_size > 0:
            size_diff_ratio = abs(current_size - baseline_size) / baseline_size
            if size_diff_ratio > 0.2:  # Mudança >20%
                analysis['confidence'] = max(analysis['confidence'], 0.4)
                analysis['indicators'].append(f"Content size change: {size_diff_ratio*100:.1f}%")
        
        return analysis
    
    def _analyze_status_changes(self, response_data: Dict) -> Dict:
        """Analisa mudanças no status HTTP"""
        analysis = {
            'detected': False,
            'confidence': 0.0,
            'indicators': []
        }
        
        status_code = response_data.get('status_code', 200)
        
        # Status codes suspeitos
        if status_code == 500:
            analysis['detected'] = True
            analysis['confidence'] = 0.7
            analysis['indicators'].append("Internal Server Error (500)")
        elif status_code in [400, 403, 406]:
            analysis['confidence'] = 0.3
            analysis['indicators'].append(f"Client error status: {status_code}")
        
        # Comparação com baseline
        if self.baseline_response:
            baseline_status = self.baseline_response.get('status_code', 200)
            if status_code != baseline_status:
                analysis['confidence'] = max(analysis['confidence'], 0.4)
                analysis['indicators'].append(f"Status change: {baseline_status} -> {status_code}")
        
        return analysis
    
    def _calculate_severity(self, confidence: float, indicators: List[str]) -> str:
        """Calcula a severidade da vulnerabilidade"""
        if confidence >= 0.8:
            return 'critical'
        elif confidence >= 0.6:
            return 'high'
        elif confidence >= 0.4:
            return 'medium'
        else:
            return 'low'
    
    def analyze_with_ai(self, response_data: Dict, payload: str) -> Dict:
        """Usa IA para análise avançada da resposta"""
        prompt = f"""
        Como especialista em segurança, analise esta resposta HTTP para detectar SQL Injection:
        
        Payload testado: {payload}
        Status Code: {response_data.get('status_code', 'N/A')}
        Response Time: {response_data.get('response_time', 'N/A')}s
        Content Length: {response_data.get('content_length', 'N/A')} bytes
        
        Conteúdo da resposta (primeiros 1000 chars):
        {response_data.get('text_content', '')[:1000]}
        
        Analise:
        1. Há evidências de SQL Injection?
        2. Qual o tipo de vulnerabilidade (error-based, blind, union-based)?
        3. Qual a confiança da detecção (0-100%)?
        4. Quais indicadores específicos foram encontrados?
        
        Responda em formato JSON:
        {{
            "vulnerable": true/false,
            "confidence": 0-100,
            "type": "error_based|time_based|union_based|boolean_based",
            "indicators": ["indicator1", "indicator2"],
            "explanation": "explicação detalhada"
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
                "vulnerable": False,
                "confidence": 0,
                "type": "unknown",
                "indicators": [],
                "explanation": "Erro na análise"
            }
