"""
Ferramentas Web para os Agentes Multi-Agente
"""
import requests
from bs4 import BeautifulSoup
from typing import Dict, List, Optional, Tuple
import re
import time
from urllib.parse import urljoin, urlparse
from config import Config

class WebTools:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': Config.USER_AGENT})
        
    def make_request(self, url: str, params: Dict = None, method: str = 'GET') -> Optional[requests.Response]:
        """Faz requisição HTTP com tratamento de erros"""
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, params=params, timeout=Config.REQUEST_TIMEOUT)
            else:
                response = self.session.post(url, data=params, timeout=Config.REQUEST_TIMEOUT)
            return response
        except Exception as e:
            print(f"Erro na requisição: {e}")
            return None
    
    def analyze_response(self, response: requests.Response) -> Dict:
        """Analisa resposta HTTP detalhadamente"""
        if not response:
            return {}
            
        analysis = {
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'content_length': len(response.content),
            'response_time': response.elapsed.total_seconds(),
            'content_type': response.headers.get('content-type', ''),
            'server': response.headers.get('server', ''),
            'cookies': dict(response.cookies),
            'text_content': response.text[:5000]  # Primeiros 5KB
        }
        
        return analysis
    
    def detect_technologies(self, response: requests.Response) -> List[str]:
        """Detecta tecnologias usadas no servidor"""
        if not response:
            return []
            
        technologies = []
        
        # Headers
        server = response.headers.get('server', '').lower()
        x_powered_by = response.headers.get('x-powered-by', '').lower()
        
        if 'apache' in server:
            technologies.append('Apache')
        if 'nginx' in server:
            technologies.append('Nginx')
        if 'php' in x_powered_by:
            technologies.append('PHP')
        if 'asp.net' in x_powered_by:
            technologies.append('ASP.NET')
        
        # Content analysis
        content = response.text.lower()
        if 'wordpress' in content:
            technologies.append('WordPress')
        if 'drupal' in content:
            technologies.append('Drupal')
        if 'joomla' in content:
            technologies.append('Joomla')
            
        return technologies
    
    def detect_waf(self, response: requests.Response) -> Tuple[bool, str]:
        """Detecta presença de WAF"""
        if not response:
            return False, ""
            
        # Check headers
        headers_text = str(response.headers).lower()
        content_text = response.text.lower()
        
        for pattern in Config.WAF_PATTERNS:
            if pattern in headers_text or pattern in content_text:
                return True, pattern
                
        # Check specific WAF signatures
        waf_headers = [
            'cf-ray',  # Cloudflare
            'x-sucuri-id',  # Sucuri
            'x-iinfo',  # Incapsula
            'x-akamai-transformed'  # Akamai
        ]
        
        for header in waf_headers:
            if header in response.headers:
                return True, header
                
        return False, ""
    
    def extract_forms(self, response: requests.Response) -> List[Dict]:
        """Extrai formulários da página"""
        if not response:
            return []
            
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = []
        
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'inputs': []
            }
            
            for input_tag in form.find_all(['input', 'select', 'textarea']):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', '')
                }
                form_data['inputs'].append(input_data)
                
            forms.append(form_data)
            
        return forms
    
    def detect_database_errors(self, response: requests.Response) -> List[str]:
        """Detecta erros de banco de dados na resposta"""
        if not response:
            return []
            
        content = response.text.lower()
        detected_errors = []
        
        for pattern in Config.SQL_ERROR_PATTERNS:
            if pattern in content:
                detected_errors.append(pattern)
                
        return detected_errors
    
    def fingerprint_database(self, response: requests.Response) -> Optional[str]:
        """Identifica o tipo de banco de dados"""
        if not response:
            return None
            
        content = response.text.lower()
        
        for db_type, patterns in Config.DB_FINGERPRINTS.items():
            for pattern in patterns:
                if pattern in content:
                    return db_type
                    
        return None
