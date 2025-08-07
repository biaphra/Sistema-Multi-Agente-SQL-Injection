"""
Configurações do Sistema Multi-Agente de Teste SQL Injection
"""
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # OpenAI Configuration
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
    OPENAI_MODEL = os.getenv('OPENAI_MODEL', 'gpt-4-turbo-preview')
    TEMPERATURE = float(os.getenv('TEMPERATURE', '0.7'))
    MAX_TOKENS = int(os.getenv('MAX_TOKENS', '2000'))
    
    # Testing Configuration
    REQUEST_TIMEOUT = 10
    MAX_RETRIES = 3
    USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
    
    # Payload Categories
    BASIC_PAYLOADS = [
        "' OR 1=1--",
        "' OR '1'='1",
        "' OR 'x'='x",
        "' OR 1=1#",
        "admin'--",
        "' UNION SELECT NULL--",
        "' AND 1=2 UNION SELECT NULL--"
    ]
    
    # Error Patterns
    SQL_ERROR_PATTERNS = [
        "sql", "syntax", "mysql", "query", "pdo", "fatal",
        "ora-", "microsoft", "odbc", "jdbc", "sqlite",
        "postgresql", "warning", "error", "exception"
    ]
    
    # WAF Detection Patterns
    WAF_PATTERNS = [
        "blocked", "forbidden", "access denied", "security",
        "cloudflare", "incapsula", "sucuri", "akamai"
    ]
    
    # Database Fingerprinting
    DB_FINGERPRINTS = {
        'mysql': ['mysql', 'mariadb', 'version()'],
        'postgresql': ['postgresql', 'pg_version', 'current_database'],
        'mssql': ['microsoft', 'sql server', '@@version'],
        'oracle': ['oracle', 'ora-', 'dual'],
        'sqlite': ['sqlite', 'sqlite_version']
    }
