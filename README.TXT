============================================================
LATERAL WATCH — EAST-WEST TRAFFIC INSPECTOR
Version: 4.0
Maturity: CMMI Level 4 (Quantitatively Managed)
============================================================

1. OVERVIEW
------------------------------------------------------------
Lateral Watch é uma ferramenta CLI voltada para identificação,
quantificação e avaliação de risco de comunicações laterais
(East-West) dentro de redes internas.

Seu foco é apoiar:
- Zero Trust validation
- Incident Response (IR)
- Forensic Readiness
- SOC e auditoria técnica
- Tomada de decisão baseada em métricas

A ferramenta NÃO altera o sistema.
Ela apenas coleta, analisa e gera evidências.

------------------------------------------------------------

2. MAIN FEATURES
------------------------------------------------------------

2.1 Lateral Traffic Detection
- Identifica conexões ESTABLISHED entre hosts internos
- Filtra comunicações East-West (RFC1918)
- Detecta uso de portas administrativas e sensíveis

2.2 Quantitative Metrics (CMMI 4)
- Total de sessões laterais
- Número de hosts únicos envolvidos
- Portas mais utilizadas
- Comparação com baseline anterior

2.3 Risk Scoring
- Score de risco baseado em:
  - Porta utilizada
  - Frequência
  - Volume de conexões
- Classificação automática:
  LOW | MEDIUM | HIGH | CRITICAL

2.4 Forensic Evidence
- Geração de relatório imutável
- Hash SHA256 do arquivo
- Metadata de execução (data, versão, ferramenta)

2.5 Enterprise-Grade CLI
- Subcomandos claros
- Opção --help curta e completa
- Mensagens de erro com ação corretiva
- Modo --dry-run para produção

2.6 Output Profissional
- JSON estruturado (SIEM-ready)
- TXT / CSV para leitura humana
- Separação entre dados, métricas e decisão

------------------------------------------------------------

3. REQUIREMENTS
------------------------------------------------------------

- Sistema Linux
- Bash 4+
- Comando `ss` disponível
- Permissões de root (ou sudo)

Motivo do root:
A inspeção de sockets e processos requer privilégios elevados.

------------------------------------------------------------

4. INSTALLATION
------------------------------------------------------------

1. Copie o script para o sistema:
   cp lateral_watch_v4.sh /usr/local/bin/lateral_watch

2. Dê permissão de execução:
   chmod +x /usr/local/bin/lateral_watch

3. Verifique:
   lateral_watch help

------------------------------------------------------------

5. BASIC USAGE
------------------------------------------------------------

5.1 Exibir ajuda rápida
--------------------------------
lateral_watch help

5.2 Exibir ajuda completa
--------------------------------
lateral_watch help-full

5.3 Executar análise padrão
--------------------------------
sudo lateral_watch scan

5.4 Executar e gerar JSON
--------------------------------
sudo lateral_watch scan --output json

5.5 Executar em modo forense
--------------------------------
sudo lateral_watch scan --output json --forensic

5.6 Simular execução (produção)
--------------------------------
lateral_watch scan --dry-run

------------------------------------------------------------

6. CLI OPTIONS (DETAILED)
------------------------------------------------------------

--ports <regex>
  Define portas consideradas sensíveis.
  Exemplo:
    --ports "22|445|3389"

--internal <regex>
  Define o padrão de IPs internos.
  Default: RFC1918

--output <format>
  Formato de saída:
    txt   - leitura humana
    csv   - planilhas e relatórios
    json  - SIEM / automação

--forensic
  Ativa modo forense:
  - Evidência imutável
  - Hash SHA256 gerado

--dry-run
  Simula execução sem coletar dados.
  Recomendado antes de rodar em produção.

--verbose
  Mostra decisões internas do script.

------------------------------------------------------------

7. OUTPUT STRUCTURE
------------------------------------------------------------

7.1 Diretórios
--------------------------------
reports/
 ├── YYYY-MM-DD/
 │   ├── lateral_HHMMSS.json
 │   ├── lateral_HHMMSS.json.sha256

baseline/
 └── last_run.txt

7.2 Estrutura do JSON
--------------------------------

- metadata
  - tool
  - version
  - timestamp

- summary
  - total_sessions
  - unique_hosts
  - risk_score
  - risk_level
  - delta_from_last_run

- metrics
  - most_used_port

- findings
  - src
  - dst
  - port
  - process

------------------------------------------------------------

8. EXIT CODES
------------------------------------------------------------

0  Execution successful
1  Execution completed with no findings
2  Execution error

------------------------------------------------------------

9. SECURITY NOTES
------------------------------------------------------------

- Nenhuma credencial é armazenada
- Nenhuma credencial é logada
- Não há comunicação externa
- Script é read-only no sistema

------------------------------------------------------------

10. WHEN TO USE THIS TOOL
------------------------------------------------------------

- Validação de Zero Trust
- Investigação de ransomware
- Pós-incidente (forensics)
- Auditorias internas
- Monitoramento East-West
- Prova técnica para gestão

------------------------------------------------------------

11. LIMITATIONS
------------------------------------------------------------

- Analisa apenas sessões ativas
- Não substitui IDS/IPS
- Não bloqueia tráfego (somente detecção)

------------------------------------------------------------

12. NEXT EVOLUTION (CMMI 5)
------------------------------------------------------------

- Auto-baseline
- Detecção de anomalia
- Execução contínua (daemon)
- Integração SIEM / SOAR
- Resposta automática controlada

------------------------------------------------------------

END OF DOCUMENT
============================================================
