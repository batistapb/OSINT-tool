# OSINT Tool

> ⚠️ Projeto educacional criado para fins de aprendizado em cyber security. Use apenas em domínios próprios ou com autorização explícita.

## O que é

Ferramenta de linha de comando que coleta informações públicas e passivas sobre um domínio: WHOIS, registros DNS, subdomínios via Certificate Transparency Logs (crt.sh) e presença/ausência de headers de segurança HTTP. Gera um relatório consolidado em texto ou JSON.

## Tecnologias

- Python 3.11+
- `requests` — chamadas HTTP
- `dnspython` — consultas DNS
- `python-whois` — consulta WHOIS
- `pytest` + `responses` — testes

## Como rodar

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m osint_tool.cli exemplo.com
```

## Testes

```bash
pip install -r requirements-dev.txt
pytest
```

## O que aprendi

- Diferença entre reconhecimento passivo (fontes públicas) e ativo (scan direto no alvo).
- Como Certificate Transparency Logs revelam subdomínios sem precisar de scanning ativo.
- Por que a ausência de headers de segurança HTTP (CSP, HSTS, X-Frame-Options) é uma falha comum e como detectá-la programaticamente.
