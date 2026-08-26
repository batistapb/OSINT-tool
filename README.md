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

Opcionalmente, enriqueça o relatório com dados de infraestrutura do [Shodan](https://www.shodan.io/) (requer uma API key gratuita) do primeiro IP encontrado via DNS:

```bash
python -m osint_tool.cli exemplo.com --shodan-key SUA_API_KEY
# ou
export SHODAN_API_KEY=SUA_API_KEY
python -m osint_tool.cli exemplo.com
```

Também é possível salvar o relatório em um arquivo HTML:

```bash
python -m osint_tool.cli exemplo.com --html-output relatorio.html
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
