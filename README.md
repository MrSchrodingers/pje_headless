# pjeoffice-headless

[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB)](https://www.python.org/)
![Status](https://img.shields.io/badge/status-alpha-yellow)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
![Dockerized](https://img.shields.io/badge/docker-ready-blue)
<img src="https://www.cnj.jus.br/wp-content/uploads/2023/09/logo-cnj-portal-20-09-1.svg" alt="Logo CNJ" height="20" width="60">

Autenticador **headless** compatível com o fluxo do **PJe Office** do **CNJ** (Conselho Nacional de Justiça).  
Este serviço expõe um endpoint HTTP local que recebe um **desafio** (challenge), assina com o seu certificado **A1 (PKCS#12)** e envia a resposta ao endpoint do tribunal.

> ⚠️ **Aviso**: projeto **não-oficial**. Implementa, de forma independente, o comportamento do cliente PJe Office com base na **codebase do PJeOffice Pro (CNJ)/ Java** e na observação do protocolo. Não é mantido pelo CNJ.

---

## Destaques

- Assinatura RSA com `MD5withRSA` (padrão histórico), `SHA1withRSA` e `SHA256withRSA`.
- Envio da cadeia de certificados em **PKIPath** (ASN.1) — implementado com `SequenceOf` tipado.
- Servidor IPv6/IPv4, CORS liberado e `Access-Control-Allow-Private-Network`.
- 🐳 **Docker** pronto para uso (imagem leve, usuário não-root, healthcheck).

---

# Instalação (sem Docker)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .
python -m pjeoffice_headless --certificate /caminho/cert.pfx --password "senha" --port 8800
````

Health-check:

```bash
curl -I http://localhost:8800/pjeOffice/
```

---

## Uso com Docker

### Build local

```bash
docker build -t pjeoffice-headless:1.0.0 .
```

### Executar

```bash
docker run --rm \
  -e PJE_CERT_PATH=/certs/cert.pfx \
  -e PJE_CERT_PASS="sua-senha" \
  -e PJE_PORT=8800 \
  -v /caminho/real/cert.pfx:/certs/cert.pfx:ro \
  -p 127.0.0.1:8800:8800 \
  pjeoffice-headless:1.0.0
```

### Compose

```bash
docker compose up -d
```

> **Dica de segurança:** mantenha o mapeamento em `127.0.0.1:8800:8800` para evitar exposição externa.
> Se precisar HTTPS no localhost, coloque um **reverse proxy** (Nginx/Caddy) com TLS fazendo proxy para `http://pjeoffice-headless:8800`.

---

## Endpoints

* `GET /pjeOffice/` — GIF 1×1 (OK) para health-check.
* `GET /pjeOffice/requisicao/?r=<payload_url_encoded>` — modo “image ping” legado.
* `POST /pjeOffice/requisicao/` — **recomendado**, com JSON no corpo.

### Envelope esperado

```json
{
  "servidor": "https://exemplo.jus.br",
  "versao": "2.5.16",
  "sessao": "AWSALB=...; AWSALBCORS=...; JSESSIONID=...",
  "tarefa": "{\"mensagem\":\"<DESAFIO>\",\"enviarPara\":\"/callback\",\"token\":\"<UUID>\",\"algoritmoAssinatura\":\"MD5withRSA\"}"
}
```

Campos:

* `servidor`: base do host de destino; será concatenado com `enviarPara`.
* `versao`: cabeçalho `versao` (default interno: `2.5.16`).
* `sessao`: cookies de sessão (opcional).
* `tarefa` (string JSON):

  * `mensagem`: desafio
  * `enviarPara`: path do endpoint remoto
  * `token`: identificador
  * `algoritmoAssinatura`: `MD5withRSA` (padrão), `SHA1withRSA` ou `SHA256withRSA`.

Exemplo `POST`:

```bash
curl -sS -X POST http://localhost:8800/pjeOffice/requisicao/ \
  -H "Content-Type: application/json" \
  -d '{"servidor":"https://exemplo.jus.br","tarefa":"{\"mensagem\":\"abc123\",\"enviarPara\":\"/api/assinatura\",\"token\":\"uuid-123\",\"algoritmoAssinatura\":\"SHA256withRSA\"}"}'
```

---

## Configurações

Constantes internas (podem ser alteradas no código):

* `PJE_VERSION="2.5.16"`
* `CONNECT_TIMEOUT=3` (s)
* `READ_TIMEOUT=10` (s)
* `SUCCESS_CODES = {200, 201, 202, 204, 302, 304}`

Variáveis de ambiente no Docker:

* `PJE_CERT_PATH` (**obrigatório**) — caminho do `.pfx/.p12` montado.
* `PJE_CERT_PASS` (**obrigatório**) — senha do certificado.
* `PJE_PORT` (opcional, default `8800`) — porta exposta pelo servidor.

---

## Referências

* **CNJ — Conselho Nacional de Justiça**: [https://www.cnj.jus.br/](https://www.cnj.jus.br/) 
* **PJeOffice Pro (CNJ)**: esta implementação foi **inspirada** e **baseada** na codebase/fluxo do *PJeOffice Pro* do CNJ e no protocolo observado nas integrações oficiais. Este projeto é **independente** e **não-oficial**. Foi feita a engenharia reversa, decompilando a aplicação Java com o Lyuten  [https://github.com/deathmarine/Luyten](https://github.com/deathmarine/Luyten).

---
