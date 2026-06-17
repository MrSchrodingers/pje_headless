# pje_headless 2.0

Autenticador headless do protocolo PJeOffice (CNJ). Servico escrito em Go que
expoe um endpoint HTTP local na porta 8800, recebe desafios de assinatura do
fluxo PJeOffice, assina com o certificado configurado e envia a resposta ao
tribunal.

Implementa o protocolo de forma independente, com base na codebase do PJeOffice
Pro (CNJ) e na observacao do protocolo. Projeto nao-oficial, sem vinculo com o
CNJ.

---

## O que e

O servico cobre a camada de **autenticacao por certificado digital** do PJeOffice:

- Recebe o desafio (`mensagem`) via HTTP.
- Assina com o certificado ativo usando `MD5withRSA`, `SHA1withRSA` ou
  `SHA256withRSA`.
- Envia `{uuid, mensagem, assinatura, certChain}` ao endpoint do tribunal
  (`servidor + enviarPara`).
- Expoe `GET /pjeOffice/` como health-check.

**Assinatura dual:** o servico suporta dois backends de assinatura por ordem de
prioridade com fallback automatico:

- `pkcs11` — token A3 (hardware, nao exportavel) via modulo PKCS#11 (ex.:
  SafeSign `libaetpkss.so`). Assina dentro do token.
- `pfx` — certificado A1 em arquivo `.pfx`/`.p12` (PKCS#12).

Quando o backend de maior prioridade esta indisponivel, o servico cai para o
proximo e emite log `WARN` com a identidade ativa. Nenhum backend disponivel
resulta em erro explicito.

---

## Arquitetura

```
cmd/pjeheadless/       # main: bootstrap, leitura de config, montagem do Signer
internal/config/       # carrega env vars; tipo Config
internal/audit/        # logging estruturado JSON (log/slog)
internal/signer/       # interface Signer; PFXSigner; PKCS11Signer; DualSigner
internal/pjeoffice/    # servidor HTTP :8800; implementacao do protocolo PJeOffice
```

Pacotes previstos no Plano 2 (em desenvolvimento, nao presentes ainda):
`browser`, `session`, `api` (gRPC).

---

## Build

Requer Go >= 1.25 e CGO habilitado (necessario para o `miekg/pkcs11`, que
compila o binding C do PKCS#11).

```bash
# Instalar dependencias de compilacao (Debian/Ubuntu)
apt-get install -y gcc libc6-dev

# Compilar o binario
go build -o bin/pjeheadless ./cmd/pjeheadless

# Ou via Makefile
make build
```

Para verificar sem gerar binario:

```bash
go vet ./...
```

---

## Execucao

O servico e configurado exclusivamente por variaveis de ambiente. Nenhum
segredo deve ser passado por argumento de linha de comando ou versionado.

### Variaveis de ambiente

| Variavel               | Padrao                       | Descricao                                             |
|------------------------|------------------------------|-------------------------------------------------------|
| `PJE_MODE`             | `full`                       | Modo do servico. `full` ativa o servidor PJeOffice. `signer-only` e roadmap (Plano 2). |
| `PJE_SIGNER_PRIORITY`  | `pkcs11,pfx`                 | Ordem de backends. Primeiro disponivel e usado.       |
| `PJE_PKCS11_MODULE`    | `/usr/lib/libaetpkss.so`     | Caminho do modulo PKCS#11 do token A3.                |
| `PJE_PKCS11_PIN`       | (sem padrao)                 | PIN do token A3.                                      |
| `PJE_PKCS11_SLOT`      | (sem padrao)                 | Slot do token (opcional; usa primeiro disponivel se vazio). |
| `PJE_PKCS11_TOKEN_LABEL` | (sem padrao)               | Label do token (opcional).                            |
| `PJE_PFX_PATH`         | (sem padrao)                 | Caminho do arquivo `.pfx`/`.p12`.                     |
| `PJE_PFX_PASS`         | (sem padrao)                 | Senha do arquivo PFX.                                 |
| `PJE_PJEOFFICE_PORT`   | `8800`                       | Porta do servidor HTTP.                               |
| `PJE_BIND_ADDR`        | `127.0.0.1`                  | Interface de bind. Padrao loopback (somente local).   |
| `PJE_CHAIN_DIR`        | (sem padrao)                 | Diretorio com certificados intermediarios/raiz (opcional). |

### Exemplo: modo PFX (A1)

```bash
PJE_SIGNER_PRIORITY=pfx \
PJE_PFX_PATH=/run/secrets/cert.pfx \
PJE_PFX_PASS=senha-do-pfx \
./bin/pjeheadless
```

### Exemplo: modo token A3 (PKCS#11) com fallback para PFX

```bash
PJE_SIGNER_PRIORITY=pkcs11,pfx \
PJE_PKCS11_MODULE=/usr/lib/libaetpkss.so \
PJE_PKCS11_PIN=pin-do-token \
PJE_PFX_PATH=/run/secrets/cert.pfx \
PJE_PFX_PASS=senha-do-pfx \
./bin/pjeheadless
```

---

## Endpoints

### `GET /pjeOffice/`

Health-check. Retorna GIF 1x1 com status 200.

```bash
curl -I http://127.0.0.1:8800/pjeOffice/
```

### `GET /pjeOffice/requisicao/?r=<payload_url_encoded>`

Modo "image ping" (legado).

### `POST /pjeOffice/requisicao/`

Modo principal. Corpo JSON:

```json
{
  "servidor": "https://exemplo.jus.br",
  "versao": "2.5.16",
  "sessao": "AWSALB=...; JSESSIONID=...",
  "tarefa": "{\"mensagem\":\"<DESAFIO>\",\"enviarPara\":\"/callback\",\"token\":\"<UUID>\",\"algoritmoAssinatura\":\"MD5withRSA\"}"
}
```

Campos:

- `servidor`: base do host de destino (concatenado com `enviarPara`).
- `versao`: cabecalho `versao` enviado ao tribunal (default interno `2.5.16`).
- `sessao`: cookies de sessao (opcional).
- `tarefa` (string JSON aninhada):
  - `mensagem`: desafio a assinar.
  - `enviarPara`: path do endpoint remoto.
  - `token`: identificador UUID.
  - `algoritmoAssinatura`: `MD5withRSA` (padrao historico), `SHA1withRSA` ou `SHA256withRSA`.

Exemplo:

```bash
curl -sS -X POST http://127.0.0.1:8800/pjeOffice/requisicao/ \
  -H "Content-Type: application/json" \
  -d '{
    "servidor": "https://exemplo.jus.br",
    "tarefa": "{\"mensagem\":\"abc123\",\"enviarPara\":\"/api/assinatura\",\"token\":\"uuid-123\",\"algoritmoAssinatura\":\"SHA256withRSA\"}"
  }'
```

---

## Seguranca

- **Bind loopback por padrao.** `PJE_BIND_ADDR` padrao e `127.0.0.1`; o servico
  nao aceita conexoes externas sem configuracao explicita.
- **SSRF scheme-guard.** Somente `http` e `https` sao aceitos como `servidor`;
  outros schemes sao rejeitados.
- **Segredos nunca versionados.** PIN, senha do PFX e qualquer credencial devem
  ser fornecidos exclusivamente via variavel de ambiente ou secret de runtime
  (Docker secret, Kubernetes secret). Nunca commitar `.pfx`, `.pem`, `.key`,
  `.env` ou `cj.txt`.
- **Token A3:** o modulo PKCS#11 (`.so`) e o daemon `pcscd` do host precisam
  estar acessiveis ao processo. Em containers, montar o socket do pcscd e o
  modulo como volumes (detalhes no Plano 2 de deploy).
- **Container nao-root.** O Dockerfile cria e usa usuario `app` sem privilegios.
- **Mixed content.** Paginas `https://` podem bloquear chamadas a `http://localhost`
  por politica do navegador. Nesse caso, coloque um reverse proxy local (Nginx/Caddy)
  com TLS apontando para `http://127.0.0.1:8800`.

---

## Docker

### Build

```bash
docker build -t pjeoffice-headless:2.0 .
```

### Execucao (modo PFX)

```bash
docker run --rm \
  -e PJE_SIGNER_PRIORITY=pfx \
  -e PJE_PFX_PATH=/run/secrets/cert.pfx \
  -e PJE_PFX_PASS=senha-do-pfx \
  -v /caminho/real/cert.pfx:/run/secrets/cert.pfx:ro \
  -p 127.0.0.1:8800:8800 \
  pjeoffice-headless:2.0
```

### Compose

```bash
docker compose up -d
```

---

## Roadmap (Plano 2 — em desenvolvimento)

Os componentes abaixo estao planejados e nao estao presentes nesta versao:

- `browser`: login headless no jus.br via `chromedp` (SSO + 2FA TOTP + captura
  do bearer token). Substitui o fluxo `selenium-wire`.
- `session`: cache do bearer em memoria com single-flight, expiracao e refresh
  sob 401.
- `api` gRPC: servicos `PjeLogin` (GetBearer/ForceRefresh/Health) e `Signer`
  (Sign/CertChain/Identity/Health) para consumo remoto.
- `RemoteSigner`: backend que delega assinatura a uma instancia em modo
  `signer-only` rodando no host do token (acesso local ou remoto por gRPC com mTLS).
- Deploy Docker standalone em servidor de token; migracao do consumidor (vigia)
  para `GetBearer` gRPC.

---

## Licenca

GNU General Public License v3.0. Projeto nao afiliado ao CNJ.
