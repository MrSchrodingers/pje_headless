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

**Assinatura dual:** o servico suporta backends de assinatura por ordem de
prioridade (`PJE_SIGNER_PRIORITY`) com fallback automatico:

- `pkcs11` — token A3 (hardware, nao exportavel) via modulo PKCS#11 (ex.:
  SafeSign `libaetpkss.so`). Assina dentro do token.
- `pfx` — certificado A1 em arquivo `.pfx`/`.p12` (PKCS#12).
- `remote` — `RemoteSigner`, que nao detem credencial local: delega a assinatura,
  via gRPC, a um `SignerService` rodando em modo `signer-only` no host que tem o
  token. Habilitado quando `remote` aparece em `PJE_SIGNER_PRIORITY` e
  `PJE_SIGNER_REMOTE_ADDR` aponta para o endpoint do servico.

Quando o backend de maior prioridade esta indisponivel, o servico cai para o
proximo e emite log `WARN` com a identidade ativa. Nenhum backend disponivel
resulta em erro explicito.

---

## Modos de operacao (`PJE_MODE`)

O binario tem quatro modos, selecionados por `PJE_MODE`:

- `full` (padrao) — servidor HTTP PJeOffice na porta `8800` (descrito acima).
- `signer-only` — expoe o `SignerService` gRPC (padrao `:9090`) sobre o `Signer`
  local. Faz login *eager* no token/PFX na inicializacao (fail-fast: PIN errado ou
  token ausente quebra na partida, nao no meio do fluxo), de modo que o `Health`
  ja reporta `ready`. E o lado servidor da topologia de assinatura remota: roda no
  host que detem o token A3.
- `login` — driver end-to-end. Executa UM login headless completo no jus.br
  (requer Chrome) e imprime `LOGIN_OK bearer_len=N`. Usa o `Signer` configurado,
  inclusive `remote` para delegar o handshake do certificado ao host do token.
  Serve para validar o fluxo dual contra o SSO real. O bearer nunca e logado por
  inteiro (apenas mascarado).
- `login-service` — expoe o `LoginService` gRPC (padrao `127.0.0.1:9091`) com
  `GetBearer` e `Health`. Reusa a sessao via `LoginManager` (cache do bearer com
  expiracao e coalescencia), disparando o login headless somente quando nao ha
  token fresco em cache.

### Topologia dual (token num host, browser noutro)

O login (`login` / `login-service`) roda onde ha Chrome instalado. Com
`PJE_SIGNER_PRIORITY=remote` e `PJE_SIGNER_REMOTE_ADDR=host-do-token:9090`, o
handshake do certificado e delegado, por gRPC, ao `SignerService` (`signer-only`)
que roda no host com o token A3. Assim o token fica isolado num host e o browser
roda em outro: cada chamada de assinatura do fluxo de login viaja ate o host do
token e volta.

---

## Arquitetura

```
cmd/pjeheadless/       # main: bootstrap, leitura de config, selecao do modo (PJE_MODE)
internal/config/       # carrega env vars; tipo Config
internal/audit/        # logging estruturado JSON (log/slog)
internal/signer/       # interface Signer; PFXSigner; PKCS11Signer; DualSigner; RemoteSigner
internal/pjeoffice/    # servidor HTTP :8800; implementacao do protocolo PJeOffice
internal/browser/      # login headless no jus.br via chromedp/CDP; SSO + 2FA TOTP + captura do bearer
internal/loginsvc/     # LoginManager: cache do bearer, expiracao e coalescencia (single-flight)
internal/grpcsigner/   # SignerService gRPC (lado servidor da assinatura remota)
internal/grpclogin/    # LoginService gRPC (entrega o bearer com reuso de sessao)
internal/signerpb/     # stubs gerados de proto/signer.proto
internal/loginpb/      # stubs gerados de proto/login.proto
proto/                 # contratos gRPC: signer.proto (SignerService) e login.proto (LoginService)
```

---

## Build

Requer Go >= 1.26 e CGO habilitado (necessario para o `miekg/pkcs11`, que
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
| `PJE_MODE`             | `full`                       | Modo do servico: `full`, `signer-only`, `login` ou `login-service` (ver "Modos de operacao"). |
| `PJE_SIGNER_PRIORITY`  | `pkcs11,pfx`                 | Ordem de backends (`pkcs11`, `pfx`, `remote`). Primeiro disponivel e usado. |
| `PJE_PKCS11_MODULE`    | `/usr/lib/libaetpkss.so`     | Caminho do modulo PKCS#11 do token A3.                |
| `PJE_PKCS11_PIN`       | (sem padrao)                 | PIN do token A3.                                      |
| `PJE_PKCS11_SLOT`      | (sem padrao)                 | Slot do token (opcional; usa primeiro disponivel se vazio). |
| `PJE_PKCS11_TOKEN_LABEL` | (sem padrao)               | Label do token (opcional).                            |
| `PJE_PFX_PATH`         | (sem padrao)                 | Caminho do arquivo `.pfx`/`.p12`.                     |
| `PJE_PFX_PASS`         | (sem padrao)                 | Senha do arquivo PFX.                                 |
| `PJE_PJEOFFICE_PORT`   | `8800`                       | Porta do servidor HTTP PJeOffice.                     |
| `PJE_BIND_ADDR`        | `127.0.0.1`                  | Interface de bind do servidor HTTP. Padrao loopback (somente local). |
| `PJE_CHAIN_DIR`        | (sem padrao)                 | Diretorio com certificados intermediarios/raiz (opcional). |
| `PJE_GRPC_ADDR`        | `:9090`                      | Bind do `SignerService` gRPC (modo `signer-only`). Padrao todas as interfaces. |
| `PJE_SIGNER_REMOTE_ADDR` | (sem padrao)               | `host:porta` do `SignerService` remoto, usado quando `remote` esta em `PJE_SIGNER_PRIORITY`. |
| `PJE_LOGIN_GRPC_ADDR`  | `127.0.0.1:9091`             | Bind do `LoginService` gRPC (modo `login-service`). Padrao loopback. |
| `PJE_2FA_TOTP_SECRET`  | (sem padrao)                 | Segredo TOTP base32 do 2FA, usado nos modos de login. Nunca hardcoded. |
| `PJE_CHROME_PATH`      | (sem padrao)                 | Caminho do binario Chrome/Chromium para os modos de login. |
| `PJE_CHROMEDP_DEBUG`   | (sem padrao)                 | Opcional; qualquer valor nao-vazio liga o trace do protocolo CDP em stderr. |

### Exemplo: modo PFX (A1)

```bash
PJE_SIGNER_PRIORITY=pfx \
PJE_PFX_PATH=/run/secrets/cert.pfx \
PJE_PFX_PASS=<senha-do-pfx> \
./bin/pjeheadless
```

### Exemplo: modo token A3 (PKCS#11) com fallback para PFX

```bash
PJE_SIGNER_PRIORITY=pkcs11,pfx \
PJE_PKCS11_MODULE=/usr/lib/libaetpkss.so \
PJE_PKCS11_PIN=<pin> \
PJE_PFX_PATH=/run/secrets/cert.pfx \
PJE_PFX_PASS=<senha-do-pfx> \
./bin/pjeheadless
```

### Exemplo: modo `signer-only` (host do token)

Roda no host que detem o token A3 e serve a assinatura por gRPC. O bind padrao
(`:9090`) escuta em todas as interfaces para atender o assinante remoto pela LAN.

```bash
PJE_MODE=signer-only \
PJE_SIGNER_PRIORITY=pkcs11 \
PJE_PKCS11_MODULE=/usr/lib/libaetpkss.so \
PJE_PKCS11_PIN=<pin> \
PJE_GRPC_ADDR=:9090 \
./bin/pjeheadless
```

### Exemplo: modo `login` (driver end-to-end, requer Chrome)

Executa um unico login headless e imprime `LOGIN_OK bearer_len=N`. Com
`PJE_SIGNER_PRIORITY=remote`, delega o handshake do certificado ao `signer-only`
do host do token; sem ele, usa o `Signer` local.

```bash
PJE_MODE=login \
PJE_SIGNER_PRIORITY=remote \
PJE_SIGNER_REMOTE_ADDR=host-do-token:9090 \
PJE_CHROME_PATH=/usr/bin/chromium \
PJE_2FA_TOTP_SECRET=<segredo-base32> \
./bin/pjeheadless
```

### Exemplo: modo `login-service` (gRPC, requer Chrome)

Expoe o `LoginService` gRPC com reuso de sessao. O bind padrao
(`127.0.0.1:9091`) escuta apenas em loopback; para servir um consumidor em outro
host, defina `PJE_LOGIN_GRPC_ADDR` para uma interface de LAN confiavel.

```bash
PJE_MODE=login-service \
PJE_SIGNER_PRIORITY=remote \
PJE_SIGNER_REMOTE_ADDR=host-do-token:9090 \
PJE_CHROME_PATH=/usr/bin/chromium \
PJE_2FA_TOTP_SECRET=<segredo-base32> \
PJE_LOGIN_GRPC_ADDR=127.0.0.1:9091 \
./bin/pjeheadless
```

---

## 2FA (TOTP)

Os modos de login (`login` e `login-service`) tratam o segundo fator
automaticamente quando a conta exige TOTP:

- **Login recorrente.** O codigo de 6 digitos e calculado a cada login a partir
  de `PJE_2FA_TOTP_SECRET` (segredo base32, RFC 6238, janela de 30s). Defina essa
  variavel com o segredo da conta; sem ela, um login que exija 2FA falha com erro
  explicito (nao submete codigo em branco).
- **Primeiro cadastro (enrollment).** Se a conta ainda nao tem autenticador e o
  SSO exige o cadastro (required-action `CONFIGURE_TOTP`), o servico cadastra um
  novo dispositivo TOTP sozinho e registra UMA unica vez, em log `INFO`, o segredo
  cunhado (`PJE_2FA_TOTP_SECRET=<segredo>`). Esse segredo e o entregavel: persista-o
  com seguranca (cofre/secret de runtime) e informe-o em `PJE_2FA_TOTP_SECRET` nos
  logins seguintes. So este ponto registra o segredo; o codigo de 6 digitos nunca
  e logado pelo fluxo.

O segredo TOTP e uma credencial: trate-o como `.env`/secret de runtime e nunca o
versione (ver "Seguranca"). Para um login MANUAL no navegador (fora do fluxo
headless), o codigo atual pode ser derivado do mesmo segredo base32 por qualquer
gerador TOTP RFC 6238.

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

### gRPC

Contratos em `proto/`. Transporte TCP puro por padrao (mTLS e item de backlog).

**`SignerService`** (`proto/signer.proto`, modo `signer-only`, padrao `:9090`):

- `Sign` — assina uma frase com o algoritmo dado; retorna a assinatura PKCS#1 v1.5 em base64.
- `CertChainPKIPath` — retorna o PKIPath ASN.1 da cadeia (folha primeiro) em base64.
- `Identity` — metadados do certificado folha (subject, issuer, serial, validade).
- `Health` — liveness/readiness; nao muta estado.

**`LoginService`** (`proto/login.proto`, modo `login-service`, padrao `127.0.0.1:9091`):

- `GetBearer` — retorna um bearer valido. Reusa o token em cache quando ainda
  fresco; dispara um login headless somente quando nao ha token fresco ou quando
  `force=true`. Chamadas concorrentes coalescem num unico login. A resposta inclui
  `expires_at_unix` (exp do JWT; `0` quando desconhecido) e `from_cache`.
- `Health` — reporta se ha um bearer nao-expirado em cache e quando ele expira;
  nao dispara login.

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
  modulo como volumes (ver Dockerfile e a secao Docker).
- **Bearer e credencial; `LoginService` em loopback por padrao.** O `LoginService`
  (`GetBearer`) devolve um bearer (uma credencial reutilizavel) em TCP puro, sem
  autenticacao por chamada. Por isso `PJE_LOGIN_GRPC_ADDR` faz bind em
  `127.0.0.1:9091` por padrao (fail-safe: nao alcancavel fora do host sem opt-in
  explicito). Para servir um consumidor em outro host, defina o bind para uma
  interface de LAN confiavel; confine a um segmento de rede confiavel. O bearer
  nunca e logado por inteiro.
- **`SignerService` em todas as interfaces por necessidade.** O `SignerService`
  (`signer-only`, padrao `:9090`) faz bind em todas as interfaces porque o host do
  token precisa servir o assinante remoto pela LAN. Mantenha-o num segmento
  confiavel. Para ambos os servicos gRPC, mTLS e item de backlog.
- **Container nao-root.** O Dockerfile cria e usa usuario `app` sem privilegios.
- **Mixed content.** Paginas `https://` podem bloquear chamadas a `http://localhost`
  por politica do navegador. Nesse caso, coloque um reverse proxy local (Nginx/Caddy)
  com TLS apontando para `http://127.0.0.1:8800`.

---

## Docker

A imagem runtime atual (`debian-slim`) **nao inclui Chrome**, entao atende os
modos `full` e `signer-only`. Os modos de login (`login` / `login-service`)
exigem Chrome: rode o binario direto no host com Chrome instalado, ou estenda a
imagem para incluir `chromium` (e, para token A3, montar o modulo PKCS#11 e o
socket do `pcscd`).

### Build

```bash
docker build -t pjeoffice-headless:2.0 .
```

### Execucao (modo PFX)

```bash
docker run --rm \
  -e PJE_SIGNER_PRIORITY=pfx \
  -e PJE_PFX_PATH=/run/secrets/cert.pfx \
  -e PJE_PFX_PASS=<senha-do-pfx> \
  -v /caminho/real/cert.pfx:/run/secrets/cert.pfx:ro \
  -p 127.0.0.1:8800:8800 \
  pjeoffice-headless:2.0
```

### Compose

```bash
docker compose up -d
```

---

## Roadmap

Ja implementado: login headless `browser` (chromedp, SSO + 2FA TOTP + captura do
bearer); reuso de sessao `loginsvc` (cache com expiracao e coalescencia); API gRPC
(`SignerService` e `LoginService`); e o `RemoteSigner` que delega a assinatura ao
host do token.

Pendente:

- Deploy do container no host do token, com Chrome para os modos de login e os
  mounts de PKCS#11 / `pcscd`.
- Migracao do consumidor (vigia) para obter o bearer via `GetBearer` gRPC.
- Hardening com mTLS nos servicos gRPC (`SignerService` e `LoginService`).

---

## Licenca

GNU General Public License v3.0. Projeto nao afiliado ao CNJ.
