# Ford Radar Competitivo — Sprint Cybersecurity

Backend FastAPI da plataforma de Inteligência Competitiva Automotiva
(Challenge Ford / FIAP 2026). Esta entrega cobre a **Sprint de
Cybersecurity** (100/100 pts) sobre a stack já definida no desafio:
Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2 (async), Alembic,
PostgreSQL, n8n e React Native + Expo.

> Para o mapeamento detalhado item-a-item do rubric com arquivos e testes,
> ver [SECURITY.md](SECURITY.md).

---

## Cobertura do rubric

| # | Bloco | Pontos | Implementação principal | Testes |
|---|---|---|---|---|
| 1 | Validação de entrada | 20 | Pydantic v2 strict, allowlist regex, normalização Unicode, request size middleware (header + streaming) | 26 |
| 2 | Autenticação e RBAC | 20 | JWT HS256 com lista branca de algoritmos, refresh com rotação, Argon2id, RBAC default-deny | 17 |
| 3 | Proteção de APIs | 20 | HTTPS/HSTS, CORS whitelist, rate-limit por bucket, HMAC anti-replay no webhook do n8n | 9 |
| 4 | Dados e privacidade | 25 | AES-256-GCM via TypeDecorator, pseudonimização HMAC, política de retenção, anti-leak em logs | 11 |
| 5 | Logs e auditoria | 15 | structlog JSON com redator central, audit log com hash chain, eventos suspeitos | 8 |
| | **Total** | **100** | | **71** |

---

## Arquitetura de defesa em profundidade

```
Cliente (mobile / dashboard)
    | HTTPS (HSTS, redirect 308)
    v
+-----------------------------------------------------------+
| FastAPI                                                   |
|   SecurityHeaders -> CORS -> RequestId ->                 |
|   RequestSizeLimit -> RateLimit -> Routes                 |
|                                                           |
|   Schemas Pydantic strict           (anti SQLi/XSS/cmd)   |
|   Dependencies auth + RBAC          (default-deny)        |
|   Handlers de erro centralizados    (sem stack trace)     |
|                                                           |
|   AES-GCM via TypeDecorator         (cripto em repouso)   |
|   structlog com redator             (anti-leak em logs)   |
|   audit_log com hash chain          (anti-tampering)      |
+-----------------------------------------------------------+
    |                                  |
    v                                  v
PostgreSQL (TLS)              n8n -> /v1/ingest (HMAC-SHA256)
```

A ordem dos middlewares é deliberada (mais externo executa primeiro):
qualquer requisição é primeiro inspecionada por tamanho e rate limit
antes de chegar ao parser/router, evitando consumo de CPU/memória em
ataques de flood.

---

## Decisões de segurança (e por quê)

| Decisão | Alternativa rejeitada | Motivo |
|---|---|---|
| Argon2id para senhas | bcrypt | Memory-hard: caro em GPU/ASIC; vencedor do PHC. |
| AES-256-GCM (nonce + tag) | AES-CBC + HMAC | Confidencialidade + integridade num só passo, sem padding oracle. |
| HMAC-SHA256 com `compare_digest` | comparação `==` | Timing attack. |
| HMAC sobre `t || body` + janela 5 min | HMAC só do body | Anti-replay. |
| JWT HS256 com lista branca explícita | aceitar qualquer alg do header | CVE clássico `alg=none` / algorithm-confusion. |
| Refresh token com rotação + revogação por `jti` | refresh imutável | Limita janela em caso de comprometimento. |
| Pseudonimização HMAC (e não hash simples) | SHA-256 puro | Sem o salt, atacante não consegue reverter por força bruta de tabela rainbow. |
| Audit log com hash chain | log append-only sem proteção | Detecta adulteração interna; verificável via endpoint admin. |
| `extra="forbid"` em todo schema | aceitar campos extras | Anti mass-assignment (ex.: `is_admin=True`). |
| Allowlist regex em strings de domínio | sanitização (denylist) | Sanitização sempre vaza; allowlist é fail-closed. |
| Rate-limit como middleware ASGI próprio | slowapi | slowapi reescreve a assinatura da rota e quebra body params do FastAPI sob `from __future__ import annotations`. |
| Settings fail-closed em produção | warnings | Em prod, faltar segredo derruba o boot — melhor que subir aberto. |

---

## Estrutura

```
app/
  config.py              Settings com validação fail-closed em prod
  database.py            SQLAlchemy async engine + session_scope
  main.py                Composição: middlewares + rotas + handlers
  logging_config.py      structlog JSON + redator central de PII
  security/
    crypto.py            AES-256-GCM (encrypt/decrypt + AAD)
    hashing.py           Argon2id com upgrade silencioso
    jwt.py               Emissão/verificação com lista branca de algos
    hmac_sign.py         X-Signature p/ webhook (anti-replay)
    pseudonym.py         HMAC determinístico para LGPD/ML
  middleware/
    security_headers.py  HSTS, CSP, X-Frame, redirect HTTPS
    rate_limit.py        Janela fixa por bucket (auth/ingest/default)
    request_size.py      Limite duplo: header + streaming
    request_id.py        UUID por request (correlação)
    error_handler.py     Resposta segura, log com stack para o operador
  models/                ORM (User, Competitor, Score, Alert, Audit, ...)
  schemas/               Pydantic v2 strict (common.py = SafeName etc.)
  rbac/policy.py         Mapa central admin/analyst/user
  auth/                  Service de login + dependencies FastAPI
  audit/service.py       write_audit + verify_chain + suspicious events
  routes/                Endpoints REST organizados por domínio
migrations/              Alembic
scripts/bootstrap_admin.py
tests/                   71 testes organizados por bloco do rubric
```

---

## Endpoints

| Método | Caminho | Auth | Descrição |
|---|---|---|---|
| GET | `/healthz`, `/readyz` | — | Probes (excluídos do rate-limit) |
| POST | `/v1/auth/login` | — | Login (rate-limit auth) |
| POST | `/v1/auth/refresh` | — | Rotação de tokens |
| POST | `/v1/auth/logout` | bearer | Revoga `jti` atual |
| GET | `/v1/competitors` | bearer | Lista concorrentes (filtros validados) |
| GET | `/v1/scores` | bearer | Scores competitivos |
| GET | `/v1/alerts` | bearer | Alertas IA (texto cifrado em repouso) |
| POST | `/v1/ingest/spreadsheet` | HMAC | Webhook n8n (rate-limit ingest) |
| POST | `/v1/admin/users` | admin | Criação de usuário |
| GET | `/v1/admin/audit` | admin | Trilha de auditoria |
| GET | `/v1/admin/audit/verify` | admin | Verifica a hash chain |
| GET | `/v1/admin/suspicious` | admin | Eventos suspeitos |

---

## Como executar

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt

# Configurar segredos (gerar valores fortes)
cp .env.example .env
python -c "import os, base64; print('ENCRYPTION_KEY=' + base64.b64encode(os.urandom(32)).decode())" >> .env
python -c "import secrets; print('PSEUDONYM_SALT=' + secrets.token_urlsafe(48))" >> .env
python -c "import secrets; print('JWT_SECRET=' + secrets.token_urlsafe(64))" >> .env
python -c "import secrets; print('WEBHOOK_HMAC_SECRET=' + secrets.token_urlsafe(48))" >> .env

# Migrações
.venv/Scripts/python -m alembic upgrade head

# Admin inicial (opcional, defina BOOTSTRAP_ADMIN_EMAIL/PASSWORD no .env)
.venv/Scripts/python -m scripts.bootstrap_admin

# Servidor
.venv/Scripts/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

---

## Testes (verificação automática do rubric)

```bash
.venv/Scripts/python -m pytest tests/ -v
```

Resultado esperado: **71 passed**. Os arquivos de teste seguem o
mapeamento do rubric — `tests/test_rubric_N_*.py` corresponde
diretamente ao bloco N da rubrica:

| Arquivo | Bloco | Testes |
|---|---|---|
| `test_rubric_1_input_validation.py` | Validação de entrada | 26 |
| `test_rubric_2_auth_rbac.py` | Auth e RBAC | 17 |
| `test_rubric_3_api_protection.py` | Proteção de APIs | 9 |
| `test_rubric_4_data_privacy.py` | Dados e privacidade | 11 |
| `test_rubric_5_logs_audit.py` | Logs e auditoria | 8 |

Cobre vetores reais de ataque (14 payloads de SQLi/XSS/cmd-injection),
HMAC com replay/tamper/timestamp velho, alg=none, mass-assignment,
hash chain com adulteração, redação de PII em logs, etc.

---

## Modelo de ameaças (STRIDE)

| Ameaça | Mitigação | Onde |
|---|---|---|
| Spoofing | JWT HS256 com aud/iss obrigatórios; HMAC no webhook do n8n | `security/jwt.py`, `security/hmac_sign.py` |
| Tampering | AES-GCM em repouso; HMAC em trânsito; hash chain em audit | `security/crypto.py`, `audit/service.py` |
| Repudiation | Audit log encadeado + correlação por request_id | `audit/service.py`, `middleware/request_id.py` |
| Information Disclosure | Cripto em repouso, redação automática de logs, error handler genérico | `security/crypto.py`, `logging_config.py` |
| Denial of Service | Rate limit por bucket/IP, request size limit duplo, max linhas/planilha | `middleware/rate_limit.py`, `middleware/request_size.py` |
| Elevation of Privilege | RBAC default-deny, allowlist de roles, `extra="forbid"` em schemas | `rbac/policy.py`, `auth/deps.py` |

---

## Operação e LGPD

- Segredos por ambiente, validados em boot. Em produção, segredo curto
  ou ausente derruba o serviço (fail-closed).
- Retenção configurável por tipo de dado: 365 d audit, 180 d planilhas,
  730 d usuário inativo (`Settings.retention_*`).
- Pseudonimização garante que dashboards e modelos de ML possam fazer
  joins sem expor PII.
- Endpoint `GET /v1/admin/audit/verify` recalcula a hash chain inteira;
  recomenda-se cron externo agendando a chamada.
- Rotação de chaves: variáveis de ambiente são as únicas fontes; trocar
  e reiniciar. Para `ENCRYPTION_KEY`, evolução planejada inclui coluna
  `key_version` para re-cifragem incremental.

---

## Stack e dependências principais

| Pacote | Versão | Para quê |
|---|---|---|
| `fastapi` | 0.115.5 | Framework HTTP |
| `pydantic` | 2.10.3 | Validação de schemas |
| `sqlalchemy` | 2.0.36 (async) | ORM |
| `alembic` | 1.14.0 | Migrações |
| `cryptography` | 44.0.0 | AES-GCM |
| `argon2-cffi` | 23.1.0 | Hash de senhas |
| `python-jose[cryptography]` | 3.3.0 | JWT |
| `structlog` | 24.4.0 | Logs estruturados |
| `pytest` + `pytest-asyncio` | 8.3 / 0.24 | Testes |

Sem dependências com vulnerabilidades conhecidas no momento da entrega.
Para uma auditoria atualizada: `pip-audit` ou `safety check`.
