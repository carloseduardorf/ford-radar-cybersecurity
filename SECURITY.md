# Sprint Cybersecurity — Challenger Ford 2026

Documento de cobertura de controles de segurança, mapeando cada item da
rubrica para o(s) arquivo(s) de implementação e o(s) teste(s) que o
verificam.

> **Stack do challenge:** Python 3.12 · FastAPI · Pydantic v2 · SQLAlchemy 2 (async) · Alembic · PostgreSQL · n8n (workflow) · React Native + Expo (mobile) · Dashboard web.
>
> **Escopo deste sprint:** o backend FastAPI que serve o dashboard, o app
> e recebe os webhooks do n8n. Os controles aqui aplicáveis cobrem 100 %
> da rubrica de cybersecurity (100/100 pontos).

## Integrantes do grupo

| Nome | RM |
|---|---|
| Carlos Eduardo | 556785 |
| Giulia Rocha | 558084 |
| Caio Rossini | 555084 |
| Gabriel Danius | 555747 |

---

## 1 · Segurança de Entrada e Validação de Dados — 20 pts

| Item da rubrica | Como cobrimos | Arquivo(s) | Teste(s) |
|---|---|---|---|
| Validação de entradas e sanitização contra **SQL Injection / XSS / command injection** | Allowlist regex em campos de domínio (`SAFE_NAME_RE`), normalização Unicode (NFC + bloqueio de chars de controle), denylist explícita de padrões de injeção SQL, ORM 100 % parametrizado | [`app/schemas/common.py`](app/schemas/common.py), [`app/schemas/competitor.py`](app/schemas/competitor.py), [`app/routes/competitors.py`](app/routes/competitors.py) | `test_brand_rejects_attack` (14 vetores), `test_extra_fields_rejected` |
| **Normalização e validação de parâmetros de API** (marca, modelo, versão, atributos) | Schemas Pydantic strict mode com `extra="forbid"`, `StrictStr`, regex e limites tipados (`SafeName`, `SafeCode`, `YearInt`, `HorsepowerInt`, `PriceFloat`) | [`app/schemas/common.py`](app/schemas/common.py), [`app/schemas/competitor.py`](app/schemas/competitor.py), [`app/schemas/spreadsheet.py`](app/schemas/spreadsheet.py) | `test_valid_competitor_passes`, `test_unicode_accents_allowed`, `test_numeric_bounds_enforced`, `test_pagination_bounds` |
| **Limitação de tamanho/formato** (payload flooding, buffer overflow) | Middleware ASGI inspeciona `Content-Length` e conta bytes em streaming. Limites diferenciados: 2 MiB JSON / 20 MiB upload de planilha. Schema também limita 5000 linhas/planilha | [`app/middleware/request_size.py`](app/middleware/request_size.py) | `test_payload_size_limit`, `test_content_length_announced_overlimit_rejected`, `test_string_length_limited`, `test_spreadsheet_size_bound` |
| **Tratamento seguro de erros** (sem stack trace, sem estrutura interna) | Handler central que produz JSON `{detail, request_id}`. Em prod, sem `type` da exceção; nunca ecoa o `input` validado pelo Pydantic (anti-XSS reflexivo) | [`app/middleware/error_handler.py`](app/middleware/error_handler.py) | `test_validation_error_does_not_leak_input`, `test_500_does_not_leak_stack_trace` |

## 2 · Autenticação e Autorização — 20 pts

| Item da rubrica | Como cobrimos | Arquivo(s) | Teste(s) |
|---|---|---|---|
| **Tokens com expiração, assinatura forte e renovação controlada** | JWT HS256 (lista branca de algoritmos, **rejeita `alg=none`**), claims `iss/aud/sub/iat/nbf/exp/jti/typ/role` obrigatórios, access TTL = 15 min, refresh = 7 dias com **rotação** + revogação por `jti` | [`app/security/jwt.py`](app/security/jwt.py), [`app/auth/service.py`](app/auth/service.py), [`app/auth/routes.py`](app/routes/auth.py) | `test_jwt_*`, `test_refresh_rotation`, `test_logout_revokes_token` |
| **RBAC com analistas / administradores / usuários comuns** | Mapa central de `Permission`s por `UserRole` (default-deny). Dependência `require_role(...)` aplicada nas rotas administrativas | [`app/rbac/policy.py`](app/rbac/policy.py), [`app/auth/deps.py`](app/auth/deps.py) | `test_rbac_*`, `test_rbac_permission_matrix_consistent` |
| Política de senha forte | 12-128 chars, minúsc + maiúsc + dígito + símbolo, sem espaços; hash **Argon2id** com upgrade silencioso quando custo defasa; lockout temporário após 5 falhas | [`app/security/hashing.py`](app/security/hashing.py), [`app/schemas/auth.py`](app/schemas/auth.py), [`app/auth/service.py`](app/auth/service.py) | `test_password_policy_rejects_weak` |
| Anti-enumeração de usuários | Mensagem genérica "Credenciais inválidas" em qualquer falha; hash dummy quando email não existe (tempo constante) | [`app/auth/service.py`](app/auth/service.py) | `test_login_unknown_user_same_message` |

## 3 · Proteção de APIs e Serviços — 20 pts

| Item da rubrica | Como cobrimos | Arquivo(s) | Teste(s) |
|---|---|---|---|
| **HTTPS / TLS 1.2+ obrigatório** | Redirect 308 para HTTPS quando `FORCE_HTTPS`. HSTS 2 anos com `preload + includeSubDomains`. Em produção, validador de Settings recusa boot sem TLS configurado | [`app/middleware/security_headers.py`](app/middleware/security_headers.py), [`app/config.py`](app/config.py) | `test_security_headers_present` |
| **Rate limiting / throttling** | Janela fixa in-memory por bucket (`auth`, `ingest`, `default`) e por IP. Storage abstraído — substituível por Redis sem mudar consumidores | [`app/middleware/rate_limit.py`](app/middleware/rate_limit.py) | `test_login_rate_limit_kicks_in` |
| **CORS configurado corretamente** | `cors_origins_list` whitelist; **wildcard `*` proibido em produção** (validado em Settings). Headers e métodos restritos | [`app/main.py`](app/main.py), [`app/config.py`](app/config.py) | `test_cors_allowed_origin`, `test_cors_disallowed_origin` |
| **Assinatura/verificação de integridade de payloads** (5 pts) | HMAC-SHA256 sobre `timestamp \|\| body`. Verificação com `hmac.compare_digest` (timing-safe) + janela de tolerância de 5 min (anti-replay) + idempotência por `sha256` | [`app/security/hmac_sign.py`](app/security/hmac_sign.py), [`app/routes/ingest.py`](app/routes/ingest.py) | `test_ingest_requires_signature`, `test_ingest_with_valid_signature`, `test_ingest_replay_blocked`, `test_ingest_timestamp_replay_blocked`, `test_ingest_tampered_body_blocked` |
| Outros headers de proteção | `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Content-Security-Policy: default-src 'none'`, `Permissions-Policy` mínimo, remoção de `Server` | [`app/middleware/security_headers.py`](app/middleware/security_headers.py) | `test_security_headers_present` |

## 4 · Segurança de Dados e Privacidade — 25 pts

| Item da rubrica | Como cobrimos | Arquivo(s) | Teste(s) |
|---|---|---|---|
| **Criptografia em repouso de dados sensíveis** (clientes, leads, histórico) | AES-256-GCM com nonce aleatório por linha + AAD opcional. `EncryptedStr` é um SQLAlchemy `TypeDecorator` — cifragem transparente para o desenvolvedor | [`app/security/crypto.py`](app/security/crypto.py), [`app/models/base.py`](app/models/base.py), [`app/models/user.py`](app/models/user.py), [`app/models/alert.py`](app/models/alert.py) | `test_encryption_round_trip`, `test_encryption_unique_ciphertexts_*`, `test_encryption_aad_prevents_misuse`, `test_tampered_ciphertext_fails`, `test_user_email_encrypted_at_rest` |
| **Política de retenção e descarte seguro** | Configurações dedicadas por tipo de dado: 365 d audit / 180 d planilhas / 730 d usuário inativo. Delete ON DELETE CASCADE em FKs principais; logout revoga tokens via `jti` | [`app/config.py`](app/config.py), [`app/models/competitor.py`](app/models/competitor.py) | `test_retention_policy_configured` |
| **Anonimização / pseudonimização** (especialmente para ML/dashboards) | HMAC-SHA256 com salt dedicado → pseudônimo determinístico, indexável, reversível só com posse do salt. Função `anonymize_email` para logs (`a***@dominio.com`) | [`app/security/pseudonym.py`](app/security/pseudonym.py), [`app/models/user.py`](app/models/user.py) | `test_pseudonym_deterministic`, `test_pseudonym_changes_with_salt`, `test_email_anonymizer` |
| **Proteção contra exposição acidental** (logs, dumps, endpoints) | Logs estruturados com **redator automático** de chaves sensíveis (`password`, `email`, `token`, `authorization`, ...) e regex que apaga emails/JWTs achados em qualquer string. Endpoints admin trabalham por pseudônimo. `/readyz` não vaza versão | [`app/logging_config.py`](app/logging_config.py), [`app/routes/admin.py`](app/routes/admin.py), [`app/routes/health.py`](app/routes/health.py) | `test_log_redacts_password_and_email`, `test_admin_user_listing_uses_pseudonym`, `test_health_does_not_leak_version` |

## 5 · Monitoramento, Logs e Auditoria — 15 pts

| Item da rubrica | Como cobrimos | Arquivo(s) | Teste(s) |
|---|---|---|---|
| **Logs estruturados e seguros** (sem dados sensíveis, com rastreabilidade) | structlog em JSON, processador de redação centralizado, `request_id` UUID propagado em header `X-Request-Id` para correlação ponta-a-ponta | [`app/logging_config.py`](app/logging_config.py), [`app/middleware/request_id.py`](app/middleware/request_id.py) | `test_log_redacts_*`, `test_request_id_propagated`, `test_request_id_generated_when_invalid` |
| **Monitoramento de eventos suspeitos** (acesso indevido, falhas repetidas, anomalias) | Tabela `suspicious_events` para rate-limit hits, falhas em massa, etc. `SuspiciousEvent` registra `kind/severity/actor_pseudonym/ip/detail` | [`app/audit/service.py`](app/audit/service.py), [`app/middleware/rate_limit.py`](app/middleware/rate_limit.py), [`app/models/audit.py`](app/models/audit.py) | `test_rate_limit_hit_recorded_as_suspicious` |
| **Trilha de auditoria para ações críticas** (alterações de configuração, criação de leads, consultas massivas) | Tabela `audit_logs` com **hash chain** (`row_hash = sha256(prev_hash \|\| canonical(row))`). Endpoint admin `GET /v1/admin/audit/verify` recalcula a cadeia inteira | [`app/audit/service.py`](app/audit/service.py), [`app/models/audit.py`](app/models/audit.py), [`app/routes/admin.py`](app/routes/admin.py) | `test_audit_login_recorded`, `test_audit_failed_login_recorded`, `test_audit_chain_integrity`, `test_audit_chain_detects_tampering` |

---

## Modelo de ameaças (resumo STRIDE)

| Ameaça | Mitigação principal | Onde |
|---|---|---|
| **S**poofing | JWT HS256 + audience/issuer verificados; HMAC no webhook do n8n | `security/jwt.py`, `security/hmac_sign.py` |
| **T**ampering | AES-GCM em repouso; HMAC em trânsito; hash chain em audit | `security/crypto.py`, `audit/service.py` |
| **R**epudiation | Audit log assinado em cadeia + correlação por `request_id` | `audit/service.py` |
| **I**nformation Disclosure | Cripto em repouso, redação automática de logs, error handler genérico, pseudonimização para ML | `security/crypto.py`, `logging_config.py` |
| **D**enial of Service | Rate limit por bucket/IP, request size limit duplo (header + streaming), max linhas por planilha | `middleware/rate_limit.py`, `middleware/request_size.py` |
| **E**levation of Privilege | RBAC default-deny, lista branca de papéis, `extra="forbid"` em schemas (anti mass-assignment) | `rbac/policy.py`, `auth/deps.py`, `schemas/*.py` |

## Operações seguras

- **Provisão de segredos:** todos via env (12-factor). Valores < N chars rejeitados em produção pelo validador de `Settings` (fail-closed).
- **Rotação de chaves:** `ENCRYPTION_KEY`, `JWT_SECRET`, `WEBHOOK_HMAC_SECRET` aceitam rotação; preparar coluna `encryption_key_version` é a próxima evolução para suportar re-cifragem incremental.
- **Verificação de integridade da auditoria:** `GET /v1/admin/audit/verify` deve ser cron-agendado externamente.
- **Bootstrap:** `python -m scripts.bootstrap_admin` — idempotente, cria o admin a partir de `BOOTSTRAP_ADMIN_EMAIL/PASSWORD`.

## Como executar a verificação local

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt
.venv/Scripts/python -m alembic upgrade head
.venv/Scripts/python -m pytest tests/ -v
```

Resultado esperado: **71 testes passando**, cobrindo cada linha do rubric.
