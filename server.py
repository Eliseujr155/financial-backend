"""
Financial Management Platform - Backend Flask + SQLite
"""
import sqlite3
import json
import uuid
import hashlib
import time
import os
from functools import wraps
from flask import Flask, request, jsonify, g, send_from_directory

app = Flask(__name__, static_folder="dist", static_url_path="")

SECRET_KEY = os.environ.get("JWT_SECRET", "orienta-fin-secret-2026")
DB_PATH = os.environ.get("DB_PATH", "financeiro.db")

# ── CORS manual ────────────────────────────────────────────────────────────────
@app.after_request
def add_cors(response):
    origin = request.headers.get("Origin", "*")
    response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response

@app.route("/api/<path:path>", methods=["OPTIONS"])
@app.route("/api/", methods=["OPTIONS"])
def options_handler(path=""):
    return "", 204

# ── DB ─────────────────────────────────────────────────────────────────────────
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db:
        db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        company TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        is_super_admin INTEGER NOT NULL DEFAULT 0,
        must_change_password INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS receitas (
        id TEXT PRIMARY KEY,
        descricao TEXT NOT NULL,
        valor REAL NOT NULL,
        data TEXT NOT NULL,
        turno TEXT NOT NULL DEFAULT 'Manhã',
        pagamentos TEXT NOT NULL DEFAULT '[]',
        categoria TEXT NOT NULL DEFAULT '',
        observacoes TEXT,
        user_id TEXT NOT NULL,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS despesas (
        id TEXT PRIMARY KEY,
        descricao TEXT NOT NULL,
        valor REAL NOT NULL,
        data TEXT NOT NULL,
        subcategoria TEXT NOT NULL,
        categoria TEXT NOT NULL DEFAULT '',
        recorrente INTEGER DEFAULT 0,
        observacoes TEXT,
        funcionario_id TEXT,
        user_id TEXT NOT NULL,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS funcionarios (
        id TEXT PRIMARY KEY,
        nome TEXT NOT NULL,
        cargo TEXT NOT NULL,
        frequencia TEXT NOT NULL DEFAULT 'mensal',
        tipo_valor TEXT NOT NULL DEFAULT 'fixo',
        valor REAL NOT NULL DEFAULT 0,
        dia_pagamento INTEGER NOT NULL DEFAULT 1,
        ativo INTEGER NOT NULL DEFAULT 1,
        user_id TEXT NOT NULL,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS despesas_fixas_rec (
        id TEXT PRIMARY KEY,
        descricao TEXT NOT NULL,
        valor REAL NOT NULL,
        dia_pagamento INTEGER NOT NULL,
        categoria TEXT NOT NULL,
        ativa INTEGER NOT NULL DEFAULT 1,
        user_id TEXT NOT NULL,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS notificacoes (
        id TEXT PRIMARY KEY,
        descricao TEXT NOT NULL,
        dia_vencimento INTEGER NOT NULL,
        ativa INTEGER NOT NULL DEFAULT 1,
        user_id TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS configuracoes (
        user_id TEXT PRIMARY KEY,
        nome_empresa TEXT NOT NULL DEFAULT 'Minha Empresa',
        cnpj TEXT DEFAULT '',
        segmento TEXT DEFAULT '',
        meta_mensal REAL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS pagamentos_processados (
        chave TEXT NOT NULL,
        user_id TEXT NOT NULL,
        PRIMARY KEY (chave, user_id)
    );

    CREATE TABLE IF NOT EXISTS slots_consultoria (
        id TEXT PRIMARY KEY,
        data TEXT NOT NULL,
        horario TEXT NOT NULL,
        mes TEXT NOT NULL,
        criado_em TEXT NOT NULL,
        criado_por TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS agendamentos_consultoria (
        id TEXT PRIMARY KEY,
        slot_id TEXT NOT NULL,
        slot_data TEXT NOT NULL,
        slot_horario TEXT NOT NULL,
        mes TEXT NOT NULL,
        user_id TEXT NOT NULL,
        user_name TEXT NOT NULL,
        user_email TEXT NOT NULL,
        user_company TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'solicitado',
        criado_em TEXT NOT NULL,
        respondido_em TEXT,
        motivo_negacao TEXT
    );

    CREATE TABLE IF NOT EXISTS relatorios_empresariais (
        id TEXT PRIMARY KEY,
        titulo TEXT NOT NULL,
        conteudo TEXT NOT NULL,
        atualizado_em TEXT NOT NULL,
        user_id TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS assinaturas (
        id TEXT PRIMARY KEY,
        nome_cliente TEXT NOT NULL,
        email_cliente TEXT,
        plano_nome TEXT NOT NULL,
        valor_mensal REAL NOT NULL,
        data_inicio TEXT NOT NULL,
        data_proxima_cobranca TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'ativa',
        observacoes TEXT,
        user_id TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """)
    # Super admin seed
    existing = db.execute("SELECT id FROM users WHERE id='superadmin'").fetchone()
    if not existing:
        db.execute("""
            INSERT INTO users (id, name, email, password_hash, company, role, is_super_admin, must_change_password, created_at)
            VALUES ('superadmin','Administrador Master','admoorienta@gmail.com',?,
                    'Orienta One','admin',1,0,'2026-01-01T00:00:00.000Z')
        """, (hash_password("orienta2810"),))
    db.commit()
    db.close()

def hash_password(pwd: str) -> str:
    return hashlib.sha256(pwd.encode()).hexdigest()

# ── JWT simples ────────────────────────────────────────────────────────────────
import hmac, base64

def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _unb64(s):
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * (pad % 4))

def make_token(payload: dict) -> str:
    header = _b64(json.dumps({"alg":"HS256","typ":"JWT"}).encode())
    body = _b64(json.dumps(payload).encode())
    sig = _b64(hmac.new(SECRET_KEY.encode(), f"{header}.{body}".encode(), "sha256").digest())
    return f"{header}.{body}.{sig}"

def verify_token(token: str):
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header, body, sig = parts
        expected = _b64(hmac.new(SECRET_KEY.encode(), f"{header}.{body}".encode(), "sha256").digest())
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(_unb64(body))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None

def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        token = auth.replace("Bearer ", "")
        payload = verify_token(token)
        if not payload:
            return jsonify({"error": "Não autorizado"}), 401
        g.current_user = payload
        return f(*args, **kwargs)
    return wrapper

def require_super_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not g.current_user.get("isSuperAdmin"):
            return jsonify({"error": "Acesso negado"}), 403
        return f(*args, **kwargs)
    return require_auth(wrapper)

def uid():
    return str(uuid.uuid4())

def now_iso():
    import datetime
    return datetime.datetime.utcnow().isoformat() + "Z"

# ── Auth routes ────────────────────────────────────────────────────────────────
@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.json or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE lower(email)=?", (email,)).fetchone()
    if not user or user["password_hash"] != hash_password(password):
        return jsonify({"error": "Credenciais inválidas"}), 401
    exp = int(time.time()) + 8 * 3600
    payload = {
        "sub": user["id"],
        "name": user["name"],
        "email": user["email"],
        "company": user["company"],
        "role": user["role"],
        "isSuperAdmin": bool(user["is_super_admin"]),
        "mustChangePassword": bool(user["must_change_password"]),
        "exp": exp,
    }
    token = make_token(payload)
    return jsonify({
        "token": token,
        "user": {k: v for k, v in payload.items() if k not in ("exp",)}
    })

@app.route("/api/auth/change-password", methods=["POST"])
@require_auth
def change_password():
    data = request.json or {}
    user_id = g.current_user["sub"]
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        return jsonify({"error": "not_found"}), 404
    if user["password_hash"] != hash_password(data.get("currentPassword", "")):
        return jsonify({"error": "wrong_password"}), 400
    db.execute("UPDATE users SET password_hash=?, must_change_password=0 WHERE id=?",
               (hash_password(data["newPassword"]), user_id))
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/auth/reset-password-by-email", methods=["POST"])
def reset_password_by_email():
    data = request.json or {}
    email = data.get("email", "").strip().lower()
    new_password = data.get("newPassword", "")
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE lower(email)=? AND is_super_admin=0", (email,)).fetchone()
    if not user:
        return jsonify({"error": "not_found"}), 404
    db.execute("UPDATE users SET password_hash=?, must_change_password=1 WHERE id=?",
               (hash_password(new_password), user["id"]))
    db.commit()
    return jsonify({"ok": True})

# ── User management (super admin) ──────────────────────────────────────────────
@app.route("/api/users", methods=["GET"])
@require_auth
def list_users():
    if not g.current_user.get("isSuperAdmin"):
        return jsonify({"error": "Acesso negado"}), 403
    db = get_db()
    rows = db.execute("SELECT id,name,email,company,role,is_super_admin,must_change_password,created_at FROM users WHERE is_super_admin=0").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/users", methods=["POST"])
@require_auth
def create_user():
    if not g.current_user.get("isSuperAdmin"):
        return jsonify({"error": "Acesso negado"}), 403
    data = request.json or {}
    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE lower(email)=?", (data["email"].lower(),)).fetchone()
    if existing:
        return jsonify({"error": "duplicate"}), 409
    new_id = uid()
    db.execute("""
        INSERT INTO users (id,name,email,password_hash,company,role,is_super_admin,must_change_password,created_at)
        VALUES (?,?,?,?,?,'user',0,1,?)
    """, (new_id, data["name"], data["email"], hash_password(data["password"]), data["company"], now_iso()))
    db.commit()
    return jsonify({"id": new_id, "name": data["name"], "email": data["email"], "company": data["company"]})

@app.route("/api/users/<user_id>/reset-password", methods=["POST"])
@require_auth
def reset_user_password(user_id):
    if not g.current_user.get("isSuperAdmin"):
        return jsonify({"error": "Acesso negado"}), 403
    data = request.json or {}
    db = get_db()
    db.execute("UPDATE users SET password_hash=?, must_change_password=1 WHERE id=? AND is_super_admin=0",
               (hash_password(data["newPassword"]), user_id))
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/users/<user_id>", methods=["DELETE"])
@require_auth
def delete_user(user_id):
    if not g.current_user.get("isSuperAdmin"):
        return jsonify({"error": "Acesso negado"}), 403
    db = get_db()
    db.execute("DELETE FROM users WHERE id=? AND is_super_admin=0", (user_id,))
    db.commit()
    return jsonify({"ok": True})

# ── Receitas ───────────────────────────────────────────────────────────────────
@app.route("/api/receitas", methods=["GET"])
@require_auth
def get_receitas():
    user_id = g.current_user["sub"]
    db = get_db()
    rows = db.execute("SELECT * FROM receitas WHERE user_id=? ORDER BY data DESC", (user_id,)).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["pagamentos"] = json.loads(d["pagamentos"] or "[]")
        result.append(d)
    return jsonify(result)

@app.route("/api/receitas", methods=["POST"])
@require_auth
def save_receita():
    user_id = g.current_user["sub"]
    data = request.json or {}
    db = get_db()
    rec_id = data.get("id") or uid()
    existing = db.execute("SELECT id FROM receitas WHERE id=? AND user_id=?", (rec_id, user_id)).fetchone()
    pagamentos = json.dumps(data.get("pagamentos", []))
    if existing:
        db.execute("""UPDATE receitas SET descricao=?,valor=?,data=?,turno=?,pagamentos=?,categoria=?,observacoes=?
                      WHERE id=? AND user_id=?""",
                   (data["descricao"], data["valor"], data["data"], data.get("turno","Manhã"),
                    pagamentos, data.get("categoria",""), data.get("observacoes"), rec_id, user_id))
    else:
        db.execute("""INSERT INTO receitas (id,descricao,valor,data,turno,pagamentos,categoria,observacoes,user_id,created_at)
                      VALUES (?,?,?,?,?,?,?,?,?,?)""",
                   (rec_id, data["descricao"], data["valor"], data["data"], data.get("turno","Manhã"),
                    pagamentos, data.get("categoria",""), data.get("observacoes"), user_id, now_iso()))
    db.commit()
    return jsonify({"id": rec_id})

@app.route("/api/receitas/<rec_id>", methods=["DELETE"])
@require_auth
def delete_receita(rec_id):
    user_id = g.current_user["sub"]
    db = get_db()
    db.execute("DELETE FROM receitas WHERE id=? AND user_id=?", (rec_id, user_id))
    db.commit()
    return jsonify({"ok": True})

# ── Despesas ───────────────────────────────────────────────────────────────────
@app.route("/api/despesas", methods=["GET"])
@require_auth
def get_despesas():
    user_id = g.current_user["sub"]
    db = get_db()
    rows = db.execute("SELECT * FROM despesas WHERE user_id=? ORDER BY data DESC", (user_id,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/despesas", methods=["POST"])
@require_auth
def save_despesa():
    user_id = g.current_user["sub"]
    data = request.json or {}
    db = get_db()
    desp_id = data.get("id") or uid()
    existing = db.execute("SELECT id FROM despesas WHERE id=? AND user_id=?", (desp_id, user_id)).fetchone()
    if existing:
        db.execute("""UPDATE despesas SET descricao=?,valor=?,data=?,subcategoria=?,categoria=?,
                      recorrente=?,observacoes=?,funcionario_id=? WHERE id=? AND user_id=?""",
                   (data["descricao"], data["valor"], data["data"], data.get("subcategoria","Despesas Gerais"),
                    data.get("categoria",""), int(data.get("recorrente",False)), data.get("observacoes"),
                    data.get("funcionarioId"), desp_id, user_id))
    else:
        db.execute("""INSERT INTO despesas (id,descricao,valor,data,subcategoria,categoria,recorrente,observacoes,funcionario_id,user_id,created_at)
                      VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                   (desp_id, data["descricao"], data["valor"], data["data"],
                    data.get("subcategoria","Despesas Gerais"), data.get("categoria",""),
                    int(data.get("recorrente",False)), data.get("observacoes"),
                    data.get("funcionarioId"), user_id, now_iso()))
    db.commit()
    return jsonify({"id": desp_id})

@app.route("/api/despesas/<desp_id>", methods=["DELETE"])
@require_auth
def delete_despesa(desp_id):
    user_id = g.current_user["sub"]
    db = get_db()
    db.execute("DELETE FROM despesas WHERE id=? AND user_id=?", (desp_id, user_id))
    db.commit()
    return jsonify({"ok": True})

# ── Funcionários ───────────────────────────────────────────────────────────────
@app.route("/api/funcionarios", methods=["GET"])
@require_auth
def get_funcionarios():
    user_id = g.current_user["sub"]
    db = get_db()
    rows = db.execute("SELECT * FROM funcionarios WHERE user_id=? ORDER BY nome", (user_id,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/funcionarios", methods=["POST"])
@require_auth
def save_funcionario():
    user_id = g.current_user["sub"]
    data = request.json or {}
    db = get_db()
    func_id = data.get("id") or uid()
    existing = db.execute("SELECT id FROM funcionarios WHERE id=? AND user_id=?", (func_id, user_id)).fetchone()
    if existing:
        db.execute("""UPDATE funcionarios SET nome=?,cargo=?,frequencia=?,tipo_valor=?,valor=?,
                      dia_pagamento=?,ativo=? WHERE id=? AND user_id=?""",
                   (data["nome"], data["cargo"], data.get("frequencia","mensal"), data.get("tipoValor","fixo"),
                    data["valor"], data.get("diaPagamento",1), int(data.get("ativo",True)), func_id, user_id))
    else:
        db.execute("""INSERT INTO funcionarios (id,nome,cargo,frequencia,tipo_valor,valor,dia_pagamento,ativo,user_id,created_at)
                      VALUES (?,?,?,?,?,?,?,?,?,?)""",
                   (func_id, data["nome"], data["cargo"], data.get("frequencia","mensal"),
                    data.get("tipoValor","fixo"), data["valor"], data.get("diaPagamento",1),
                    int(data.get("ativo",True)), user_id, now_iso()))
    db.commit()
    return jsonify({"id": func_id})

@app.route("/api/funcionarios/<func_id>", methods=["DELETE"])
@require_auth
def delete_funcionario(func_id):
    user_id = g.current_user["sub"]
    db = get_db()
    db.execute("DELETE FROM funcionarios WHERE id=? AND user_id=?", (func_id, user_id))
    db.commit()
    return jsonify({"ok": True})

# ── Despesas Fixas Recorrentes ─────────────────────────────────────────────────
@app.route("/api/despesas-fixas", methods=["GET"])
@require_auth
def get_despesas_fixas():
    user_id = g.current_user["sub"]
    db = get_db()
    rows = db.execute("SELECT * FROM despesas_fixas_rec WHERE user_id=?", (user_id,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/despesas-fixas", methods=["POST"])
@require_auth
def save_despesa_fixa():
    user_id = g.current_user["sub"]
    data = request.json or {}
    db = get_db()
    fix_id = data.get("id") or uid()
    existing = db.execute("SELECT id FROM despesas_fixas_rec WHERE id=? AND user_id=?", (fix_id, user_id)).fetchone()
    if existing:
        db.execute("""UPDATE despesas_fixas_rec SET descricao=?,valor=?,dia_pagamento=?,categoria=?,ativa=?
                      WHERE id=? AND user_id=?""",
                   (data["descricao"], data["valor"], data["diaPagamento"], data.get("categoria",""),
                    int(data.get("ativa",True)), fix_id, user_id))
    else:
        db.execute("""INSERT INTO despesas_fixas_rec (id,descricao,valor,dia_pagamento,categoria,ativa,user_id,created_at)
                      VALUES (?,?,?,?,?,?,?,?)""",
                   (fix_id, data["descricao"], data["valor"], data["diaPagamento"],
                    data.get("categoria",""), int(data.get("ativa",True)), user_id, now_iso()))
    db.commit()
    return jsonify({"id": fix_id})

@app.route("/api/despesas-fixas/<fix_id>", methods=["DELETE"])
@require_auth
def delete_despesa_fixa(fix_id):
    user_id = g.current_user["sub"]
    db = get_db()
    db.execute("DELETE FROM despesas_fixas_rec WHERE id=? AND user_id=?", (fix_id, user_id))
    db.commit()
    return jsonify({"ok": True})

# ── Pagamentos automáticos ─────────────────────────────────────────────────────
@app.route("/api/pagamentos-automaticos", methods=["POST"])
@require_auth
def processar_pagamentos_automaticos():
    import datetime
    user_id = g.current_user["sub"]
    db = get_db()
    hoje = datetime.date.today()
    ano = hoje.year
    mes = hoje.month
    dia = hoje.day
    criados = 0

    def pad(n): return str(n).zfill(2)
    def iso_week(d):
        return d.isocalendar()[1]
    def dia_semana_iso(d):
        return d.isoweekday()  # 1=Mon..7=Sun

    funcionarios = db.execute(
        "SELECT * FROM funcionarios WHERE user_id=? AND ativo=1 AND tipo_valor='fixo'", (user_id,)
    ).fetchall()

    for f in funcionarios:
        if f["frequencia"] == "mensal":
            chave = f"{f['id']}-{ano}-{pad(mes)}"
            if dia >= f["dia_pagamento"]:
                exists = db.execute("SELECT 1 FROM pagamentos_processados WHERE chave=? AND user_id=?",
                                    (chave, user_id)).fetchone()
                if not exists:
                    import calendar
                    last_day = calendar.monthrange(ano, mes)[1]
                    d_str = f"{ano}-{pad(mes)}-{pad(min(f['dia_pagamento'], last_day))}"
                    desp_id = uid()
                    db.execute("""INSERT INTO despesas (id,descricao,valor,data,subcategoria,categoria,recorrente,observacoes,funcionario_id,user_id,created_at)
                                  VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                               (desp_id, f"Salário — {f['nome']}", f["valor"], d_str,
                                "Tabela Salarial", "Salário Base", 0,
                                f"Lançamento automático · {f['cargo']}", f["id"], user_id, now_iso()))
                    db.execute("INSERT INTO pagamentos_processados VALUES (?,?)", (chave, user_id))
                    criados += 1
        else:
            semana = iso_week(hoje)
            chave = f"{f['id']}-{ano}-W{pad(semana)}"
            if dia_semana_iso(hoje) == f["dia_pagamento"]:
                exists = db.execute("SELECT 1 FROM pagamentos_processados WHERE chave=? AND user_id=?",
                                    (chave, user_id)).fetchone()
                if not exists:
                    desp_id = uid()
                    db.execute("""INSERT INTO despesas (id,descricao,valor,data,subcategoria,categoria,recorrente,observacoes,funcionario_id,user_id,created_at)
                                  VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                               (desp_id, f"Pagamento Semanal — {f['nome']}", f["valor"],
                                str(hoje), "Tabela Salarial", "Salário Base", 0,
                                f"Lançamento automático semanal · {f['cargo']}", f["id"], user_id, now_iso()))
                    db.execute("INSERT INTO pagamentos_processados VALUES (?,?)", (chave, user_id))
                    criados += 1

    fixas = db.execute("SELECT * FROM despesas_fixas_rec WHERE user_id=? AND ativa=1", (user_id,)).fetchall()
    for r in fixas:
        chave = f"fix-{r['id']}-{ano}-{pad(mes)}"
        if dia >= r["dia_pagamento"]:
            exists = db.execute("SELECT 1 FROM pagamentos_processados WHERE chave=? AND user_id=?",
                                (chave, user_id)).fetchone()
            if not exists:
                import calendar
                last_day = calendar.monthrange(ano, mes)[1]
                d_str = f"{ano}-{pad(mes)}-{pad(min(r['dia_pagamento'], last_day))}"
                desp_id = uid()
                db.execute("""INSERT INTO despesas (id,descricao,valor,data,subcategoria,categoria,recorrente,observacoes,funcionario_id,user_id,created_at)
                              VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                           (desp_id, r["descricao"], r["valor"], d_str,
                            "Despesas Fixas", r["categoria"], 0,
                            "Lançamento automático (despesa fixa)", None, user_id, now_iso()))
                db.execute("INSERT INTO pagamentos_processados VALUES (?,?)", (chave, user_id))
                criados += 1

    db.commit()
    return jsonify({"criados": criados})

# ── Notificações ───────────────────────────────────────────────────────────────
@app.route("/api/notificacoes", methods=["GET"])
@require_auth
def get_notificacoes():
    user_id = g.current_user["sub"]
    db = get_db()
    rows = db.execute("SELECT * FROM notificacoes WHERE user_id=?", (user_id,)).fetchall()
    if not rows:
        defaults = [
            (uid(), "Conta de Luz", 10, 1),
            (uid(), "Conta de Água", 15, 1),
            (uid(), "Internet", 20, 1),
            (uid(), "Aluguel", 5, 1),
        ]
        for d in defaults:
            db.execute("INSERT INTO notificacoes VALUES (?,?,?,?,?)", (*d, user_id))
        db.commit()
        rows = db.execute("SELECT * FROM notificacoes WHERE user_id=?", (user_id,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/notificacoes", methods=["POST"])
@require_auth
def save_notificacao():
    user_id = g.current_user["sub"]
    data = request.json or {}
    db = get_db()
    notif_id = data.get("id") or uid()
    existing = db.execute("SELECT id FROM notificacoes WHERE id=? AND user_id=?", (notif_id, user_id)).fetchone()
    if existing:
        db.execute("UPDATE notificacoes SET descricao=?,dia_vencimento=?,ativa=? WHERE id=? AND user_id=?",
                   (data["descricao"], data["diaVencimento"], int(data.get("ativa",True)), notif_id, user_id))
    else:
        db.execute("INSERT INTO notificacoes VALUES (?,?,?,?,?)",
                   (notif_id, data["descricao"], data["diaVencimento"], int(data.get("ativa",True)), user_id))
    db.commit()
    return jsonify({"id": notif_id})

@app.route("/api/notificacoes/<notif_id>", methods=["DELETE"])
@require_auth
def delete_notificacao(notif_id):
    user_id = g.current_user["sub"]
    db = get_db()
    db.execute("DELETE FROM notificacoes WHERE id=? AND user_id=?", (notif_id, user_id))
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/notificacoes/pendentes", methods=["GET"])
@require_auth
def get_notificacoes_pendentes():
    import datetime
    user_id = g.current_user["sub"]
    db = get_db()
    mes_atual = datetime.date.today().strftime("%Y-%m")
    notificacoes = db.execute("SELECT * FROM notificacoes WHERE user_id=? AND ativa=1", (user_id,)).fetchall()
    despesas = db.execute("SELECT * FROM despesas WHERE user_id=? AND data LIKE ?", (user_id, f"{mes_atual}%")).fetchall()
    pendentes = []
    for n in notificacoes:
        found = any(
            d["subcategoria"] == "Despesas Recorrentes" and
            n["descricao"].lower() in d["descricao"].lower()
            for d in despesas
        )
        if not found:
            pendentes.append(dict(n))
    return jsonify(pendentes)

# ── Configurações ──────────────────────────────────────────────────────────────
@app.route("/api/configuracoes", methods=["GET"])
@require_auth
def get_configuracoes():
    user_id = g.current_user["sub"]
    db = get_db()
    row = db.execute("SELECT * FROM configuracoes WHERE user_id=?", (user_id,)).fetchone()
    if not row:
        db.execute("INSERT INTO configuracoes VALUES (?,?,?,?,?)",
                   (user_id, "Minha Empresa", "", "", 0))
        db.commit()
        return jsonify({"nomeEmpresa": "Minha Empresa", "cnpj": "", "segmento": "", "metaMensal": 0})
    return jsonify({
        "nomeEmpresa": row["nome_empresa"],
        "cnpj": row["cnpj"],
        "segmento": row["segmento"],
        "metaMensal": row["meta_mensal"],
    })

@app.route("/api/configuracoes", methods=["POST"])
@require_auth
def save_configuracoes():
    user_id = g.current_user["sub"]
    data = request.json or {}
    db = get_db()
    db.execute("""INSERT INTO configuracoes (user_id,nome_empresa,cnpj,segmento,meta_mensal)
                  VALUES (?,?,?,?,?)
                  ON CONFLICT(user_id) DO UPDATE SET
                  nome_empresa=excluded.nome_empresa,
                  cnpj=excluded.cnpj,
                  segmento=excluded.segmento,
                  meta_mensal=excluded.meta_mensal""",
               (user_id, data.get("nomeEmpresa","Minha Empresa"),
                data.get("cnpj",""), data.get("segmento",""), data.get("metaMensal",0)))
    db.commit()
    return jsonify({"ok": True})

# ── Slots e Agendamentos de Consultoria ───────────────────────────────────────
@app.route("/api/slots-consultoria", methods=["GET"])
@require_auth
def get_slots():
    db = get_db()
    rows = db.execute("SELECT * FROM slots_consultoria ORDER BY data, horario").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/slots-consultoria", methods=["POST"])
@require_auth
def save_slot():
    if not g.current_user.get("isSuperAdmin"):
        return jsonify({"error": "Acesso negado"}), 403
    data = request.json or {}
    db = get_db()
    slot_id = data.get("id") or uid()
    existing = db.execute("SELECT id FROM slots_consultoria WHERE id=?", (slot_id,)).fetchone()
    if existing:
        db.execute("UPDATE slots_consultoria SET data=?,horario=?,mes=? WHERE id=?",
                   (data["data"], data["horario"], data["mes"], slot_id))
    else:
        db.execute("INSERT INTO slots_consultoria VALUES (?,?,?,?,?,?)",
                   (slot_id, data["data"], data["horario"], data["mes"], now_iso(), g.current_user["sub"]))
    db.commit()
    return jsonify({"id": slot_id})

@app.route("/api/slots-consultoria/<slot_id>", methods=["DELETE"])
@require_auth
def delete_slot(slot_id):
    if not g.current_user.get("isSuperAdmin"):
        return jsonify({"error": "Acesso negado"}), 403
    db = get_db()
    db.execute("DELETE FROM slots_consultoria WHERE id=?", (slot_id,))
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/agendamentos-consultoria", methods=["GET"])
@require_auth
def get_agendamentos():
    db = get_db()
    if g.current_user.get("isSuperAdmin"):
        rows = db.execute("SELECT * FROM agendamentos_consultoria ORDER BY criado_em DESC").fetchall()
    else:
        rows = db.execute("SELECT * FROM agendamentos_consultoria WHERE user_id=? ORDER BY criado_em DESC",
                          (g.current_user["sub"],)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/agendamentos-consultoria", methods=["POST"])
@require_auth
def save_agendamento():
    data = request.json or {}
    db = get_db()
    ag_id = data.get("id") or uid()
    user = g.current_user
    existing = db.execute("SELECT id FROM agendamentos_consultoria WHERE id=?", (ag_id,)).fetchone()
    if existing:
        if user.get("isSuperAdmin"):
            db.execute("""UPDATE agendamentos_consultoria SET status=?,respondido_em=?,motivo_negacao=?
                          WHERE id=?""",
                       (data.get("status","solicitado"), data.get("respondidoEm"), data.get("motivoNegacao"), ag_id))
        else:
            return jsonify({"error": "Sem permissão"}), 403
    else:
        slot = db.execute("SELECT * FROM slots_consultoria WHERE id=?", (data["slotId"],)).fetchone()
        if not slot:
            return jsonify({"error": "Slot não encontrado"}), 404
        db.execute("""INSERT INTO agendamentos_consultoria
                      (id,slot_id,slot_data,slot_horario,mes,user_id,user_name,user_email,user_company,status,criado_em)
                      VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                   (ag_id, data["slotId"], slot["data"], slot["horario"], data["mes"],
                    user["sub"], user["name"], user["email"], user["company"], "solicitado", now_iso()))
    db.commit()
    return jsonify({"id": ag_id})

# ── Relatórios Empresariais ────────────────────────────────────────────────────
@app.route("/api/relatorios", methods=["GET"])
@require_auth
def get_relatorios():
    user_id = g.current_user["sub"]
    is_admin = g.current_user.get("isSuperAdmin")
    db = get_db()
    if is_admin:
        rows = db.execute("SELECT * FROM relatorios_empresariais ORDER BY atualizado_em DESC").fetchall()
    else:
        rows = db.execute("SELECT * FROM relatorios_empresariais WHERE user_id=? ORDER BY atualizado_em DESC",
                          (user_id,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/relatorios", methods=["POST"])
@require_auth
def save_relatorio():
    user_id = g.current_user["sub"]
    data = request.json or {}
    db = get_db()
    rel_id = data.get("id") or uid()
    existing = db.execute("SELECT id FROM relatorios_empresariais WHERE id=?", (rel_id,)).fetchone()
    if existing:
        db.execute("UPDATE relatorios_empresariais SET titulo=?,conteudo=?,atualizado_em=? WHERE id=?",
                   (data["titulo"], data["conteudo"], now_iso(), rel_id))
    else:
        db.execute("INSERT INTO relatorios_empresariais VALUES (?,?,?,?,?)",
                   (rel_id, data["titulo"], data["conteudo"], now_iso(), user_id))
    db.commit()
    return jsonify({"id": rel_id})

@app.route("/api/relatorios/<rel_id>", methods=["DELETE"])
@require_auth
def delete_relatorio(rel_id):
    user_id = g.current_user["sub"]
    db = get_db()
    if g.current_user.get("isSuperAdmin"):
        db.execute("DELETE FROM relatorios_empresariais WHERE id=?", (rel_id,))
    else:
        db.execute("DELETE FROM relatorios_empresariais WHERE id=? AND user_id=?", (rel_id, user_id))
    db.commit()
    return jsonify({"ok": True})

# ── Assinaturas Mensais ────────────────────────────────────────────────────
@app.route("/api/assinaturas", methods=["GET"])
@require_auth
def get_assinaturas():
    user_id = g.current_user["sub"]
    db = get_db()
    rows = db.execute("SELECT * FROM assinaturas WHERE user_id=? ORDER BY data_proxima_cobranca ASC", (user_id,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/assinaturas", methods=["POST"])
@require_auth
def save_assinatura():
    user_id = g.current_user["sub"]
    data = request.json or {}
    db = get_db()
    ass_id = data.get("id") or uid()
    existing = db.execute("SELECT id FROM assinaturas WHERE id=? AND user_id=?", (ass_id, user_id)).fetchone()
    if existing:
        db.execute("""UPDATE assinaturas SET nome_cliente=?,email_cliente=?,plano_nome=?,valor_mensal=?,
                      data_inicio=?,data_proxima_cobranca=?,status=?,observacoes=? WHERE id=? AND user_id=?""",
                   (data["nomeCliente"], data.get("emailCliente"), data["planome"], data["valorMensal"],
                    data["dataInicio"], data["dataProximaCobranca"], data.get("status","ativa"), 
                    data.get("observacoes"), ass_id, user_id))
    else:
        db.execute("""INSERT INTO assinaturas (id,nome_cliente,email_cliente,plano_nome,valor_mensal,
                      data_inicio,data_proxima_cobranca,status,observacoes,user_id,created_at)
                      VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                   (ass_id, data["nomeCliente"], data.get("emailCliente"), data["planome"],
                    data["valorMensal"], data["dataInicio"], data["dataProximaCobranca"],
                    data.get("status","ativa"), data.get("observacoes"), user_id, now_iso()))
    db.commit()
    return jsonify({"id": ass_id})

@app.route("/api/assinaturas/<ass_id>", methods=["DELETE"])
@require_auth
def delete_assinatura(ass_id):
    user_id = g.current_user["sub"]
    db = get_db()
    db.execute("DELETE FROM assinaturas WHERE id=? AND user_id=?", (ass_id, user_id))
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/assinaturas/proximas-cobrancas", methods=["GET"])
@require_auth
def get_proximas_cobrancas():
    import datetime
    user_id = g.current_user["sub"]
    db = get_db()
    hoje = datetime.date.today()
    fim_mes = (hoje.replace(day=1) + datetime.timedelta(days=32)).replace(day=1) - datetime.timedelta(days=1)
    
    rows = db.execute("""SELECT * FROM assinaturas 
                         WHERE user_id=? AND status='ativa' 
                         AND data_proxima_cobranca >= ? AND data_proxima_cobranca <= ?
                         ORDER BY data_proxima_cobranca ASC""",
                      (user_id, str(hoje), str(fim_mes))).fetchall()
    return jsonify([dict(r) for r in rows])

# ── Serve frontend (SPA) ───────────────────────────────────────────────────────
@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_spa(path):
    dist = os.path.join(os.path.dirname(__file__), "dist")
    full = os.path.join(dist, path)
    if path and os.path.exists(full):
        return send_from_directory(dist, path)
    return send_from_directory(dist, "index.html")

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    print(f"🚀 Servidor iniciado em http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
