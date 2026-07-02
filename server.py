"""Financial Management Platform - Backend CORRIGIDO"""
import sqlite3, json, uuid, hashlib, time, os, hmac, base64
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify, g, send_from_directory

app = Flask(__name__, static_folder="dist", static_url_path="")
SECRET_KEY = "orienta-fin-secret-2026"
DB_PATH = "financeiro.db"

print(f"\n📁 Banco: {DB_PATH}")

# ════════════════════════════════════════════════════════════════════════
# INICIALIZAR BANCO
# ════════════════════════════════════════════════════════════════════════

def init_db():
    """Criar banco e tabelas - CERTEZA que funciona"""
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    c = db.cursor()
    
    try:
        # Usuários
        c.execute("""CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            company TEXT,
            is_super_admin INTEGER DEFAULT 0,
            created_at TEXT
        )""")
        
        # Receitas
        c.execute("""CREATE TABLE IF NOT EXISTS receitas (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            descricao TEXT NOT NULL,
            valor REAL NOT NULL,
            data TEXT NOT NULL,
            turno TEXT,
            pagamentos TEXT,
            categoria TEXT,
            observacoes TEXT,
            created_at TEXT
        )""")
        
        # Despesas
        c.execute("""CREATE TABLE IF NOT EXISTS despesas (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            descricao TEXT NOT NULL,
            valor REAL NOT NULL,
            data TEXT NOT NULL,
            subcategoria TEXT,
            categoria TEXT,
            recorrente INTEGER,
            observacoes TEXT,
            created_at TEXT
        )""")
        
        # Funcionários
        c.execute("""CREATE TABLE IF NOT EXISTS funcionarios (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            nome TEXT NOT NULL,
            cargo TEXT NOT NULL,
            frequencia TEXT,
            tipo_valor TEXT,
            valor REAL,
            dia_pagamento INTEGER,
            ativo INTEGER,
            created_at TEXT
        )""")
        
        # Despesas Fixas
        c.execute("""CREATE TABLE IF NOT EXISTS despesas_fixas_rec (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            descricao TEXT NOT NULL,
            valor REAL NOT NULL,
            dia_pagamento INTEGER,
            categoria TEXT,
            ativa INTEGER,
            created_at TEXT
        )""")
        
        # Assinaturas
        c.execute("""CREATE TABLE IF NOT EXISTS assinaturas (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            nome_cliente TEXT NOT NULL,
            email_cliente TEXT,
            plano_nome TEXT,
            valor_mensal REAL,
            data_inicio TEXT,
            data_proxima_cobranca TEXT,
            status TEXT,
            observacoes TEXT,
            created_at TEXT
        )""")
        
        # Configurações
        c.execute("""CREATE TABLE IF NOT EXISTS configuracoes (
            user_id TEXT PRIMARY KEY,
            nome_empresa TEXT,
            cnpj TEXT,
            segmento TEXT,
            meta_mensal REAL
        )""")
        
        # Criar super admin se não existir
        existing = c.execute("SELECT id FROM users WHERE email='admoorienta@gmail.com'").fetchone()
        if not existing:
            admin_id = str(uuid.uuid4())
            pwd = hashlib.sha256("orienta2810".encode()).hexdigest()
            c.execute("""INSERT INTO users VALUES (?,?,?,?,?,?,?)""",
                     (admin_id, "Admin", "admoorienta@gmail.com", pwd, "Orienta", 1, datetime.utcnow().isoformat()))
            print("✅ Super admin criado")
        
        db.commit()
        db.close()
        print("✅ Banco inicializado\n")
        return True
    except Exception as e:
        print(f"❌ Erro ao inicializar: {e}")
        return False

# ════════════════════════════════════════════════════════════════════════
# CONEXÃO BANCO
# ════════════════════════════════════════════════════════════════════════

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

# ════════════════════════════════════════════════════════════════════════
# CORS
# ════════════════════════════════════════════════════════════════════════

@app.after_request
def cors(r):
    r.headers["Access-Control-Allow-Origin"] = "*"
    r.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    r.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return r

@app.route("/api/<p>", methods=["OPTIONS"])
def opts(p=""):
    return "", 204

# ════════════════════════════════════════════════════════════════════════
# JWT
# ════════════════════════════════════════════════════════════════════════

def make_token(payload):
    h = base64.urlsafe_b64encode(json.dumps({"alg":"HS256","typ":"JWT"}).encode()).rstrip(b"=").decode()
    b = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    s = base64.urlsafe_b64encode(hmac.new(SECRET_KEY.encode(), f"{h}.{b}".encode(), "sha256").digest()).rstrip(b"=").decode()
    return f"{h}.{b}.{s}"

def verify_token(token):
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        h, b, s = parts
        exp_s = base64.urlsafe_b64encode(hmac.new(SECRET_KEY.encode(), f"{h}.{b}".encode(), "sha256").digest()).rstrip(b"=").decode()
        if not hmac.compare_digest(s, exp_s):
            return None
        payload = json.loads(base64.urlsafe_b64decode(b + "==="))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except:
        return None

def require_auth(f):
    @wraps(f)
    def w(*a, **kw):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        payload = verify_token(token)
        if not payload:
            return jsonify({"error": "Não autorizado"}), 401
        g.current_user = payload
        return f(*a, **kw)
    return w

# ════════════════════════════════════════════════════════════════════════
# AUTH
# ════════════════════════════════════════════════════════════════════════

@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.json or {}
    email = data.get("email", "").lower()
    pwd = data.get("password", "")
    
    if not email or not pwd:
        return jsonify({"error": "Email e senha obrigatórios"}), 400
    
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE lower(email)=?", (email,)).fetchone()
    
    if not user:
        return jsonify({"error": "Email não encontrado"}), 401
    
    pwd_hash = hashlib.sha256(pwd.encode()).hexdigest()
    if user["password_hash"] != pwd_hash:
        return jsonify({"error": "Senha incorreta"}), 401
    
    exp = int(time.time()) + 28800
    payload = {
        "sub": user["id"],
        "name": user["name"],
        "email": user["email"],
        "company": user["company"],
        "isSuperAdmin": bool(user["is_super_admin"]),
        "exp": exp
    }
    
    print(f"✅ Login: {email}")
    return jsonify({"token": make_token(payload), "user": {k:v for k,v in payload.items() if k!="exp"}})

# ════════════════════════════════════════════════════════════════════════
# RECEITAS
# ════════════════════════════════════════════════════════════════════════

@app.route("/api/receitas", methods=["GET"])
@require_auth
def get_receitas():
    uid = g.current_user["sub"]
    db = get_db()
    rows = db.execute("SELECT * FROM receitas WHERE user_id=? ORDER BY data DESC", (uid,)).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["pagamentos"] = json.loads(d["pagamentos"] or "[]")
        result.append(d)
    return jsonify(result)

@app.route("/api/receitas", methods=["POST"])
@require_auth
def save_receita():
    uid = g.current_user["sub"]
    data = request.json or {}
    
    if not data.get("descricao") or not data.get("valor"):
        return jsonify({"error": "Descricao e valor obrigatórios"}), 400
    
    db = get_db()
    rid = data.get("id") or str(uuid.uuid4())
    
    try:
        valor = float(data.get("valor"))
    except:
        return jsonify({"error": "Valor inválido"}), 400
    
    pagtos = json.dumps(data.get("pagamentos", []))
    
    # Verificar se existe
    existing = db.execute("SELECT id FROM receitas WHERE id=? AND user_id=?", (rid, uid)).fetchone()
    
    if existing:
        db.execute("""UPDATE receitas SET descricao=?, valor=?, data=?, turno=?, pagamentos=?, categoria=?, observacoes=?
                      WHERE id=? AND user_id=?""",
                  (data.get("descricao"), valor, data.get("data"), data.get("turno", "Manhã"),
                   pagtos, data.get("categoria", ""), data.get("observacoes"), rid, uid))
    else:
        db.execute("""INSERT INTO receitas VALUES (?,?,?,?,?,?,?,?,?,?)""",
                  (rid, uid, data.get("descricao"), valor, data.get("data"),
                   data.get("turno", "Manhã"), pagtos, data.get("categoria", ""),
                   data.get("observacoes"), datetime.utcnow().isoformat()))
    
    db.commit()
    print(f"✅ Receita salva: {rid} - R${valor}")
    return jsonify({"id": rid})

@app.route("/api/receitas/<rid>", methods=["DELETE"])
@require_auth
def del_receita(rid):
    uid = g.current_user["sub"]
    db = get_db()
    db.execute("DELETE FROM receitas WHERE id=? AND user_id=?", (rid, uid))
    db.commit()
    print(f"✅ Receita deletada: {rid}")
    return jsonify({"ok": True})

# ════════════════════════════════════════════════════════════════════════
# DESPESAS
# ════════════════════════════════════════════════════════════════════════

@app.route("/api/despesas", methods=["GET"])
@require_auth
def get_despesas():
    uid = g.current_user["sub"]
    db = get_db()
    rows = db.execute("SELECT * FROM despesas WHERE user_id=? ORDER BY data DESC", (uid,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/despesas", methods=["POST"])
@require_auth
def save_despesa():
    uid = g.current_user["sub"]
    data = request.json or {}
    
    if not data.get("descricao") or not data.get("valor"):
        return jsonify({"error": "Descricao e valor obrigatórios"}), 400
    
    db = get_db()
    did = data.get("id") or str(uuid.uuid4())
    
    try:
        valor = float(data.get("valor"))
    except:
        return jsonify({"error": "Valor inválido"}), 400
    
    # Verificar se existe
    existing = db.execute("SELECT id FROM despesas WHERE id=? AND user_id=?", (did, uid)).fetchone()
    
    if existing:
        db.execute("""UPDATE despesas SET descricao=?, valor=?, data=?, subcategoria=?, categoria=?, recorrente=?, observacoes=?
                      WHERE id=? AND user_id=?""",
                  (data.get("descricao"), valor, data.get("data"),
                   data.get("subcategoria", "Despesas Gerais"), data.get("categoria", ""),
                   int(data.get("recorrente", 0)), data.get("observacoes"), did, uid))
    else:
        db.execute("""INSERT INTO despesas VALUES (?,?,?,?,?,?,?,?,?,?)""",
                  (did, uid, data.get("descricao"), valor, data.get("data"),
                   data.get("subcategoria", "Despesas Gerais"), data.get("categoria", ""),
                   int(data.get("recorrente", 0)), data.get("observacoes"),
                   datetime.utcnow().isoformat()))
    
    db.commit()
    print(f"✅ Despesa salva: {did} - R${valor}")
    return jsonify({"id": did})

@app.route("/api/despesas/<did>", methods=["DELETE"])
@require_auth
def del_despesa(did):
    uid = g.current_user["sub"]
    db = get_db()
    db.execute("DELETE FROM despesas WHERE id=? AND user_id=?", (did, uid))
    db.commit()
    print(f"✅ Despesa deletada: {did}")
    return jsonify({"ok": True})

# ════════════════════════════════════════════════════════════════════════
# FUNCIONÁRIOS
# ════════════════════════════════════════════════════════════════════════

@app.route("/api/funcionarios", methods=["GET"])
@require_auth
def get_funcionarios():
    uid = g.current_user["sub"]
    db = get_db()
    rows = db.execute("SELECT * FROM funcionarios WHERE user_id=? ORDER BY nome", (uid,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/funcionarios", methods=["POST"])
@require_auth
def save_funcionario():
    uid = g.current_user["sub"]
    data = request.json or {}
    
    if not data.get("nome") or not data.get("cargo"):
        return jsonify({"error": "Nome e cargo obrigatórios"}), 400
    
    db = get_db()
    fid = data.get("id") or str(uuid.uuid4())
    
    try:
        valor = float(data.get("valor", 0))
    except:
        valor = 0
    
    existing = db.execute("SELECT id FROM funcionarios WHERE id=? AND user_id=?", (fid, uid)).fetchone()
    
    if existing:
        db.execute("""UPDATE funcionarios SET nome=?, cargo=?, frequencia=?, tipo_valor=?, valor=?, dia_pagamento=?, ativo=?
                      WHERE id=? AND user_id=?""",
                  (data.get("nome"), data.get("cargo"), data.get("frequencia", "mensal"),
                   data.get("tipoValor", "fixo"), valor, int(data.get("diaPagamento", 1)),
                   int(data.get("ativo", 1)), fid, uid))
    else:
        db.execute("""INSERT INTO funcionarios VALUES (?,?,?,?,?,?,?,?,?,?)""",
                  (fid, uid, data.get("nome"), data.get("cargo"),
                   data.get("frequencia", "mensal"), data.get("tipoValor", "fixo"),
                   valor, int(data.get("diaPagamento", 1)), int(data.get("ativo", 1)),
                   datetime.utcnow().isoformat()))
    
    db.commit()
    print(f"✅ Funcionário salvo: {fid}")
    return jsonify({"id": fid})

@app.route("/api/funcionarios/<fid>", methods=["DELETE"])
@require_auth
def del_funcionario(fid):
    uid = g.current_user["sub"]
    db = get_db()
    db.execute("DELETE FROM funcionarios WHERE id=? AND user_id=?", (fid, uid))
    db.commit()
    print(f"✅ Funcionário deletado: {fid}")
    return jsonify({"ok": True})

# ════════════════════════════════════════════════════════════════════════
# DESPESAS FIXAS
# ════════════════════════════════════════════════════════════════════════

@app.route("/api/despesas-fixas", methods=["GET"])
@require_auth
def get_fixas():
    uid = g.current_user["sub"]
    db = get_db()
    rows = db.execute("SELECT * FROM despesas_fixas_rec WHERE user_id=?", (uid,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/despesas-fixas", methods=["POST"])
@require_auth
def save_fixa():
    uid = g.current_user["sub"]
    data = request.json or {}
    
    if not data.get("descricao") or not data.get("valor"):
        return jsonify({"error": "Descricao e valor obrigatórios"}), 400
    
    db = get_db()
    xid = data.get("id") or str(uuid.uuid4())
    
    try:
        valor = float(data.get("valor"))
    except:
        return jsonify({"error": "Valor inválido"}), 400
    
    existing = db.execute("SELECT id FROM despesas_fixas_rec WHERE id=? AND user_id=?", (xid, uid)).fetchone()
    
    if existing:
        db.execute("""UPDATE despesas_fixas_rec SET descricao=?, valor=?, dia_pagamento=?, categoria=?, ativa=?
                      WHERE id=? AND user_id=?""",
                  (data.get("descricao"), valor, int(data.get("diaPagamento", 5)),
                   data.get("categoria", ""), int(data.get("ativa", 1)), xid, uid))
    else:
        db.execute("""INSERT INTO despesas_fixas_rec VALUES (?,?,?,?,?,?,?,?)""",
                  (xid, uid, data.get("descricao"), valor, int(data.get("diaPagamento", 5)),
                   data.get("categoria", ""), int(data.get("ativa", 1)),
                   datetime.utcnow().isoformat()))
    
    db.commit()
    print(f"✅ Despesa fixa salva: {xid} - R${valor}")
    return jsonify({"id": xid})

@app.route("/api/despesas-fixas/<xid>", methods=["DELETE"])
@require_auth
def del_fixa(xid):
    uid = g.current_user["sub"]
    db = get_db()
    db.execute("DELETE FROM despesas_fixas_rec WHERE id=? AND user_id=?", (xid, uid))
    db.commit()
    print(f"✅ Despesa fixa deletada: {xid}")
    return jsonify({"ok": True})

# ════════════════════════════════════════════════════════════════════════
# ASSINATURAS
# ════════════════════════════════════════════════════════════════════════

@app.route("/api/assinaturas", methods=["GET"])
@require_auth
def get_assinaturas():
    uid = g.current_user["sub"]
    db = get_db()
    rows = db.execute("SELECT * FROM assinaturas WHERE user_id=? ORDER BY data_proxima_cobranca", (uid,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/assinaturas", methods=["POST"])
@require_auth
def save_assinatura():
    uid = g.current_user["sub"]
    data = request.json or {}
    
    if not data.get("nomeCliente") or not data.get("valorMensal"):
        return jsonify({"error": "Nome e valor obrigatórios"}), 400
    
    db = get_db()
    aid = data.get("id") or str(uuid.uuid4())
    
    try:
        valor = float(data.get("valorMensal"))
    except:
        return jsonify({"error": "Valor inválido"}), 400
    
    existing = db.execute("SELECT id FROM assinaturas WHERE id=? AND user_id=?", (aid, uid)).fetchone()
    
    if existing:
        db.execute("""UPDATE assinaturas SET nome_cliente=?, email_cliente=?, plano_nome=?, valor_mensal=?,
                      data_inicio=?, data_proxima_cobranca=?, status=?, observacoes=?
                      WHERE id=? AND user_id=?""",
                  (data.get("nomeCliente"), data.get("emailCliente"), data.get("planome"),
                   valor, data.get("dataInicio"), data.get("dataProximaCobranca"),
                   data.get("status", "ativa"), data.get("observacoes"), aid, uid))
    else:
        db.execute("""INSERT INTO assinaturas VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                  (aid, uid, data.get("nomeCliente"), data.get("emailCliente"),
                   data.get("planome"), valor, data.get("dataInicio"),
                   data.get("dataProximaCobranca"), data.get("status", "ativa"),
                   data.get("observacoes"), datetime.utcnow().isoformat()))
    
    db.commit()
    print(f"✅ Assinatura salva: {aid} - R${valor}")
    return jsonify({"id": aid})

@app.route("/api/assinaturas/<aid>", methods=["DELETE"])
@require_auth
def del_assinatura(aid):
    uid = g.current_user["sub"]
    db = get_db()
    db.execute("DELETE FROM assinaturas WHERE id=? AND user_id=?", (aid, uid))
    db.commit()
    print(f"✅ Assinatura deletada: {aid}")
    return jsonify({"ok": True})

# ════════════════════════════════════════════════════════════════════════
# CONFIGURAÇÕES
# ════════════════════════════════════════════════════════════════════════

@app.route("/api/configuracoes", methods=["GET"])
@require_auth
def get_config():
    uid = g.current_user["sub"]
    db = get_db()
    cfg = db.execute("SELECT * FROM configuracoes WHERE user_id=?", (uid,)).fetchone()
    if not cfg:
        db.execute("INSERT INTO configuracoes VALUES (?,?,?,?,?)",
                  (uid, "Minha Empresa", "", "", 0))
        db.commit()
        return jsonify({"nomeEmpresa": "Minha Empresa", "cnpj": "", "segmento": "", "metaMensal": 0})
    return jsonify({
        "nomeEmpresa": cfg["nome_empresa"],
        "cnpj": cfg["cnpj"],
        "segmento": cfg["segmento"],
        "metaMensal": cfg["meta_mensal"]
    })

@app.route("/api/configuracoes", methods=["POST"])
@require_auth
def save_config():
    uid = g.current_user["sub"]
    data = request.json or {}
    db = get_db()
    
    existing = db.execute("SELECT user_id FROM configuracoes WHERE user_id=?", (uid,)).fetchone()
    
    if existing:
        db.execute("""UPDATE configuracoes SET nome_empresa=?, cnpj=?, segmento=?, meta_mensal=?
                      WHERE user_id=?""",
                  (data.get("nomeEmpresa", "Minha Empresa"), data.get("cnpj", ""),
                   data.get("segmento", ""), float(data.get("metaMensal", 0)), uid))
    else:
        db.execute("""INSERT INTO configuracoes VALUES (?,?,?,?,?)""",
                  (uid, data.get("nomeEmpresa", "Minha Empresa"), data.get("cnpj", ""),
                   data.get("segmento", ""), float(data.get("metaMensal", 0))))
    
    db.commit()
    print(f"✅ Configurações salvas")
    return jsonify({"ok": True})

# ════════════════════════════════════════════════════════════════════════
# ADMIN - USUÁRIOS
# ════════════════════════════════════════════════════════════════════════

@app.route("/api/users", methods=["GET"])
@require_auth
def list_users():
    if not g.current_user.get("isSuperAdmin"):
        return jsonify({"error": "Negado"}), 403
    db = get_db()
    users = db.execute("SELECT id, name, email, company, is_super_admin, created_at FROM users WHERE is_super_admin=0").fetchall()
    return jsonify([dict(u) for u in users])

@app.route("/api/users", methods=["POST"])
@require_auth
def create_user():
    if not g.current_user.get("isSuperAdmin"):
        return jsonify({"error": "Negado"}), 403
    data = request.json or {}
    
    if not data.get("name") or not data.get("email") or not data.get("password"):
        return jsonify({"error": "Faltam dados"}), 400
    
    email = data.get("email", "").lower()
    db = get_db()
    
    if db.execute("SELECT id FROM users WHERE lower(email)=?", (email,)).fetchone():
        return jsonify({"error": "Email existe"}), 409
    
    uid = str(uuid.uuid4())
    pwd_hash = hashlib.sha256(data.get("password").encode()).hexdigest()
    
    db.execute("INSERT INTO users VALUES (?,?,?,?,?,?,?)",
              (uid, data.get("name"), email, pwd_hash, data.get("company", ""),
               0, datetime.utcnow().isoformat()))
    db.commit()
    
    print(f"✅ Usuário criado: {email}")
    return jsonify({"id": uid})

@app.route("/api/users/<uid>", methods=["DELETE"])
@require_auth
def del_user(uid):
    if not g.current_user.get("isSuperAdmin"):
        return jsonify({"error": "Negado"}), 403
    db = get_db()
    db.execute("DELETE FROM users WHERE id=? AND is_super_admin=0", (uid,))
    db.commit()
    print(f"✅ Usuário deletado: {uid}")
    return jsonify({"ok": True})

# ════════════════════════════════════════════════════════════════════════
# SERVE FRONTEND
# ════════════════════════════════════════════════════════════════════════

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve(path):
    d = os.path.join(os.path.dirname(__file__), "dist")
    if path and os.path.isfile(os.path.join(d, path)):
        return send_from_directory(d, path)
    return send_from_directory(d, "index.html")

# ════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    print(f"🚀 Servidor em http://localhost:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=False)
