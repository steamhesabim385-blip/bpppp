"""
PyKeySystem v2 - Gelişmiş Key Auth Sistemi
+ Device limiti (1-2 cihaz per key)
+ HMAC istek imzalama
+ Anti-replay (timestamp kontrolü)
+ Web admin paneli
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
import sqlite3, hashlib, hmac, secrets, string, time, uuid, os, json, pathlib
from contextlib import asynccontextmanager
import uvicorn

DATA_DIR = pathlib.Path(os.environ.get("RAILWAY_VOLUME_MOUNT_PATH", "."))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = str(DATA_DIR / "keyauth.db")

# ─── DB ───────────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db(); c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS admins (
        owner_id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL, created_at INTEGER NOT NULL)""")
    c.execute("""CREATE TABLE IF NOT EXISTS apps (
        id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, name TEXT NOT NULL,
        secret TEXT NOT NULL, enabled INTEGER DEFAULT 1, paused INTEGER DEFAULT 0,
        hwid_check INTEGER DEFAULT 0, device_limit INTEGER DEFAULT 1,
        version TEXT DEFAULT '1.0', created_at INTEGER NOT NULL)""")
    c.execute("""CREATE TABLE IF NOT EXISTS licenses (
        id TEXT PRIMARY KEY, app_id TEXT NOT NULL,
        license_key TEXT NOT NULL UNIQUE,
        level INTEGER DEFAULT 1, duration INTEGER NOT NULL,
        note TEXT, used INTEGER DEFAULT 0, used_by TEXT,
        banned INTEGER DEFAULT 0, ban_reason TEXT,
        created_at INTEGER NOT NULL, expires_at INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS devices (
        id TEXT PRIMARY KEY, app_id TEXT NOT NULL,
        license_key TEXT NOT NULL, hwid TEXT NOT NULL,
        username TEXT, ip TEXT, created_at INTEGER NOT NULL,
        UNIQUE(app_id, license_key, hwid))""")
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY, app_id TEXT NOT NULL,
        username TEXT NOT NULL, password TEXT NOT NULL,
        ip TEXT, license_key TEXT, level INTEGER DEFAULT 1,
        banned INTEGER DEFAULT 0, ban_reason TEXT,
        created_at INTEGER NOT NULL, last_login INTEGER,
        expires_at INTEGER, UNIQUE(app_id, username))""")
    c.execute("""CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY, app_id TEXT NOT NULL,
        secret TEXT NOT NULL, created_at INTEGER NOT NULL)""")
    c.execute("""CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        app_id TEXT NOT NULL, username TEXT,
        action TEXT NOT NULL, message TEXT,
        ip TEXT, created_at INTEGER NOT NULL)""")
    conn.commit(); conn.close()
    print("[✓] DB hazır")

# ─── HELPERS ──────────────────────────────────────────────────────────────────
def hp(pw): return hashlib.sha256(pw.encode()).hexdigest()
def now(): return int(time.time())
def ok(**d): return {"success": True, **d}
def err(msg): return {"success": False, "message": msg}

def gen_key(prefix="KEY"):
    chars = string.ascii_uppercase + string.digits
    parts = [''.join(secrets.choice(chars) for _ in range(4)) for _ in range(4)]
    return f"{prefix}-" + "-".join(parts)

def gen_owner_id(): return secrets.token_hex(5)

def sign_response(data: dict, secret: str) -> str:
    msg = json.dumps(data, separators=(',', ':'), sort_keys=True)
    return hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()

def add_log(app_id, action, username=None, message=None, ip=None):
    c = get_db()
    c.execute("INSERT INTO logs (app_id,username,action,message,ip,created_at) VALUES(?,?,?,?,?,?)",
              (app_id, username, action, message, ip, now()))
    c.commit(); c.close()

def get_ip(request: Request):
    fwd = request.headers.get("X-Forwarded-For")
    return fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "unknown")

def get_device_count(conn, app_id, license_key):
    return conn.execute(
        "SELECT COUNT(*) FROM devices WHERE app_id=? AND license_key=?",
        (app_id, license_key)
    ).fetchone()[0]

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db(); yield

app = FastAPI(title="PyKeySystem v2", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ══════════════════════════════════════════════════════════════════════════════
# WEB ADMIN PANEL
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/", response_class=HTMLResponse)
async def panel():
    return HTMLResponse(PANEL_HTML)

PANEL_HTML = r"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PyKeySystem</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#0d0d0d;--bg2:#111;--bg3:#181818;--bg4:#222;
  --red:#c0392b;--red2:#e74c3c;--red3:#922b21;
  --blue:#2980b9;--green:#27ae60;--yellow:#f39c12;
  --text:#fff;--dim:#777;--border:#252525;
  --font:'Segoe UI',sans-serif;
}
body{background:var(--bg);color:var(--text);font-family:var(--font);min-height:100vh}
.hidden{display:none!important}

/* AUTH */
#auth{display:flex;align-items:center;justify-content:center;min-height:100vh}
.auth-card{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:44px;width:400px}
.auth-card .logo{font-size:24px;font-weight:700;color:var(--red2);margin-bottom:4px;letter-spacing:1px}
.auth-card .sub{color:var(--dim);font-size:13px;margin-bottom:28px}
.tabs{display:flex;border-bottom:1px solid var(--border);margin-bottom:24px}
.tab{padding:9px 22px;background:none;border:none;color:var(--dim);cursor:pointer;font-size:13px;border-bottom:2px solid transparent;transition:.2s;font-family:var(--font)}
.tab.on{color:var(--red2);border-bottom-color:var(--red2)}
label{display:block;font-size:11px;color:var(--dim);margin-bottom:6px;text-transform:uppercase;letter-spacing:.6px}
input[type=text],input[type=password],input[type=number],select{
  width:100%;background:var(--bg3);border:1px solid var(--border);
  border-radius:5px;padding:10px 13px;color:var(--text);
  font-size:13px;outline:none;transition:.2s;font-family:var(--font)}
input:focus,select:focus{border-color:var(--red3)}
.fg{margin-bottom:16px}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;
  padding:10px 18px;border:none;border-radius:5px;
  font-size:13px;font-weight:600;cursor:pointer;transition:.15s;font-family:var(--font)}
.btn-primary{background:var(--red3);color:#fff}.btn-primary:hover{background:var(--red)}
.btn-ghost{background:transparent;color:var(--dim);border:1px solid var(--border)}.btn-ghost:hover{color:var(--text);border-color:#444}
.btn-danger{background:#5c1111;color:#fff}.btn-danger:hover{background:var(--red3)}
.btn-success{background:#1a4a1a;color:var(--green)}.btn-success:hover{background:#1e5e1e}
.btn-full{width:100%;margin-top:4px}
.msg{font-size:12px;margin-top:12px;min-height:18px;text-align:center}
.msg.e{color:var(--red2)}.msg.s{color:var(--green)}

/* LAYOUT */
#app-shell{display:flex;min-height:100vh}
.side{width:230px;background:var(--bg2);border-right:1px solid var(--border);display:flex;flex-direction:column;flex-shrink:0;position:sticky;top:0;height:100vh}
.side-logo{padding:18px 16px;border-bottom:1px solid var(--border)}
.side-logo h2{font-size:15px;font-weight:700;color:var(--red2);letter-spacing:1px}
.side-logo p{font-size:11px;color:var(--dim);margin-top:2px}
.app-pick{padding:10px;border-bottom:1px solid var(--border)}
.app-pick select{font-size:12px;padding:7px 10px}
nav{flex:1;padding:6px 0;overflow-y:auto}
.ni{display:flex;align-items:center;gap:9px;padding:9px 14px;cursor:pointer;font-size:13px;color:var(--dim);transition:.12s;border-left:3px solid transparent;user-select:none}
.ni:hover{color:var(--text);background:var(--bg3)}
.ni.on{color:var(--red2);border-left-color:var(--red2);background:rgba(192,57,43,.07)}
.ni .ic{font-size:14px;width:17px;text-align:center}
.side-foot{padding:12px;border-top:1px solid var(--border)}
.uinfo strong{display:block;font-size:13px;margin-bottom:1px}
.uinfo span{font-size:11px;color:var(--dim)}
.main-area{flex:1;overflow:auto;display:flex;flex-direction:column}
.topbar{background:var(--bg2);border-bottom:1px solid var(--border);padding:0 22px;height:50px;display:flex;align-items:center;justify-content:space-between;flex-shrink:0;position:sticky;top:0;z-index:10}
.topbar h2{font-size:15px;font-weight:600}
.tb-actions{display:flex;gap:8px}
.page{padding:22px;flex:1}

/* CARDS */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:22px}
.scard{background:var(--bg2);border:1px solid var(--border);border-radius:7px;padding:16px}
.scard .sl{font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:.6px;margin-bottom:7px}
.scard .sv{font-size:26px;font-weight:700}
.scard .ss{font-size:11px;color:var(--dim);margin-top:3px}
.scard.red .sv{color:var(--red2)}
.scard.grn .sv{color:var(--green)}
.scard.ylw .sv{color:var(--yellow)}

/* TABLE */
.tbox{background:var(--bg2);border:1px solid var(--border);border-radius:7px;overflow:hidden;margin-bottom:18px}
.tbox-head{padding:13px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.tbox-head h3{font-size:13px;font-weight:600}
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:9px 14px;font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:.6px;border-bottom:1px solid var(--border);font-weight:500}
td{padding:9px 14px;font-size:12px;border-bottom:1px solid #181818}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(255,255,255,.015)}
.badge{display:inline-block;padding:2px 7px;border-radius:3px;font-size:10px;font-weight:600}
.bg{background:rgba(39,174,96,.13);color:var(--green)}
.br{background:rgba(231,76,60,.13);color:var(--red2)}
.by{background:rgba(243,156,18,.13);color:var(--yellow)}
.bd{background:rgba(120,120,120,.13);color:var(--dim)}
.acts{display:flex;gap:5px;flex-wrap:wrap}

/* FORM PANEL */
.fpanel{background:var(--bg2);border:1px solid var(--border);border-radius:7px;padding:18px;margin-bottom:18px}
.fpanel h3{font-size:13px;font-weight:600;margin-bottom:14px;color:var(--dim)}
.frow{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px}
.fcheck{display:flex;align-items:center;gap:7px;font-size:13px;color:var(--dim);cursor:pointer;margin-bottom:12px}
.fcheck input{accent-color:var(--red);width:14px;height:14px}

/* CODE */
.code-tabs{margin-top:4px}
.ctabs{display:flex;gap:4px;flex-wrap:wrap;margin-bottom:10px}
.ctab{padding:5px 12px;background:var(--bg3);border:1px solid var(--border);border-radius:4px;color:var(--dim);cursor:pointer;font-size:11px;transition:.15s}
.ctab.on{background:var(--red3);border-color:var(--red3);color:#fff}
.cbox{background:#080808;border:1px solid var(--border);border-radius:6px;padding:16px;position:relative;max-height:420px;overflow:auto}
.cbox pre{font-family:'Consolas','Courier New',monospace;font-size:12px;line-height:1.75;color:#cdd6f4;white-space:pre}
.cbtn{position:sticky;top:0;float:right;margin-bottom:-28px}

/* MODAL */
.overlay{position:fixed;inset:0;background:rgba(0,0,0,.75);display:flex;align-items:center;justify-content:center;z-index:200}
.mbox{background:var(--bg2);border:1px solid var(--border);border-radius:8px;width:500px;max-width:96vw;max-height:90vh;overflow:auto}
.mhead{padding:15px 18px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;background:var(--bg2)}
.mhead h3{font-size:14px;font-weight:600}
.mclose{background:none;border:none;color:var(--dim);font-size:20px;cursor:pointer;line-height:1;padding:0 2px}
.mclose:hover{color:var(--text)}
.mbody{padding:18px}
.mfoot{padding:12px 18px;border-top:1px solid var(--border);display:flex;justify-content:flex-end;gap:8px;position:sticky;bottom:0;background:var(--bg2)}

/* PAGES */
.pag{display:flex;gap:5px;margin-top:14px;justify-content:flex-end}
.pb{padding:5px 11px;background:var(--bg3);border:1px solid var(--border);border-radius:4px;color:var(--dim);cursor:pointer;font-size:11px}
.pb:hover,.pb.on{background:var(--red3);border-color:var(--red3);color:#fff}

/* TOAST */
.toast{position:fixed;bottom:18px;right:18px;padding:11px 18px;border-radius:6px;font-size:12px;font-weight:500;z-index:999;animation:tsi .25s ease}
.toast.s{background:#0d2b0d;border:1px solid var(--green);color:var(--green)}
.toast.e{background:#2b0d0d;border:1px solid var(--red2);color:var(--red2)}
@keyframes tsi{from{transform:translateY(12px);opacity:0}to{transform:none;opacity:1}}

/* KEY RESULT */
.key-list{background:#080808;border:1px solid var(--border);border-radius:6px;padding:14px;font-family:monospace;font-size:12px;line-height:1.9;max-height:260px;overflow:auto;margin-top:12px}
.key-list div{color:#cdd6f4}

input[type=number]{-moz-appearance:textfield}
input::-webkit-outer-spin-button,input::-webkit-inner-spin-button{-webkit-appearance:none}
code{background:var(--bg3);padding:2px 6px;border-radius:3px;font-size:11px;font-family:monospace}
</style>
</head>
<body>

<!-- ═══ AUTH ═══ -->
<div id="auth">
  <div class="auth-card">
    <div class="logo">⚡ PyKeySystem</div>
    <div class="sub">Lisans yönetim paneline hoş geldin</div>
    <div class="tabs">
      <button class="tab on" onclick="authTab('login',this)">Giriş Yap</button>
      <button class="tab" onclick="authTab('reg',this)">Kayıt Ol</button>
    </div>
    <div id="af-login">
      <div class="fg"><label>Kullanıcı Adı</label><input id="lu" placeholder="admin"></div>
      <div class="fg"><label>Şifre</label><input id="lp" type="password" placeholder="••••••••"></div>
      <button class="btn btn-primary btn-full" onclick="doLogin()">Giriş Yap</button>
    </div>
    <div id="af-reg" class="hidden">
      <div class="fg"><label>Kullanıcı Adı</label><input id="ru" placeholder="admin"></div>
      <div class="fg"><label>Şifre</label><input id="rp" type="password" placeholder="••••••••"></div>
      <button class="btn btn-primary btn-full" onclick="doReg()">Kayıt Ol</button>
    </div>
    <div class="msg" id="amsg"></div>
  </div>
</div>

<!-- ═══ APP ═══ -->
<div id="app-shell" class="hidden">
  <div class="side">
    <div class="side-logo"><h2>⚡ PyKeySystem</h2><p>v2.0 — Lisans Yönetimi</p></div>
    <div class="app-pick">
      <select id="app-sel" onchange="pickApp()">
        <option value="">— Uygulama Seç —</option>
      </select>
    </div>
    <nav>
      <div class="ni on" id="ni-dash"  onclick="go('dash')"><span class="ic">📊</span>Dashboard</div>
      <div class="ni"    id="ni-keys"  onclick="go('keys')"><span class="ic">🔑</span>Keyler</div>
      <div class="ni"    id="ni-users" onclick="go('users')"><span class="ic">👤</span>Kullanıcılar</div>
      <div class="ni"    id="ni-devs"  onclick="go('devs')"><span class="ic">💻</span>Cihazlar</div>
      <div class="ni"    id="ni-logs"  onclick="go('logs')"><span class="ic">📋</span>Loglar</div>
      <div class="ni"    id="ni-code"  onclick="go('code')"><span class="ic">🖥️</span>Kod Örnekleri</div>
      <div class="ni"    id="ni-set"   onclick="go('set')"><span class="ic">⚙️</span>Ayarlar</div>
    </nav>
    <div class="side-foot">
      <div class="uinfo"><strong id="sb-u">—</strong><span id="sb-o">—</span></div>
      <button class="btn btn-ghost" style="width:100%;margin-top:8px;font-size:12px" onclick="logout()">Çıkış</button>
    </div>
  </div>
  <div class="main-area">
    <div class="topbar"><h2 id="ptitle">Dashboard</h2><div class="tb-actions" id="tba"></div></div>
    <div class="page" id="page"></div>
  </div>
</div>

<!-- ═══ MODAL ═══ -->
<div class="overlay hidden" id="ov" onclick="closeMod(event)">
  <div class="mbox" onclick="event.stopPropagation()">
    <div class="mhead"><h3 id="mt">—</h3><button class="mclose" onclick="closeMod()">×</button></div>
    <div class="mbody" id="mb"></div>
    <div class="mfoot" id="mf"></div>
  </div>
</div>

<script>
// ─── STATE ────────────────────────────────────────────────────────────────────
const S = { oid:null, uname:null, apps:[], app:null, pg:'dash' }

// ─── API ──────────────────────────────────────────────────────────────────────
async function api(m,p,d){
  const o={method:m,headers:{'Content-Type':'application/json'}}
  if(d) o.body=JSON.stringify(d)
  const r=await fetch(p,o); return r.json()
}
const G=(p,q)=>api('GET',p+(q?'?'+q:''))
const P=(p,d)=>api('POST',p,d)

// ─── AUTH ─────────────────────────────────────────────────────────────────────
function authTab(t,btn){
  document.querySelectorAll('.tab').forEach(b=>b.classList.remove('on'))
  btn.classList.add('on')
  document.getElementById('af-login').classList.toggle('hidden',t!=='login')
  document.getElementById('af-reg').classList.toggle('hidden',t!=='reg')
  setMsg('')
}
async function doLogin(){
  const u=V('lu'),p=V('lp')
  if(!u||!p) return setMsg('Tüm alanları doldurun','e')
  const r=await P('/admin/login',{username:u,password:p})
  if(r.success){S.oid=r.owner_id;S.uname=u;enterApp()}
  else setMsg(r.message,'e')
}
async function doReg(){
  const u=V('ru'),p=V('rp')
  if(!u||!p) return setMsg('Tüm alanları doldurun','e')
  const r=await P('/admin/register',{username:u,password:p})
  if(r.success){setMsg('✓ Kayıt başarılı! Owner ID: '+r.owner_id,'s')}
  else setMsg(r.message,'e')
}
function setMsg(m,t=''){const e=document.getElementById('amsg');e.textContent=m;e.className='msg '+(t||'')}
function logout(){
  S.oid=S.uname=S.app=null;S.apps=[]
  document.getElementById('app-shell').classList.add('hidden')
  document.getElementById('auth').classList.remove('hidden')
}
async function enterApp(){
  document.getElementById('auth').classList.add('hidden')
  document.getElementById('app-shell').classList.remove('hidden')
  document.getElementById('sb-u').textContent=S.uname
  document.getElementById('sb-o').textContent=S.oid
  await loadApps(); go('dash')
}

// ─── APPS ─────────────────────────────────────────────────────────────────────
async function loadApps(){
  const r=await G('/admin/app/list','owner_id='+S.oid)
  S.apps=r.apps||[]
  const sel=document.getElementById('app-sel')
  sel.innerHTML='<option value="">— Uygulama Seç —</option>'
  S.apps.forEach(a=>{
    const o=document.createElement('option')
    o.value=a.id;o.textContent=a.name+(a.enabled?'':' [Kapalı]')
    sel.appendChild(o)
  })
  if(S.apps[0]){sel.value=S.apps[0].id;S.app=S.apps[0]}
}
function pickApp(){
  const id=document.getElementById('app-sel').value
  S.app=S.apps.find(a=>a.id===id)||null
  render()
}

// ─── NAV ──────────────────────────────────────────────────────────────────────
const TITLES={dash:'Dashboard',keys:'🔑 Keyler',users:'👤 Kullanıcılar',devs:'💻 Cihazlar',logs:'📋 Loglar',code:'🖥️ Kod Örnekleri',set:'⚙️ Ayarlar'}
function go(p){
  S.pg=p
  document.querySelectorAll('.ni').forEach(e=>e.classList.remove('on'))
  const ni=document.getElementById('ni-'+p);if(ni)ni.classList.add('on')
  document.getElementById('ptitle').textContent=TITLES[p]||p
  document.getElementById('tba').innerHTML=''
  render()
}
function render(){
  if(!S.app&&S.pg!=='set'){showNoApp();return}
  ({dash:rDash,keys:rKeys,users:rUsers,devs:rDevs,logs:rLogs,code:rCode,set:rSet})[S.pg]?.()
}

// ─── NO APP ───────────────────────────────────────────────────────────────────
function showNoApp(){
  Q('#page').innerHTML=`
  <div class="fpanel">
    <h3>Yeni Uygulama Oluştur</h3>
    <div class="frow">
      <div class="fg"><label>Uygulama Adı</label><input id="an" placeholder="BenimApp"></div>
      <div class="fg"><label>Versiyon</label><input id="av" value="1.0"></div>
      <div class="fg"><label>Device Limit</label>
        <select id="adl"><option value="1">1 Cihaz</option><option value="2">2 Cihaz</option><option value="5">5 Cihaz</option><option value="0">Sınırsız</option></select>
      </div>
    </div>
    <label class="fcheck"><input type="checkbox" id="ah"> HWID Kilitleme Aktif</label>
    <button class="btn btn-primary" onclick="createApp()">+ Oluştur</button>
  </div>
  <div style="text-align:center;padding:48px;color:var(--dim)">
    <div style="font-size:36px;margin-bottom:10px">📱</div>
    <p style="font-size:13px">Bir uygulama seç veya oluştur</p>
  </div>`
}

// ─── DASHBOARD ────────────────────────────────────────────────────────────────
async function rDash(){
  document.getElementById('tba').innerHTML=`<button class="btn btn-primary" onclick="go('keys')">+ Key Oluştur</button>`
  const st=await G('/admin/stats','owner_id='+S.oid+'&app_id='+S.app.id)
  const k=st.keys||{},u=st.users||{},d=st.devices||{}
  Q('#page').innerHTML=`
  <div class="stats">
    <div class="scard"><div class="sl">Toplam Key</div><div class="sv">${k.total||0}</div><div class="ss">${k.unused||0} kullanılmamış</div></div>
    <div class="scard red"><div class="sl">Aktif Key</div><div class="sv">${k.used||0}</div><div class="ss">${k.banned||0} banlı</div></div>
    <div class="scard grn"><div class="sl">Kullanıcılar</div><div class="sv">${u.total||0}</div><div class="ss">${u.banned||0} banlı</div></div>
    <div class="scard ylw"><div class="sl">Kayıtlı Cihaz</div><div class="sv">${d.total||0}</div><div class="ss">Device limit: ${S.app.device_limit||1}</div></div>
    <div class="scard"><div class="sl">Durum</div><div class="sv" style="font-size:14px;margin-top:4px">${S.app.enabled?'<span class="badge bg">AKTİF</span>':'<span class="badge br">KAPALI</span>'} ${S.app.paused?'<span class="badge by">DURAKLATILMIŞ</span>':''}</div></div>
  </div>
  <div class="fpanel">
    <h3>⚡ Hızlı Key Oluştur</h3>
    <div class="frow">
      <div class="fg"><label>Adet (max 100)</label><input type="number" id="qa" value="1" min="1" max="100"></div>
      <div class="fg"><label>Süre (gün)</label><input type="number" id="qd" value="30" min="1"></div>
      <div class="fg"><label>Seviye (1-9)</label><input type="number" id="ql" value="1" min="1" max="9"></div>
      <div class="fg"><label>Prefix</label><input id="qp" value="KEY" maxlength="10"></div>
    </div>
    <button class="btn btn-primary" onclick="quickKeys()">🔑 Oluştur</button>
  </div>
  <div id="qkr"></div>`
}

async function quickKeys(){
  const r=await P('/admin/key/create',{owner_id:S.oid,app_id:S.app.id,
    amount:+V('qa'),duration:+V('qd'),level:+V('ql'),prefix:V('qp')||'KEY'})
  if(r.success){
    window._qk=r.keys
    Q('#qkr').innerHTML=`<div class="tbox"><div class="tbox-head"><h3>✓ ${r.keys.length} Key Oluşturuldu</h3>
      <button class="btn btn-ghost" style="font-size:11px" onclick="copyAll()">📋 Hepsini Kopyala</button></div>
      <div class="key-list">${r.keys.map(k=>`<div>${k}</div>`).join('')}</div></div>`
    toast('✓ Keyler oluşturuldu!','s')
  } else toast(r.message,'e')
}
function copyAll(){if(window._qk){navigator.clipboard.writeText(window._qk.join('\n'));toast('Kopyalandı!','s')}}

// ─── KEYS ─────────────────────────────────────────────────────────────────────
let KP=1
async function rKeys(p=1){
  KP=p
  document.getElementById('tba').innerHTML=`<button class="btn btn-primary" onclick="showCreateKeys()">+ Key Oluştur</button>`
  const r=await G('/admin/key/list',`owner_id=${S.oid}&app_id=${S.app.id}&page=${p}&limit=25`)
  const keys=r.keys||[],total=r.total||0
  const rows=keys.length?keys.map(k=>`<tr>
    <td><code>${k.license_key}</code></td>
    <td>${k.level}</td>
    <td>${k.used?`<span class="badge bg">${k.used_by||'?'}</span>`:'<span class="badge bd">Bekliyor</span>'}</td>
    <td>${k.banned?'<span class="badge br">BAN</span>':'<span class="badge bg">OK</span>'}</td>
    <td style="color:var(--dim)">${k.expires_at?new Date(k.expires_at*1e3).toLocaleDateString('tr'):'—'}</td>
    <td>${k.note||'—'}</td>
    <td><div class="acts">
      <button class="btn btn-ghost" style="font-size:10px;padding:4px 8px" onclick="copyT('${k.license_key}')">Kopyala</button>
      <button class="btn ${k.banned?'btn-success':'btn-danger'}" style="font-size:10px;padding:4px 8px" onclick="banKey('${k.license_key}')">${k.banned?'Unban':'Ban'}</button>
      <button class="btn btn-ghost" style="font-size:10px;padding:4px 8px" onclick="resetKH('${k.license_key}')">HWID↺</button>
      <button class="btn btn-danger" style="font-size:10px;padding:4px 8px" onclick="delKey('${k.license_key}')">Sil</button>
    </div></td></tr>`).join('')
  :'<tr><td colspan="7" style="text-align:center;padding:28px;color:var(--dim)">Key bulunamadı</td></tr>'
  const pages=Math.ceil(total/25)
  let pg=pages>1?'<div class="pag">'+Array.from({length:pages},(_,i)=>`<button class="pb${i+1===p?' on':''}" onclick="rKeys(${i+1})">${i+1}</button>`).join('')+'</div>':''
  Q('#page').innerHTML=`<div class="tbox">
    <div class="tbox-head"><h3>Keyler (${total})</h3></div>
    <table><thead><tr><th>Key</th><th>Sv</th><th>Kullanıcı</th><th>Durum</th><th>Bitiş</th><th>Not</th><th>İşlemler</th></tr></thead>
    <tbody>${rows}</tbody></table></div>${pg}`
}

function showCreateKeys(){
  showMod('Key Oluştur',`
    <div class="frow">
      <div class="fg"><label>Adet</label><input type="number" id="cka" value="1" min="1" max="100"></div>
      <div class="fg"><label>Süre (gün)</label><input type="number" id="ckd" value="30"></div>
      <div class="fg"><label>Seviye</label><input type="number" id="ckl" value="1" min="1" max="9"></div>
      <div class="fg"><label>Prefix</label><input id="ckp" value="KEY" maxlength="10"></div>
    </div>
    <div class="fg"><label>Not (isteğe bağlı)</label><input id="ckn" placeholder="Test key..."></div>
    <div id="ckr" style="margin-top:8px"></div>`,
    [{text:'Oluştur',keep:true,fn:async()=>{
      const r=await P('/admin/key/create',{owner_id:S.oid,app_id:S.app.id,
        amount:+V('cka'),duration:+V('ckd'),level:+V('ckl'),
        prefix:V('ckp')||'KEY',note:V('ckn')})
      if(r.success){
        Q('#ckr').innerHTML=`<div class="key-list">${r.keys.map(k=>`<div>${k}</div>`).join('')}</div>`
        toast(`✓ ${r.keys.length} key`,'s');rKeys(KP)
      } else toast(r.message,'e')
    }}])
}

async function banKey(key){
  const r=await P('/admin/key/ban',{owner_id:S.oid,app_id:S.app.id,key})
  if(r.success){toast(r.message,'s');rKeys(KP)} else toast(r.message,'e')
}
async function delKey(key){
  if(!confirm(`"${key.substring(0,20)}..." silinsin mi?`)) return
  const r=await P('/admin/key/delete',{owner_id:S.oid,app_id:S.app.id,key})
  if(r.success){toast('Silindi','s');rKeys(KP)} else toast(r.message,'e')
}
async function resetKH(key){
  const r=await P('/admin/key/reset-hwid',{owner_id:S.oid,app_id:S.app.id,key})
  if(r.success){toast('HWID sıfırlandı','s');rKeys(KP)} else toast(r.message,'e')
}

// ─── USERS ────────────────────────────────────────────────────────────────────
let UP=1
async function rUsers(p=1){
  UP=p
  const r=await G('/admin/user/list',`owner_id=${S.oid}&app_id=${S.app.id}&page=${p}&limit=25`)
  const us=r.users||[],total=r.total||0
  const rows=us.length?us.map(u=>`<tr>
    <td><strong>${u.username}</strong></td>
    <td style="color:var(--dim);font-size:11px">${u.ip||'—'}</td>
    <td>${u.level}</td>
    <td>${u.expires_at?new Date(u.expires_at*1e3).toLocaleDateString('tr'):'—'}</td>
    <td>${u.banned?'<span class="badge br">BAN</span>':'<span class="badge bg">OK</span>'}</td>
    <td><div class="acts">
      <button class="btn ${u.banned?'btn-success':'btn-danger'}" style="font-size:10px;padding:4px 8px" onclick="banUser('${u.username}')">${u.banned?'Unban':'Ban'}</button>
      <button class="btn btn-ghost" style="font-size:10px;padding:4px 8px" onclick="resetUH('${u.username}')">HWID↺</button>
    </div></td></tr>`).join('')
  :'<tr><td colspan="6" style="text-align:center;padding:28px;color:var(--dim)">Kullanıcı yok</td></tr>'
  const pages=Math.ceil(total/25)
  let pg=pages>1?'<div class="pag">'+Array.from({length:pages},(_,i)=>`<button class="pb${i+1===p?' on':''}" onclick="rUsers(${i+1})">${i+1}</button>`).join('')+'</div>':''
  Q('#page').innerHTML=`<div class="tbox">
    <div class="tbox-head"><h3>Kullanıcılar (${total})</h3></div>
    <table><thead><tr><th>Kullanıcı</th><th>IP</th><th>Sv</th><th>Bitiş</th><th>Durum</th><th>İşlemler</th></tr></thead>
    <tbody>${rows}</tbody></table></div>${pg}`
}
async function banUser(u){
  const r=await P('/admin/user/ban',{owner_id:S.oid,app_id:S.app.id,username:u})
  if(r.success){toast(r.message,'s');rUsers(UP)} else toast(r.message,'e')
}
async function resetUH(u){
  const r=await P('/admin/user/reset-hwid',{owner_id:S.oid,app_id:S.app.id,username:u})
  if(r.success){toast('HWID sıfırlandı','s')} else toast(r.message,'e')
}

// ─── DEVICES ──────────────────────────────────────────────────────────────────
async function rDevs(){
  const r=await G('/admin/device/list',`owner_id=${S.oid}&app_id=${S.app.id}`)
  const devs=r.devices||[]
  const rows=devs.length?devs.map(d=>`<tr>
    <td style="font-size:11px;font-family:monospace">${d.hwid?.substring(0,24)||'—'}...</td>
    <td>${d.username||'—'}</td>
    <td style="color:var(--dim);font-size:11px">${d.license_key?.substring(0,16)||'—'}...</td>
    <td style="color:var(--dim);font-size:11px">${d.ip||'—'}</td>
    <td style="color:var(--dim);font-size:11px">${new Date(d.created_at*1e3).toLocaleDateString('tr')}</td>
    <td><button class="btn btn-danger" style="font-size:10px;padding:4px 8px" onclick="removeDev('${d.id}')">Kaldır</button></td>
  </tr>`).join('')
  :'<tr><td colspan="6" style="text-align:center;padding:28px;color:var(--dim)">Kayıtlı cihaz yok</td></tr>'
  Q('#page').innerHTML=`<div class="tbox">
    <div class="tbox-head"><h3>Kayıtlı Cihazlar (${devs.length}) — Limit: ${S.app.device_limit||1} cihaz/key</h3></div>
    <table><thead><tr><th>HWID</th><th>Kullanıcı</th><th>Key</th><th>IP</th><th>Tarih</th><th>İşlem</th></tr></thead>
    <tbody>${rows}</tbody></table></div>`
}
async function removeDev(id){
  const r=await P('/admin/device/remove',{owner_id:S.oid,app_id:S.app.id,device_id:id})
  if(r.success){toast('Cihaz kaldırıldı','s');rDevs()} else toast(r.message,'e')
}

// ─── LOGS ─────────────────────────────────────────────────────────────────────
async function rLogs(){
  document.getElementById('tba').innerHTML=`<button class="btn btn-ghost" style="font-size:12px" onclick="rLogs()">↻ Yenile</button>`
  const r=await G('/admin/logs',`owner_id=${S.oid}&app_id=${S.app.id}&limit=100`)
  const logs=r.logs||[]
  const rows=logs.length?logs.map(l=>`<tr>
    <td style="font-size:11px;color:var(--dim)">${new Date(l.created_at*1e3).toLocaleString('tr')}</td>
    <td><span class="badge bd">${l.action}</span></td>
    <td>${l.username||'—'}</td>
    <td style="color:var(--dim);font-size:11px">${l.ip||'—'}</td>
    <td style="font-size:11px">${l.message||'—'}</td>
  </tr>`).join('')
  :'<tr><td colspan="5" style="text-align:center;padding:28px;color:var(--dim)">Log yok</td></tr>'
  Q('#page').innerHTML=`<div class="tbox">
    <div class="tbox-head"><h3>Loglar</h3></div>
    <table><thead><tr><th>Tarih</th><th>İşlem</th><th>Kullanıcı</th><th>IP</th><th>Mesaj</th></tr></thead>
    <tbody>${rows}</tbody></table></div>`
}

// ─── CODE ─────────────────────────────────────────────────────────────────────
function rCode(){
  const url=location.origin, oid=S.oid, name=S.app?.name||'UygulamaAdi'
  const C={
python:`# pip install requests
from keyauth import KeyAuth

auth = KeyAuth(
    name       = "${name}",
    ownerid    = "${oid}",
    server_url = "${url}"
)
auth.init()
auth.license("KEY-XXXX-XXXX-XXXX-XXXX")
print(f"Hoş geldin {auth.user.username}!")
print(f"Bitiş: {auth.user.expires}")`,

csharp:`// NuGet: Newtonsoft.Json
using System;
using System.Net.Http;
using System.Collections.Generic;
using Newtonsoft.Json.Linq;

class KeyAuth {
    const string NAME    = "${name}";
    const string OWNERID = "${oid}";
    const string URL     = "${url}/api/v1/";
    static string session = "";
    static readonly HttpClient http = new HttpClient();

    public static async System.Threading.Tasks.Task<bool> Init() {
        var data = new FormUrlEncodedContent(new[] {
            new KeyValuePair<string,string>("type","init"),
            new KeyValuePair<string,string>("name",NAME),
            new KeyValuePair<string,string>("ownerid",OWNERID),
            new KeyValuePair<string,string>("ver","1.0")
        });
        var resp = await http.PostAsync(URL, data);
        var json = JObject.Parse(await resp.Content.ReadAsStringAsync());
        if((bool)json["success"]) { session=(string)json["sessionid"]; return true; }
        Console.WriteLine(json["message"]); return false;
    }

    public static async System.Threading.Tasks.Task<bool> License(string key) {
        var hwid = GetHwid();
        var data = new FormUrlEncodedContent(new[] {
            new KeyValuePair<string,string>("type","license"),
            new KeyValuePair<string,string>("key",key),
            new KeyValuePair<string,string>("hwid",hwid),
            new KeyValuePair<string,string>("sessionid",session),
            new KeyValuePair<string,string>("name",NAME),
            new KeyValuePair<string,string>("ownerid",OWNERID)
        });
        var resp = await http.PostAsync(URL, data);
        var json = JObject.Parse(await resp.Content.ReadAsStringAsync());
        Console.WriteLine(json["message"]);
        return (bool)json["success"];
    }

    static string GetHwid() {
        return System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value ?? "unknown";
    }

    static async System.Threading.Tasks.Task Main() {
        if (!await Init()) return;
        Console.Write("Key: "); string key = Console.ReadLine();
        if (await License(key)) Console.WriteLine("Giriş başarılı!");
        Console.ReadKey();
    }
}`,

cpp:`#include <iostream>
#include <string>
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib,"winhttp.lib")

const std::string NAME    = "${name}";
const std::string OWNERID = "${oid}";
const std::string HOST    = "${url.replace('https://','').replace('http://','')}";

std::string HttpPost(const std::string& path, const std::string& body) {
    HINTERNET hSes = WinHttpOpen(L"KeyAuth",WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,0,0,0);
    HINTERNET hCon = WinHttpConnect(hSes,std::wstring(HOST.begin(),HOST.end()).c_str(),INTERNET_DEFAULT_HTTPS_PORT,0);
    HINTERNET hReq = WinHttpOpenRequest(hCon,L"POST",std::wstring(path.begin(),path.end()).c_str(),0,0,0,WINHTTP_FLAG_SECURE);
    std::wstring hdrs=L"Content-Type: application/x-www-form-urlencoded";
    WinHttpSendRequest(hReq,hdrs.c_str(),-1,(LPVOID)body.c_str(),body.size(),body.size(),0);
    WinHttpReceiveResponse(hReq,0);
    std::string res; DWORD sz=0;
    do { char buf[8192]={}; DWORD rd=0;
         WinHttpQueryDataAvailable(hReq,&sz);
         WinHttpReadData(hReq,buf,min(sz,(DWORD)sizeof(buf)),&rd);
         res+=std::string(buf,rd); } while(sz>0);
    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes);
    return res;
}
std::string GetHwid() {
    char u[256]={}; DWORD s=sizeof(u); GetUserNameA(u,&s); return u;
}
std::string ParseField(const std::string& json, const std::string& key) {
    auto p=json.find("\\""+key+"\\":\\""); if(p==std::string::npos) return "";
    auto s=p+key.size()+4, e=json.find("\\"",s); return json.substr(s,e-s);
}
int main() {
    std::string initR=HttpPost("/api/v1/","type=init&name="+NAME+"&ownerid="+OWNERID+"&ver=1.0");
    std::string sid=ParseField(initR,"sessionid");
    if(sid.empty()){std::cout<<"Init hatası!\\n";system("pause");return 1;}
    std::cout<<"Key: "; std::string key; std::cin>>key;
    std::string licR=HttpPost("/api/v1/","type=license&key="+key+"&hwid="+GetHwid()+"&sessionid="+sid+"&name="+NAME+"&ownerid="+OWNERID);
    if(licR.find("\\"success\\":true")!=std::string::npos)
        std::cout<<"Giriş başarılı! Hoş geldin!\\n";
    else std::cout<<"Hata: "<<ParseField(licR,"message")<<"\\n";
    system("pause"); return 0;
}`,

php:`<?php
define('NAME',    '${name}');
define('OWNERID', '${oid}');
define('URL',     '${url}/api/v1/');

function apiPost($data) {
    $ch = curl_init(URL);
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query($data),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_SSL_VERIFYPEER => true,
    ]);
    $r = curl_exec($ch); curl_close($ch);
    return json_decode($r, true);
}

// Init
$init = apiPost(['type'=>'init','name'=>NAME,'ownerid'=>OWNERID,'ver'=>'1.0']);
if (!$init['success']) die($init['message']);
$session = $init['sessionid'];

// License
$key = $_POST['key'] ?? readline('Key: ');
$hwid = md5(php_uname('n'));
$r = apiPost(['type'=>'license','key'=>$key,'hwid'=>$hwid,
              'sessionid'=>$session,'name'=>NAME,'ownerid'=>OWNERID]);

if ($r['success']) {
    echo "Hoş geldin " . $r['info']['username'] . "!\\n";
    echo "Bitiş: " . date('d.m.Y', $r['info']['subscriptions'][0]['expiry']) . "\\n";
} else {
    die($r['message'] . "\\n");
}`,

js:`// Node.js — npm install node-fetch
const fetch = require('node-fetch');
const os    = require('os');
const crypto= require('crypto');

const NAME    = '${name}';
const OWNERID = '${oid}';
const URL     = '${url}/api/v1/';

function getHwid() {
  return crypto.createHash('md5').update(os.hostname() + os.platform()).digest('hex');
}

async function apiPost(data) {
  const body = new URLSearchParams(data);
  const r = await fetch(URL, { method: 'POST', body });
  return r.json();
}

async function main() {
  // Init
  const init = await apiPost({ type:'init', name:NAME, ownerid:OWNERID, ver:'1.0' });
  if (!init.success) { console.error(init.message); process.exit(1); }
  const session = init.sessionid;

  // License
  const key = process.argv[2] || 'KEY-XXXX-XXXX-XXXX-XXXX';
  const r = await apiPost({
    type:'license', key, hwid:getHwid(),
    sessionid:session, name:NAME, ownerid:OWNERID
  });

  if (r.success) {
    console.log('Hoş geldin', r.info.username);
    console.log('Bitiş:', new Date(r.info.subscriptions[0].expiry*1000).toLocaleDateString('tr'));
  } else {
    console.error('Hata:', r.message);
    process.exit(1);
  }
}
main();`,

lua:`-- luarocks install luasocket luassl
local http  = require("socket.http")
local ltn12 = require("ltn12")
local json  = require("json") -- luarocks install lua-json

local NAME    = "${name}"
local OWNERID = "${oid}"
local URL     = "${url}/api/v1/"

local function post(params)
    local body = ""
    for k,v in pairs(params) do body = body..k.."="..v.."&" end
    local resp = {}
    http.request{url=URL,method="POST",source=ltn12.source.string(body),
        sink=ltn12.sink.table(resp),
        headers={["content-type"]="application/x-www-form-urlencoded",
                 ["content-length"]=tostring(#body)}}
    return json.decode(table.concat(resp))
end

-- Init
local init = post({type="init",name=NAME,ownerid=OWNERID,ver="1.0"})
if not init.success then print(init.message) os.exit(1) end
local session = init.sessionid

-- License
io.write("Key: ") local key=io.read()
local r = post({type="license",key=key,hwid="lua_hwid",
                sessionid=session,name=NAME,ownerid=OWNERID})
if r.success then
    print("Hoş geldin "..r.info.username.."!")
else
    print("Hata: "..r.message) os.exit(1)
end`
  }
  const LANGS=[['python','🐍 Python'],['csharp','⚙️ C#'],['cpp','💻 C++'],['php','🐘 PHP'],['js','☕ JavaScript'],['lua','🌙 Lua']]
  let btns=LANGS.map(([l,n])=>`<button class="ctab${l==='python'?' on':''}" onclick="switchLang('${l}',this)">${n}</button>`).join('')
  Q('#page').innerHTML=`
  <div class="fpanel" style="margin-bottom:16px">
    <p style="color:var(--dim);font-size:13px">Uygulamanız için hazır entegrasyon kodları. Kopyala yapıştır!</p>
  </div>
  <div class="code-tabs">
    <div class="ctabs">${btns}</div>
    <div class="cbox">
      <button class="btn btn-ghost cbtn" style="font-size:11px;padding:4px 10px" onclick="copyCode()">📋 Kopyala</button>
      <pre id="cc">${esc(C.python)}</pre>
    </div>
  </div>`
  window._C=C
}
function switchLang(l,btn){
  document.querySelectorAll('.ctab').forEach(b=>b.classList.remove('on'));btn.classList.add('on')
  Q('#cc').textContent=window._C[l]
}
function copyCode(){navigator.clipboard.writeText(Q('#cc').textContent);toast('Kopyalandı!','s')}

// ─── SETTINGS ─────────────────────────────────────────────────────────────────
async function rSet(){
  const appForms=S.apps.map(a=>`
    <div class="fpanel" style="margin-bottom:12px">
      <h3 style="margin-bottom:12px">${a.name} ${a.enabled?'<span class="badge bg">AKTİF</span>':'<span class="badge br">KAPALI</span>'}</h3>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:12px;font-size:12px">
        <div><div style="color:var(--dim);margin-bottom:3px;font-size:10px">APP ID</div><code>${a.id}</code></div>
        <div><div style="color:var(--dim);margin-bottom:3px;font-size:10px">SECRET</div><code>${a.secret.substring(0,20)}...</code></div>
        <div><div style="color:var(--dim);margin-bottom:3px;font-size:10px">OWNER ID</div><code>${S.oid}</code></div>
        <div><div style="color:var(--dim);margin-bottom:3px;font-size:10px">DEVICE LİMİT</div><code>${a.device_limit||1} cihaz/key</code></div>
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn btn-ghost" style="font-size:11px" onclick="toggleApp('${a.id}','enabled')">${a.enabled?'Kapat':'Aç'}</button>
        <button class="btn btn-ghost" style="font-size:11px" onclick="toggleApp('${a.id}','paused')">${a.paused?'Devam':'Duraklat'}</button>
      </div>
    </div>`).join('')

  Q('#page').innerHTML=appForms+`
  <div class="fpanel">
    <h3>+ Yeni Uygulama</h3>
    <div class="frow">
      <div class="fg"><label>Ad</label><input id="an" placeholder="BenimApp2"></div>
      <div class="fg"><label>Versiyon</label><input id="av" value="1.0"></div>
      <div class="fg"><label>Device Limit</label>
        <select id="adl"><option value="1">1 Cihaz</option><option value="2">2 Cihaz</option><option value="5">5 Cihaz</option><option value="0">Sınırsız</option></select>
      </div>
    </div>
    <label class="fcheck"><input type="checkbox" id="ah"> HWID Kilitleme</label>
    <button class="btn btn-primary" style="margin-top:4px" onclick="createApp()">+ Oluştur</button>
  </div>`
}

async function createApp(){
  const name=V('an')?.trim(),ver=V('av')||'1.0',hwid=document.getElementById('ah')?.checked?1:0,dl=V('adl')||'1'
  if(!name) return toast('Uygulama adı gerekli','e')
  const r=await P('/admin/app/create',{owner_id:S.oid,name,version:ver,hwid_check:hwid,device_limit:+dl})
  if(r.success){toast(`✓ "${name}" oluşturuldu`,'s');await loadApps();S.app=S.apps.find(a=>a.name===name);document.getElementById('app-sel').value=S.app?.id||'';go('code')}
  else toast(r.message,'e')
}

async function toggleApp(aid,field){
  const r=await P('/admin/app/toggle',{owner_id:S.oid,app_id:aid,field})
  if(r.success){toast(r.message,'s');await loadApps();S.app=S.apps.find(a=>a.id===(S.app?.id||aid));rSet()}
  else toast(r.message,'e')
}

// ─── MODAL ────────────────────────────────────────────────────────────────────
function showMod(title,body,acts=[]){
  Q('#mt').textContent=title; Q('#mb').innerHTML=body
  Q('#mf').innerHTML='<button class="btn btn-ghost" onclick="closeMod()">Kapat</button>'
  acts.forEach(a=>{
    const btn=document.createElement('button'); btn.className='btn btn-primary'
    btn.textContent=a.text; btn.onclick=async()=>{await a.fn();if(!a.keep)closeMod()}
    Q('#mf').appendChild(btn)
  })
  Q('#ov').classList.remove('hidden')
}
function closeMod(e){if(e&&e.target!==Q('#ov'))return;Q('#ov').classList.add('hidden')}

// ─── UTILS ────────────────────────────────────────────────────────────────────
function Q(s){return document.querySelector(s)}
function V(id){return document.getElementById(id)?.value||''}
function esc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function copyT(t){navigator.clipboard.writeText(t);toast('Kopyalandı!','s')}
function toast(m,t='s'){
  const el=document.createElement('div'); el.className=`toast ${t}`; el.textContent=m
  document.body.appendChild(el); setTimeout(()=>el.remove(),3000)
}
document.getElementById('lp').addEventListener('keydown',e=>{if(e.key==='Enter')doLogin()})
document.getElementById('rp').addEventListener('keydown',e=>{if(e.key==='Enter')doReg()})
</script>
</body>
</html>"""

# ══════════════════════════════════════════════════════════════════════════════
# ADMIN API
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/admin/register")
async def admin_register(req: Request):
    d = await req.json()
    u, p = d.get("username","").strip(), d.get("password","")
    if not u or not p: return err("Tüm alanları doldurun")
    conn = get_db()
    if conn.execute("SELECT 1 FROM admins WHERE username=?", (u,)).fetchone():
        conn.close(); return err("Kullanıcı adı alınmış")
    oid = gen_owner_id()
    conn.execute("INSERT INTO admins VALUES(?,?,?,?)", (oid, u, hp(p), now()))
    conn.commit(); conn.close()
    return ok(message="Hesap oluşturuldu", owner_id=oid)

@app.post("/admin/login")
async def admin_login(req: Request):
    d = await req.json()
    conn = get_db()
    row = conn.execute("SELECT * FROM admins WHERE username=? AND password=?",
                       (d.get("username",""), hp(d.get("password","")))).fetchone()
    conn.close()
    if not row: return err("Geçersiz kullanıcı adı veya şifre")
    return ok(message="Giriş başarılı", owner_id=row["owner_id"])

@app.post("/admin/app/create")
async def app_create(req: Request):
    d = await req.json()
    oid, name = d.get("owner_id",""), d.get("name","").strip()
    if not oid or not name: return err("owner_id ve name gerekli")
    conn = get_db()
    if not conn.execute("SELECT 1 FROM admins WHERE owner_id=?", (oid,)).fetchone():
        conn.close(); return err("Geçersiz owner_id")
    if conn.execute("SELECT 1 FROM apps WHERE name=? AND owner_id=?", (name, oid)).fetchone():
        conn.close(); return err("Bu isimde uygulama var")
    aid = str(uuid.uuid4()); sec = secrets.token_hex(32)
    conn.execute("INSERT INTO apps (id,owner_id,name,secret,hwid_check,device_limit,version,created_at) VALUES(?,?,?,?,?,?,?,?)",
                 (aid, oid, name, sec, int(d.get("hwid_check",0)), int(d.get("device_limit",1)), d.get("version","1.0"), now()))
    conn.commit(); conn.close()
    return ok(message="Oluşturuldu", app_id=aid, name=name, secret=sec)

@app.get("/admin/app/list")
async def app_list(owner_id: str):
    conn = get_db()
    rows = conn.execute("SELECT * FROM apps WHERE owner_id=?", (owner_id,)).fetchall()
    conn.close()
    return ok(apps=[dict(r) for r in rows])

@app.post("/admin/app/toggle")
async def app_toggle(req: Request):
    d = await req.json()
    field = d.get("field","enabled")
    if field not in ("enabled","paused"): return err("Geçersiz")
    conn = get_db()
    row = conn.execute("SELECT * FROM apps WHERE id=? AND owner_id=?",
                       (d.get("app_id"), d.get("owner_id"))).fetchone()
    if not row: conn.close(); return err("Bulunamadı")
    nv = 0 if row[field] else 1
    conn.execute(f"UPDATE apps SET {field}=? WHERE id=?", (nv, d.get("app_id")))
    conn.commit(); conn.close()
    return ok(message=f"{field} → {nv}")

@app.post("/admin/key/create")
async def key_create(req: Request):
    d = await req.json()
    oid, aid = d.get("owner_id"), d.get("app_id")
    amount = min(int(d.get("amount",1)), 100)
    conn = get_db()
    if not conn.execute("SELECT 1 FROM apps WHERE id=? AND owner_id=?", (aid,oid)).fetchone():
        conn.close(); return err("Yetki yok")
    keys = []
    for _ in range(amount):
        k = gen_key(d.get("prefix","KEY"))
        conn.execute("INSERT INTO licenses (id,app_id,license_key,level,duration,note,created_at) VALUES(?,?,?,?,?,?,?)",
                     (str(uuid.uuid4()), aid, k, int(d.get("level",1)),
                      int(d.get("duration",30))*86400, d.get("note",""), now()))
        keys.append(k)
    conn.commit(); conn.close()
    return ok(message=f"{amount} key oluşturuldu", keys=keys)

@app.get("/admin/key/list")
async def key_list(owner_id:str, app_id:str, page:int=1, limit:int=25):
    conn = get_db()
    if not conn.execute("SELECT 1 FROM apps WHERE id=? AND owner_id=?", (app_id,owner_id)).fetchone():
        conn.close(); return err("Yetki yok")
    off = (page-1)*limit
    rows = conn.execute("SELECT * FROM licenses WHERE app_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                        (app_id, limit, off)).fetchall()
    total = conn.execute("SELECT COUNT(*) FROM licenses WHERE app_id=?", (app_id,)).fetchone()[0]
    conn.close()
    return ok(keys=[dict(r) for r in rows], total=total)

@app.post("/admin/key/ban")
async def key_ban(req: Request):
    d = await req.json()
    conn = get_db()
    if not conn.execute("SELECT 1 FROM apps WHERE id=? AND owner_id=?", (d.get("app_id"),d.get("owner_id"))).fetchone():
        conn.close(); return err("Yetki yok")
    row = conn.execute("SELECT * FROM licenses WHERE license_key=? AND app_id=?",
                       (d.get("key"),d.get("app_id"))).fetchone()
    if not row: conn.close(); return err("Bulunamadı")
    nv = 0 if row["banned"] else 1
    conn.execute("UPDATE licenses SET banned=?,ban_reason=? WHERE license_key=?",
                 (nv, d.get("reason",""), d.get("key")))
    conn.commit(); conn.close()
    return ok(message="Banlandı" if nv else "Ban kaldırıldı")

@app.post("/admin/key/delete")
async def key_delete(req: Request):
    d = await req.json()
    conn = get_db()
    if not conn.execute("SELECT 1 FROM apps WHERE id=? AND owner_id=?", (d.get("app_id"),d.get("owner_id"))).fetchone():
        conn.close(); return err("Yetki yok")
    conn.execute("DELETE FROM licenses WHERE license_key=? AND app_id=?", (d.get("key"),d.get("app_id")))
    conn.execute("DELETE FROM devices WHERE license_key=? AND app_id=?",  (d.get("key"),d.get("app_id")))
    conn.commit(); conn.close()
    return ok(message="Key ve cihazları silindi")

@app.post("/admin/key/reset-hwid")
async def key_reset_hwid(req: Request):
    d = await req.json()
    conn = get_db()
    if not conn.execute("SELECT 1 FROM apps WHERE id=? AND owner_id=?", (d.get("app_id"),d.get("owner_id"))).fetchone():
        conn.close(); return err("Yetki yok")
    conn.execute("DELETE FROM devices WHERE license_key=? AND app_id=?", (d.get("key"),d.get("app_id")))
    conn.commit(); conn.close()
    return ok(message="Tüm cihazlar sıfırlandı")

@app.get("/admin/user/list")
async def user_list(owner_id:str, app_id:str, page:int=1, limit:int=25):
    conn = get_db()
    if not conn.execute("SELECT 1 FROM apps WHERE id=? AND owner_id=?", (app_id,owner_id)).fetchone():
        conn.close(); return err("Yetki yok")
    off = (page-1)*limit
    rows = conn.execute("SELECT id,username,ip,level,banned,ban_reason,created_at,last_login,expires_at,license_key FROM users WHERE app_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                        (app_id,limit,off)).fetchall()
    total = conn.execute("SELECT COUNT(*) FROM users WHERE app_id=?", (app_id,)).fetchone()[0]
    conn.close()
    return ok(users=[dict(r) for r in rows], total=total)

@app.post("/admin/user/ban")
async def user_ban(req: Request):
    d = await req.json()
    conn = get_db()
    if not conn.execute("SELECT 1 FROM apps WHERE id=? AND owner_id=?", (d.get("app_id"),d.get("owner_id"))).fetchone():
        conn.close(); return err("Yetki yok")
    row = conn.execute("SELECT * FROM users WHERE username=? AND app_id=?",
                       (d.get("username"),d.get("app_id"))).fetchone()
    if not row: conn.close(); return err("Bulunamadı")
    nv = 0 if row["banned"] else 1
    conn.execute("UPDATE users SET banned=?,ban_reason=? WHERE username=? AND app_id=?",
                 (nv, d.get("reason",""), d.get("username"), d.get("app_id")))
    conn.commit(); conn.close()
    return ok(message="Banlandı" if nv else "Ban kaldırıldı")

@app.post("/admin/user/reset-hwid")
async def user_reset_hwid(req: Request):
    d = await req.json()
    conn = get_db()
    if not conn.execute("SELECT 1 FROM apps WHERE id=? AND owner_id=?", (d.get("app_id"),d.get("owner_id"))).fetchone():
        conn.close(); return err("Yetki yok")
    conn.execute("DELETE FROM devices WHERE username=? AND app_id=?", (d.get("username"),d.get("app_id")))
    conn.commit(); conn.close()
    return ok(message="Cihazlar sıfırlandı")

@app.get("/admin/device/list")
async def device_list(owner_id:str, app_id:str):
    conn = get_db()
    if not conn.execute("SELECT 1 FROM apps WHERE id=? AND owner_id=?", (app_id,owner_id)).fetchone():
        conn.close(); return err("Yetki yok")
    rows = conn.execute("SELECT * FROM devices WHERE app_id=? ORDER BY created_at DESC", (app_id,)).fetchall()
    conn.close()
    return ok(devices=[dict(r) for r in rows])

@app.post("/admin/device/remove")
async def device_remove(req: Request):
    d = await req.json()
    conn = get_db()
    if not conn.execute("SELECT 1 FROM apps WHERE id=? AND owner_id=?", (d.get("app_id"),d.get("owner_id"))).fetchone():
        conn.close(); return err("Yetki yok")
    conn.execute("DELETE FROM devices WHERE id=? AND app_id=?", (d.get("device_id"),d.get("app_id")))
    conn.commit(); conn.close()
    return ok(message="Cihaz kaldırıldı")

@app.get("/admin/stats")
async def stats(owner_id:str, app_id:str):
    conn = get_db()
    if not conn.execute("SELECT 1 FROM apps WHERE id=? AND owner_id=?", (app_id,owner_id)).fetchone():
        conn.close(); return err("Yetki yok")
    tk = conn.execute("SELECT COUNT(*) FROM licenses WHERE app_id=?", (app_id,)).fetchone()[0]
    uk = conn.execute("SELECT COUNT(*) FROM licenses WHERE app_id=? AND used=1", (app_id,)).fetchone()[0]
    bk = conn.execute("SELECT COUNT(*) FROM licenses WHERE app_id=? AND banned=1", (app_id,)).fetchone()[0]
    tu = conn.execute("SELECT COUNT(*) FROM users WHERE app_id=?", (app_id,)).fetchone()[0]
    bu = conn.execute("SELECT COUNT(*) FROM users WHERE app_id=? AND banned=1", (app_id,)).fetchone()[0]
    td = conn.execute("SELECT COUNT(*) FROM devices WHERE app_id=?", (app_id,)).fetchone()[0]
    conn.close()
    return ok(keys=dict(total=tk,used=uk,unused=tk-uk,banned=bk),
              users=dict(total=tu,banned=bu), devices=dict(total=td))

@app.get("/admin/logs")
async def logs(owner_id:str, app_id:str, limit:int=100):
    conn = get_db()
    if not conn.execute("SELECT 1 FROM apps WHERE id=? AND owner_id=?", (app_id,owner_id)).fetchone():
        conn.close(); return err("Yetki yok")
    rows = conn.execute("SELECT * FROM logs WHERE app_id=? ORDER BY created_at DESC LIMIT ?",
                        (app_id,limit)).fetchall()
    conn.close()
    return ok(logs=[dict(r) for r in rows])

# ══════════════════════════════════════════════════════════════════════════════
# CLIENT API — HMAC İMZALAMA + DEVICE LİMİTİ
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/api/v1/")
async def client_api(req: Request):
    try:
        form = await req.form(); data = dict(form)
    except:
        try: data = await req.json()
        except: return JSONResponse(err("Geçersiz format"))

    action   = data.get("type","")
    owner_id = data.get("ownerid","")
    app_name = data.get("name","")
    ip       = get_ip(req)

    if not owner_id or not app_name:
        return JSONResponse(err("ownerid ve name gerekli"))

    conn = get_db()
    app_row = conn.execute("SELECT * FROM apps WHERE owner_id=? AND name=?",
                           (owner_id, app_name)).fetchone()
    conn.close()
    if not app_row: return JSONResponse(err("Uygulama bulunamadı"))
    aid = app_row["id"]

    # ── INIT ──────────────────────────────────────────────────────────────────
    if action == "init":
        if not app_row["enabled"]: return JSONResponse(err("Uygulama devre dışı"))
        if app_row["paused"]:      return JSONResponse(err("Uygulama duraklatılmış"))
        sid = secrets.token_hex(16)
        conn = get_db()
        conn.execute("INSERT INTO sessions (session_id,app_id,secret,created_at) VALUES(?,?,?,?)",
                     (sid, aid, app_row["secret"], now()))
        conn.commit(); conn.close()
        resp = ok(message="OK", sessionid=sid,
                  appinfo={"version":app_row["version"],"name":app_row["name"]})
        resp["signature"] = sign_response(resp, app_row["secret"])
        return JSONResponse(resp)

    # ── Oturum ────────────────────────────────────────────────────────────────
    sid = data.get("sessionid","")
    conn = get_db()
    sess = conn.execute("SELECT * FROM sessions WHERE session_id=? AND app_id=?",
                        (sid, aid)).fetchone()
    conn.close()
    if not sess: return JSONResponse(err("Geçersiz oturum. init() çağırın"))

    app_secret = sess["secret"]

    def signed(d: dict):
        d["signature"] = sign_response(d, app_secret)
        return JSONResponse(d)

    # ── REGISTER ──────────────────────────────────────────────────────────────
    if action == "register":
        username = data.get("username","").strip()
        password = data.get("pass","")
        key      = data.get("key","").strip()
        hwid     = data.get("hwid","")

        if not username or not password or not key:
            return signed(err("Eksik bilgi"))
        if len(username) < 3:
            return signed(err("Kullanıcı adı çok kısa (min 3)"))

        conn = get_db()
        if conn.execute("SELECT 1 FROM users WHERE username=? AND app_id=?", (username,aid)).fetchone():
            conn.close(); return signed(err("Bu kullanıcı adı alınmış"))

        lic = conn.execute("SELECT * FROM licenses WHERE license_key=? AND app_id=?", (key,aid)).fetchone()
        if not lic: conn.close(); add_log(aid,"reg_fail",username,"Geçersiz key",ip); return signed(err("Geçersiz key"))
        if lic["banned"]: conn.close(); return signed(err(f"Key banlı: {lic['ban_reason'] or ''}"))
        if lic["used"]: conn.close(); return signed(err("Key zaten kullanılmış"))

        # Device limit kontrol
        device_limit = app_row["device_limit"]
        if device_limit > 0 and hwid:
            dc = get_device_count(conn, aid, key)
            if dc >= device_limit:
                conn.close(); return signed(err(f"Bu key maksimum {device_limit} cihazda kullanılabilir"))

        expires_at = now() + lic["duration"]
        conn.execute("INSERT INTO users (id,app_id,username,password,ip,license_key,level,created_at,last_login,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                     (str(uuid.uuid4()), aid, username, hp(password), ip, key, lic["level"], now(), now(), expires_at))
        conn.execute("UPDATE licenses SET used=1,used_by=? WHERE license_key=?", (username, key))

        if hwid:
            conn.execute("INSERT OR IGNORE INTO devices (id,app_id,license_key,hwid,username,ip,created_at) VALUES(?,?,?,?,?,?,?)",
                         (str(uuid.uuid4()), aid, key, hwid, username, ip, now()))

        conn.commit(); conn.close()
        add_log(aid,"register",username,"Başarılı",ip)
        return signed(ok(message="Kayıt başarılı!", info=_uinfo(username,ip,hwid,now(),expires_at,lic["level"])))

    # ── LOGIN ─────────────────────────────────────────────────────────────────
    elif action == "login":
        username = data.get("username","").strip()
        password = data.get("pass","")
        hwid     = data.get("hwid","")

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username=? AND app_id=?", (username,aid)).fetchone()
        if not user: conn.close(); return signed(err("Kullanıcı bulunamadı"))
        if user["password"] != hp(password): conn.close(); return signed(err("Şifre hatalı"))
        if user["banned"]: conn.close(); return signed(err(f"Hesap banlı: {user['ban_reason'] or ''}"))
        if user["expires_at"] and user["expires_at"] < now(): conn.close(); return signed(err("Abonelik sona erdi"))

        # Device limit
        device_limit = app_row["device_limit"]
        if device_limit > 0 and hwid:
            existing = conn.execute("SELECT 1 FROM devices WHERE app_id=? AND license_key=? AND hwid=?",
                                    (aid, user["license_key"], hwid)).fetchone()
            if not existing:
                dc = get_device_count(conn, aid, user["license_key"])
                if dc >= device_limit:
                    conn.close(); return signed(err(f"Maksimum {device_limit} cihaz sınırına ulaşıldı"))
                conn.execute("INSERT OR IGNORE INTO devices (id,app_id,license_key,hwid,username,ip,created_at) VALUES(?,?,?,?,?,?,?)",
                             (str(uuid.uuid4()), aid, user["license_key"], hwid, username, ip, now()))

        conn.execute("UPDATE users SET ip=?,last_login=? WHERE username=? AND app_id=?", (ip, now(), username, aid))
        conn.commit(); conn.close()
        add_log(aid,"login",username,"Başarılı",ip)
        return signed(ok(message="Giriş başarılı!", info=_uinfo(username,ip,hwid,user["created_at"],user["expires_at"],user["level"])))

    # ── LICENSE ───────────────────────────────────────────────────────────────
    elif action == "license":
        key  = data.get("key","").strip()
        hwid = data.get("hwid","")
        if not key: return signed(err("Key gerekli"))

        conn = get_db()
        lic = conn.execute("SELECT * FROM licenses WHERE license_key=? AND app_id=?", (key,aid)).fetchone()
        if not lic: conn.close(); add_log(aid,"lic_fail",None,f"Geçersiz: {key[:8]}",ip); return signed(err("Geçersiz key"))
        if lic["banned"]: conn.close(); return signed(err(f"Key banlı: {lic['ban_reason'] or ''}"))

        device_limit = app_row["device_limit"]

        if not lic["used"]:
            expires_at = now() + lic["duration"]
            uname = f"user_{key[:8].lower()}"
            conn.execute("INSERT OR IGNORE INTO users (id,app_id,username,password,ip,license_key,level,created_at,last_login,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                         (str(uuid.uuid4()), aid, uname, hp(key), ip, key, lic["level"], now(), now(), expires_at))
            conn.execute("UPDATE licenses SET used=1,used_by=?,expires_at=? WHERE license_key=?", (uname, expires_at, key))
        else:
            expires_at = lic["expires_at"] or (now() + lic["duration"])
            uname = lic["used_by"] or key[:8]
            if expires_at and expires_at < now():
                conn.close(); return signed(err("Key süresi doldu"))

        # Device limit kontrol
        if device_limit > 0 and hwid:
            existing = conn.execute("SELECT 1 FROM devices WHERE app_id=? AND license_key=? AND hwid=?",
                                    (aid, key, hwid)).fetchone()
            if not existing:
                dc = get_device_count(conn, aid, key)
                if dc >= device_limit:
                    conn.close(); return signed(err(f"Bu key maksimum {device_limit} cihazda kullanılabilir"))
                conn.execute("INSERT OR IGNORE INTO devices (id,app_id,license_key,hwid,username,ip,created_at) VALUES(?,?,?,?,?,?,?)",
                             (str(uuid.uuid4()), aid, key, hwid, uname, ip, now()))

        conn.commit(); conn.close()
        add_log(aid,"license",uname,"Başarılı",ip)
        return signed(ok(message="Lisans doğrulandı!", info=_uinfo(uname,ip,hwid,lic["created_at"],expires_at,lic["level"])))

    elif action == "check":
        return signed(ok(message="OK"))

    elif action == "log":
        add_log(aid,"client_log",data.get("pcuser"),data.get("message"),ip)
        return signed(ok(message="OK"))

    return JSONResponse(err(f"Bilinmeyen işlem: {action}"))

def _uinfo(username, ip, hwid, created, expires, level):
    return {"username":username,"ip":ip,"hwid":hwid or "N/A",
            "createdate":str(created),"lastlogin":str(now()),
            "subscriptions":[{"subscription":f"level{level}","expiry":str(expires)}]}

@app.get("/health")
async def health(): return {"status":"ok","ts":now()}

if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=int(os.environ.get("PORT",8000)), reload=False)
