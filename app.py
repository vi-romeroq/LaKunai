import streamlit as st
import streamlit.components.v1 as components
from dotenv import load_dotenv
import os
import datetime
import pandas as pd
from analyzer import StandardAnalyzer
import hashlib

# --- Cloud-Ready Database ORM (SQLAlchemy Setup) ---
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker

load_dotenv()
DB_URL = os.getenv("DATABASE_URL", "sqlite:///lakunai_fallback.db")
connect_args = {"check_same_thread": False} if "sqlite" in DB_URL else {}
engine = create_engine(DB_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    role = Column(String, default="AUDITOR_LEGAL")
    plan = Column(String, default="FREE")

class Usage(Base):
    __tablename__ = "usage"
    username = Column(String, primary_key=True)
    count = Column(Integer, default=0)

class Audit(Base):
    __tablename__ = "audits"
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String, index=True)
    doc_name = Column(String)
    risk_tier = Column(String)
    audit_date = Column(DateTime)

Base.metadata.create_all(bind=engine)

def get_usage(username):
    try:
        db = SessionLocal()
        u = db.query(Usage).filter(Usage.username == username).first()
        return u.count if u else 0
    finally:
        db.close()

def increment_usage(username):
    try:
        db = SessionLocal()
        u = db.query(Usage).filter(Usage.username == username).first()
        if u: u.count += 1
        else: db.add(Usage(username=username, count=1))
        db.commit()
    finally:
        db.close()

def save_audit(username, doc_name, risk_tier):
    try:
        db = SessionLocal()
        new_audit = Audit(username=username, doc_name=doc_name, risk_tier=risk_tier, audit_date=datetime.datetime.now())
        db.add(new_audit)
        db.commit()
    finally:
        db.close()

def get_audits(username):
    try:
        db = SessionLocal()
        audits = db.query(Audit).filter(Audit.username == username).order_by(Audit.id.desc()).all()
        return [(a.doc_name, a.risk_tier, a.audit_date.strftime("%Y-%m-%d %H:%M:%S")) for a in audits]
    finally:
        db.close()

def register_user(username, password, role="AUDITOR_LEGAL"):
    db = SessionLocal()
    try:
        if db.query(User).filter(User.username == username).first(): return False
        db.add(User(username=username, password_hash=hashlib.sha256(password.encode()).hexdigest(), role=role, plan="FREE"))
        db.commit()
        return True
    finally:
        db.close()

def authenticate_user(username, password):
    db = SessionLocal()
    try:
        u = db.query(User).filter(User.username == username).first()
        if u and u.password_hash == hashlib.sha256(password.encode()).hexdigest():
            return u.username, u.role, u.plan
        return None, None, None
    finally:
        db.close()

@st.cache_data
def get_extracted_text(file_content_bytes, file_name):
    class DummyFile:
        def __init__(self, b, n): self.bytes, self.name = b, n
        def read(self): return self.bytes
        def getvalue(self): return self.bytes
        def seek(self, *args): pass
    return StandardAnalyzer().extract_text(DummyFile(file_content_bytes, file_name))


st.set_page_config(page_title="Lakunai | AI Enterprise GRC", page_icon="🧿", layout="wide", initial_sidebar_state="expanded")

# --- ULTRA PREMIUM CSS DESIGN ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;600;800&family=JetBrains+Mono:wght@400;700&display=swap');
    .stApp { 
        background-color: #050b14 !important;
        background-image: radial-gradient(circle at 50% 0%, #0c1838 0%, #050b14 60%);
        background: radial-gradient(circle at 10% 20%, rgb(9, 14, 25) 0%, rgb(3, 7, 18) 100%);
        color: #f1f5f9; font-family: 'Plus Jakarta Sans', sans-serif; 
    }
    .stApp::before {
        content: ""; position: fixed; inset: 0; pointer-events: none;
        background-image: 
            radial-gradient(circle at top right, rgba(56, 189, 248, 0.08) 0%, transparent 40%),
            radial-gradient(circle at bottom left, rgba(129, 140, 248, 0.08) 0%, transparent 40%);
        z-index: 0;
    }
    [data-testid="stHeader"] { background-color: transparent !important; }
    .block-container {
        background: rgba(15, 23, 42, 0.3) !important; 
        backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);
        border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 24px;
        padding-top: 3rem !important; padding-bottom: 3rem !important; margin-top: 2rem;
        box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.1);
        z-index: 1; position: relative;
    }
    [data-testid="stSidebar"] { 
        background: rgba(2, 6, 23, 0.8) !important; backdrop-filter: blur(30px); border-right: 1px solid rgba(255, 255, 255, 0.05); 
    }
    [data-testid="stSidebar"] p, [data-testid="stSidebar"] label, [data-testid="stSidebar"] small, [data-testid="stSidebar"] span, [data-testid="stSidebar"] h1, [data-testid="stSidebar"] h2, [data-testid="stSidebar"] h3 {
        color: #ffffff !important; text-shadow: 0 1px 3px rgba(0,0,0,0.8); font-weight: 600 !important;
    }
    [data-testid="stSidebar"] [data-baseweb="select"] span {
        color: #f8fafc !important;
    }
    .stButton>button { 
        background: linear-gradient(135deg, #0284c7 0%, #2563eb 100%); color: white !important; border: 1px solid rgba(255,255,255,0.1) !important; 
        border-radius: 12px !important; font-weight: 600; font-family: 'Plus Jakarta Sans', sans-serif;
        padding: 0.8rem 2rem !important; transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
        box-shadow: 0 4px 20px -2px rgba(37, 99, 235, 0.4) !important; letter-spacing: 0.5px;
    }
    .stButton>button:hover { 
        transform: translateY(-3px) scale(1.02); box-shadow: 0 8px 30px rgba(37, 99, 235, 0.6) !important; 
        background: linear-gradient(135deg, #38bdf8 0%, #3b82f6 100%) !important;
    }
    .stTabs [data-baseweb="tab-list"] { background-color: transparent !important; gap: 15px; border-bottom: 1px solid rgba(255, 255, 255, 0.08); padding-bottom: 2px;}
    .stTabs [data-baseweb="tab"] { background-color: transparent !important; border: none !important; color: #94a3b8 !important; font-family: 'Plus Jakarta Sans', sans-serif; font-weight: 600; font-size: 1.05rem; padding: 12px 16px; transition: all 0.2s;}
    .stTabs [aria-selected="true"] { color: #38bdf8 !important; border-bottom: 3px solid #38bdf8 !important; background: linear-gradient(0deg, rgba(56, 189, 248, 0.1) 0%, transparent 100%) !important; text-shadow: 0 0 15px rgba(56, 189, 248, 0.4);}
    .stTabs [data-baseweb="tab"]:hover { color: #f8fafc !important; }
    .stTextInput input, .stSelectbox [data-baseweb="select"], .stTextArea textarea { 
        background-color: rgba(30, 41, 59, 0.5) !important; color: white !important; 
        border: 1px solid rgba(255,255,255,0.1) !important; border-radius: 10px; font-family: 'JetBrains Mono', monospace;
    }
    .stTextInput input:focus { border-color: #38bdf8 !important; box-shadow: 0 0 0 1px #38bdf8 !important; }
    .risk-badge { padding: 8px 18px; border-radius: 30px; font-weight: 800; display: inline-block; margin-bottom: 25px; text-transform: uppercase; letter-spacing: 1.5px; font-size: 0.85rem;}
    .risk-unacceptable { background: linear-gradient(90deg, rgba(239,68,68,0.2), transparent); border: 1px solid #ef4444; color: #fca5a5; box-shadow: 0 0 20px rgba(239,68,68,0.3);}
    .risk-high { background: linear-gradient(90deg, rgba(249,115,22,0.2), transparent); border: 1px solid #f97316; color: #fdba74; box-shadow: 0 0 20px rgba(249,115,22,0.3);}
    .risk-limited { background: linear-gradient(90deg, rgba(234,179,8,0.2), transparent); border: 1px solid #eab308; color: #fde047; box-shadow: 0 0 20px rgba(234,179,8,0.3);}
    .risk-minimal { background: linear-gradient(90deg, rgba(34,197,94,0.2), transparent); border: 1px solid #22c55e; color: #86efac; box-shadow: 0 0 20px rgba(34,197,94,0.3);}
</style>
""", unsafe_allow_html=True)

T = {
    "Spanish": {
        "hero_sub": "Cierra los vacíos antes de que<br><span>te cuesten millones.</span>",
        "auth": "### 🔐 Acceso Cifrado (RBAC)", "user_l": "Usuario Corporativo", "pass_l": "Contraseña Segura", "btn_login": "🔑 Autenticar Módulo",
        "warn": "Role-Based Access Control Activo", "limit": "⚠️ **Límite Corporativo Alcanzado**", "rem": "Auditorías de la Suite:",
        "inv_txt": "🌟 **Memoria Institucional Activa:** Búsqueda retrospectiva RAG activada para tu compañía.",
        "lang": "🌐 Idioma (i18n):", "domain": "📂 Industria:", "jur": "⚖️ Marco Regulatorio:",
        
        "t1": "🛡️ Auditoría Documental", "t2": "📊 Dashboard de IA", "t3": "🛠️ Buró Legal (RAG)", "t4": "📄 Model Cards", "t5": "🎯 Red-Teaming (Auditoría Viva)", "t6": "🔗 Hub de APIs (DevOps)",
        
        "t1_h": "### Ingesta de Políticas y Contratos", "up_l": "📂 Documentos (Filtro Anti-PII Activo)", "run_a": "🚀 Ejecutar Análisis de Riesgo GRC",
        "spin": "Procesando de forma segura vía LLM...", "err_ext": "Sin texto.", "risk_t": "Clasificación Automática de Riesgo:",
        "rep_t": "### 📊 Reporte Estratégico Oficial", "down_r": "📥 Descargar Reporte (PDF/TXT)",
        "audit_succ": "✅ Auditoría guardada en la Base de Datos Histórica (Vectorial RAG).",
        
        "t2_h": "### Estado Global de Riesgo (Dashboard)", "t2_n": "Sin registros en la base de datos central.", "t2_w": "Inicia sesión segura.",
        "t2_c": ["Documento", "Nivel de Riesgo", "Timestamp del Sistema"],
        
        "t3_h": "### Asistente Legal de Mitigación (Memoria RAG)", "t3_d": "Nuestra IA redactará automáticamente las cláusulas exactas. Al tener RAG activado, recordará tu contexto corporativo completo.",
        "t3_n": "Rastreador inactivo. Requiere una auditoría previa.", "t3_ctx": "Contexto legal activo:",
        
        "t4_h": "### Motor Transparencia: AI Model Cards", "t4_d": "Sube el manual de tu modelo y Lakunai extraerá su equivalente a un ISO/UE Model Card oficial.",
        "t4_btn": "🛠️ Compilar Model Card ISO", "t4_up": "📂 Sube los Datasets / Arquitectura",
        
        "t5_h": "### Laboratorio de Hacker Ético Adversarial 🎯", "t5_d": "Ingresa un Endpoint real. LAKUNAI ejecutará peticiones HTTP POST reales inyectando prompts tóxicos.",
        "t5_url": "URL / Endpoint Real del Modelo de IA", "t5_atk": "⚔️ Lanzar Ataque GRC (Red-Teaming)",
        
        "t6_h": "### Hub de Integración Continua (CI/CD) 🔗", "t7": "📖 Sobre Lakunai", "t6_d": "Sincroniza Lakunai directamente con tus flujos de despliegue.",
    },
    "English": {
        "hero_sub": "The AI that finds what<br><span>the law can't see.</span>",
        "auth": "### 🔐 RBAC Secure Access", "user_l": "Corporate User", "pass_l": "Secure Password", "btn_login": "🔑 Authenticate",
        "warn": "Role-Based Access Control Active", "limit": "⚠️ **Corporate Limit Reached**", "rem": "Suite Audits:",
        "inv_txt": "🌟 **Institutional Memory Active:** RAG retrospective search enabled for your company.",
        "lang": "🌐 UI Language:", "domain": "📂 Industry:", "jur": "⚖️ Regulatory Framework:",
        
        "t1": "🛡️ Document Audit", "t2": "📊 AI Dashboard", "t3": "🛠️ Remediation Desk", "t4": "📄 Model Cards", "t5": "🎯 Red-Teaming (Live Audit)", "t6": "🔗 DevOps API Hub",
        
        "t1_h": "### Ingest Policies & Contracts", "up_l": "📂 Upload Documents (Anti-PII Active)", "run_a": "🚀 Execute GRC Risk Analysis",
        "spin": "Processing securely via LLM...", "err_ext": "No text.", "risk_t": "Automated Risk Classification:",
        "rep_t": "### 📊 Official Strategic Report", "down_r": "📥 Download SEC/Audit Ready Report",
        "audit_succ": "✅ Audit saved to Historical Vectorial DB (RAG).",
        
        "t2_h": "### Global Risk Status (Dashboard)", "t2_n": "No active records in the central DB.", "t2_w": "Secure login required.",
        "t2_c": ["Document", "Risk Threshold", "System Timestamp"],
        
        "t3_h": "### Legal Mitigation Assistant (RAG Memory)", "t3_d": "The AI Counsel will automatically draft the precise clauses. With RAG enabled, it remembers your entire corporate context.",
        "t3_n": "Tracker inactive. Requires a prior audit.", "t3_ctx": "Active legal context:",
        
        "t4_h": "### Transparency Engine: AI Model Cards", "t4_d": "Upload your model's pipeline/documentation and Lakunai will extract an ISO/EU standard Model Card.",
        "t4_btn": "🛠️ Compile ISO Model Card", "t4_up": "📂 Upload Technical Architecture",
        
        "t5_h": "### Ethical Hacker / Adversarial Lab 🎯", "t5_d": "Enter a real endpoint. LAKUNAI will execute HTTP POST requests injecting toxic prompts to test the target.",
        "t5_url": "AI Model HTTP Endpoint", "t5_atk": "⚔️ Launch GRC Attack (Red-Teaming)",
        
        "t6_h": "### Continuous Integration Hub (CI/CD) 🔗", "t6_d": "Sync Lakunai directly with your deployment pipelines.",
    }
}

def main():
    if 'auth_username' not in st.session_state: 
        st.session_state['auth_username'] = None
        st.session_state['auth_role'] = None
        st.session_state['auth_plan'] = None

    import os as os_sys
    if os_sys.path.exists("logo.png"):
        st.sidebar.image("logo.png", use_container_width=True)
    else:
        st.sidebar.image("https://cdn-icons-png.flaticon.com/512/2059/2059080.png", width=70)
    target_lang_opt = st.sidebar.selectbox("🌐 GRC Language / Interfaz:", ["Spanish", "English"])
    loc = T.get(target_lang_opt, T["Spanish"])
    
    hero_html = f"""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@700;800;900&display=swap');
        .hero-container {{ text-align: center; padding: 2.5rem 1rem; background: linear-gradient(180deg, rgba(15,23,42,0.8) 0%, rgba(2,6,23,0.9) 100%); border-radius: 24px; margin-bottom: 2rem; border: 1px solid rgba(56, 189, 248, 0.15); position: relative; overflow: hidden;}}
        .hero-container::before {{ content: ''; position: absolute; left: 0; top: 0; width: 100%; height: 2px; background: linear-gradient(90deg, transparent, #38bdf8, transparent); opacity: 0.5; }}
        .hero-badge {{ display: inline-block; background: rgba(56, 189, 248, 0.1); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 30px; padding: 6px 20px; font-size: 0.8rem; letter-spacing: 3px; text-transform: uppercase; color: #7dd3fc; margin-bottom: 20px; font-family: 'Plus Jakarta Sans', sans-serif; font-weight: 800; box-shadow: 0 0 20px rgba(56,189,248,0.1);}}
        .hero-title {{ font-family: 'Plus Jakarta Sans', sans-serif !important; font-size: 3.5rem; font-weight: 900; color: #ffffff; line-height: 1.1; margin-bottom: 0px; letter-spacing: -1px;}}
        .hero-title span {{ background: linear-gradient(90deg, #38bdf8, #818cf8); -webkit-background-clip: text; -webkit-text-fill-color: transparent; filter: drop-shadow(0 0 10px rgba(56,189,248,0.3));}}
    </style>
    <div class="hero-container">
        <div class="hero-badge">⚡ LAKUNAI ENTERPRISE ENGINE (V10)</div>
        <p class="hero-title">{loc["hero_sub"]}</p>
    </div>
    """
    components.html(hero_html, height=280, scrolling=False)
    
    if not st.session_state['auth_username']:
        auth_tabs = st.sidebar.tabs(["🔑 Ingresar", "📝 Registro", "👁️ Anónimo"])
        
        with auth_tabs[0]:
            st.markdown("### Acceso Corporativo")
            u_in = st.text_input("Usuario", key="log_u")
            p_in = st.text_input("Contraseña", type="password", key="log_p")
            if st.button("Iniciar Sesión", use_container_width=True):
                un, role, plan = authenticate_user(u_in, p_in)
                if un:
                    st.session_state['auth_username'] = un
                    st.session_state['auth_role'] = role
                    st.session_state['auth_plan'] = plan
                    st.rerun()
                else:
                    st.error("Credenciales erróneas o cuenta inexistente.")
        
        with auth_tabs[1]:
            st.markdown("### Cuenta Nueva")
            r_un = st.text_input("Usuario", key="reg_u")
            r_pw = st.text_input("Contraseña", type="password", key="reg_p")
            r_rol = st.selectbox("Rol", ["AUDITOR_LEGAL", "ADMINISTRADOR", "INGENIERO_IA"])
            if st.button("Crear Cuenta Gratuita (3 Auditorías)", use_container_width=True):
                if r_un and r_pw:
                    if register_user(r_un, r_pw, r_rol):
                        st.success("✅ Cuenta B2B Creada. Ya puedes iniciar sesión.")
                    else:
                        st.error("❌ Ese nombre de usuario ya está tomado.")
                else:
                    st.error("Llena ambos campos.")
        
        with auth_tabs[2]:
            st.markdown("### Modo Exploración")
            st.caption("Prueba la IA 1 vez sin dejar datos.")
            if st.button("Auditar Gratis (1 Crédito)", use_container_width=True):
                st.session_state['auth_username'] = "GUEST_SESSION"
                st.session_state['auth_role'] = "INVITADO"
                st.session_state['auth_plan'] = "GUEST"
                st.rerun()
        st.stop()
    else:
        username = st.session_state['auth_username']
        role = st.session_state['auth_role']
        plan = st.session_state['auth_plan']
        
        st.sidebar.markdown(f"### 👤 Mi Perfil")
        st.sidebar.write(f"**Usuario:** `{username}`")
        st.sidebar.write(f"**Plan:** `{'👑 PRO Ilimitado' if plan == 'PRO' else 'Suscripción Gratuita'}`")
        st.sidebar.success(f"🔒 Nivel de Seguridad: **{role}**")
        st.sidebar.markdown("---")
        
        if plan == "GUEST":
            usage_count = st.session_state.get('guest_uses', 0)
            MAX_FREE_USES = 1
        else:
            usage_count = get_usage(username)
            MAX_FREE_USES = 3 if plan == "FREE" else 1000000 
        
        if plan == "FREE":
            st.sidebar.progress(usage_count / MAX_FREE_USES)
            if usage_count >= MAX_FREE_USES:
                st.sidebar.error("⚠️ **Cuota Terminada**")
                st.sidebar.markdown("<a href='https://lakunai.lemonsqueezy.com/checkout/buy/7f17e6f7-3f4f-4b8f-9892-92249b540952' target='_blank' style='display:inline-block; padding:8px 16px; background:#2563eb; color:white; border-radius:8px; text-decoration:none; font-weight:bold; width:100%; text-align:center;'>🚀 MEJORAR A LAKUNAI PRO ($199/m)</a>", unsafe_allow_html=True)
            else:
                st.sidebar.caption(f"Auditorías Usadas: {usage_count} / {MAX_FREE_USES}")
        elif plan == "GUEST":
            st.sidebar.progress(usage_count / MAX_FREE_USES)
            if usage_count >= MAX_FREE_USES:
                st.sidebar.error("⚠️ **Prueba Anónima Terminada**")
                st.sidebar.markdown("Para seguir auditando, **cierra sesión (abajo)** y créate una cuenta gratuita sumando 3 créditos más.")
            else:
                st.sidebar.caption(f"De un solo uso: {usage_count} / {MAX_FREE_USES}")
        else:
            st.sidebar.info("∞ Licencias Ilimitadas (Enterprise)")
            
        if st.sidebar.button("Cerrar Sesión"):
            st.session_state['auth_username'] = None
            st.session_state['auth_role'] = None
            st.session_state['auth_plan'] = None
            st.rerun()


    domain = st.sidebar.selectbox(loc["domain"], [
        "👩‍💼 Recursos Humanos (Sesgos en Contratación)", 
        "⛏️ Minería / Automatización Industrial", 
        "🏥 Salud y Privacidad Médica (Datos de Pacientes)", 
        "🎓 Educación (Evaluación Académica Justa)", 
        "⚖️ Legal Corporativo (Contratos y NDAs)", 
        "💳 Servicios Financieros o Retail (Decisión de Crédito)"
    ])
    jurisdiction = st.sidebar.selectbox(loc["jur"], ["Chile (Ley N° 19.628 / Proyecto Ley IA)", "EU AI Act (Europa)", "USA (NIST AI RMF)"])

    allowed_tab_names = []
    t7_name = loc.get("t7", "📖 Sobre Lakunai")
    if role == "ADMINISTRADOR": allowed_tab_names = [t7_name, loc["t1"], loc["t2"], loc["t3"], loc["t4"], loc["t5"], loc["t6"]]
    elif role == "AUDITOR_LEGAL": allowed_tab_names = [t7_name, loc["t1"], loc["t2"], loc["t3"]]
    elif role == "INGENIERO_IA": allowed_tab_names = [t7_name, loc["t2"], loc["t4"], loc["t5"], loc["t6"]]
    elif role == "INVITADO": allowed_tab_names = [t7_name, loc["t1"]]
        
    tabs = st.tabs(allowed_tab_names)
    username = st.session_state['auth_username']
    tab_idx = 0

    # 0. SOBRE LAKUNAI (Landing)
    if loc.get("t7", "📖 Sobre Lakunai") in allowed_tab_names:
        with tabs[tab_idx]:
            st.markdown("""
            <div style="text-align:center; padding:10px 0 40px 0;">
                <h1 style="color:#f8fafc; font-size:2.8rem; font-weight:800; line-height:1.2; margin-bottom:15px; font-family:'Plus Jakarta Sans', sans-serif;">¿ESTÁ TU EMPRESA REALMENTE PREPARADA<br><span style="color:#38bdf8;">PARA ADOPTAR LA INTELIGENCIA ARTIFICIAL?</span></h1>
                <h3 style="color:#94a3b8; font-weight:400; font-size:1.3rem;">Lakunai audita tu infraestructura proactivamente para identificar y mitigar riesgos antes de un despliegue de IA.</h3>
            </div>
            """, unsafe_allow_html=True)
            c1, c2, c3 = st.columns(3)
            with c1:
                st.markdown("""<div style='background:linear-gradient(180deg, rgba(15,23,42,0.9), rgba(2,6,23,0.9)); padding:30px; border-radius:20px; border-top:4px solid #38bdf8; height:100%; box-shadow:0 10px 30px rgba(0,0,0,0.5);'>
                <div style='font-size:2.5rem; margin-bottom:15px;'>🔍</div>
                <h4 style='color:#f8fafc; font-size:1.1rem; line-height:1.4; font-weight:800;'>DETECTA PELIGROS OCULTOS</h4>
                <p style='color:#cbd5e1; font-size:0.95rem; line-height:1.6;'>Un humano no lo ve, Lakunai sí. Analiza al instante cómo configuras tu IA.<br><br><i>Ejemplo: Alerta sobre discriminación de género en filtros de RR.HH, previniendo demandas y escándalos.</i></p></div>""", unsafe_allow_html=True)
            with c2:
                st.markdown("""<div style='background:linear-gradient(180deg, rgba(15,23,42,0.9), rgba(2,6,23,0.9)); padding:30px; border-radius:20px; border-top:4px solid #818cf8; height:100%; box-shadow:0 10px 30px rgba(0,0,0,0.5);'>
                <div style='font-size:2.5rem; margin-bottom:15px;'>🛡️</div>
                <h4 style='color:#f8fafc; font-size:1.1rem; line-height:1.4; font-weight:800;'>CENSURA DATOS AUTOMÁTICAMENTE</h4>
                <p style='color:#cbd5e1; font-size:0.95rem; line-height:1.6;'>Antes de salir a internet, borramos RUTs, Tarjetas de Crédito y correos electrónicos. Tus clientes y tu empresa están a salvo del robo de identidad y filtraciones.</p></div>""", unsafe_allow_html=True)
            with c3:
                st.markdown("""<div style='background:linear-gradient(180deg, rgba(15,23,42,0.9), rgba(2,6,23,0.9)); padding:30px; border-radius:20px; border-top:4px solid #2dd4bf; height:100%; box-shadow:0 10px 30px rgba(0,0,0,0.5);'>
                <div style='font-size:2.5rem; margin-bottom:15px;'>⚖️</div>
                <h4 style='color:#f8fafc; font-size:1.1rem; line-height:1.4; font-weight:800;'>TE GUÍA EN LA SOLUCIÓN</h4>
                <p style='color:#cbd5e1; font-size:0.95rem; line-height:1.6;'>Te entregamos propuestas de redacción dinámicas para apoyar a tus equipos legales a mitigar ágilmente los riesgos identificados. Basado en leyes de EE.UU., Europa y Chile.</p></div>""", unsafe_allow_html=True)
            tab_idx += 1

    # 1. AUDIT
    if loc["t1"] in allowed_tab_names:
        with tabs[tab_idx]:
            st.markdown(loc["t1_h"])
            uploaded_files = st.file_uploader(loc["up_l"], type=["pdf", "txt", "docx"], accept_multiple_files=True)
            analyze_btn = st.button(loc["run_a"], use_container_width=True, disabled=((usage_count >= 3 and plan == 'FREE') or (st.session_state.get('guest_uses', 0) >= 1 and plan == 'GUEST')))
            
            if analyze_btn and uploaded_files:
                with st.spinner(loc["spin"]):
                    analyzer = StandardAnalyzer()
                    combined_text = ""
                    doc_names = [f.name for f in uploaded_files]
                    for f in uploaded_files:
                        extracted = get_extracted_text(f.getvalue(), f.name)
                        if extracted.strip():
                            clean_text = analyzer.scrub_pii(extracted)
                            combined_text += f"\\n\\n--- Docs: {f.name} ---\\n{clean_text}\\n"
                    
                    if combined_text.strip():
                        st.markdown("---")
                        risk_tier = analyzer.classify_risk_tier(combined_text, jurisdiction)
                        badge_class = f"risk-{risk_tier.lower()}"
                        st.markdown(f'<div class="risk-badge {badge_class}">{loc["risk_t"]} {risk_tier}</div>', unsafe_allow_html=True)
                        
                        if plan == "GUEST":
                            st.session_state['guest_uses'] = st.session_state.get('guest_uses', 0) + 1
                        else:
                            save_audit(username, ", ".join(doc_names), risk_tier)
                            increment_usage(username)
                        
                        # --- LOCAL FAISS/BM25 RAG MEMORY PERSISTENCE ---
                        rag_dir = f"data_rag/{username}"
                        os.makedirs(rag_dir, exist_ok=True)
                        timestamp_str = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
                        for d_name in doc_names:
                            safe_name = "".join([c for c in d_name if c.isalpha() or c.isdigit()]).rstrip()
                            if not safe_name: safe_name = "doc"
                            with open(f"{rag_dir}/{timestamp_str}_{safe_name}.txt", "w", encoding="utf-8") as f_rag:
                                f_rag.write(combined_text)
                        
                        st.markdown(loc["rep_t"])
                        generator = analyzer.analyze_stream(combined_text, domain, jurisdiction=jurisdiction, language=target_lang_opt)
                        result_text = st.write_stream(generator)
                        
                        st.session_state['last_audit'] = result_text
                        st.session_state['last_audit_docs'] = ", ".join(doc_names)
                        st.download_button(loc["down_r"], data=result_text, file_name="Lakunai_Audit.txt")
                        st.success(loc["audit_succ"])
        tab_idx += 1

    # 2. INVENTORY (DASHBOARD)
    if loc["t2"] in allowed_tab_names:
        with tabs[tab_idx]:
            st.markdown(loc["t2_h"])
            audits = get_audits(username)
            if audits:
                df = pd.DataFrame(audits, columns=loc["t2_c"])
                col1, col2, col3 = st.columns(3)
                risk_counts = df[loc["t2_c"][1]].value_counts()
                
                with col1: st.metric("Total Analizados", len(df))
                with col2: st.metric("Nivel Dominante", risk_counts.idxmax() if not risk_counts.empty else "N/A")
                with col3: 
                    h_r = risk_counts.get('UNACCEPTABLE', 0) + risk_counts.get('HIGH', 0)
                    st.metric(f"Severidad GRC", f"{h_r} Alertas")
                
                st.dataframe(df, use_container_width=True, hide_index=True)
                st.markdown("### Histograma de Riesgo Oficial")
                st.bar_chart(risk_counts, color="#38bdf8")
            else:
                st.info(loc["t2_n"])
        tab_idx += 1

    # 3. REMEDIATION (WITH RAG)
    if loc["t3"] in allowed_tab_names:
        with tabs[tab_idx]:
            st.markdown(loc["t3_h"])
            st.write(loc["t3_d"])
            if 'last_audit' not in st.session_state:
                st.info(loc["t3_n"])
            else:
                st.success(f"{loc['t3_ctx']} **{st.session_state['last_audit_docs']}**")
                if "messages" not in st.session_state: st.session_state.messages = []
                for m in st.session_state.messages:
                    with st.chat_message(m["role"]): st.markdown(m["content"])
                if prompt := st.chat_input("Ex: Modifica la cláusula 3.1 considerando lo que falló ayer..."):
                    st.session_state.messages.append({"role": "user", "content": prompt})
                    with st.chat_message("user"): st.markdown(prompt)
                    
                    with st.chat_message("assistant"):
                        # --- BM25 RAG RETRIEVAL ---
                        rag_dir = f"data_rag/{username}"
                        retrieved_context = ""
                        if os.path.exists(rag_dir):
                            import glob
                            from rank_bm25 import BM25Okapi
                            files = glob.glob(f"{rag_dir}/*.txt")
                            if files:
                                corpus = []
                                for f in files:
                                    with open(f, "r", encoding="utf-8") as fr: corpus.append(fr.read())
                                tokenized_corpus = [doc.split(" ") for doc in corpus]
                                bm25 = BM25Okapi(tokenized_corpus)
                                tokenized_query = prompt.split(" ")
                                top_doc = bm25.get_top_n(tokenized_query, corpus, n=1)[0]
                                retrieved_context = f"--- HISTORICAL RAG CONTEXT ---\\n{top_doc[:3000]}\\n\\n"
                        
                        full_context = retrieved_context + "--- LATEST AUDIT ---\\n" + st.session_state.get('last_audit', '')
                        analyzer = StandardAnalyzer()
                        response = st.write_stream(analyzer.remediate_stream(full_context, prompt))
                    st.session_state.messages.append({"role": "assistant", "content": response})
        tab_idx += 1

    # 4. MODEL CARDS
    if loc["t4"] in allowed_tab_names:
        with tabs[tab_idx]:
            st.markdown(loc["t4_h"])
            st.write(loc["t4_d"])
            tech_file = st.file_uploader(loc["t4_up"], type=["pdf", "txt"])
            if st.button(loc["t4_btn"], use_container_width=True) and tech_file:
                with st.spinner(loc["spin"]):
                    analyzer = StandardAnalyzer()
                    clean_text = analyzer.scrub_pii(get_extracted_text(tech_file.getvalue(), tech_file.name))
                    if clean_text:
                        card_result = st.write_stream(analyzer.generate_model_card_stream(clean_text))
                        st.download_button(loc["down_r"], data=card_result, file_name=f"MC_{tech_file.name}.md")
        tab_idx += 1

    # 5. RED TEAMING
    if loc["t5"] in allowed_tab_names:
        with tabs[tab_idx]:
            st.markdown(loc["t5_h"])
            st.write(loc["t5_d"])
            model_endpoint = st.text_input(loc["t5_url"], "http://localhost:8000/v1/chat/completions")
            
            if st.button(loc["t5_atk"], use_container_width=True):
                with st.spinner("Inyectando Payloads y Evaluando Modelo (HTTP Real / Simulado)..."):
                    analyzer = StandardAnalyzer()
                    st.write_stream(analyzer.perform_red_teaming_stream(model_endpoint))
                    increment_usage(username)
        tab_idx += 1

    # 6. CI/CD INTEGRATION HUB
    if loc["t6"] in allowed_tab_names:
        with tabs[tab_idx]:
            st.markdown(loc["t6_h"])
            st.write(loc["t6_d"])
            st.markdown("#### 🔑 Token de Integración Continua")
            st.code("LAKUNAI-G-8X912-AF20X-L29", language="bash")
            st.markdown("⚠️ *No insertes este token directamente, usa GitHub Secrets.*")
            st.markdown("#### GitHub Actions YAML (Auditoría Automática)")
            st.code("""
name: "Lakunai Compliance Check"
on: [pull_request]

jobs:
  compliance_audit:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Run GRC Matrix Scanner
      uses: Lakunai-AI/action-scanner@v1
      with:
        api-key: ${{ secrets.LAKUNAI_TOKEN }}
        model-path: './arquitectura/modelo_v2.bin'
        framework: 'EU_AI_ACT'
            """, language="yaml")
            st.markdown("#### API de Consola cURL")
            st.code("""
curl -X POST https://api.lakunai.io/v1/audit/live \\
  -H "Authorization: Bearer $LAKUNAI_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"model_endpoint": "https://mi-modelo.empresa.cl", "tests": ["toxicity", "gender_bias"]}'
            """, language="bash")
        tab_idx += 1


    st.markdown("<br><br><br><br><br><div style='text-align: center; color: #475569; font-size: 0.85rem; border-top:1px solid rgba(255,255,255,0.05); padding-top:20px;'>© 2026 LaKunAI Soluciones Inteligentes. Tu Blindaje Completo para la adopción segura de IA.</div>", unsafe_allow_html=True)

if __name__ == "__main__":
    main()
