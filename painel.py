# Estrutura proposta:
# - config.py
# - security.py
# - sftp_utils.py
# - ui.py
# - main.py

# === config.py ===
import os
import streamlit as st

FERNET_KEY = st.secrets["FERNET_KEY"].encode() if "FERNET_KEY" in st.secrets else os.environ["FERNET_KEY"].encode()
SFTP_HOST = st.secrets["SFTP_HOST"] if "SFTP_HOST" in st.secrets else os.environ["SFTP_HOST"]
SFTP_PORT = int(st.secrets["SFTP_PORT"]) if "SFTP_PORT" in st.secrets else int(os.environ.get("SFTP_PORT", 22))
USER_DATABASE = (st.secrets["USER_DATABASE"] if "USER_DATABASE" in st.secrets else os.environ["USER_DATABASE"]).replace(" ", "").split(",")
TOKEN_EXPIRATION_SECONDS = 30

# === security.py ===
import re, ast, datetime
from cryptography.fernet import Fernet
from typing import Dict, Union
from config import FERNET_KEY
import logging

logger = logging.getLogger(__name__)

cipher = Fernet(FERNET_KEY)

def sanitize_filename(filename: str) -> str:
    return re.sub(r'[^\w.-]', '_', filename)

def validate_email(email: str) -> bool:
    return bool(re.match(r"^[\w\.-]+@[\w\.-]+\.\w{2,}$", email))

def encrypt_token(data: Dict) -> str:
    return cipher.encrypt(str(data).encode()).decode()

def decrypt_token(token: str) -> Dict[str, Union[str, bool]]:
    try:
        decoded = cipher.decrypt(token.encode())
        parsed = ast.literal_eval(decoded.decode())
        if not isinstance(parsed, dict):
            raise ValueError("Formato inválido")
        parsed['decryption'] = True
        return parsed
    except Exception as e:
        logger.error(f"Erro no token: {str(e)}")
        return {'decryption': False}

def encrypt_file(data: bytes) -> bytes:
    return cipher.encrypt(data)

def gerar_token(usuario: str, senha: str, duracao_segundos: int) -> str:
    exp = (datetime.datetime.utcnow() + datetime.timedelta(seconds=duracao_segundos)).isoformat()
    return encrypt_token({'user': usuario, 'secret': senha, 'expiration_date': exp})

def token_expirado(token: str) -> bool:
    d = decrypt_token(token)
    if not d.get('decryption'):
        return True
    return datetime.datetime.fromisoformat(d["expiration_date"]) <= datetime.datetime.utcnow()

# === sftp_utils.py ===
import paramiko
import logging
from config import SFTP_HOST, SFTP_PORT

logger = logging.getLogger(__name__)

def sftp_login_test(username: str, password: str) -> bool:
    try:
        with paramiko.Transport((SFTP_HOST, SFTP_PORT)) as transport:
            transport.connect(username=username, password=password)
        return True
    except paramiko.AuthenticationException:
        logger.warning("Falha na autenticação SFTP")
        return False
    except Exception as e:
        logger.error(f"Erro na conexão SFTP: {str(e)}")
        return False

def sftp_fileupload(username: str, password: str, local_path: str, remote_path: str, callback=None) -> bool:
    try:
        with paramiko.Transport((SFTP_HOST, SFTP_PORT)) as transport:
            transport.connect(username=username, password=password)
            with paramiko.SFTPClient.from_transport(transport) as sftp:
                sftp.put(local_path, remote_path, callback=callback)
        return True
    except Exception as e:
        logger.error(f"Erro ao enviar via SFTP: {str(e)}")
        return False

# === ui.py ===
import streamlit as st

def setup_style():
    st.set_page_config(page_title="HYPERsec | Upload Seguro", layout="wide", page_icon="🔒")
    st.markdown("""
    <style>
        body { background-color: #0F1117; color: #E0E0E0; }
        .block-container { padding-top: 2rem; padding-bottom: 2rem; }
        .stButton>button {
            background-color: #1F2937;
            color: #FFFFFF;
            font-weight: bold;
            border-radius: 8px;
            padding: 0.5em 1em;
            border: none;
        }
        .stTextInput>div>input, .stPasswordInput>div>input {
            background-color: #1E1E1E;
            color: #FFFFFF;
        }
        .stFileUploader>label { color: #D1D5DB; }
        .stMarkdown h1, .stMarkdown h2, .stMarkdown h3 {
            color: #00BFFF;
        }
        code, pre {
            background-color: #1A1A1A;
            color: #00FF7F;
        }
    </style>
    """, unsafe_allow_html=True)

# === main.py ===
import streamlit as st
import hashlib, tempfile, os, datetime, io, zipfile
from security import *
from sftp_utils import *
from config import TOKEN_EXPIRATION_SECONDS, USER_DATABASE
from ui import setup_style

setup_style()

st.title("HYPERsec SYSTEM")
st.markdown("### Sistema de Transmissão Segura com Criptografia de Arquivos")

with st.sidebar:
    st.markdown("## Autenticação")
    user = st.text_input("Usuário (e-mail)")
    secret = st.text_input("Senha de Acesso", type="password")

    if st.button("Gerar Token de Sessão"):
        if not user or not secret:
            st.warning("Preencha usuário e senha.")
        elif not validate_email(user):
            st.error("Formato de e-mail inválido.")
        elif user not in USER_DATABASE:
            st.error("Usuário não autorizado.")
        elif not sftp_login_test(user, secret):
            st.error("Credenciais inválidas no SFTP.")
        else:
            st.session_state.token = gerar_token(user, secret, TOKEN_EXPIRATION_SECONDS)

    if st.session_state.get("token"):
        dados = decrypt_token(st.session_state.token)
        exp = datetime.datetime.fromisoformat(dados["expiration_date"]) - datetime.timedelta(hours=3)
        st.markdown(f"**Token expira às:** {exp.strftime('%H:%M:%S')}")
        st.code(st.session_state.token, language="text")

    st.markdown("---")
    arquivo = st.file_uploader("Selecionar Arquivo para Upload")
    enviar = st.button("Executar Upload Seguro")

status_area = st.empty()
progress_bar = st.progress(0)
log_area = st.empty()

if enviar:
    if not st.session_state.get("token"):
        status_area.error("Token não gerado. Autentique-se primeiro.")
    elif not arquivo:
        status_area.error("Nenhum arquivo selecionado.")
    elif token_expirado(st.session_state.token):
        status_area.error("Token expirado ou inválido.")
    else:
        dados = decrypt_token(st.session_state.token)
        if not sftp_login_test(dados['user'], dados['secret']):
            status_area.error("Autenticação SFTP falhou.")
        else:
            try:
                file_bytes = arquivo.read()
                progress_bar.progress(10)
                md5 = hashlib.md5(file_bytes).hexdigest()
                zip_buffer = io.BytesIO()
                with zipfile.ZipFile(zip_buffer, mode='w', compression=zipfile.ZIP_DEFLATED) as zf:
                    zf.writestr(arquivo.name, file_bytes)
                zip_buffer.seek(0)
                encrypted_bytes = encrypt_file(zip_buffer.read())
                sha256 = hashlib.sha256(encrypted_bytes).hexdigest()
                progress_bar.progress(50)
                nome_final = f"{sanitize_filename(arquivo.name)}_{md5}.zip.fernet"
                with tempfile.NamedTemporaryFile(delete=False) as temp:
                    temp.write(encrypted_bytes)
                    temp_path = temp.name
                remote_path = f"/upload/{nome_final}"
                if sftp_fileupload(dados['user'], dados['secret'], temp_path, remote_path, lambda s, t: progress_bar.progress(50 + int(50 * s / t))):
                    status_area.success("✅ Enviado com sucesso!")
                    log_area.markdown(f"""
                        - **Arquivo Original:** `{sanitize_filename(arquivo.name)}`
                        - **Tamanho:** `{len(file_bytes)/1024:.2f} KB`
                        - **MD5:** `{md5}`
                        - **SHA-256:** `{sha256}`
                        - **Nome Final:** `{nome_final}`
                        - **Caminho Remoto:** `{remote_path}`
                        - **Usuário:** `{dados['user']}`
                    """)
                else:
                    status_area.error("Erro ao enviar.")
                os.unlink(temp_path)
            except Exception as e:
                progress_bar.progress(0)
                status_area.error(f"Erro inesperado: {str(e)}")
                log_area.exception(e)
