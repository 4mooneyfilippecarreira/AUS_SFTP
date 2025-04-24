import zipfile
import streamlit as st
import hashlib
import os
import tempfile
import datetime
import ast
import paramiko
from cryptography.fernet import Fernet
import io

# --- CONFIGURAÇÕES --- #
FERNET_KEY = os.environ["FERNET_KEY"].encode()
SFTP_HOST = os.environ["SFTP_HOST"]
SFTP_PORT = int(os.environ.get("SFTP_PORT", 22))
USER_DATABASE = os.environ["USER_DATABASE"].replace(" ", "").split(",")

# --- FUNÇÕES --- #
def f_encrypt_token(dados: dict) -> str:
    return Fernet(FERNET_KEY).encrypt(str(dados).encode()).decode()

def f_decrypt_token(token: str) -> dict:
    try:
        decrypted = Fernet(FERNET_KEY).decrypt(token.encode())
        parsed = ast.literal_eval(decrypted.decode())
        parsed['decryption'] = True
        return parsed
    except Exception:
        return {'decryption': False}

def f_encrypt_file(data: bytes) -> bytes:
    return Fernet(FERNET_KEY).encrypt(data)

def sftp_login_test(username: str, password: str) -> bool:
    try:
        transport = paramiko.Transport((SFTP_HOST, SFTP_PORT))
        transport.connect(username=username, password=password)
        transport.close()
        return True
    except Exception:
        return False

def sftp_fileupload(username: str, password: str, local_path: str, remote_path: str) -> bool:
    try:
        transport = paramiko.Transport((SFTP_HOST, SFTP_PORT))
        transport.connect(username=username, password=password)
        sftp = paramiko.SFTPClient.from_transport(transport)
        sftp.put(local_path, remote_path)
        sftp.close()
        transport.close()
        return True
    except Exception:
        return False

def gerar_nome_criptografado(nome_original: str, md5: str) -> str:
    nome, ext = os.path.splitext(nome_original)
    return f"{nome}_{md5}{ext}.zip.fernet"

def compactar_para_zip(nome_arquivo: str, dados: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode='w', compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(nome_arquivo, dados)
    return buffer.getvalue()

# --- INTERFACE STREAMLIT --- #
st.set_page_config(page_title="Upload Seguro via SFTP", layout="wide", page_icon="🔐")

if "token" not in st.session_state:
    st.session_state.token = None

with st.sidebar:
    st.markdown("## 🔐 Autenticação")
    user = st.text_input("👤 Usuário (e-mail)")
    secret = st.text_input("🔑 Senha", type="password")
    if st.button("🔑 Gerar Token"):
        if not user or not secret:
            st.warning("⚠️ Preencha usuário e senha.")
        elif user not in USER_DATABASE:
            st.error("⛔ Usuário não autorizado.")
        else:
            expiration = (datetime.datetime.now() + datetime.timedelta(seconds=30)).isoformat()
            token = f_encrypt_token({'user': user, 'secret': secret, 'expiration_date': expiration})
            st.session_state.token = token

    if st.session_state.token:
        st.markdown("### Token válido por 30 segundos")
        st.code(st.session_state.token, language="text")

    st.markdown("---")
    st.markdown("## Enviar Arquivo")
    arquivo = st.file_uploader("📁 Selecione o arquivo para envio")
    enviar = st.button("Enviar com Segurança")

st.markdown("## 🛡️ Status do Envio")
status_area = st.empty()
progress_bar = st.progress(0)
log_area = st.empty()

if enviar:
    if not st.session_state.token:
        status_area.error("❌ Token não gerado. Gere o token primeiro.")
    elif not arquivo:
        status_area.error("❌ Nenhum arquivo selecionado.")
    else:
        status_area.info("🔍 Validando token de segurança...")
        token_data = f_decrypt_token(st.session_state.token)

        if not token_data.get("decryption"):
            status_area.error("❌ Token inválido.")
        elif datetime.datetime.fromisoformat(token_data["expiration_date"]) <= datetime.datetime.now():
            status_area.error("⌛ Token expirado. Gere um novo.")
        elif not sftp_login_test(token_data["user"], token_data["secret"]):
            status_area.error("🔐 Falha na autenticação via SFTP.")
        else:
            file_bytes = arquivo.read()
            md5_hash = hashlib.md5(file_bytes).hexdigest()
            nome_final = gerar_nome_criptografado(arquivo.name, md5_hash)

            status_area.info("📦 Compactando o arquivo...")
            zip_bytes = compactar_para_zip(arquivo.name, file_bytes)
            progress_bar.progress(30)

            status_area.info("🔐 Criptografando o arquivo compactado...")
            encrypted_bytes = f_encrypt_file(zip_bytes)
            progress_bar.progress(50)

            temp_path = os.path.join(tempfile.gettempdir(), nome_final)
            with open(temp_path, 'wb') as f:
                f.write(encrypted_bytes)
            progress_bar.progress(70)

            status_area.info("🔌 Enviando via SFTP...")
            remote_path = f"/upload/{nome_final}"
            if sftp_fileupload(token_data["user"], token_data["secret"], temp_path, remote_path):
                progress_bar.progress(100)
                status_area.success("✅ Arquivo enviado com sucesso!")
                log_area.markdown(f"""
                ### 📄 Detalhes da Transmissão Segura
                - **Arquivo Original:** `{arquivo.name}`
                - **Hash MD5:** `{md5_hash}`
                - **Arquivo Criptografado:** `{nome_final}`
                - **Local de Envio:** `{remote_path}`
                - **Token Utilizado:**
                ```text
                {st.session_state.token}
                ```
                """)
            else:
                progress_bar.progress(0)
                status_area.error("❌ Falha no envio via SFTP.")
