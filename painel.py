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
import re
import logging
from typing import Dict, Union

# --- CONFIGURAÇÕES --- #
FERNET_KEY = st.secrets["FERNET_KEY"].encode() if "FERNET_KEY" in st.secrets else os.environ["FERNET_KEY"].encode()
SFTP_HOST = st.secrets["SFTP_HOST"] if "SFTP_HOST" in st.secrets else os.environ["SFTP_HOST"]
SFTP_PORT = int(st.secrets["SFTP_PORT"]) if "SFTP_PORT" in st.secrets else int(os.environ.get("SFTP_PORT", 22))
USER_DATABASE = (st.secrets["USER_DATABASE"] if "USER_DATABASE" in st.secrets else os.environ["USER_DATABASE"]).replace(
    " ", "").split(",")
TOKEN_EXPIRATION_SECONDS = 30

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# --- FUNÇÕES --- #
def get_cipher() -> Fernet:
    return Fernet(FERNET_KEY)


def sanitize_filename(filename: str) -> str:
    return re.sub(r'[^\w.-]', '_', filename)


def validate_email(email: str) -> bool:
    return bool(re.match(r"^[\w\.-]+@[\w\.-]+\.\w{2,}$", email))


def f_encrypt_token(dados: Dict) -> str:
    return get_cipher().encrypt(str(dados).encode()).decode()


def f_decrypt_token(token: str) -> Dict[str, Union[bool, str]]:
    try:
        decrypted = get_cipher().decrypt(token.encode())
        parsed = ast.literal_eval(decrypted.decode())
        if not isinstance(parsed, dict):
            raise ValueError("Token inválido: não é um dicionário")
        parsed['decryption'] = True
        return parsed
    except Exception as e:
        logger.error(f"Erro ao descriptografar token: {str(e)}")
        return {'decryption': False}


def f_encrypt_file(data: bytes) -> bytes:
    return get_cipher().encrypt(data)


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


def sftp_fileupload(username: str, password: str, local_path: str, remote_path: str) -> bool:
    try:
        with paramiko.Transport((SFTP_HOST, SFTP_PORT)) as transport:
            transport.connect(username=username, password=password)
            with paramiko.SFTPClient.from_transport(transport) as sftp:
                def progress_callback(sent: int, total: int):
                    progress = 50 + int(50 * (sent / total))
                    progress_bar.progress(min(progress, 100))

                sftp.put(local_path, remote_path, callback=progress_callback)
        return True
    except Exception as e:
        logger.error(f"Erro ao enviar via SFTP: {str(e)}")
        return False


def gerar_nome_criptografado(nome_original: str, md5: str) -> str:
    nome_sanitizado = sanitize_filename(nome_original)
    nome, ext = os.path.splitext(nome_sanitizado)
    return f"{nome}_{md5}{ext}.zip.fernet"


def compactar_para_zip(nome_arquivo: str, dados: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode='w', compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(nome_arquivo, dados)
    buffer.seek(0)
    return buffer.read()


# --- STREAMLIT INTERFACE --- #
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
        elif not validate_email(user):
            st.error("⛔ Formato de e-mail inválido.")
        elif user not in USER_DATABASE:
            st.error("⛔ Usuário não autorizado.")
        elif not sftp_login_test(user, secret):
            st.error("🔐 Usuário ou senha inválidos para o SFTP.")
            logger.warning(f"Autenticação SFTP falhou para {user}")
        else:
            expiration = (datetime.datetime.now() + datetime.timedelta(seconds=TOKEN_EXPIRATION_SECONDS)).isoformat()
            token_data = {'user': user, 'secret': secret, 'expiration_date': expiration}
            token = f_encrypt_token(token_data)
            st.session_state.token = token
            logger.info(f"Token gerado para usuário: {user}")

    if st.session_state.token:
        exp_time = datetime.datetime.fromisoformat(
            f_decrypt_token(st.session_state.token)["expiration_date"]
        ).strftime("%H:%M:%S")
        st.markdown(f"### ⏳ Expira às {exp_time}")
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
        status_area.info("🔍 Validando token...")
        token_data = f_decrypt_token(st.session_state.token)

        if not token_data.get("decryption"):
            status_area.error("❌ Token inválido.")
        elif datetime.datetime.fromisoformat(token_data["expiration_date"]) <= datetime.datetime.now():
            status_area.error("⌛ Token expirado.")
        elif not sftp_login_test(token_data["user"], token_data["secret"]):
            status_area.error("🔐 Falha na autenticação.")
        else:
            try:
                status_area.info("📥 Lendo arquivo...")
                file_bytes = arquivo.read()
                progress_bar.progress(10)

                md5_hash = hashlib.md5(file_bytes).hexdigest()
                status_area.info("📦 Compactando...")
                zip_bytes = compactar_para_zip(arquivo.name, file_bytes)
                progress_bar.progress(30)

                status_area.info("🔐 Criptografando...")
                encrypted_bytes = f_encrypt_file(zip_bytes)
                encrypted_hash = hashlib.sha256(encrypted_bytes).hexdigest()
                progress_bar.progress(50)

                nome_final = gerar_nome_criptografado(arquivo.name, md5_hash)
                with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                    temp_file.write(encrypted_bytes)
                    temp_path = temp_file.name

                status_area.info("🔌 Enviando via SFTP...")
                remote_path = f"/upload/{nome_final}"
                if sftp_fileupload(token_data["user"], token_data["secret"], temp_path, remote_path):
                    status_area.success("✅ Arquivo enviado com sucesso!")
                    logger.info(f"Arquivo {arquivo.name} enviado com sucesso para {remote_path}")
                    log_area.markdown(f"""
                    ### 📄 Detalhes da Transmissão Segura
                    - **Arquivo Original:** `{sanitize_filename(arquivo.name)}`
                    - **Tamanho:** `{len(file_bytes) / 1024:.2f} KB`
                    - **Hash MD5:** `{md5_hash}`
                    - **Hash Criptografado (SHA-256):** `{encrypted_hash}`
                    - **Arquivo Criptografado:** `{nome_final}`
                    - **Local de Envio:** `{remote_path}`
                    - **Usuário:** `{token_data['user']}`
                    - **Token Utilizado:**
                    ```text
                    {st.session_state.token}
                    ```
                    """)
                else:
                    progress_bar.progress(0)
                    status_area.error("❌ Falha no envio.")
                os.unlink(temp_path)
            except Exception as e:
                progress_bar.progress(0)
                status_area.error(f"❌ Erro: {str(e)}")
                logger.error(f"Erro inesperado: {str(e)}")
