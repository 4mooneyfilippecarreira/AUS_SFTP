import streamlit as st
import hashlib
import os
import tempfile
import datetime
import ast
import time
import paramiko
from cryptography.fernet import Fernet


# --- CONFIGURAÇÕES --- #
FERNET_KEY = os.environ["FERNET_KEY"].encode()
SFTP_HOST = os.environ["SFTP_HOST"]
SFTP_PORT = int(os.environ.get("SFTP_PORT", 22))
USER_DATABASE = os.environ["USER_DATABASE"].replace(" ", "").split(",")


# --- FUNÇÕES --- #
def f_encrypt_token(dados: dict) -> str:
    f = Fernet(FERNET_KEY)
    text = str(dados).encode('utf-8')
    return f.encrypt(text).decode()


def f_decrypt_token(token: str) -> dict:
    f = Fernet(FERNET_KEY)
    try:
        decrypted = f.decrypt(token.encode())
        parsed = ast.literal_eval(decrypted.decode())
        parsed['decryption'] = True
        return parsed
    except Exception:
        return {'decryption': False}


def f_encrypt_file(data: bytes) -> bytes:
    f = Fernet(FERNET_KEY)
    return f.encrypt(data)


def sftp_login_test(username: str, password: str):
    try:
        transport = paramiko.Transport((SFTP_HOST, SFTP_PORT))
        transport.connect(username=username, password=password)
        transport.close()
        return True
    except Exception:
        return False


def sftp_fileupload(username: str, password: str, local_path: str, remote_path: str):
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


def gerar_nome_criptografado(nome_original: str, md5: str):
    nome, ext = os.path.splitext(nome_original)
    return f"{nome}_{md5}_{ext}.fernet"


# --- INTERFACE STREAMLIT --- #
st.set_page_config(page_title="Upload Seguro via SFTP", layout="wide", page_icon="🔐")

# Estados
if "token" not in st.session_state:
    st.session_state.token = None

with st.sidebar:
    st.markdown("## 🔐 Autenticação")
    user = st.text_input("👤 Usuário (e-mail)")
    secret = st.text_input("🔑 Senha", type="password")
    gerar_token = st.button("🔑 Gerar Token")

    if gerar_token:
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

# Áreas principais
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
        elif token_data["expiration_date"] <= datetime.datetime.now().isoformat():
            status_area.error("⌛ Token expirado. Gere um novo.")
        elif not sftp_login_test(token_data["user"], token_data["secret"]):
            status_area.error("🔐 Falha na autenticação via SFTP.")
        else:
            progress_bar.progress(10)
            status_area.info("🔄 Criptografando o arquivo...")

            file_bytes = arquivo.read()
            md5_hash = hashlib.md5(file_bytes).hexdigest()

            # Compactação para .zip
            status_area.info("📦 Compactando o arquivo (.zip)...")
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, mode='w', compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr(arquivo.name, file_bytes)
            zip_buffer.seek(0)
            compressed_bytes = zip_buffer.read()

            progress_bar.progress(30)

            # Criptografia do arquivo zipado
            status_area.info("🔐 Criptografando o arquivo compactado...")
            encrypted_file = f_encrypt_file(compressed_bytes)

            # Nome final criptografado
            nome_criptografado = gerar_nome_criptografado(arquivo.name, md5_hash)
            nome_criptografado = nome_criptografado.replace(".fernet", ".zip.fernet")


            progress_bar.progress(40)

            status_area.info("💾 Salvando arquivo temporariamente criptografado...")
            temp_dir = tempfile.gettempdir()
            temp_path = os.path.join(temp_dir, nome_criptografado)

            with open(temp_path, 'wb') as f:
                f.write(encrypted_file)

            time.sleep(0.5)
            progress_bar.progress(60)

            status_area.info("🔌 Estabelecendo conexão com servidor SFTP...")
            remote_path = f"/upload/{nome_criptografado}"
            time.sleep(1)
            uploaded = sftp_fileupload(token_data["user"], token_data["secret"], temp_path, remote_path)

            if uploaded:
                progress_bar.progress(100)
                status_area.success("✅ Arquivo enviado com sucesso com criptografia Fernet!")

                log_area.markdown(f"""
                ### 📄 Detalhes da Transmissão Segura
                - **Arquivo Original:** `{arquivo.name}`
                - **Hash MD5:** `{md5_hash}`
                - **Arquivo Criptografado:** `{nome_criptografado}`
                - **Local de Envio:** `{remote_path}`
                - **Modo de Transmissão:** 🔐 Criptografado e Enviado via SFTP
                - **Token Utilizado:** 
                ```text
                {st.session_state.token}
                ```
                """)
            else:
                progress_bar.progress(0)
                status_area.error("❌ Falha ao enviar o arquivo. Verifique a conexão ou permissões.")
