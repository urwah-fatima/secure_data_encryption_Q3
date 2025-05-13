# Importing Necessary Libraries
import streamlit as st
import hashlib
from cryptography.fernet import Fernet
from datetime import datetime, timedelta

# ========== Fernet Key Setup (Use pre-generated key) ==========
KEY = b'Zt0mvPRq9kUBf9TzHkEKwWqK0-rx0z4PspV-wDU9WrA='  # Valid 32-byte base64 key
cipher = Fernet(KEY)

# ========== In-Memory Data Store ==========
stored_data = {}  # Format: {encrypted_text: {"encrypted_text": ..., "passkey": ...}}

# ========== Constants ==========
LOCKOUT_THRESHOLD = 3
LOCKOUT_DURATION = timedelta(seconds=60)

# ========== Session State Defaults ==========
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "lock_time" not in st.session_state:
    st.session_state.lock_time = None

# ========== Helper Functions ==========
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

def reset_lockout():
    st.session_state.failed_attempts = 0
    st.session_state.lock_time = None

def register_failure():
    st.session_state.failed_attempts += 1
    if st.session_state.failed_attempts >= LOCKOUT_THRESHOLD:
        st.session_state.lock_time = datetime.now()

def is_locked_out():
    lock_time = st.session_state.lock_time
    if lock_time:
        if datetime.now() < lock_time + LOCKOUT_DURATION:
            return True
        else:
            reset_lockout()
    return False

# ========== Streamlit UI ==========
st.set_page_config(page_title="🔐 Secure Data System", layout="wide")
st.title("🛡️ Secure Data Encryption System")

menu = ["Home", "Stored Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# ========== Home Page ==========
if choice == "Home":
    st.subheader("🏠 Welcome!")
    st.markdown("This is a secure data encryption system. You can store and retrieve your data securely.")

# ========== Store Data ==========
elif choice == "Stored Data":
    st.subheader("📂 Store Data")
    user_data = st.text_area("Enter Text To Secure", height=200)
    passkey = st.text_input("Choose A Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            encrypted_text = encrypt_data(user_data)
            hashed_passkey = hash_passkey(passkey)
            stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            st.success("✅ Data encrypted and saved securely.")
            st.code(encrypted_text, language="text")
        else:
            st.warning("⚠️ Please enter both text and passkey.")

# ========== Retrieve Data ==========
elif choice == "Retrieve Data":
    st.subheader("🔓 Retrieve Data")

    if is_locked_out():
        remaining = (st.session_state.lock_time + LOCKOUT_DURATION) - datetime.now()
        st.error(f"🚫 Locked out due to too many failed attempts! Try again in {int(remaining.total_seconds())} seconds.")
        st.stop()

    encrypted_input = st.text_area("Paste Encrypted Data:")
    passkey = st.text_input("Enter Your Passkey", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey:
            hashed_passkey = hash_passkey(passkey)
            entry = stored_data.get(encrypted_input)

            if entry and entry["passkey"] == hashed_passkey:
                decrypted = decrypt_data(encrypted_input)
                st.success("✅ Data decrypted successfully.")
                st.code(decrypted, language="text")
                reset_lockout()
            else:
                register_failure()
                attempts_left = max(0, LOCKOUT_THRESHOLD - st.session_state.failed_attempts)
                if attempts_left > 0:
                    st.error(f"⚠️ Incorrect passkey. {attempts_left} attempts left.")
                else:
                    st.error("❌ Incorrect passkey! You are now locked out.")
                    st.experimental_rerun()
        else:
            st.warning("⚠️ Both fields are required!")

# ========== Login / Reauthorization ==========
elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            reset_lockout()
            st.success("✅ Reauthorized successfully! You can now retry decryption.")
        else:
            st.error("❌ Incorrect password!")
