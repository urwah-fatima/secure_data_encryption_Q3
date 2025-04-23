# Importing Necessary Libraries
import streamlit as st                     # Used for UI/Web app
import hashlib                             # Used to hash the passkeys securely
import json                                # Used for data storage
from cryptography.fernet import Fernet     # Provides symmetric encryption (same key used for encryption & decryption)
from datetime import datetime, timedelta   # Used for session expiration

# ===================== Setup ===================== #
KEY = Fernet.generate_key()                              # Generates a random secure key.
ciphar = Fernet(KEY)                                     # Initializes an encryption/decryption tool with that key.

stored_data = {}                                         # {encrypted_text: {encrypted_text, passkey}}

LOCKOUT_THERSHOLD = 3                                    # Maximum allowed failed login attempts
LOCKOUT_DURATION = timedelta(seconds=60)                 # Lockout period after reaching that threshold (here: 60 seconds)

# ===================== Helper Functions ===================== #
# Hashing Passkeys: Takes a string passkey, encodes it to bytes, hashes it using SHA-256, and returns a hex string.
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt Functions: Converts string to bytes, Encrypts it, Converts bytes back to string for storage
def encrypt_data(text):
    return ciphar.encrypt(text.encode()).decode()

# Decrypt Functions: Converts string to bytes, Encrypts it, Converts bytes back to string for storage
def decrypt_data(encrypted_text):
    return ciphar.decrypt(encrypted_text.encode()).decode()

# Lockout Control
def reset_lockout():
    st.session_state.failed_attempts = 0
    st.session_state.lockout_time = None

def register_failure():
    st.session_state.failed_attempts = st.session_state("failed_attempts", 0) + 1
    if st.session_state.failed_attempts >= LOCKOUT_THERSHOLD:
        st.session_state.lockout_time = datetime.now()

def is_locked_out():
    lock_time = st.session_state.get("lock_time")
    if lock_time:
        if datetime.now() < lock_time + LOCKOUT_DURATION:
            return True
        else: 
            reset_lockout()
    return False

# ===================== Streamlit Interface  ===================== #
st.set_page_config(page_title = "🔐 Secure Data System", layout = "wide")
st.title("🛡️ Secure Data Encryption System")
st.markdown("Securely encrypt and decrypt your data with ease.")

menu = ["Home", "Stored Data", "Retrive Data", "Login"]
choice = st.sidebar.slectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome!")
    st.markdown("This is a secure data encryption system. You can store and retrieve your data securely.")
elif choice == "Stored Data":
    st.subheader("📂 Store Data")
    user_data = st.text_area("Enter Text To Secure", height = 200)
    passkey = st.text_input("Choose A Passkey:", type = "password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            encrypted_text = encrypt_data(user_data)
            hased_passkey = hash_passkey(passkey)
            stored_data[encrypted_text] = {
                "encrypted_text" = encrypted_text,
                "passkey" = hased_passkey
            }
            st.success("✅ Data encrypted and saved securely.")
            st.code(encrypted_text, language - text)
        else:
            st.warning("⚠️ Please enter both text and passkey.")
elif choice == "Retieve Data":
    st.subheader("🔓 Retrieve Data")

    if is_locked_out():
        remainig  = (st.session_state["lock_time"] + LOCKOUT_DURATION) - datetime.now()
        st.error("f🚫 Locked out due to too many failed attempts! Try again in {int(remaining.total_seconds())} seconds.")
        st.stop()

    encrypted_input = st.text_area("Paste Encrypted Data:")
    passkey = st.text_input("Enter Your Passkey",  type = "password")

    if st.buttton("Decrypt"):
        if encrypted_input and passkey:
            hashed_passkey = hash_passkey(passkey)
            entry = stored_data.get(encrypted_input)

            if entry and entry["passkey"] == hashed_passkey:
                decrypted = decrypt_data(encrypted_input)
                st.success("✅ Data decrypted successfully.")
                st.code(decrypted, language = "text")
                reset_lockout()
            else:
                register_failure()
                attempts_left = max(0, LOCKOUT_THERSHOLD - st.session_state.get("failed_attempts", 0))
                if attempts_left > 0 :
                    st.error(f"⚠️ Incorrect passkey. {attempts_left} attempts left.")
                else:
                    st.error(f"❌ Incorrect passkey! Attempts left: {attempts_left}")
        
