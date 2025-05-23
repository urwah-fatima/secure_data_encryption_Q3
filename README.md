secure_data_encryption_Q3
🛡️ Secure Data Encryption System using Streamlit This application allows users to securely store and retrieve text data using encrypted passkeys, all within a user-friendly Streamlit interface. No external databases are used; all data is stored in-memory.

📌 Features:

🔐 AES-based encryption using Fernet from the cryptography library.

🔑 Passkey hashing using SHA-256 for secure verification.

🚫 Login lockout mechanism after 3 failed attempts.

🧠 In-memory storage (no database needed).

🔄 Login override with a master password.

⚡ Lightweight and fast (no external storage required).

🧩 Tech Stack:

Frontend: Streamlit (Python UI framework)

Backend:

hashlib (for passkey hashing)

cryptography.fernet (for AES encryption)

datetime (to handle session lockouts)

🔧 How It Works:

Passkey Hashing User passkeys are hashed using SHA-256 and stored (never stored in plain text).
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()
Encryption Text is encrypted using Fernet (AES-based), ensuring confidentiality.
cipher = Fernet(KEY)
encrypted_text = cipher.encrypt(user_text.encode()).decode()
Decryption with Validation Decryption only succeeds if the hashed passkey matches the stored hash.
if entry and entry["passkey"] == hashed_passkey:
    decrypted = cipher.decrypt(encrypted_input.encode()).decode()
Lockout Mechanism Users are locked out for 60 seconds after 3 failed decryption attempts.
LOCKOUT_THRESHOLD = 3
LOCKOUT_DURATION = timedelta(seconds=60)
Session state tracks attempts and lockout time using:

st.session_state.failed_attempts
st.session_state.lockout_time
Login Override A master password (admin123) can be used to reset failed attempts and regain access.
if login_pass == "admin123":
    failed_attempts = 0
✅ Testing Scenarios:

Feature	How to Test
Store data	Go to Stored Data, input text and passkey
Retrieve data	Go to Retrieve Data, paste encrypted text and passkey
Lockout feature	Enter wrong passkey 3 times
Override login	Go to Login, enter admin123
🔒 Security Notes:

Passkeys are never stored in plain text.

All encryption/decryption is done using industry-standard AES via Fernet.

App operates completely in memory (no database or file storage).

Session-based lockout ensures brute-force prevention.