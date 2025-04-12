import streamlit as st
import json
import os
from cryptography.fernet import Fernet

# Constants
DATA_FILE = "users.json"
FERNET_KEY = b'Wwzqv2SLvnQrNS0uTWxkzDgFZAc_fYjMXbn3pP_GJ9g='  # Pre-generated key
fernet = Fernet(FERNET_KEY)

# Load users from file
def load_users():
    if not os.path.exists(DATA_FILE):
        with open(DATA_FILE, "w") as f:
            json.dump({}, f)
    try:
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        with open(DATA_FILE, "w") as f:
            json.dump({}, f)
        return {}

# Save users to file
def save_users(users):
    with open(DATA_FILE, "w") as f:
        json.dump(users, f, indent=2)

# Authenticate login
def authenticate(username, password):
    users = load_users()
    return username in users and users[username]["password"] == password

# Signup
def signup(username, password):
    users = load_users()
    if username in users:
        return False
    users[username] = {"password": password, "data": []}
    save_users(users)
    return True

# Save user encrypted message
def save_user_message(username, encrypted_text):
    users = load_users()
    users[username]["data"].append(encrypted_text)
    save_users(users)

# Streamlit App
st.set_page_config(page_title="Data Encryption System", layout="centered")
st.title("Data Encryption System 🔐")

# Session state init
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = None

# Login or Signup Page
if not st.session_state.logged_in:
    tabs = st.tabs(["🔑 Login", "📝 Signup"])

    with tabs[0]:
        st.subheader("Login")
        username = st.text_input("Username", key="login_user")
        password = st.text_input("Password", type="password", key="login_pass")

        if st.button("Login"):
            if authenticate(username, password):
                st.session_state.logged_in = True
                st.session_state.username = username
                st.rerun()  # ✅ fixes the need to click twice
            else:
                st.error("Invalid username or password.")

    with tabs[1]:
        st.subheader("Create New Account")
        new_user = st.text_input("New Username", key="signup_user")
        new_pass = st.text_input("New Password", type="password", key="signup_pass")

        if st.button("Create Account"):
            if signup(new_user, new_pass):
                st.success("Account created! Please log in.")
            else:
                st.warning("Username already exists.")

# Main App (after login)
else:
    st.subheader(f"Welcome, {st.session_state.username}!")
    menu = st.radio("Select Option", ["🔐 Encrypt", "🔓 Decrypt", "📦 View Saved Data", "🚪 Logout"])

    if menu == "🔐 Encrypt":
        text = st.text_area("Enter text to encrypt:")
        if st.button("Encrypt"):
            if text:
                encrypted = fernet.encrypt(text.encode()).decode()
                st.success("Encrypted text:")
                st.code(encrypted)
                save_user_message(st.session_state.username, encrypted)
            else:
                st.warning("Please enter some text.")

    elif menu == "🔓 Decrypt":
        enc_text = st.text_area("Paste encrypted text:")
        password = st.text_input("Enter decryption password (default: 1234)", type="password")
        if st.button("Decrypt"):
            if password != "1234":
                st.error("Incorrect password.")
            elif not enc_text:
                st.warning("Please enter encrypted text.")
            else:
                try:
                    decrypted = fernet.decrypt(enc_text.encode()).decode()
                    st.success("Decrypted text:")
                    st.code(decrypted)
                except Exception:
                    st.error("Failed to decrypt. Invalid input or key.")

    elif menu == "📦 View Saved Data":
        users = load_users()
        data = users.get(st.session_state.username, {}).get("data", [])
        st.subheader("Your Saved Encrypted Messages:")
        if data:
            for i, msg in enumerate(data, 1):
                st.code(f"{i}. {msg}")
        else:
            st.info("No saved data yet.")

    elif menu == "🚪 Logout":
        st.session_state.logged_in = False
        st.session_state.username = None
        st.success("Logged out successfully.")
