import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# --- Session State Initialization ---
if "my_key" not in st.session_state:
    st.session_state.my_key = Fernet.generate_key()
    st.session_state.cipher = Fernet(st.session_state.my_key)
    st.session_state.data_store = {}
    st.session_state.attempts = 0
    st.session_state.logged_in = True
    st.session_state.current_page = "Home"

# --- Helper Functions ---
def make_hash(word):
    return hashlib.sha256(word.encode()).hexdigest()

def lock_text(msg):
    return st.session_state.cipher.encrypt(msg.encode()).decode()

def unlock_text(ciphertext, given_key):
    right_hash = make_hash(given_key)
    record = st.session_state.data_store.get(ciphertext)

    if record and record["key"] == right_hash:
        st.session_state.attempts = 0
        return st.session_state.cipher.decrypt(ciphertext.encode()).decode()
    else:
        st.session_state.attempts += 1
        return None

# --- Page Navigation Control ---
pages = ["Home", "Store Data", "Retrieve Data", "Login"]
page = st.sidebar.selectbox("Go to", pages, index=pages.index(st.session_state.current_page))
st.session_state.current_page = page

# --- Main UI ---
st.title("🔒 Secure Data Locker")

if page == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("This app lets you save and view secret messages using a key.")

elif page == "Store Data":
    st.subheader("📂 Store Data Securely")
    message = st.text_area("Type your message:")
    user_key = st.text_input("Enter a key", type="password")

    if st.button("Save"):
        if message and user_key:
            hashed = make_hash(user_key)
            encrypted = lock_text(message)
            st.session_state.data_store[encrypted] = {"text": encrypted, "key": hashed}
            st.success("✅ Data stored securely!")
            st.code(encrypted)
        else:
            st.error("⚠️ Both fields are required!")

elif page == "Retrieve Data":
    if st.session_state.attempts >= 3 or not st.session_state.logged_in:
        st.warning("Too many wrong tries. Please log in.")
        st.session_state.logged_in = False
        st.session_state.current_page = "Login"
        st.rerun()

    st.subheader("View Secret Message")

    enc = st.text_area("Paste the encrypted text:")
    key_try = st.text_input("Enter your key", type="password")

    if st.button("Decrypt"):
        if enc and key_try:
            result = unlock_text(enc, key_try)
            if result:
                st.success(f"✅ Decrypted Data: {result}")
            else:
                tries_left = 3 - st.session_state.attempts
                st.error(f"❌ Incorrect passkey! Attempts remaining: {tries_left}")
        else:
            st.warning("Both fields must be filled.")

elif page == "Login":
    st.subheader("Login")

    password = st.text_input("Enter password", type="password")

    if st.button("Login"):
        if password == "samra123":
            st.session_state.attempts = 0
            st.session_state.logged_in = True
            st.session_state.current_page = "Retrieve Data"  # redirect after login
            st.success("✅ Logged in. Redirecting...")
            st.rerun()
        else:
            st.error("❌ Incorrect password!")
