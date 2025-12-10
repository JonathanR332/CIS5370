import os
from cryptography.fernet import Fernet
from datetime import datetime

# -------------------- USERS --------------------

USERS = {
    "JRizo": {"password": "123", "role": "admin"},
    "admin": {"password": "123", "role": "admin"},
    "user": {"password": "123", "role": "user"}
}

# -------------------- FILE PATHS --------------------

CLIENT_FILE = "Clients/clients.txt"
PLAIN_DOC_DIR = "plain_documents"
ENC_DOC_DIR = "encrypted_documents"
KEY_FILE = "vault.key"
LOG_FILE = "access.log"

os.makedirs(PLAIN_DOC_DIR, exist_ok=True)
os.makedirs(ENC_DOC_DIR, exist_ok=True)

# -------------------- LOAD CLIENTS --------------------

def load_clients():
    if not os.path.exists(CLIENT_FILE):
        return []
    with open(CLIENT_FILE, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

clients = load_clients()

# -------------------- ENCRYPTION SETUP --------------------

if not os.path.exists(KEY_FILE):
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
else:
    with open(KEY_FILE, "rb") as f:
        key = f.read()

cipher = Fernet(key)

# -------------------- DECRYPT FILE OPTION --------------------

def decrypt_file(user):
    files = [f for f in os.listdir(ENC_DOC_DIR) if f.endswith(".enc")]

    if not files:
        print("No encrypted files found.")
        pause()
        return

    clear()
    print("=== DECRYPT A FILE ===\n")
    for i, f in enumerate(files, start=1):
        print(f"{i}. {f}")

    try:
        choice = int(input("\nSelect file number: "))
        enc_fname = files[choice - 1]
    except:
        print("Invalid selection.")
        pause()
        return

    enc_path = os.path.join(ENC_DOC_DIR, enc_fname)
    out_fname = enc_fname.replace(".enc", "")
    out_path = os.path.join(PLAIN_DOC_DIR, out_fname)

    try:
        with open(enc_path, "rb") as f:
            decrypted = cipher.decrypt(f.read())

        with open(out_path, "wb") as f:
            f.write(decrypted)

        print(f"Decrypted file saved to: {out_path}")
        log_event(user, f"Decrypted {enc_fname}")
        pause()
    except Exception as e:
        print("Decryption failed:", e)
        pause()

# -------------------- LOAD DOCUMENT FILES --------------------

def load_documents():
    docs = []
    for i, fname in enumerate(os.listdir(PLAIN_DOC_DIR), start=1):
        if fname.endswith(".txt"):
            docs.append({"id": i, "title": fname})
    return docs

# -------------------- UTILITIES --------------------

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def pause():
    input("\nPress ENTER to continue...")

def log_event(user, action):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now()} | {user} | {action}\n")

# -------------------- LOGIN --------------------

def login():
    clear()
    print("=== SECURE LOGIN ===\n")
    u = input("Username: ")
    p = input("Password: ")

    user = USERS.get(u)
    if user and user["password"] == p:
        log_event(u, "Logged in")
        return u, user["role"]
    else:
        print("Invalid credentials.")
        pause()
        return None, None

# -------------------- CLIENTS FROM TXT --------------------

def show_clients(user):
    filtered = clients.copy()

    while True:
        clear()
        print("=== CLIENT LIST (FROM FILE) ===\n")
        for c in filtered[:50]:
            print(c)
        print(f"\nTotal Clients: {len(filtered)}")

        print("\n[s] Search | [r] Reset | [q] Back")
        choice = input("Choice: ").lower()

        if choice == "s":
            term = input("Search: ").lower()
            filtered = [c for c in clients if term in c.lower()]
            log_event(user, f"Searched clients: {term}")
        elif choice == "r":
            filtered = clients.copy()
        elif choice == "q":
            return

# -------------------- DOCUMENT VAULT --------------------

def show_documents(user):
    docs = load_documents()

    while True:
        clear()
        print("=== ENCRYPTED DOCUMENT VAULT ===\n")
        for d in docs:
            print(f"{d['id']}. {d['title']}")

        print("\n[v] View | [d] Download | [b] Back")
        choice = input("Choice: ").lower()

        if choice == "b":
            return

        try:
            doc_id = int(input("Enter document ID: "))
            doc = next(d for d in docs if d["id"] == doc_id)
        except:
            print("Invalid document ID.")
            pause()
            continue

        plain_path = os.path.join(PLAIN_DOC_DIR, doc["title"])
        enc_path = os.path.join(ENC_DOC_DIR, doc["title"] + ".enc")

        if not os.path.exists(enc_path):
            print("This file is not encrypted yet.")
            pause()
            continue

        with open(enc_path, "rb") as f:
            decrypted = cipher.decrypt(f.read()).decode()

        if choice == "v":
            clear()
            print(f"=== {doc['title']} ===\n")
            print(decrypted)
            log_event(user, f"Viewed {doc['title']}")
            pause()

        elif choice == "d":
            with open(doc["title"], "w", encoding="utf-8") as f:
                f.write(decrypted)
            print("Downloaded locally.")
            log_event(user, f"Downloaded {doc['title']}")
            pause()

# -------------------- ENCRYPT FILE OPTION --------------------

def encrypt_file(user):
    files = [f for f in os.listdir(PLAIN_DOC_DIR) if f.endswith((".txt", ".docx"))]

    if not files:
        print("No TXT files to encrypt.")
        pause()
        return

    clear()
    print("=== ENCRYPT A FILE ===\n")
    for i, f in enumerate(files, start=1):
        print(f"{i}. {f}")

    try:
        choice = int(input("\nSelect file number: "))
        fname = files[choice - 1]
    except:
        print("Invalid selection.")
        pause()
        return

    plain_path = os.path.join(PLAIN_DOC_DIR, fname)
    enc_path = os.path.join(ENC_DOC_DIR, fname + ".enc")

    with open(plain_path, "rb") as f:
        encrypted = cipher.encrypt(f.read())

    with open(enc_path, "wb") as f:
        f.write(encrypted)

    print(f"Encrypted file saved to: {enc_path}")
    log_event(user, f"Encrypted {fname}")
    pause()

# -------------------- LOG VIEW --------------------

def view_logs(role):
    if role != "admin":
        print("Admin only.")
        pause()
        return

    clear()
    print("=== ACCESS LOGS ===\n")
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE) as f:
            print(f.read())
    else:
        print("No logs found.")
    pause()

# -------------------- MAIN MENU --------------------

def main_menu(user, role):
    while True:
        clear()
        print("======================================")
        print(" SECURE TERMINAL CYBERSECURITY SYSTEM ")
        print("======================================\n")
        print("1. View Clients (from TXT)")
        print("2. View All Documents")
        print("3. Encrypt a TXT File")
        print("4. Decrypt a TXT File")
        print("5. View Logs (Admin)")
        print("0. Logout\n")

        choice = input("Select option: ")

        if choice == "1":
            show_clients(user)
        elif choice == "2":
            show_documents(user)
        elif choice == "3":
            encrypt_file(user)
        elif choice == "4":
            decrypt_file(user) 
        elif choice == "5":
            view_logs(role)
        elif choice == "0":
            log_event(user, "Logged out")
            return
        else:
            print("Invalid option.")
            pause()

# -------------------- RUN --------------------

if __name__ == "__main__":
    while True:
        user, role = login()
        if user:
            main_menu(user, role)
