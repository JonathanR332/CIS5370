import os
from cryptography.fernet import Fernet
from datetime import datetime

# users for the login
USERS = {
    "JRizo": {"password": "123", "role":"admin"}, #my user
    "admin": {"password":"123", "role":"admin"}, #generic admin user
    "user": {"password":"123", "role":"user"} #generic user
}

# These paths are easily changed, if you are not using the same setup as given in the github please change.
CLIENT_FILE = "Clients/clients.txt"
PLAIN_DOC_DIR = "plain_documents"
ENC_DOC_DIR = "encrypted_documents"
KEY_FILE = "vault.key"
LOG_FILE = "access.log"

# making sure folders exist (they should anyway)
os.makedirs(PLAIN_DOC_DIR, exist_ok=True)
os.makedirs(ENC_DOC_DIR, exist_ok=True)



# loading the client list from txt file again this is interchangable.
def load_clients_file():
    if not os.path.exists(CLIENT_FILE):
        return []
    data = []
    with open(CLIENT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                data.append(line.strip())
    return data

clients = load_clients_file()



# encryption key stuff
if not os.path.exists(KEY_FILE):
    # making a key just it case it does not exist. This will not work at all without it.
    k = Fernet.generate_key() #using Fernet to generate my key (This is the encryption technique.)
    with open(KEY_FILE, "wb") as f:
        f.write(k)
else:
    # read the key again
    with open(KEY_FILE, "rb") as f:
        key = f.read()

cipher = Fernet(key)



# small helpers
def clear():
    os.system("cls" if os.name=="nt" else "clear")

def pause():
    input("\nPress ENTER to continue...")

def log_event(user, txt):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now()} | {user} | {txt}\n")



# login screen
def login():
    clear()
    print("Welcome please Login!")
    loginUser = input("Username: ")
    pword = input("Password: ")

    if loginUser in USERS and USERS[loginUser]["password"] == pword:
        log_event(loginUser, "Logged in")
        return loginUser, USERS[loginUser]["role"]
    else:
        print("Login failed. Please try again!") 
        pause()
        return None, None #sends you back



# show clients from the txt file
def show_clients(user):
    filtered = clients[:]  # copy of the original list

    while True:
        clear()
        print("=== CLIENT LIST ===\n")

        # for demo purposes we have created a clients.txt file with only 50 patients.
        for c in filtered[:50]:
            print(c)

        print(f"\nTotal Clients: {len(filtered)}")

        print("\n(s) Search  | (r) Reset | (q) Quit") #menu, this will be repeated in the other functions.
        selection = input("Choice: ").lower()

        if selection == "s":
            s = input("Search: ").lower()
            filtered = [c for c in clients if s in c.lower()]
            log_event(user, f"Searched clients for {s}")
        elif selection == "r":
            filtered = clients[:]
        elif selection == "q":
            return



# list the available document files
def load_docs():
    items = []
    n = 1
    for name in os.listdir(PLAIN_DOC_DIR):
        if name.endswith(".txt"):
            items.append({"id": n, "title": name})
            n += 1
    return items



# document vault viewer
def show_documents(user):
    docs = load_docs()

    while True:
        clear()
        print("=== DOCUMENT VAULT ===\n")

        for d in docs:
            print(f"{d['id']}. {d['title']}")

        print("\n[v] View   |  [d] Download  |  [b] Back")
        choice = input("Choice: ").lower()

        if choice == "b":
            return

        # pick the document ID after user presses v/d
        try:
            doc_id = int(input("Document ID: "))
            doc = next(d for d in docs if d["id"] == doc_id)
        except:
            print("Invalid ID.")
            pause()
            continue

        # paths
        plain_file = os.path.join(PLAIN_DOC_DIR, doc["title"])
        enc_file = os.path.join(ENC_DOC_DIR, doc["title"] + ".enc")

        if not os.path.exists(enc_file):
            print("File isn’t encrypted yet.")
            pause()
            continue

        with open(enc_file, "rb") as f:
            # decrypt to text
            try:
                decrypted_text = cipher.decrypt(f.read()).decode()
            except:
                print("There was an error in decrypting your file. Please try again.")
                pause()
                continue

        if choice == "v":
            clear()
            print(f"=== Viewing: {doc['title']} ===\n")
            print(decrypted_text)
            log_event(user, f"Viewed {doc['title']}")
            pause()

        elif choice == "d":
            # save the decrypted text in the working folder
            with open(doc["title"], "w", encoding="utf-8") as out:
                out.write(decrypted_text)
            print("File downloaded.")
            log_event(user, f"Downloaded {doc['title']}")
            pause()



# encrypt a file option
def encrypt_file(user):
    files = [x for x in os.listdir(PLAIN_DOC_DIR) if x.endswith(".txt") or x.endswith(".docx")]     # allowing docx and tct files.


    if not files:
        print("There is nothing to encrypt.") #incase of errors
        pause()
        return

    clear()
    print("=== ENCRYPT FILE ===\n")
    for i, f in enumerate(files, start=1): #assigning numbers to the file names. reused
        print(f"{i}. {f}")

    try:
        choice = int(input("\nSelect file number: "))
        file_name = files[choice - 1] #enumerated
    except:
        print("Invalid selection. Please try again.")
        pause()
        return

    in_path = os.path.join(PLAIN_DOC_DIR, file_name)
    out_path = os.path.join(ENC_DOC_DIR, file_name + ".enc") #simple way to let you know this has file has been encrypted. without you having to open it

    with open(in_path, "rb") as f:
        data = f.read()

    enc = cipher.encrypt(data)

    with open(out_path, "wb") as f:
        f.write(enc)

    print(f"Saved: {out_path}")
    log_event(user, f"Encrypted {file_name}")
    pause()



# decrypt option
def decrypt_file(user):
    files = [x for x in os.listdir(ENC_DOC_DIR) if x.endswith(".enc")]

    if not files:
        print("No encrypted files.")
        pause()
        return

    clear()
    print("DECRYPT FILE\n")

    for i, f in enumerate(files, start=1): #assign numbers
        print(f"{i}. {f}")

    try:
        choice = int(input("\nPick file: "))
        file_name = files[choice - 1]
    except:
        print("Invalid.")
        pause()
        return

    encpath = os.path.join(ENC_DOC_DIR, file_name)
    out_name = file_name.replace(".enc", "")
    out_path = os.path.join(PLAIN_DOC_DIR, out_name)

    try:
        with open(encpath, "rb") as f:
            raw = cipher.decrypt(f.read())

        with open(out_path, "wb") as f:
            f.write(raw)

        print("Decrypted OK:", out_path)
        log_event(user, f"Decrypted {file_name}")
        pause()
    except Exception as e: #exception handling
        print("Error:", e)
        pause()



# view logs specifically for admins 
def view_logs(role):
    if role != "admin": # again only for admins can be changed though
        print("Admins only.")
        pause()
        return

    clear()
    print("=== LOGS ===\n")

    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            print(f.read())
    else:
        print("No logs yet.") #in case there is either no log file aka it is deletd or nothing has happened yet.
    pause()



# main menu loop
def main_menu(user, role):
    while True:
        clear()
        print("Welcome")
        print("-------------------------------------------------------")

        

        print("1. View Clients")
        print("2. View Documents")
        print("3. Encrypt File")
        print("4. Decrypt File")
        print("5. View Logs (Admin)")
        print("0. Logout\n")

        Action = input("Select: ")

        if Action == "1":
            show_clients(user)
        elif Action == "2":
            show_documents(user)
        elif Action == "3":
            encrypt_file(user)
        elif Action == "4":
            decrypt_file(user)
        elif Action == "5":
            view_logs(role)
        elif Action == "0":
            log_event(user, "Logged out")
            return
        else:
            print("Try again.")
            pause()



# run everything
if __name__ == "__main__":
    while True:
        u, r = login()
        if u:
            main_menu(u, r)
