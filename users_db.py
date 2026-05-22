import pickle
import os
import threading
import random
import string
import hashlib
import smtplib
import ssl
import uuid
from email.message import EmailMessage
import base64
import time

FILE_NAME = "users.pkl"
lock = threading.Lock()

email_sender = "itaybelogorodsky@gmail.com"
email_password = 'suki lwll kawu knns'
pass_enc = ''.join([e.decode()[:2] for e in
[base64.b64encode(m.encode()) for m in email_password]])
security_code = str(uuid.uuid4())
half_length = len(security_code) // 2
security_code = security_code[:half_length]


def send_email(email_receiver, email_subject, email_body):
    em = EmailMessage()
    em['From'] = email_sender
    em['To'] = email_receiver
    em['Subject'] = email_subject
    em.set_content(email_body)

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
        email_password = ''.join(
            [base64.b64decode(e).decode() for e in
             [pass_enc[i:i+2] + '==' for i in range(0, len(pass_enc), 2)]]
        )

        smtp.login(email_sender, email_password)
        smtp.sendmail(email_sender, email_receiver, em.as_string())




def load_users():
    if not os.path.exists(FILE_NAME):
        return {}
    try:
        with open(FILE_NAME, "rb") as f:
            return pickle.load(f)
    except:
        return {}

def save_users(users):
    with open(FILE_NAME, "wb") as f:
        pickle.dump(users, f)

def IsUserExist(username):
    with lock:
        users = load_users()
        return username in users


def generate_random_string(n):
    characters = string.ascii_letters + string.digits  # a-z, A-Z, 0-9
    random_string = ''.join(random.choice(characters) for _ in range(n))
    return random_string
def SaveUser(username, password, email, pepper):
    with lock:
        sha_256 = hashlib.sha256()
        users = load_users()
        salt = generate_random_string(5)
        password = pepper + password + salt
        sha_256.update(password.encode())
        hash_password = sha_256.hexdigest()
        users[username] = {
            "password": hash_password,
            "email": email,
            "salt": salt
        }
        save_users(users)

def IsPasswordOK(username, password,pepper):
    with lock:
        sha_256 = hashlib.sha256()
        users = load_users()
        if username not in users:
            return False
        password = pepper + password + users[username]["salt"]
        sha_256.update(password.encode())
        hash_password = sha_256.hexdigest()
        return users[username]["password"] == hash_password


def generate_code():
    return str(random.randint(10000,99999))

def StartRegister(username,password,email):

    users = load_users()

    for u in users.values():
        if u["email"] == email:
            return False

    code = generate_code()

    users["pending_"+email] = {
        "username": username,
        "password": password,
        "code": code,
        "expiry": time.time() + 300
    }

    save_users(users)

    send_email(email,"Verification code",code)

    return True

def VerifyRegister(email,code):

    users = load_users()

    key = "pending_"+email

    if key not in users:
        return False

    data = users[key]

    if time.time() > data["expiry"]:
        del users[key]
        save_users(users)
        return False

    if data["code"] != code:
        return False

    # קודם מוחקים pending
    del users[key]
    save_users(users)

    # ואז יוצרים משתמש אמיתי
    SaveUser(data["username"],data["password"],email,"P3P3P3ER")

    return True

def StartReset(email):

    users = load_users()

    for username,data in users.items():
        if data["email"] == email:

            code = generate_code()

            users["reset_"+email] = {
                "username": username,
                "code": code,
                "expiry": time.time()+300
            }

            save_users(users)

            send_email(email,"Reset code",code)

            return True

    return False

def VerifyReset(email,code):

    users = load_users()

    key = "reset_"+email

    if key not in users:
        return None

    data = users[key]

    if time.time() > data["expiry"]:
        del users[key]
        save_users(users)
        return None

    if data["code"] != code:
        return None

    return data["username"]

def ChangePassword(username,new_password,pepper):

    users = load_users()

    salt = generate_random_string(5)

    sha = hashlib.sha256()
    sha.update((pepper+new_password+salt).encode())

    users[username]["password"] = sha.hexdigest()
    users[username]["salt"] = salt

    save_users(users)