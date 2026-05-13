"""Native browser cookie extraction for Chromium-based browsers and Firefox.

Supports:
- Chromium-based: Brave, Chrome, Chromium, Edge, Opera, Vivaldi, Helium
- Firefox
- cookies.txt (Netscape format)

Encrypted Chromium cookies (v10/v11) are decrypted using:
- AES-CBC with PBKDF2-derived key (via pyaes)
- OS keyring (secretstorage / KWallet) for v11 key
"""

import base64
import hashlib
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from glob import glob
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


# ── Browser paths ──────────────────────────────────────────────────────

def _config_home() -> str:
    return os.environ.get('XDG_CONFIG_HOME', os.path.expanduser('~/.config'))


def _chromium_browser_paths() -> Dict[str, List[str]]:
    if sys.platform in ('win32', 'cygwin'):
        local = os.path.expandvars('%LOCALAPPDATA%')
        roaming = os.path.expandvars('%APPDATA%')
        return {
            'brave': [os.path.join(local, R'BraveSoftware\Brave-Browser\User Data')],
            'chrome': [os.path.join(local, R'Google\Chrome\User Data')],
            'chromium': [os.path.join(local, R'Chromium\User Data')],
            'edge': [os.path.join(local, R'Microsoft\Edge\User Data')],
            'opera': [os.path.join(roaming, R'Opera Software\Opera Stable')],
            'vivaldi': [os.path.join(local, R'Vivaldi\User Data')],
        }
    elif sys.platform == 'darwin':
        appdata = os.path.expanduser('~/Library/Application Support')
        return {
            'brave': [os.path.join(appdata, 'BraveSoftware/Brave-Browser')],
            'chrome': [os.path.join(appdata, 'Google/Chrome')],
            'chromium': [os.path.join(appdata, 'Chromium')],
            'edge': [os.path.join(appdata, 'Microsoft Edge')],
            'opera': [os.path.join(appdata, 'com.operasoftware.Opera')],
            'vivaldi': [os.path.join(appdata, 'Vivaldi')],
        }
    else:
        config = _config_home()
        return {
            'brave': [os.path.join(config, 'BraveSoftware/Brave-Browser')],
            'chrome': [os.path.join(config, 'google-chrome')],
            'chromium': [os.path.join(config, 'chromium')],
            'edge': [os.path.join(config, 'microsoft-edge')],
            'opera': [os.path.join(config, 'opera')],
            'vivaldi': [os.path.join(config, 'vivaldi')],
        }


def _find_cookie_db(root: str) -> Optional[str]:
    """Walk Chromium profile dirs to find Cookies database."""
    for dirpath, dirnames, files in os.walk(root):
        if 'Cookies' in files:
            return os.path.join(dirpath, 'Cookies')
        skip = {'Cache', 'Code Cache', 'GPUCache', 'ShaderCache',
                'GrShaderCache', 'GraphiteDawnCache', 'Component Cache',
                'component_crx_cache', 'segmentation_platform'}
        dirnames[:] = [d for d in dirnames if d not in skip]
    return None


# ── AES-CBC decryption ────────────────────────────────────────────────

def _aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    import pyaes
    dec = pyaes.Decrypter(pyaes.AESModeOfOperationCBC(key, iv))
    plaintext = dec.feed(ciphertext) + dec.feed()
    return plaintext


def _get_v10_key() -> bytes:
    return hashlib.pbkdf2_hmac('sha1', b'peanuts', b'saltysalt', 1, 16)


def _get_empty_key() -> bytes:
    return hashlib.pbkdf2_hmac('sha1', b'', b'saltysalt', 1, 16)


def _get_keyring_key() -> Optional[bytes]:
    for name in ('Chromium', 'Chrome', 'Brave', 'Helium'):
        try:
            import secretstorage
            import dbus
            try:
                con = secretstorage.dbus_init()
                col = secretstorage.get_default_collection(con)
                for item in col.get_all_items():
                    if f'{name} Safe Storage' in item.get_label():
                        secret = item.get_secret()
                        con.close()
                        return secret
                con.close()
            except dbus.exceptions.DBusException:
                pass
        except ImportError:
            pass

        try:
            result = subprocess.run(
                ['kwallet-query', '--read-password', f'{name} Safe Storage',
                 '--folder', f'{name} Keys', 'kdewallet'],
                capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and not result.stdout.lower().startswith('failed'):
                return result.stdout.rstrip('\n').encode()
        except FileNotFoundError:
            pass
        except Exception:
            pass
    return None


def _make_v11_key(keyring_secret: bytes) -> Optional[bytes]:
    """Derive AES key from keyring secret.

    Chromium v11 on Linux: keyring stores a base64-encoded blob.
    The AES key is PBKDF2-HMAC-SHA1(keyring_secret, 'saltysalt', 1, 16)
    where keyring_secret is the raw bytes from keyring (ASCII base64 string).
    """
    return hashlib.pbkdf2_hmac('sha1', keyring_secret, b'saltysalt', 1, 16)


def _decrypt_chrome_value(encrypted_value: bytes) -> Optional[str]:
    if not encrypted_value:
        return ''

    version = encrypted_value[:3]
    payload = encrypted_value[3:]

    if version not in (b'v10', b'v11'):
        try:
            return encrypted_value.decode('utf-8')
        except UnicodeDecodeError:
            return None

    iv = payload[:16]
    ciphertext = payload[16:]

    if len(ciphertext) < 16 or len(ciphertext) % 16 != 0:
        return None

    keys_to_try = [(_get_v10_key(), 'v10')]

    if version == b'v11':
        kr_key = _get_keyring_key()
        if kr_key:
            v11_key = _make_v11_key(kr_key)
            if v11_key:
                keys_to_try.insert(0, (v11_key, 'v11'))

    keys_to_try.append((_get_empty_key(), 'empty'))

    for key, label in keys_to_try:
        try:
            pt = _aes_cbc_decrypt(ciphertext, key, iv)
            # Chromium >= schema version 24 prepends a 16-byte HMAC-SHA256 hash
            val = pt[16:] if len(pt) > 16 else pt
            decoded = val.decode('utf-8')
            if decoded:
                return decoded
        except Exception:
            continue

    return None


# ── Chromium extraction ────────────────────────────────────────────────

def _extract_chrome_cookies(browser: str, cookie_path: Optional[str] = None,
                             domain_filter: Optional[str] = None) -> Dict[str, str]:
    if cookie_path:
        db_path = cookie_path
    else:
        paths = _chromium_browser_paths().get(browser, [])
        if browser == 'helium':
            paths = [os.path.expanduser('~/.config/net.imput.helium')]
        db_path = None
        for root in paths:
            if os.path.exists(root):
                db_path = _find_cookie_db(root)
                if db_path:
                    break

    if not db_path or not os.path.exists(db_path):
        raise FileNotFoundError(f'Could not find Cookies database for {browser}')

    hardcoded_paths = {
        'helium': os.path.expanduser('~/.config/net.imput.helium'),
    }
    browser_dir = db_path.replace('/Cookies', '').replace('/Default/Cookies', '')

    with tempfile.TemporaryDirectory(prefix='instaloader_') as tmpdir:
        copy_path = os.path.join(tmpdir, 'Cookies')
        shutil.copy(db_path, copy_path)
        conn = sqlite3.connect(copy_path)
        conn.text_factory = bytes
        cur = conn.cursor()

        cur.execute('SELECT host_key, name, value, encrypted_value FROM cookies')
        cookies: Dict[str, str] = {}
        for row in cur.fetchall():
            host_key = row[0].decode()
            name = row[1].decode()
            value = row[2].decode() if row[2] else ''
            encrypted_value = row[3] if row[3] else b''

            if domain_filter and domain_filter not in host_key:
                continue

            if not value and encrypted_value:
                decrypted = _decrypt_chrome_value(encrypted_value)
                if decrypted is not None:
                    value = decrypted
                else:
                    continue

            cookies[name] = value

        conn.close()
        return cookies


# ── Firefox extraction ─────────────────────────────────────────────────

def _firefox_dirs() -> List[str]:
    if sys.platform in ('cygwin', 'win32'):
        return [os.path.expandvars(R'%APPDATA%\Mozilla\Firefox\Profiles')]
    elif sys.platform == 'darwin':
        return [os.path.expanduser('~/Library/Application Support/Firefox/Profiles')]
    return [
        os.path.join(_config_home(), 'mozilla/firefox'),
        os.path.expanduser('~/.mozilla/firefox'),
        os.path.expanduser('~/.var/app/org.mozilla.firefox/config/mozilla/firefox'),
        os.path.expanduser('~/.var/app/org.mozilla.firefox/.mozilla/firefox'),
        os.path.expanduser('~/snap/firefox/common/.mozilla/firefox'),
    ]


def _extract_firefox_cookies(profile_path: Optional[str] = None,
                              domain_filter: Optional[str] = None) -> Dict[str, str]:
    roots = [profile_path] if profile_path else _firefox_dirs()
    db_path = None
    for root in roots:
        for pattern in ('', '*/', 'Profiles/*/'):
            matches = list(glob(os.path.join(os.path.abspath(root), pattern, 'cookies.sqlite')))
            if matches:
                db_path = matches[0]
                break
        if db_path:
            break
    if not db_path:
        raise FileNotFoundError('Could not find Firefox cookies database')

    with tempfile.TemporaryDirectory(prefix='instaloader_') as tmpdir:
        copy_path = os.path.join(tmpdir, 'cookies.sqlite')
        shutil.copy(db_path, copy_path)
        conn = sqlite3.connect(copy_path)
        cur = conn.cursor()
        cur.execute('SELECT host, name, value FROM moz_cookies')
        cookies = {}
        for row in cur.fetchall():
            if domain_filter and domain_filter not in (row[0] or ''):
                continue
            cookies[row[1]] = row[2]
        conn.close()
        return cookies


# ── cookies.txt (Netscape format) ───────────────────────────────────────

def _parse_netscape_cookies(filepath: str) -> Dict[str, str]:
    cookies: Dict[str, str] = {}
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('HttpOnly'):
                continue
            parts = line.split('\t')
            if len(parts) >= 7:
                cookies[parts[5]] = parts[6]
    return cookies


# ── Public API ──────────────────────────────────────────────────────────

SUPPORTED_BROWSERS = {
    'brave', 'chrome', 'chromium', 'edge', 'firefox',
    'librewolf', 'opera', 'opera_gx', 'safari',
    'vivaldi', 'helium',
}


def extract_cookies(browser: str, domain: str = 'instagram',
                    cookie_path: Optional[str] = None,
                    profile: Optional[str] = None) -> Dict[str, str]:
    browser = browser.lower()

    if cookie_path and cookie_path.endswith('.txt'):
        cookies = _parse_netscape_cookies(cookie_path)
        return {k: v for k, v in cookies.items() if domain in str(k)}

    if browser == 'firefox':
        cookies = _extract_firefox_cookies(profile or cookie_path, domain)
    elif browser in ('brave', 'chrome', 'chromium', 'edge', 'opera', 'vivaldi', 'helium'):
        cookies = _extract_chrome_cookies(browser, cookie_path, domain)
    else:
        raise ValueError(f'Unsupported browser: {browser}')

    if not cookies:
        raise ValueError(f'No cookies found for {domain} in {browser}')

    return cookies
