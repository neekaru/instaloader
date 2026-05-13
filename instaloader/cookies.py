"""Native browser cookie extraction for Chromium-based browsers, Firefox, and Safari.

Supports:
- Chromium-based: Brave, Chrome, Chromium, Edge, Opera, Vivaldi, Helium
- Firefox
- Safari (macOS binary cookie format)
- cookies.txt (Netscape format)

Encrypted Chromium cookies (v10/v11) are decrypted using:
- AES-CBC with PBKDF2-derived key (via pyaes)
- Linux: secretstorage / KWallet for v11 key
- macOS: security CLI (Keychain) for v10/v11 key
"""

import base64
import hashlib
import logging
import os
import re
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from glob import glob
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


# ── Platform helpers ────────────────────────────────────────────────────

def _config_home() -> str:
    return os.environ.get('XDG_CONFIG_HOME', os.path.expanduser('~/.config'))


def _is_macos() -> bool:
    return sys.platform == 'darwin'


def _is_linux() -> bool:
    return sys.platform.startswith('linux')


def _is_windows() -> bool:
    return sys.platform in ('win32', 'cygwin')


# ── Browser paths ──────────────────────────────────────────────────────

def _chromium_browser_paths() -> Dict[str, List[str]]:
    if _is_windows():
        local = os.path.expandvars('%LOCALAPPDATA%')
        roaming = os.path.expandvars('%APPDATA%')
        return {
            'brave': [os.path.join(local, R'BraveSoftware\Brave-Browser\User Data')],
            'chrome': [os.path.join(local, R'Google\Chrome\User Data')],
            'chromium': [os.path.join(local, R'Chromium\User Data')],
            'edge': [os.path.join(local, R'Microsoft\Edge\User Data')],
            'opera': [os.path.join(roaming, R'Opera Software\Opera Stable')],
            'vivaldi': [os.path.join(local, R'Vivaldi\User Data')],
            'helium': [os.path.join(local, R'Helium\User Data')],
        }
    elif _is_macos():
        appdata = os.path.expanduser('~/Library/Application Support')
        return {
            'brave': [os.path.join(appdata, 'BraveSoftware/Brave-Browser')],
            'chrome': [os.path.join(appdata, 'Google/Chrome')],
            'chromium': [os.path.join(appdata, 'Chromium')],
            'edge': [os.path.join(appdata, 'Microsoft Edge')],
            'opera': [os.path.join(appdata, 'com.operasoftware.Opera')],
            'vivaldi': [os.path.join(appdata, 'Vivaldi')],
            'helium': [os.path.join(appdata, 'Helium')],
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
            'helium': [os.path.join(config, 'net.imput.helium')],
        }


def _find_cookie_db(root: str) -> Optional[str]:
    for dirpath, dirnames, files in os.walk(root):
        if 'Cookies' in files:
            return os.path.join(dirpath, 'Cookies')
        skip = {'Cache', 'Code Cache', 'GPUCache', 'ShaderCache',
                'GrShaderCache', 'GraphiteDawnCache', 'Component Cache',
                'component_crx_cache', 'segmentation_platform'}
        dirnames[:] = [d for d in dirnames if d not in skip]
    return None


# ── AES-CBC ────────────────────────────────────────────────────────────

def _aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    import pyaes
    dec = pyaes.Decrypter(pyaes.AESModeOfOperationCBC(key, iv))
    return dec.feed(ciphertext) + dec.feed()


def _pbkdf2(password: bytes, iterations: int = 1) -> bytes:
    return hashlib.pbkdf2_hmac('sha1', password, b'saltysalt', iterations, 16)


def _get_keyring_key() -> Optional[bytes]:
    if _is_macos():
        return _get_macos_keyring_key()
    return _get_linux_keyring_key()


def _get_macos_keyring_key() -> Optional[bytes]:
    for name in ('Chromium', 'Chrome', 'Brave', 'Helium'):
        try:
            result = subprocess.run(
                ['security', 'find-generic-password', '-w',
                 '-a', name, '-s', f'{name} Safe Storage'],
                capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return result.stdout.rstrip('\n').encode()
        except FileNotFoundError:
            pass
        except Exception:
            pass
    return None


def _get_linux_keyring_key() -> Optional[bytes]:
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


# ── Chrome cookie decryption ───────────────────────────────────────────

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

    kr_key = _get_keyring_key() if version == b'v11' else None

    if kr_key:
        keys_to_try = [
            (_pbkdf2(kr_key, 1003 if _is_macos() else 1), 'v11'),
            (_pbkdf2(b'peanuts'), 'v10'),
            (_pbkdf2(b''), 'empty'),
        ]
    else:
        keys_to_try = [
            (_pbkdf2(b'peanuts'), 'v10'),
            (_pbkdf2(b''), 'empty'),
        ]

    for key, _label in keys_to_try:
        try:
            pt = _aes_cbc_decrypt(ciphertext, key, iv)
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
        db_path = None
        for root in paths:
            if os.path.exists(root):
                db_path = _find_cookie_db(root)
                if db_path:
                    break

    if not db_path or not os.path.exists(db_path):
        raise FileNotFoundError(f'Could not find Cookies database for {browser}')

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
    if _is_windows():
        return [os.path.expandvars(R'%APPDATA%\Mozilla\Firefox\Profiles')]
    elif _is_macos():
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


# ── Safari extraction (macOS binary cookies) ───────────────────────────

def _safari_cookie_paths() -> List[str]:
    return [
        os.path.expanduser('~/Library/Cookies/Cookies.binarycookies'),
        os.path.expanduser('~/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies'),
    ]


def _parse_safari_cookies(data: bytes) -> Dict[str, str]:
    """Parse Safari binary cookie format (Cookies.binarycookies).

    Reference: https://github.com/libyal/dtformats/blob/main/documentation/Safari%20Cookies.asciidoc
    """
    cookies: Dict[str, str] = {}
    offset = 0

    if data[offset:offset + 4] != b'cook':
        raise ValueError('Not a Safari cookies file')
    offset += 4

    num_pages = struct.unpack_from('>I', data, offset)[0]
    offset += 4
    page_sizes = [struct.unpack_from('>I', data, offset + i * 4)[0] for i in range(num_pages)]
    offset += num_pages * 4

    for page_size in page_sizes:
        page = data[offset:offset + page_size]
        offset += page_size

        if page[:4] != b'\x00\x00\x01\x00':
            continue

        num_cookies = struct.unpack_from('<I', page, 4)[0]
        record_offsets = [struct.unpack_from('<I', page, 8 + i * 4)[0] for i in range(num_cookies)]
        if not record_offsets:
            continue

        for rec_off in record_offsets:
            if rec_off + 4 > len(page):
                continue
            rec_size = struct.unpack_from('<I', page, rec_off)[0]
            if rec_off + rec_size > len(page):
                continue
            rec = page[rec_off:rec_off + rec_size]

            flags = struct.unpack_from('<I', rec, 8)[0]
            is_secure = bool(flags & 0x0001)
            domain_off = struct.unpack_from('<I', rec, 16)[0]
            name_off = struct.unpack_from('<I', rec, 20)[0]
            path_off = struct.unpack_from('<I', rec, 24)[0]
            value_off = struct.unpack_from('<I', rec, 28)[0]

            def read_str(start):
                end = rec.index(b'\x00', start) if b'\x00' in rec[start:] else len(rec)
                return rec[start:end].decode('utf-8', errors='replace')

            try:
                domain = read_str(domain_off)
                name = read_str(name_off)
                path = read_str(path_off)
                value = read_str(value_off)
                cookies[name] = value
            except (ValueError, IndexError):
                continue

    return cookies


def _extract_safari_cookies(domain_filter: Optional[str] = None) -> Dict[str, str]:
    for path in _safari_cookie_paths():
        if os.path.isfile(path):
            with open(path, 'rb') as f:
                data = f.read()
            cookies = _parse_safari_cookies(data)
            if domain_filter:
                cookies = {k: v for k, v in cookies.items()
                          if domain_filter in str(k)}
            if cookies:
                return cookies
    return {}


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

    if browser in ('brave', 'chrome', 'chromium', 'edge', 'opera', 'vivaldi', 'helium'):
        cookies = _extract_chrome_cookies(browser, cookie_path, domain)
    elif browser == 'firefox':
        cookies = _extract_firefox_cookies(profile or cookie_path, domain)
    elif browser in ('safari',):
        if not _is_macos():
            raise ValueError('Safari is only supported on macOS')
        cookies = _extract_safari_cookies(domain)
    else:
        raise ValueError(f'Unsupported browser: {browser}')

    if not cookies:
        raise ValueError(f'No cookies found for {domain} in {browser}')

    return cookies
