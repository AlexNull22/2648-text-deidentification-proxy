"""Encrypted, session-scoped placeholder mappings. Dependency: cryptography.

Values retain their exact original spelling and whitespace. No case folding or
normalization is applied. Keys remain in memory and are never stored in SQLite.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path

from cryptography.fernet import Fernet

KINDS = ("PERSON", "CORP", "EMAIL", "PHONE", "LOCATION", "POSTAL", "CARD")
SESSION = re.compile(r"[A-Za-z0-9_-]{1,80}\Z", re.ASCII)
TOKEN = re.compile(r"\[(PERSON|CORP|EMAIL|PHONE|LOCATION|POSTAL|CARD)_([^\[\]\r\n]*)\]")
TOKENISH = re.compile(r"\[([A-Z][A-Z0-9_]*)_([0-9]+)\]")
SENTINEL = b"2648-encrypted-mapping-vault-version-2-authenticated-bindings"


class VaultError(Exception):
    """Safe public error: messages never include entity values, text, or keys."""


class Vault:
    def __init__(self, path, key: bytes | str):
        try:
            encoded = key.encode("ascii") if isinstance(key, str) else key
            if not isinstance(encoded, bytes):
                raise ValueError()
            self._fernet = Fernet(encoded)
            raw_key = base64.urlsafe_b64decode(encoded)
            self._lookup_key = hmac.new(raw_key, b"2648-vault-lookup-key-v1", hashlib.sha256).digest()
        except Exception:
            raise VaultError("Invalid vault encryption key") from None
        try:
            self._path = Path(path).absolute()
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._initialize()
        except VaultError:
            raise
        except Exception:
            raise VaultError("Unable to initialize encrypted vault") from None

    def _connect(self):
        connection = sqlite3.connect(self._path, timeout=30, isolation_level=None)
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def _initialize(self):
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
                if not tables:
                    connection.execute("CREATE TABLE vault_meta (meta_key TEXT PRIMARY KEY NOT NULL, encrypted_value BLOB NOT NULL)")
                    connection.execute("CREATE TABLE vault_mappings (session_id TEXT NOT NULL, kind TEXT NOT NULL, ordinal INTEGER NOT NULL CHECK(ordinal>0), lookup_digest BLOB NOT NULL, ciphertext BLOB NOT NULL, PRIMARY KEY(session_id,kind,ordinal), UNIQUE(session_id,kind,lookup_digest))")
                    connection.execute("INSERT INTO vault_meta VALUES (?,?)", ("key_check", self._fernet.encrypt(SENTINEL)))
                elif tables != {"vault_meta", "vault_mappings"}:
                    raise VaultError("Unsupported vault database format")
                self._verify(connection)
                expected = {"session_id", "kind", "ordinal", "lookup_digest", "ciphertext"}
                if {row[1] for row in connection.execute("PRAGMA table_info(vault_mappings)")} != expected:
                    raise VaultError("Unsupported vault database format")
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def _verify(self, connection):
        try:
            record = connection.execute("SELECT encrypted_value FROM vault_meta WHERE meta_key=?", ("key_check",)).fetchone()
            if record is None or not hmac.compare_digest(self._fernet.decrypt(record[0]), SENTINEL):
                raise ValueError()
        except Exception:
            raise VaultError("Vault key validation or database integrity check failed") from None

    @contextmanager
    def _transaction(self, write=False):
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            try:
                self._verify(connection)
                yield connection
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    @staticmethod
    def _session(session_id):
        if not isinstance(session_id, str) or SESSION.fullmatch(session_id) is None:
            raise VaultError("Session ID must be an ASCII label of 1 to 80 letters, digits, underscores, or hyphens")

    def _plaintext(self, ciphertext, session_id, kind, ordinal):
        try:
            envelope = json.loads(self._fernet.decrypt(ciphertext).decode("utf-8"))
            if not isinstance(envelope, dict) or set(envelope) != {"v", "session", "kind", "ordinal", "value"}:
                raise ValueError()
            if type(envelope["v"]) is not int or envelope["v"] != 1 or envelope["session"] != session_id or envelope["kind"] != kind or type(envelope["ordinal"]) is not int or envelope["ordinal"] != ordinal or not isinstance(envelope["value"], str) or not envelope["value"]:
                raise ValueError()
            return envelope["value"].encode("utf-8")
        except Exception:
            raise VaultError("Vault entry integrity check failed") from None

    def token_for(self, session_id: str, kind: str, value: str) -> str:
        self._session(session_id)
        if not isinstance(kind, str) or kind not in KINDS:
            raise VaultError("Unsupported entity kind")
        if not isinstance(value, str) or not value:
            raise VaultError("Entity value must be a non-empty string")
        try:
            plaintext = value.encode("utf-8")
            identity = session_id.encode("ascii") + b"\0" + kind.encode("ascii") + b"\0" + plaintext
            digest = hmac.new(self._lookup_key, identity, hashlib.sha256).digest()
            with self._transaction(write=True) as connection:
                record = connection.execute("SELECT ordinal,ciphertext FROM vault_mappings WHERE session_id=? AND kind=? AND lookup_digest=?", (session_id, kind, digest)).fetchone()
                if record:
                    if not hmac.compare_digest(self._plaintext(record[1], session_id, kind, record[0]), plaintext):
                        raise VaultError("Vault entry integrity check failed")
                    ordinal = record[0]
                else:
                    ordinal = connection.execute("SELECT COALESCE(MAX(ordinal),0)+1 FROM vault_mappings WHERE session_id=? AND kind=?", (session_id, kind)).fetchone()[0]
                    envelope = json.dumps({"v": 1, "session": session_id, "kind": kind, "ordinal": ordinal, "value": value}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                    connection.execute("INSERT INTO vault_mappings VALUES (?,?,?,?,?)", (session_id, kind, ordinal, digest, self._fernet.encrypt(envelope)))
                if type(ordinal) is not int or ordinal < 1:
                    raise VaultError("Vault entry integrity check failed")
                return f"[{kind}_{ordinal:02d}]"
        except VaultError:
            raise
        except Exception:
            raise VaultError("Unable to create or retrieve encrypted mapping") from None

    def restore_text(self, session_id: str, text: str) -> str:
        self._session(session_id)
        if not isinstance(text, str):
            raise VaultError("Text must be a string")
        try:
            if any(match.group(1) not in KINDS for match in TOKENISH.finditer(text)):
                raise VaultError("Unknown placeholder kind")
            matches, replacements = list(TOKEN.finditer(text)), {}
            with self._transaction() as connection:
                for match in matches:
                    token, kind, number = match.group(0), match.group(1), match.group(2)
                    if token in replacements:
                        continue
                    if not re.fullmatch(r"[0-9]{2,}", number) or int(number) < 1 or token != f"[{kind}_{int(number):02d}]":
                        raise VaultError("Unknown or malformed placeholder token")
                    record = connection.execute("SELECT ciphertext,lookup_digest FROM vault_mappings WHERE session_id=? AND kind=? AND ordinal=?", (session_id, kind, int(number))).fetchone()
                    if record is None:
                        raise VaultError("Unknown placeholder token for this session")
                    plaintext = self._plaintext(record[0], session_id, kind, int(number))
                    digest = hmac.new(self._lookup_key, session_id.encode("ascii") + b"\0" + kind.encode("ascii") + b"\0" + plaintext, hashlib.sha256).digest()
                    if not hmac.compare_digest(digest, record[1]):
                        raise VaultError("Vault entry integrity check failed")
                    replacements[token] = plaintext.decode("utf-8")
            # A single pass preserves token-like text contained inside original values.
            return TOKEN.sub(lambda match: replacements[match.group(0)], text)
        except VaultError:
            raise
        except Exception:
            raise VaultError("Unable to restore encrypted mapping") from None

    def stats(self, session_id: str) -> dict:
        self._session(session_id)
        try:
            counts = dict.fromkeys(KINDS, 0)
            with self._transaction() as connection:
                for kind, count in connection.execute("SELECT kind,COUNT(*) FROM vault_mappings WHERE session_id=? GROUP BY kind", (session_id,)):
                    if kind not in counts:
                        raise VaultError("Vault entry integrity check failed")
                    counts[kind] = count
            return counts
        except VaultError:
            raise
        except Exception:
            raise VaultError("Unable to read encrypted vault statistics") from None

    def close(self):
        """Compatibility no-op: each operation owns and closes its connection."""

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
