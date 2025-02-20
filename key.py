import os
import json
import logging
import getpass
import hashlib
import base64
from typing import Optional, Dict, Any

import coincurve
from coincurve.utils import sha256

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes

logging.basicConfig(level=logging.INFO)


class KeyManager:

    def __init__(
        self,
        key_dir: Optional[str] = None,
        ephemeral_mode: bool = False,
        use_encryption: bool = True,
        salt_str: str = "KeyMgrDefaultSalt",
        passphrase_source: str = "ask"
    ):
        self.ephemeral_mode = ephemeral_mode
        self.use_encryption = use_encryption and (not ephemeral_mode)
        self.salt_str = salt_str
        self.passphrase_source = passphrase_source

       
        if not ephemeral_mode:
            if key_dir:
                os.makedirs(key_dir, exist_ok=True)
                self.json_file = os.path.join(key_dir, "keys.json")
            else:
                self.json_file = "keys.json"
        else:
            self.json_file = "ephemeral_keys.json"

       
        self.secret_key = None
        if self.use_encryption:
            passphrase = None
            if self.passphrase_source == "ask":
                passphrase = getpass.getpass("[KeyManager] Enter passphrase to unlock/create keys.json: ")
            elif self.passphrase_source == "env":
                passphrase = os.environ.get("KEYMGR_PASSPHRASE", None)
                if not passphrase:
                    logging.warning("[KeyManager] passphrase_source='env' but KEYMGR_PASSPHRASE not found => can't decrypt.")
            elif self.passphrase_source == "none":
                logging.warning("[KeyManager] passphrase_source='none' => no pass => decryption likely to fail.")
                passphrase = None

            if passphrase:
                self.secret_key = self._derive_key_from_passphrase(passphrase, self.salt_str)
            else:
                # passphrase=None => значит будет без шифрования
                pass
        else:
            logging.info("[KeyManager] ephemeral or no encryption => skipping passphrase logic.")

        self.keys: Dict[str, Any] = {}

        # Загружаем с диска (если не ephemeral)
        if not self.ephemeral_mode:
            self._load_keys()
        else:
            logging.warning("[KeyManager] ephemeral_mode => skip disk load => in-memory only.")

        logging.info(f"[KeyManager] init => ephemeral={self.ephemeral_mode}, encryption={self.use_encryption}, pass_src={self.passphrase_source}")





    def _load_keys(self):
        if not os.path.isfile(self.json_file):
            logging.info(f"[KeyManager] no file => skip => {self.json_file}")
            return
        try:
            with open(self.json_file, "rb") as f:
                file_data = f.read()
            if self.use_encryption and self.secret_key:
                file_data = self._aes_decrypt(file_data)
            js_str = file_data.decode("utf-8")
            loaded = json.loads(js_str)
            if isinstance(loaded, dict):
                self.keys = loaded
            logging.info(f"[KeyManager] loaded => {self.json_file}, encrypted={self.use_encryption}")
        except Exception as e:
            logging.error(f"[KeyManager] load error => {e}")

    def _save_keys(self):
        if self.ephemeral_mode:
            return
        try:
            raw_js = json.dumps(self.keys, indent=4)
            bytes_data = raw_js.encode("utf-8")
            if self.use_encryption and self.secret_key:
                bytes_data = self._aes_encrypt(bytes_data)

            tmp_path = self.json_file + ".tmp"
            with open(tmp_path, "wb") as f:
                f.write(bytes_data)
            os.replace(tmp_path, self.json_file)
            logging.info(f"[KeyManager] saved => {self.json_file}, encryption={self.use_encryption}")
        except Exception as e:
            logging.error(f"[KeyManager] save error => {e}")


    def create_schnorr_keys(self, node_id: str):
       
        if node_id in self.keys:
            raise ValueError(f"[KeyManager] Schnorr for {node_id} already exist.")

        # Генерация 32-байтного приватного ключа
        priv_bytes = os.urandom(32)
        priv = coincurve.PrivateKey(priv_bytes)
        pub = priv.public_key.format(compressed=True)  # 33 bytes

        self.keys[node_id] = {
            "schnorr_priv": priv_bytes.hex(),
            "schnorr_pub":  pub.hex()
        }
        self._save_keys()
        logging.info(f"[KeyManager] create Schnorr => node={node_id}")

    def get_schnorr_privkey(self, node_id: str) -> Optional[coincurve.PrivateKey]:
      
        if node_id not in self.keys:
            return None
        hx = self.keys[node_id].get("schnorr_priv")
        if not hx:
            return None
        try:
            priv_bytes = bytes.fromhex(hx)
            return coincurve.PrivateKey(priv_bytes)
        except Exception as e:
            logging.error(f"[KeyManager] get_schnorr_privkey => {e}")
            return None

    def get_schnorr_pubkey(self, node_id: str) -> Optional[bytes]:
     
        if node_id not in self.keys:
            return None
        hx = self.keys[node_id].get("schnorr_pub")
        if not hx:
            return None
        try:
            return bytes.fromhex(hx)
        except Exception as e:
            logging.error(f"[KeyManager] get_schnorr_pubkey => {e}")
            return None


    def sign_transaction(self, node_id: str, data_obj: dict) -> str:
     
        priv = self.get_schnorr_privkey(node_id)
        if not priv:
            raise ValueError(f"No Schnorr private key for {node_id}")
        raw = json.dumps(data_obj, sort_keys=True).encode("utf-8")
        msg_hash = sha256(raw)  # 32-байтный хеш
        signature = priv.sign_schnorr(message=msg_hash, aux_rand=None, raw=False)
        # signature -> 64 bytes
        return signature.hex()

    def verify_transaction(self, node_id: str, data_obj: dict, sig_hex: str) -> bool:
      
        pub_bytes = self.get_schnorr_pubkey(node_id)
        if not pub_bytes:
            logging.warning(f"[KeyManager] no schnorr pubkey => {node_id}")
            return False

        raw = json.dumps(data_obj, sort_keys=True).encode("utf-8")
        msg_hash = sha256(raw)
        try:
            sig = bytes.fromhex(sig_hex)
            pk = coincurve.PublicKey(pub_bytes)
            ok = pk.verify_schnorr(signature=sig, message=msg_hash, aux_rand=None, raw=False)
            return ok
        except Exception as e:
            logging.error(f"[KeyManager] verify => {e}")
            return False

    
    def verify_message(self, node_id: str, data_obj: dict, sig_hex: str) -> bool:
        return self.verify_transaction(node_id, data_obj, sig_hex)


   
    def _aes_encrypt(self, plain: bytes) -> bytes:
        if not self.secret_key:
            return plain
        aes = AESGCM(self.secret_key)
        nonce = os.urandom(12)
        ct = aes.encrypt(nonce, plain, None)
        return nonce + ct

    def _aes_decrypt(self, enc: bytes) -> bytes:
        if not self.secret_key:
            return enc
        if len(enc) < 12:
            raise ValueError("Encrypted data too short.")
        aes = AESGCM(self.secret_key)
        nonce = enc[:12]
        cipher = enc[12:]
        plain = aes.decrypt(nonce, cipher, None)
        return plain


    def _derive_key_from_passphrase(self, passphrase: str, salt_str: str) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_str.encode('utf-8'),
            iterations=100_000,
            backend=default_backend()
        )
        return kdf.derive(passphrase.encode('utf-8'))