import os
import json
import logging
import getpass
import hashlib
import base64
from typing import Optional, Dict, Any

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logging.basicConfig(level=logging.INFO)

class KeyManager:
    """
    Пример KeyManager, который хранит ECDSA-ключи для узлов (node_id или addr_...),
    умеет шифровать их в JSON-файле, а также подписывать/проверять JSON-сообщения.
    """

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

        # Определяем, куда сохранять
        if not ephemeral_mode:
            if key_dir:
                os.makedirs(key_dir, exist_ok=True)
                self.json_file = os.path.join(key_dir, "keys.json")
            else:
                self.json_file = "keys.json"
        else:
            self.json_file = "ephemeral_keys.json"

        # Для AES‐шифрования (если нужно)
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

    # ----------------------------------------------------------------
    # LOAD/SAVE
    # ----------------------------------------------------------------
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

    # ----------------------------------------------------------------
    # ECDSA (генерация/хранение)
    # ----------------------------------------------------------------
    def create_ecdsa_keys(self, node_id: str):
        """
        Генерируем ECDSA на secp256r1, сохраняем PEM в self.keys[node_id].
        node_id может быть 'addr_...' или любым другим строковым идентификатором.
        """
        if node_id in self.keys:
            raise ValueError(f"[KeyManager] ECDSA for {node_id} already exist.")

        priv_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        pub_key = priv_key.public_key()

        private_pem = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")

        public_pem = pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

        self.keys[node_id] = {
            "private_key": private_pem,
            "public_key": public_pem
        }
        self._save_keys()
        logging.info(f"[KeyManager] create ECDSA => node={node_id}")

    def store_ec_privkey(self, node_id: str, priv_key: ec.EllipticCurvePrivateKey):
        """
        Если уже есть готовый приватный ключ (priv_key),
        можно сохранить его в KeyManager (перезапись).
        """
        private_pem = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")

        public_pem = priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

        self.keys[node_id] = {
            "private_key": private_pem,
            "public_key": public_pem
        }
        self._save_keys()

    def get_ec_privkey(self, node_id: str) -> Optional[ec.EllipticCurvePrivateKey]:
        if node_id not in self.keys:
            return None
        pem_str = self.keys[node_id].get("private_key")
        if not pem_str:
            return None
        try:
            priv = serialization.load_pem_private_key(
                pem_str.encode("utf-8"),
                password=None,
                backend=default_backend()
            )
            return priv
        except Exception as e:
            logging.error(f"[KeyManager] get_ec_privkey => {e}")
            return None

    def get_ec_pubkey(self, node_id: str) -> Optional[ec.EllipticCurvePublicKey]:
        if node_id not in self.keys:
            return None
        pub_pem = self.keys[node_id].get("public_key")
        if not pub_pem:
            return None
        try:
            pub = serialization.load_pem_public_key(
                pub_pem.encode("utf-8"),
                backend=default_backend()
            )
            return pub
        except Exception as e:
            logging.error(f"[KeyManager] get_ec_pubkey => {e}")
            return None

    # ----------------------------------------------------------------
    # Подпись/проверка транзакций
    # ----------------------------------------------------------------
    def sign_transaction(self, node_id: str, data_obj: dict) -> str:
        """
        Подписываем (ECDSA) словарь data_obj (json.dumps sort_keys=True) 
        под именем node_id (который может быть 'addr_...' и т.д.)
        """
        priv = self.get_ec_privkey(node_id)
        if not priv:
            raise ValueError(f"No ECDSA private key for {node_id}")
        raw = json.dumps(data_obj, sort_keys=True).encode("utf-8")
        sig = priv.sign(raw, ec.ECDSA(hashes.SHA256()))
        return sig.hex()

    def verify_transaction(self, node_id: str, data_obj: dict, sig_hex: str) -> bool:
        """
        Обёртка для проверки транзакций (аналогична verify_message).
        """
        return self._verify_message_internal(node_id, data_obj, sig_hex)

    # Для совместимости, если где-то осталось "verify_message(...)"
    def verify_message(self, node_id: str, data_obj: dict, sig_hex: str)->bool:
        return self._verify_message_internal(node_id, data_obj, sig_hex)

    def _verify_message_internal(self, node_id: str, data_obj: dict, sig_hex: str)->bool:
        pub = self.get_ec_pubkey(node_id)
        if not pub:
            logging.warning(f"[KeyManager] no ec pubkey => {node_id}")
            return False
        raw = json.dumps(data_obj, sort_keys=True).encode("utf-8")
        try:
            s = bytes.fromhex(sig_hex)
            pub.verify(s, raw, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            logging.error(f"[KeyManager] verify => {e}")
            return False

    # ----------------------------------------------------------------
    # AES (для шифрования файла keys.json)
    # ----------------------------------------------------------------
    def create_aes_key(self, node_id:str):
        if node_id not in self.keys:
            raise ValueError(f"[KeyManager] node_id={node_id} not found => ECDSA first.")
        if "aes_key" in self.keys[node_id]:
            raise ValueError(f"AES key already exists for {node_id}")

        k = os.urandom(32)  # 256 bit
        self.keys[node_id]["aes_key"] = k.hex()
        self._save_keys()
        logging.info(f"[KeyManager] AES key => created for node={node_id}")

    def get_aes_key(self, node_id:str)->Optional[bytes]:
        if node_id not in self.keys:
            return None
        hx = self.keys[node_id].get("aes_key")
        if not hx:
            return None
        return bytes.fromhex(hx)

    # ----------------------------------------------------------------
    # (Optional) MW key
    # ----------------------------------------------------------------
    def create_mw_key(self, node_id:str):
        if node_id not in self.keys:
            raise ValueError(f"[KeyManager] node={node_id} not found => ECDSA first.")
        if "mw_secp_priv" in self.keys[node_id]:
            logging.warning(f"[KeyManager] MW key for {node_id} already exist.")
            return
        mw = os.urandom(32)
        self.keys[node_id]["mw_secp_priv"] = mw.hex()
        self._save_keys()
        logging.info(f"[KeyManager] MW key => created => node={node_id}")

    def get_mw_key(self, node_id:str)->Optional[bytes]:
        if node_id not in self.keys:
            return None
        hx = self.keys[node_id].get("mw_secp_priv")
        if not hx:
            return None
        return bytes.fromhex(hx)

    # ----------------------------------------------------------------
    # AES-256-GCM внутренних данных
    # ----------------------------------------------------------------
    def _aes_encrypt(self, plain: bytes)->bytes:
        if not self.secret_key:
            return plain
        aes = AESGCM(self.secret_key)
        nonce = os.urandom(12)
        ct = aes.encrypt(nonce, plain, None)
        return nonce + ct

    def _aes_decrypt(self, enc: bytes)->bytes:
        if not self.secret_key:
            return enc
        if len(enc)<12:
            raise ValueError("Encrypted data too short.")
        aes = AESGCM(self.secret_key)
        nonce = enc[:12]
        cipher = enc[12:]
        plain = aes.decrypt(nonce, cipher, None)
        return plain

    def _derive_key_from_passphrase(self, passphrase:str, salt_str:str)->bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_str.encode('utf-8'),
            iterations=100_000,
            backend=default_backend()
        )
        return kdf.derive(passphrase.encode('utf-8'))