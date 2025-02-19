import logging
import time
import os
import json
import asyncio
from typing import Optional, List, Dict, Any, Set

logging.basicConfig(level=logging.INFO)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from chordnode import ChordNode, LWWValue
from key import KeyManager
from tekeracub import CubTekera
from networknod import NodeNetwork
from trans import Transaction
from multi import MultiSigTransaction

class KubrykWallet:
   

    def __init__(
        self,
        my_address: str,
        key_manager: KeyManager,
        cub_tekera: CubTekera,
        network: Optional[NodeNetwork] = None,
        mining_module=None,
        chord_node: Optional[ChordNode] = None,
        wallet_file: str = "kubryk_wallet.json",
        passphrase: Optional[str] = None,
        encrypt_wallet: bool = True,
        ephemeral_mode: bool = False
    ):
       
        self.my_address = my_address
        self.key_manager = key_manager
        self.cub_tekera = cub_tekera
        self.network = network
        self.mining_module = mining_module
        self.chord_node = chord_node

        self.wallet_file = wallet_file
        self.encrypt_wallet = encrypt_wallet
        self.ephemeral_mode = ephemeral_mode

        self.logger = logging.getLogger(f"KubrykWallet-{my_address}")

        # Генерируем/derive AES-ключ из passphrase, если хотим шифровать
        if passphrase and encrypt_wallet:
            self.secret_key = self._derive_key_from_passphrase(passphrase)
        else:
            self.secret_key = None

        # Локальное хранилище
        # {
        #   "subwallets": {
        #       "main": {"balance":..., "mw_outputs":[...]},
        #       ...
        #   },
        #   "history": [...]
        # }
        self.local_data: Dict[str, Any] = {}
        self._wallet_lock = asyncio.Lock()

        if not ephemeral_mode:
            self._load_local_data()
        else:
            self.logger.warning("[KubrykWallet] ephemeral_mode => skip load from disk.")

        # Если нет subwallets => создаём "main"
        if "subwallets" not in self.local_data:
            self.local_data["subwallets"] = {}
        if "main" not in self.local_data["subwallets"]:
            self.local_data["subwallets"]["main"] = {"balance": 0, "mw_outputs": []}
        if "history" not in self.local_data:
            self.local_data["history"] = []

        # Callback наград (например, из MiningModule)
        if self.mining_module and hasattr(self.mining_module, "set_wallet_callback"):
            self.mining_module.set_wallet_callback(self.on_mining_reward)

        self.logger.info(
            f"[KubrykWallet] address={my_address}, ephemeral={ephemeral_mode}, encrypt={encrypt_wallet}"
        )

    async def initialize(self):
        """
        Проверяем/создаём ключи (ECDSA, MW) и обновляем баланс (subwallet=main).
        """
        await self._ensure_keys_created()
        main_bal = await self._fetch_remote_balance()
        async with self._wallet_lock:
            self.local_data["subwallets"]["main"]["balance"] = main_bal
            await self._save_local_data()
        self.logger.info(f"[KubrykWallet] address={self.my_address} init => main_balance={main_bal} terabit")

    async def _ensure_keys_created(self):
        """
        Если в key_manager нет записи для my_address => генерируем ECDSA, MW.
        """
        async with self._wallet_lock:
            if self.my_address not in self.key_manager.keys:
                self.logger.info(f"[KubrykWallet] Creating ECDSA => {self.my_address}")
                self.key_manager.create_ecdsa_keys(self.my_address)
            else:
                self.logger.info(f"[KubrykWallet] ECDSA exists => {self.my_address}")

            node_keys = self.key_manager.keys.get(self.my_address, {})
            if "mw_secp_priv" not in node_keys:
                self.logger.info(f"[KubrykWallet] Creating MW => {self.my_address}")
                self.key_manager.create_mw_key(self.my_address)
            else:
                self.logger.info(f"[KubrykWallet] MW key => found => {self.my_address}")

    # ----------------------------------------------------------------
    # subwallet
    # ----------------------------------------------------------------
    def subwallet_names(self)->List[str]:
        return sorted(list(self.local_data["subwallets"].keys()))

    def create_subwallet(self, name:str):
        if name in self.local_data["subwallets"]:
            self.logger.warning(f"[KubrykWallet] subwallet={name} already exists.")
            return
        self.local_data["subwallets"][name] = {"balance": 0, "mw_outputs": []}
        self.logger.info(f"[KubrykWallet] create_subwallet => {name}")

    async def get_subwallet_balance(self, subname:str="main") -> int:
        async with self._wallet_lock:
            sw = self.local_data["subwallets"].get(subname)
            if not sw:
                raise ValueError(f"No subwallet={subname}")
            return sw["balance"]

    async def update_subwallet_balance_from_remote(self, subname:str="main"):
        """
        Для примера — тянем общий баланс из CubTekera.get_total_terabit().
        """
        if subname != "main":
            self.logger.warning(
                f"[KubrykWallet] update_subwallet_balance_from_remote => sub={subname} => ignoring => only main sync."
            )
            return
        remote_bal = await self._fetch_remote_balance()
        async with self._wallet_lock:
            self.local_data["subwallets"]["main"]["balance"] = remote_bal
            await self._save_local_data()
        self.logger.info(
            f"[KubrykWallet] subwallet={subname} => updated from remote => {remote_bal}"
        )

    # ----------------------------------------------------------------
    # callback для наград (mining_module)
    # ----------------------------------------------------------------
    def on_mining_reward(self, amount: int, from_module: str):
        self.logger.info(f"[KubrykWallet] => got reward={amount} from {from_module}")
        asyncio.create_task(self._handle_mining_reward(amount))

    async def _handle_mining_reward(self, amount: int):
        async with self._wallet_lock:
            self.local_data["subwallets"]["main"]["balance"] += amount
            await self._add_history(f"mining_reward => +{amount}")
            await self._save_local_data()

    # ----------------------------------------------------------------
    # Single-sig TEKERA
    # ----------------------------------------------------------------
    async def send_coins(
        self,
        recipient_address: str,
        amount: int,
        subwallet: str = "main",
        await_bft: bool = False,
        transaction_manager = None  # <--- нужно прокинуть в Wallet
    ) -> bool:
    
        if amount <= 0:
            self.logger.warning("[KubrykWallet] send_coins => amount<=0 => skip.")
            return False

        if not transaction_manager:
            self.logger.error("[KubrykWallet] send_coins => no transaction_manager => skip.")
            return False

        async with self._wallet_lock:
            sw = self.local_data["subwallets"].get(subwallet)
            if not sw:
                self.logger.warning(f"No subwallet={subwallet}")
                return False
            bal = sw["balance"]
            if amount > bal:
                self.logger.warning(f"subwallet={subwallet} => not enough => have={bal}, need={amount}")
                return False

   
        tx_id = await transaction_manager.propose_bft_transfer(
            recipient_id=recipient_address,
            amount_terabit=amount
        )
        if not tx_id:
            self.logger.error("[KubrykWallet] send_coins => propose_bft_transfer => fail => no tx_id")
            return False

        self.logger.info(f"[KubrykWallet] send_coins => proposed tx_id={tx_id}, amt={amount}")

   
        if await_bft:
            ok = await transaction_manager.await_bft_confirmation(tx_id, timeout=30.0)
            self.logger.info(f"[KubrykWallet] BFT confirm => tx_id={tx_id}, success={ok}")
            if not ok:
            
                return False

   
        async with self._wallet_lock:
            sw["balance"] -= amount
            await self._add_history(
                f"send_coins => sub={subwallet}, to={recipient_address}, amt={amount}, tx_id={tx_id}"
            )
            await self._save_local_data()

        self.logger.info(f"[KubrykWallet] send_coins => done => newBal={sw['balance']}")
        return True
    # ----------------------------------------------------------------
    # MultiSig
    # ----------------------------------------------------------------
    async def send_coins_multi_sig(
        self,
        recipient_address: str,
        amount: int,
        authorized_signers: Set[str],
        required_sign: int = 2,
        subwallet: str = "main",
        await_bft: bool = False,
        transaction_manager = None
    ) -> bool:
  
    
        if amount <= 0:
            self.logger.warning("[KubrykWallet] multi_sig => amount<=0 => skip.")
            return False
        if not transaction_manager:
            self.logger.error("[KubrykWallet] multi_sig => no transaction_manager => skip.")
            return False

   
        async with self._wallet_lock:
            sw = self.local_data["subwallets"].get(subwallet)
            if not sw:
                self.logger.warning(f"[KubrykWallet] multi_sig => no subwallet={subwallet}")
                return False
            bal = sw["balance"]
            if amount > bal:
                self.logger.warning(
                    f"[KubrykWallet] multi_sig => not enough => have={bal}, need={amount}"
                )
                return False

   
        mst = MultiSigTransaction(
            key_manager=self.key_manager,
            authorized_signers=authorized_signers,
            required_signatures=required_sign
        )
   
        mst.create_transaction(
            sender_address=self.my_address,
            recipient_address=recipient_address,
            amount=amount,
            currency="TEKERA"
        )

   
        if self.my_address in authorized_signers:
            enough_sigs = mst.add_signature(self.my_address)
       
        else:
            self.logger.warning(f"[KubrykWallet] multi_sig => we are not in authorized_signers => partial tx.")

    
    
        # if not mst.is_valid():
        #     self.logger.warning("[KubrykWallet] multi_sig => not valid => skip.")
        #     return False

   
   
        tx_id = await transaction_manager.execute_multi_sig(mst)
        if not tx_id:
            self.logger.warning("[KubrykWallet] multi_sig => no tx_id => skip.")
            return False

        self.logger.info(f"[KubrykWallet] multi_sig => proposed => tx_id={tx_id}")

   
        if await_bft:
            ok = await transaction_manager.await_bft_confirmation(tx_id, timeout=30.0)
            self.logger.info(f"[KubrykWallet] multi-sig => bft confirm => {ok}")
            if not ok:
                return False

   
        async with self._wallet_lock:
            sw["balance"] -= amount
            await self._add_history(
                f"multi_sig => sub={subwallet}, amt={amount}, tx_id={tx_id}"
            )
            await self._save_local_data()

        self.logger.info(f"[KubrykWallet] multi_sig => done => newBal={sw['balance']}")
        return True
    # ----------------------------------------------------------------
    # MW Logic
    # ----------------------------------------------------------------
    async def convert_to_mw(self, amount: int, subwallet: str="main"):
        if amount <= 0:
            self.logger.warning("[KubrykWallet] convert_to_mw => amt<=0 => skip.")
            return
        async with self._wallet_lock:
            sw = self.local_data["subwallets"].get(subwallet)
            if not sw:
                self.logger.warning(f"[KubrykWallet] no subwallet={subwallet}")
                return
            bal = sw["balance"]
            if amount > bal:
                self.logger.warning(f"not enough => have={bal}, need={amount}")
            new_bal = bal - amount
            if new_bal < 0:
                new_bal = 0
            sw["balance"] = new_bal

            import os
            salt = os.urandom(8).hex()
            mw_priv = self.key_manager.get_mw_key(self.my_address)
            raw_str = f"{self.my_address}|{amount}|{salt}|{mw_priv}"
            commit_hex = hashlib.sha256(raw_str.encode()).hexdigest()

            sw["mw_outputs"].append({
                "commit": commit_hex,
                "amount": amount,
                "blinding_owner": mw_priv.hex(),
                "salt": salt
            })
            await self._add_history(f"convert_to_mw => sub={subwallet}, commit={commit_hex}, amt={amount}")
            await self._save_local_data()

        self.logger.info(f"[KubrykWallet] convert_to_mw => sub={subwallet}, commit={commit_hex}, newBal={new_bal}")
        if self.network:
            msg = {
                "type":"mw_convert_in",
                "address": self.my_address,
                "commit": commit_hex,
                "amount": amount
            }
            await self.network._send_to_node("miningCoordinator", msg)

    async def mw_send_coins(self, subwallet: str, commit_hex: str, amount: int, recipient_address: str):
        if amount <= 0:
            self.logger.warning("[KubrykWallet] mw_send_coins => amt<=0 => skip.")
            return
        async with self._wallet_lock:
            sw = self.local_data["subwallets"].get(subwallet)
            if not sw:
                self.logger.warning(f"[KubrykWallet] no subwallet={subwallet}")
                return
            commit_in = None
            for c in sw["mw_outputs"]:
                if c["commit"] == commit_hex:
                    commit_in = c
                    break
            if not commit_in:
                self.logger.warning(f"commit={commit_hex} not found => skip.")
                return
            if amount > commit_in["amount"]:
                self.logger.warning(f"not enough in commit => {commit_in['amount']} < {amount}")
                return

            leftover = commit_in["amount"] - amount
            commit_in["amount"] = leftover
            if leftover <= 0:
                sw["mw_outputs"].remove(commit_in)

            import os
            salt = os.urandom(8).hex()
            out_commit = hashlib.sha256(f"{recipient_address}|{amount}|{salt}".encode()).hexdigest()
            tx_data = {
                "commits_in": [commit_in["commit"]],
                "commits_out": [out_commit],
                "kernel": {"signature":"dummy","excess":"dummy"},
                "amount": amount,
                "sender": self.my_address,
                "recipient": recipient_address
            }
            await self._add_history(f"mw_send_coins => sub={subwallet}, from={commit_hex}, out={out_commit}, amt={amount}")
            await self._save_local_data()

        if self.network:
            msg = {
                "type": "mw_transaction",
                "mw_data": tx_data
            }
            await self.network._send_to_node("miningCoordinator", msg)
        self.logger.info(f"[KubrykWallet] mw_send_coins => sub={subwallet}, in={commit_hex}, out={out_commit}, amt={amount}")

    async def convert_from_mw(self, commit_hex: str, subwallet: str="main") -> bool:
        async with self._wallet_lock:
            sw = self.local_data["subwallets"].get(subwallet)
            if not sw:
                self.logger.warning(f"[KubrykWallet] no subwallet={subwallet}")
                return False
            commit_in = None
            for c in sw["mw_outputs"]:
                if c["commit"] == commit_hex:
                    commit_in = c
                    break
            if not commit_in:
                self.logger.warning(f"mw commit={commit_hex} not found => skip.")
                return False
            amt = commit_in["amount"]
            sw["mw_outputs"].remove(commit_in)
            sw["balance"] += amt
            await self._add_history(f"convert_from_mw => sub={subwallet}, commit={commit_hex}, amt={amt}")
            await self._save_local_data()

        if self.network:
            msg = {
                "type": "mw_convert_out",
                "address": self.my_address,
                "commit": commit_hex,
                "amount": amt
            }
            await self.network._send_to_node("miningCoordinator", msg)
        self.logger.info(f"[KubrykWallet] convert_from_mw => sub={subwallet}, commit={commit_hex}, amt={amt}")
        return True

    # ----------------------------------------------------------------
    # CRDT sync
    # ----------------------------------------------------------------
    async def store_wallet_in_chord(self):
        if not self.chord_node:
            self.logger.warning("[KubrykWallet] store_wallet_in_chord => no chord_node => skip.")
            return
        async with self._wallet_lock:
            data_js = json.dumps(self.local_data, sort_keys=True)
        val_obj = LWWValue(data_js, time.time())
        key = f"kubryk_wallet_{self.my_address}"
        await self.chord_node.replicate_locally(key, val_obj)
        self.logger.info(f"[KubrykWallet] store_wallet_in_chord => key={key}")

    async def load_wallet_from_chord(self):
        if not self.chord_node:
            self.logger.warning("[KubrykWallet] load_wallet_from_chord => no chord_node => skip.")
            return
        key = f"kubryk_wallet_{self.my_address}"
        vo = self.chord_node.get_local(key)
        if not vo:
            self.logger.info("[KubrykWallet] no wallet data in chord => skip load.")
            return
        raw_val = vo.value
        if isinstance(raw_val, dict) and raw_val.get("deleted") is True:
            self.logger.warning("[KubrykWallet] chord => found tombstone => skip load.")
            return
        if not isinstance(raw_val, str):
            self.logger.warning("[KubrykWallet] chord => data not str => skip.")
            return
        try:
            loaded_dict = json.loads(raw_val)
        except:
            self.logger.error("[KubrykWallet] chord => fail parse JSON => skip.")
            return

        async with self._wallet_lock:
            self.local_data = loaded_dict
        self.logger.info("[KubrykWallet] load_wallet_from_chord => done => replaced local_data.")

    async def delete_wallet_in_chord(self):
        if not self.chord_node:
            return
        key = f"kubryk_wallet_{self.my_address}"
        tomb = {"deleted": True}
        val_obj = LWWValue(tomb, time.time())
        await self.chord_node.replicate_locally(key, val_obj)
        self.logger.info(f"[KubrykWallet] delete_wallet_in_chord => key={key}, tombstone set")

    # ----------------------------------------------------------------
    # Internals
    # ----------------------------------------------------------------
    async def _add_history(self, desc: str):
        self.local_data["history"].append({
            "ts": time.time(),
            "desc": desc
        })

    async def _save_local_data(self):
        if self.ephemeral_mode:
            return
        try:
            data_js = json.dumps(self.local_data, indent=4)
            file_bytes = data_js.encode("utf-8")
            if self.secret_key and self.encrypt_wallet:
                file_bytes = self._aes_encrypt(file_bytes)

            tmp_path = self.wallet_file + ".tmp"
            with open(tmp_path, "wb") as f:
                f.write(file_bytes)
            os.replace(tmp_path, self.wallet_file)
            self.logger.info(f"[KubrykWallet] saved => {self.wallet_file}, encrypted={bool(self.secret_key)}")
        except Exception as e:
            self.logger.error(f"[KubrykWallet] save error => {e}")

    def _load_local_data(self):
        if not os.path.isfile(self.wallet_file):
            self.logger.info(f"[KubrykWallet] no local file => skip => {self.wallet_file}")
            return
        try:
            with open(self.wallet_file, "rb") as f:
                data_bytes = f.read()
            if self.secret_key and self.encrypt_wallet:
                data_bytes = self._aes_decrypt(data_bytes)
            data_js = data_bytes.decode("utf-8")
            loaded = json.loads(data_js)
            self.local_data = loaded
            self.logger.info(f"[KubrykWallet] loaded => {self.wallet_file}, encrypt={bool(self.secret_key)}")
        except Exception as e:
            self.logger.error(f"[KubrykWallet] load error => {e}")

    async def _fetch_remote_balance(self) -> int:
        """
        Тянем общий баланс с cub_tekera.get_total_terabit().
        """
        bal = 0
        try:
            bal = await self.cub_tekera.get_total_terabit()
        except Exception as e:
            self.logger.error(f"[KubrykWallet] _fetch_remote_balance => {e}")
        return bal

    def _aes_encrypt(self, plain: bytes) -> bytes:
        aes = AESGCM(self.secret_key)
        nonce = os.urandom(12)
        return nonce + aes.encrypt(nonce, plain, None)

    def _aes_decrypt(self, enc: bytes) -> bytes:
        aes = AESGCM(self.secret_key)
        if len(enc)<12:
            raise ValueError("Encrypted data too short.")
        nonce = enc[:12]
        cipher = enc[12:]
        return aes.decrypt(nonce, cipher, None)

    def _derive_key_from_passphrase(self, passphrase: str) -> bytes:
        salt = self.my_address.encode("utf-8")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000
        )
        return kdf.derive(passphrase.encode("utf-8"))