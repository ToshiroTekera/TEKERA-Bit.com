import logging
import asyncio
import json
import time
import os
from typing import Optional, Dict, List, Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

logging.basicConfig(level=logging.INFO)

from trans import Transaction
from key import KeyManager
from tekeracub import CubTekera
from networknod import NodeNetwork
from chordnode import ChordNode, LWWValue
from POH import ProofOfHistory
from multi import MultiSigTransaction
from sealevel_engine import AdvancedSealevelEngine, BaseTransaction

class TransactionManager:
  

    def __init__(
        self,
        node_id: str,
        key_manager: KeyManager,
        cub_tekera: CubTekera,
        network: NodeNetwork,
        hotstuff_consensus,  
        poh: Optional[ProofOfHistory] = None,
        chord_node: Optional[ChordNode] = None,
        sealevel_engine: Optional[AdvancedSealevelEngine] = None,
        data_file: str = "transactions_pool.json",
        ephemeral_mode: bool = False,
        use_encryption: bool = False,
        passphrase: Optional[str] = None
    ):
        self.node_id = node_id
        self.key_manager = key_manager
        self.cub_tekera = cub_tekera
        self.network = network
        self.hotstuff_consensus = hotstuff_consensus
        self.poh = poh
        self.chord_node = chord_node
        self.sealevel = sealevel_engine or AdvancedSealevelEngine()

        self.data_file = data_file
        self.ephemeral_mode = ephemeral_mode
        self.use_encryption = use_encryption and (not ephemeral_mode)

        self.transactions: Dict[str, Transaction] = {}

       
        self.secret_key: Optional[bytes] = None
        if passphrase and self.use_encryption:
            self.secret_key = self._derive_key_from_passphrase(passphrase)

        
        self.logger = logging.getLogger(f"TransactionManager-{node_id}")
        self.logger.info(f"[TransactionManager] node={node_id}, ephemeral={self.ephemeral_mode}, encryption={self.use_encryption}")

   
        if not self.ephemeral_mode:
            self._load_transactions()

    # ----------------------------------------------------------------
    # propose_bft_transfer (single-sig)
    # ----------------------------------------------------------------

    async def propose_bft_transfer(self, recipient_id: str, amount_terabit: int) -> Optional[str]:
        if amount_terabit <= 0:
            self.logger.warning(f"[TransactionManager] propose_bft_transfer => invalid amount={amount_terabit}")
            return None

        sender_address = self.cub_tekera.address

        tx = Transaction.create(
            sender=sender_address,  # адрес вида "addr_..."
            recipient=recipient_id,
            amount_terabit=amount_terabit,
            currency="TEKERA"
        )

        sign_data = tx.to_dict(exclude_signature=True)

        sign_hex = self.key_manager.sign_transaction(
            sender_address,  
            sign_data
        )
        tx.signature = sign_hex

        self.transactions[tx.tx_id] = tx
        self._save_transactions()

        block_data = {"tekeraTx": tx.to_dict()}
        raw_js = json.dumps(block_data)

        if len(raw_js) > 100_000 and self.network.turbine_manager:
            flow_id = f"bftTx_{tx.tx_id}"
            all_peers = list(self.network.connections.keys())
            await self.network.turbine_manager.start_broadcast_data(
                flow_id=flow_id,
                data_bytes=raw_js.encode('utf-8'),
                all_peers=all_peers,
                fanout=3
            )
            self.logger.info(f"[TransactionManager] propose_bft_transfer => large => used Turbine => tx_id={tx.tx_id}")
        else:
            await self.hotstuff_consensus.propose_block(block_data)

        self.logger.info(
            f"[TransactionManager] propose_bft_transfer => tx_id={tx.tx_id}, from={sender_address}, to={recipient_id}, amt={amount_terabit}"
        )

        
        if self.poh:
            ev = {
                "type": "bft_transfer_propose",
                "tx_id": tx.tx_id,
                "sender": tx.sender,
                "recipient": tx.recipient,
                "amount_terabit": tx.amount_terabit,
                "timestamp": time.time()
            }
            await self.poh.record_event(ev)

        
        return tx.tx_id

    def get_unconfirmed_txs(self, limit: int = 10) -> List[dict]:

        out = []
   
        tx_list = list(self.transactions.values())

        for tx_obj in tx_list:
            current_status = getattr(tx_obj, "status", None)
       
            if current_status in (None, "new"):
                out.append(tx_obj.to_dict())
                       
                tx_obj.status = "pending"

                if len(out) >= limit:
                    break
    
        self._save_transactions()
        self.logger.info(f"[TransactionManager] get_unconfirmed_txs => found {len(out)} tx to propose")
        return out


    async def apply_tx(self, tx_dict: dict):
 

        tx_id = tx_dict.get("tx_id")
        if not tx_id:
            self.logger.warning("[TransactionManager] apply_tx => no tx_id => skip")
            return

        self.logger.info(f"[TransactionManager] apply_tx => tx_id={tx_id}")

   
        tx_obj = self.transactions.get(tx_id)
        if not tx_obj:
       
            self.logger.info(f"[TransactionManager] apply_tx => unknown tx_id={tx_id}, create ephemeral Transaction object.")
            from trans import Transaction
            tx_obj = Transaction.from_dict(tx_dict)
            self.transactions[tx_id] = tx_obj
   
        if tx_obj.status == "confirmed":
            self.logger.info(f"[TransactionManager] apply_tx => tx_id={tx_id} already confirmed => skip re-apply")
            return
        if tx_obj.status == "rejected":
            self.logger.info(f"[TransactionManager] apply_tx => tx_id={tx_id} already rejected => skip")
            return

    
        sender = tx_dict.get("sender")
        recipient = tx_dict.get("recipient")
        amount = tx_dict.get("amount_terabit", 0)
        if not sender or not recipient or amount <= 0:
            self.logger.warning(f"[TransactionManager] apply_tx => invalid fields => {tx_dict}")
            tx_obj.status = "rejected"
            self._save_transactions()
            return
  
        if sender != "COINBASE":
            sign_hex = tx_dict.get("signature")
             
            if not sign_hex:
                self.logger.warning(f"[TransactionManager] apply_tx => no signature => reject => {tx_id}")
                tx_obj.status = "rejected"
                self._save_transactions()
                return
    
        self.logger.info(f"[TransactionManager] apply_tx => OK => tx_id={tx_id}, from={sender}, to={recipient}, amt={amount}")

   
        # tx_obj.status = "confirmed"
        # self._save_transactions()
        # self.logger.info(f"[TransactionManager] apply_tx => confirm => tx_id={tx_id}")

   
        tx_obj.status = "applied"
        self._save_transactions()

    # ----------------------------------------------------------------
    # propose_ml_reward (coinbase)
    # ----------------------------------------------------------------
    async def propose_ml_reward(
        self,
        solver_id: str,
        reward_terabit: int,
        proof_data: dict
    ) -> Optional[str]:
        if reward_terabit <= 0:
            self.logger.warning(f"[TransactionManager] propose_ml_reward => invalid reward={reward_terabit}")
            return None

        tx = Transaction.create(
            sender="COINBASE",
            recipient=solver_id,
            amount_terabit=reward_terabit,
            currency="TEKERA"
        )
        tx.signature = None  

        self.transactions[tx.tx_id] = tx
        self._save_transactions()

        block_data = {
            "mlRewardTx": tx.to_dict(),
            "mlProof": proof_data
        }
        raw_js = json.dumps(block_data)

        # FEC? 
        if len(raw_js) > 500_000 and self.network.fec_channel:
            self.network.fec_channel.send_file(raw_js.encode('utf-8'))
            self.logger.info(f"[TransactionManager] propose_ml_reward => large => used FecChannel => tx_id={tx.tx_id}")
        else:
            await self.hotstuff_consensus.propose_block(block_data)

        self.logger.info(
            f"[TransactionManager] propose_ml_reward => tx_id={tx.tx_id}, solver={solver_id}, reward={reward_terabit}"
        )

        if self.poh:
            ev = {
                "type": "ml_reward_propose",
                "tx_id": tx.tx_id,
                "solver": solver_id,
                "reward_terabit": reward_terabit,
                "timestamp": time.time()
            }
            await self.poh.record_event(ev)

        return tx.tx_id

    # ----------------------------------------------------------------
    # Mark confirmation + wait BFT
    # ----------------------------------------------------------------
    async def await_bft_confirmation(self, tx_id: str, timeout: float = 30.0) -> bool:
        start = time.time()
        while (time.time() - start) < timeout:
            tx = self.transactions.get(tx_id)
            if tx and getattr(tx, "status", "") == "confirmed":
                self.logger.info(f"[TransactionManager] BFT confirm => tx_id={tx_id}")
                return True
            await asyncio.sleep(1.0)
        self.logger.warning(f"[TransactionManager] BFT confirm not arrived => tx_id={tx_id}")
        return False

    def mark_tx_confirmed(self, tx_id: str):
        if tx_id in self.transactions:
            self.transactions[tx_id].status = "confirmed"
            self._save_transactions()
            self.logger.info(f"[TransactionManager] mark_tx_confirmed => tx_id={tx_id}")

    # ----------------------------------------------------------------
    # Sealevel batch
    # ----------------------------------------------------------------
    async def run_sealevel_batch(self, tx_list: List[Transaction]):
        adapter_list = [TxAdapter(t) for t in tx_list]
        self.sealevel.global_state["__cub_tekera__"] = self.cub_tekera
        await self.sealevel.process_batch(adapter_list)
        self.logger.info(f"[TransactionManager] run_sealevel_batch => done => {len(tx_list)} tx")

        if self.poh:
            ev = {
                "type": "sealevel_batch",
                "count": len(tx_list),
                "timestamp": time.time()
            }
            await self.poh.record_event(ev)

    # ----------------------------------------------------------------
    # Load/Save pool (JSON) + AES
    # ----------------------------------------------------------------
    def _load_transactions(self):
        if not os.path.isfile(self.data_file):
            self.logger.info(f"[TransactionManager] no file => skip => {self.data_file}")
            return
        try:
            with open(self.data_file, "rb") as f:
                enc_data = f.read()
            if self.use_encryption and self.secret_key:
                enc_data = self._aes_decrypt(enc_data)
            js_str = enc_data.decode("utf-8")
            arr = json.loads(js_str)
            for item in arr:
                tx = Transaction.from_dict(item)
                self.transactions[tx.tx_id] = tx
            self.logger.info(f"[TransactionManager] loaded => {len(self.transactions)} from {self.data_file}")
        except Exception as e:
            self.logger.error(f"[TransactionManager] load => {e}")

    def _save_transactions(self):
        if self.ephemeral_mode:
            return
        try:
            arr = [t.to_dict() for t in self.transactions.values()]
            raw_js = json.dumps(arr, indent=4)
            raw_bytes = raw_js.encode("utf-8")
            if self.use_encryption and self.secret_key:
                raw_bytes = self._aes_encrypt(raw_bytes)

            tmp_path = self.data_file + ".tmp"
            with open(tmp_path, "wb") as f:
                f.write(raw_bytes)
            os.replace(tmp_path, self.data_file)
            self.logger.info(f"[TransactionManager] saved => {self.data_file}, total={len(arr)}")
        except Exception as e:
            self.logger.error(f"[TransactionManager] save => {e}")

    def _aes_encrypt(self, plain: bytes) -> bytes:
        aes = AESGCM(self.secret_key)
        nonce = os.urandom(12)
        return nonce + aes.encrypt(nonce, plain, None)

    def _aes_decrypt(self, enc: bytes) -> bytes:
        aes = AESGCM(self.secret_key)
        if len(enc) < 12:
            raise ValueError("encrypted data too short.")
        nonce = enc[:12]
        cipher = enc[12:]
        return aes.decrypt(nonce, cipher, None)

    def _derive_key_from_passphrase(self, passphrase: str) -> bytes:
        salt = (self.node_id + "_txmanager").encode("utf-8")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000
        )
        return kdf.derive(passphrase.encode("utf-8"))

    # ----------------------------------------------------------------
    # MultiSig logic 
    # ----------------------------------------------------------------
    def is_multi_sig_valid(self, mst: MultiSigTransaction) -> bool:
        if len(mst.signatures) < mst.required_signatures:
            return False
        if not mst.transaction:
            return False

        tx_data = mst.transaction.to_dict(exclude_signature=True)
        for signer_id, sig_hex in mst.signatures.items():
            if signer_id not in mst.authorized_signers:
                self.logger.warning(f"[TxManager] multiSig => signer={signer_id} not in authorized => fail")
                return False
            ok = self.key_manager.verify_transaction(signer_id, tx_data, sig_hex)
            if not ok:
                self.logger.warning(f"[TxManager] multiSig => invalid signature from {signer_id}")
                return False
        return True

    async def execute_multi_sig(self, mst: MultiSigTransaction):
        if not mst.transaction:
            self.logger.warning("[TransactionManager] multiSig => no transaction => skip.")
            return None
        sender = mst.transaction.sender
        if sender not in [self.node_id, "COINBASE"]:
            self.logger.warning(f"[TransactionManager] multiSig => sender={sender}, we are={self.node_id} => skip.")
            return None

        if not self.is_multi_sig_valid(mst):
            self.logger.warning("[TransactionManager] multiSig => invalid => skip.")
            return None

        block_data = {"tekeraTx": mst.transaction.to_dict()}
        await self.hotstuff_consensus.propose_block(block_data)
        self.logger.info(f"[TransactionManager] multi_sig => proposed block => tx_id={mst.transaction.tx_id}")

        if self.poh:
            ev = {
                "type": "multi_sig_propose_bft",
                "tx_id": mst.transaction.tx_id,
                "sender": sender,
                "recipient": mst.transaction.recipient,
                "amount_terabit": mst.transaction.amount_terabit,
                "signatures_count": len(mst.signatures),
                "timestamp": time.time()
            }
            await self.poh.record_event(ev)
        return True

    async def broadcast_multi_sig(self, mst: MultiSigTransaction):
        if not self.network:
            self.logger.warning("[TransactionManager] no network => skip broadcast_multi_sig.")
            return
        multi_data = mst.to_dict()
        msg = {
            "type": "multi_sig",
            "multi_sig": multi_data
        }
        await self.network.broadcast_transaction(self.node_id, msg)
        self.logger.info(f"[TransactionManager] broadcast_multi_sig => tx_id={mst.transaction.tx_id}")

        if self.poh:
            ev = {
                "type": "multi_sig",
                "tx_id": mst.transaction.tx_id,
                "sender": mst.transaction.sender,
                "recipient": mst.transaction.recipient,
                "amount_terabit": mst.transaction.amount_terabit,
                "signatures_count": len(mst.signatures),
                "timestamp": time.time()
            }
            await self.poh.record_event(ev)

        if self.chord_node:
            key = f"multi_sig_{mst.transaction.tx_id}"
            val_obj = LWWValue(msg, time.time())
            await self.chord_node.replicate_locally(key, val_obj)
            self.logger.info(f"[TransactionManager] multi_sig => chord => key={key}")

    async def delete_transaction_in_chord(self, tx_id: str, tx_type: str = "single"):
        if not self.chord_node:
            self.logger.warning("[TransactionManager] no chord_node => skip.")
            return
        if tx_type not in ("single","multi_sig"):
            self.logger.warning(f"[TransactionManager] unknown tx_type={tx_type} => skip.")
            return

        key = f"{tx_type}_tx_{tx_id}" if tx_type=="single" else f"multi_sig_{tx_id}"
        tombstone = {"deleted": True}
        val_obj = LWWValue(tombstone, time.time())
        await self.chord_node.replicate_locally(key, val_obj)
        self.logger.info(f"[TransactionManager] delete_in_chord => {key}, set tombstone")


class TxAdapter(BaseTransaction):
    def __init__(self, raw_tx: Transaction):
        super().__init__(raw_tx.tx_id)
        self.raw_tx = raw_tx
        self.read_keys.add(raw_tx.sender)
        self.write_keys.add(raw_tx.sender)
        self.write_keys.add(raw_tx.recipient)

    async def execute(self, global_state: dict):
        amt = self.raw_tx.amount_terabit
        sender = self.raw_tx.sender
        recipient = self.raw_tx.recipient

        if "__cub_tekera__" not in global_state:
            logging.warning("[TxAdapter] no cub_tekera in global_state => skip.")
            return

        cub = global_state["__cub_tekera__"]

        logging.info(f"[TxAdapter] execute => tx_id={self.raw_tx.tx_id}, from={sender}, to={recipient}, amt={amt}")
        
