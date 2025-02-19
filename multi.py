import uuid
import asyncio
import logging
from typing import Optional, Dict, Set
 import json
from key import KeyManager
from trans import Transaction
from tekeracub import CubTekera
from sealevel_engine import BaseTransaction

logging.basicConfig(level=logging.INFO)

class MultiSigTransaction:
   
    def __init__(
        self,
        key_manager: KeyManager,
        authorized_signers: Set[str],
        required_signatures: int = 2
    ):
        self.key_manager = key_manager
        self.authorized_signers = authorized_signers
        self.required_signatures = required_signatures

        self.transaction: Optional[Transaction] = None
        self.signatures: Dict[str, str] = {}
        logging.info(f"[MultiSigTransaction] init => authorized={authorized_signers}, req_signs={required_signatures}")

    def create_transaction(
        self,
        sender_node_id: str,
        recipient_node_id: str,
        amount_terabit: int,
        currency: str = "TEKERA"
    ):
        tx_id = str(uuid.uuid4())
        self.transaction = Transaction(
            tx_id=tx_id,
            sender=sender_node_id,
            recipient=recipient_node_id,
            amount_terabit=amount_terabit,
            currency=currency
        )
        self.signatures.clear()
        logging.info(f"[MultiSigTransaction] Created => tx_id={tx_id}, from={sender_node_id}, to={recipient_node_id}, amount={amount_terabit}, required={self.required_signatures}")

    def add_signature(self, node_id: str):
       
        if not self.transaction:
            raise ValueError("[MultiSigTransaction] No .transaction to sign.")
        if node_id not in self.authorized_signers:
            raise ValueError(f"[MultiSigTransaction] node_id={node_id} not in authorized_signers => can't sign.")
        if node_id in self.signatures:
            raise ValueError(f"[MultiSigTransaction] node {node_id} already signed.")

        tx_data = self.transaction.to_dict(exclude_signature=True)
        sign_hex = self.key_manager.sign_transaction(node_id, tx_data)
        self.signatures[node_id] = sign_hex

        logging.info(f"[MultiSigTransaction] node={node_id} подписал tx={self.transaction.tx_id}, total_signs={len(self.signatures)}/{self.required_signatures}")
        return (len(self.signatures) >= self.required_signatures)

    def is_valid(self) -> bool:
      
        if not self.transaction:
            logging.warning("[MultiSigTransaction] no transaction => invalid.")
            return False
        if len(self.signatures) < self.required_signatures:
            logging.warning(f"[MultiSigTransaction] Not enough sigs => {len(self.signatures)}/{self.required_signatures}")
            return False

        tx_data = self.transaction.to_dict(exclude_signature=True)
        for node_id, sig_hex in self.signatures.items():
            if node_id not in self.authorized_signers:
                logging.warning(f"[MultiSigTransaction] node={node_id} not authorized => invalid.")
                return False
            ok = self.key_manager.verify_transaction(node_id, tx_data, sig_hex)
            if not ok:
                logging.warning(f"[MultiSigTransaction] invalid signature from node={node_id}.")
                return False

        return True

    def to_dict(self) -> dict:
       
        if not self.transaction:
            raise ValueError("[MultiSigTransaction] no transaction => can't to_dict.")
        return {
            "tx": self.transaction.to_dict(),
            "signatures": self.signatures,
            "authorized": list(self.authorized_signers),
            "required": self.required_signatures
        }

    @classmethod
    def from_dict(cls, data: dict, key_manager: KeyManager) -> "MultiSigTransaction":
        """
        Восстанавливаем MST из словаря
        {
          "tx": {...},
          "signatures": {...},
          "authorized": [...],
          "required": int
        }
        """
        from trans import Transaction
        auth = set(data["authorized"])
        req = data["required"]
        mst = cls(key_manager, auth, req)
        mst.transaction = Transaction.from_dict(data["tx"])
        mst.signatures = data["signatures"]
        return mst

    async def propose_bft(self, bft_consensus, cub: CubTekera):
      
       

        if not bft_consensus:
            logging.warning("[MultiSigTransaction] no bft_consensus => can't propose.")
            return
        if not self.is_valid():
            logging.warning("[MultiSigTransaction] not enough or invalid sig => skip propose BFT.")
            return

        block_data = {"multiSigTx": self.to_dict()}
        logging.info(f"[MultiSigTransaction] propose_bft => {block_data}")
        await bft_consensus.propose_block(block_data)

    async def execute(self, cub: CubTekera):
       
        if not self.is_valid():
            raise ValueError("[MultiSigTransaction] not enough or invalid sig => can't execute.")
        if not self.transaction:
            raise ValueError("[MultiSigTransaction] no transaction => can't execute.")
        amt = self.transaction.amount_terabit
        rec = self.transaction.recipient
       
        new_bal, sig_hex = await cub.transfer_terabit(amt, rec)
        logging.info(f"[MultiSigTransaction] execute => done => newBal={new_bal}, tx_id={self.transaction.tx_id}")
        return (new_bal, sig_hex)

    @staticmethod
    async def commit_multi_sig(tx_data: dict, cub: CubTekera):
       
        from multi_sig_transaction import MultiSigTransaction
        from trans import Transaction

        
        mst = MultiSigTransaction.from_dict(tx_data, cub.key_manager)
        if not mst.is_valid():
            logging.warning("[MultiSigTransaction] commit => invalid => skip.")
            return

        await mst.execute(cub)
        logging.info(f"[MultiSigTransaction] commit_multi_sig => final done => tx_id={mst.transaction.tx_id}")


class MultiSigTxAdapter(BaseTransaction):
   
    def __init__(self, mst: MultiSigTransaction):
        if not mst.transaction:
            raise ValueError("No .transaction in MultiSigTransaction")
        super().__init__(mst.transaction.tx_id)
        self.mst = mst
        snd = mst.transaction.sender
        rcp = mst.transaction.recipient
        self.read_keys.add(snd)
        self.write_keys.add(snd)
        self.write_keys.add(rcp)

    async def execute(self, global_state: dict):
        if not self.mst.is_valid():
            logging.warning(f"[MultiSigTxAdapter] not valid => skip={self.mst.transaction.tx_id}")
            return
        cub = global_state.get("__cub_tekera__")
        if not cub:
            logging.warning("[MultiSigTxAdapter] no cub => skip.")
            return
        await self.mst.execute(cub)
        logging.info(f"[MultiSigTxAdapter] done => multiSigTx={self.mst.transaction.tx_id}")
