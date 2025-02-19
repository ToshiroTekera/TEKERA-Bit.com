

import time
import logging
import uuid
from typing import Optional
from dataclasses import dataclass, field

logging.basicConfig(level=logging.INFO)

@dataclass
class Transaction:
   

    tx_id: str
    sender: str
    recipient: str
    amount_terabit: int
    currency: str = "TEKERA"
    nonce: int = 0
    fee: int = 0
    version: int = 1
    status: str = "pending"
    timestamp: float = field(default_factory=time.time)
    signature: Optional[str] = None

    def to_dict(self, exclude_signature: bool = False) -> dict:
      
        d = {
            "tx_id": self.tx_id,
            "sender": self.sender,
            "recipient": self.recipient,
            "amount_terabit": self.amount_terabit,
            "currency": self.currency,
            "nonce": self.nonce,
            "fee": self.fee,
            "version": self.version,
            "status": self.status,
            "timestamp": self.timestamp
        }
        if (not exclude_signature) and (self.signature is not None):
            d["signature"] = self.signature
        return d

    @staticmethod
    def from_dict(data: dict) -> "Transaction":
        """
        Десериализация из dict.
        """
        return Transaction(
            tx_id = data["tx_id"],
            sender = data["sender"],
            recipient = data["recipient"],
            amount_terabit = data["amount_terabit"],
            currency = data.get("currency","TEKERA"),
            nonce = data.get("nonce",0),
            fee = data.get("fee",0),
            version = data.get("version",1),
            status = data.get("status","pending"),
            timestamp = data.get("timestamp", time.time()),
            signature = data.get("signature")
        )

    @staticmethod
    def create(
        sender: str,
        recipient: str,
        amount_terabit: int,
        currency: str = "TEKERA",
        nonce: int = 0,
        fee: int = 0,
        version: int = 1
    ) -> "Transaction":
      
        return Transaction(
            tx_id=str(uuid.uuid4()),
            sender=sender,
            recipient=recipient,
            amount_terabit=amount_terabit,
            currency=currency,
            nonce=nonce,
            fee=fee,
            version=version,
            status="pending"
        )