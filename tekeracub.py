import os
import time
import asyncio
import logging
import hashlib
from typing import Optional, Dict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from key import KeyManager
from chordnode import ChordNode, LWWValue
from trans import Transaction

logging.basicConfig(level=logging.INFO)

class CubTekera:
    """
    Обновлённая версия, где CubTekera НЕ делает напрямую propose_block(...).
    Вместо этого вызывает методы TransactionManager для BFT-транзакций.
    """

    TEKERA_TO_TERABIT = 1_000_000_000_000
    GLOBAL_MAX_SUPPLY = 500_000_000  # 500 млн TEKERA

    def __init__(
        self,
        key_manager: KeyManager,
        node_id: str,
        chord_node: ChordNode,
        stake_ledger=None,
        transaction_manager=None,           # <-- теперь вместо hotstuff_consensus
        use_plain_receiver_balance: bool = False
    ):
        """
        hotstuff_consensus убрали. 
        Вместо этого принимаем transaction_manager (или None).
        """
        self.key_manager = key_manager
        self.node_id = node_id
        self.chord_node = chord_node
        self.stake_ledger = stake_ledger
        self.transaction_manager = transaction_manager
        self.use_plain_receiver_balance = use_plain_receiver_balance
        self.address = node_id 
       

        # 2) AES-ключ для локального баланса (зашифрованный)
        self.aes_key = self.key_manager.get_aes_key(node_id)
        self.aesgcm = AESGCM(self.aes_key) if self.aes_key else None

        self._lock = asyncio.Lock()

        logging.info(
            f"[CubTekera] init => node_id={node_id}, address={self.address}, plain={use_plain_receiver_balance}"
        )

    def _calc_address_from_pubkey(self, pubkey) -> str:
        pem = pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        h = hashlib.sha256(pem).hexdigest()
        return "addr_" + h[:16]

    async def initialize(self):
        await self._ensure_balance_exists()
        await self._ensure_minted_total_exists()

        bal_terabits = await self.get_local_balance_terabit()
        bal_tekera = bal_terabits / self.TEKERA_TO_TERABIT
        logging.info(
            f"[CubTekera] node={self.node_id}, address={self.address}, local_balance={bal_terabits} Tbits (~{bal_tekera} TEKERA)"
        )

    # ----------------------------------------------------------------
    #  Local balance
    # ----------------------------------------------------------------
    async def _ensure_balance_exists(self):
        crdt_key = f"balance_{self.address}"
        vo = self.chord_node.get_local(crdt_key)
        if vo is None:
            await self._save_balance(0)

    async def _save_balance(self, balance_terabit: int):
        if not self.aesgcm:
            logging.warning("[CubTekera] no aesgcm => skip storing => store plain int.")
            val_obj = LWWValue(balance_terabit, time.time())
            await self.chord_node.replicate_locally(f"balance_{self.address}", val_obj)
            return

        nonce = os.urandom(12)
        raw_bytes = balance_terabit.to_bytes(16, 'big')
        cipher = self.aesgcm.encrypt(nonce, raw_bytes, None)
        record = {
            "nonce": nonce.hex(),
            "ciphertext": cipher.hex()
        }
        val_obj = LWWValue(record, time.time())
        await self.chord_node.replicate_locally(f"balance_{self.address}", val_obj)

    async def _load_balance(self) -> int:
        crdt_key = f"balance_{self.address}"
        vo = self.chord_node.get_local(crdt_key)
        if not vo:
            await self._save_balance(0)
            return 0

        if not self.aesgcm:
            val_raw = vo.value
            if isinstance(val_raw, int):
                return val_raw
            logging.warning("[CubTekera] no aesgcm => record not int => return 0.")
            return 0

        record = vo.value
        if not isinstance(record, dict) or "nonce" not in record or "ciphertext" not in record:
            logging.warning("[CubTekera] record is invalid => return 0.")
            return 0

        nonce = bytes.fromhex(record["nonce"])
        cipher = bytes.fromhex(record["ciphertext"])
        plain = self.aesgcm.decrypt(nonce, cipher, None)
        return int.from_bytes(plain, 'big')

    async def get_local_balance_terabit(self) -> int:
        return await self._load_balance()

    async def load_balance_of(self, address: str) -> int:
        """
        Возвращаем баланс другого адреса (в режиме plain, если use_plain_receiver_balance=True),
        иначе 0 (fallback).
        """
        if address == self.address:
            return await self._load_balance()

        if self.use_plain_receiver_balance:
            crdt_key = f"balance_{address}_plain"
            vo = self.chord_node.get_local(crdt_key)
            if vo is None:
                return 0
            return int(vo.value)

        logging.warning(f"[CubTekera] load_balance_of => can't decrypt other => return 0.")
        return 0

    # ----------------------------------------------------------------
    # Global minted
    # ----------------------------------------------------------------
    async def _ensure_minted_total_exists(self):
        key = "global_minted_total"
        vo = self.chord_node.get_local(key)
        if vo is None:
            val = LWWValue(0, time.time())
            await self.chord_node.replicate_locally(key, val)

    async def _load_minted_total(self) -> int:
        key = "global_minted_total"
        vo = self.chord_node.get_local(key)
        if not vo:
            val = LWWValue(0, time.time())
            await self.chord_node.replicate_locally(key, val)
            return 0
        return int(vo.value)

    async def _save_minted_total(self, minted_terabit: int):
        key = "global_minted_total"
        val = LWWValue(minted_terabit, time.time())
        await self.chord_node.replicate_locally(key, val)

    @property
    def max_supply_terabit(self) -> int:
        return self.GLOBAL_MAX_SUPPLY * self.TEKERA_TO_TERABIT

    # ----------------------------------------------------------------
    # Minting & reward
    # ----------------------------------------------------------------
    async def _internal_mint(self, recipient_address: str, amount_terabit: int) -> int:
        async with self._lock:
            minted_so_far = await self._load_minted_total()
            leftover = self.max_supply_terabit - minted_so_far
            if leftover <= 0:
                logging.warning("[CubTekera] supply exhausted => 0 minted.")
                return 0

            actual = min(amount_terabit, leftover)
            if actual <= 0:
                return 0

            # Зачисляем
            if recipient_address == self.address:
                oldb = await self._load_balance()
                newb = oldb + actual
                await self._save_balance(newb)
                logging.info(f"[CubTekera] minted => self.address={self.address}, +{actual}, newBal={newb}")
            else:
                if self.use_plain_receiver_balance:
                    await self._increase_plain_balance(recipient_address, actual)
                else:
                    logging.info(f"[CubTekera] minted => addr={recipient_address}, +{actual} (no encryption)")

            new_minted = minted_so_far + actual
            await self._save_minted_total(new_minted)
            return actual

    async def _increase_plain_balance(self, address: str, add_amt: int):
        crdt_key = f"balance_{address}_plain"
        vo = self.chord_node.get_local(crdt_key)
        old_val = 0 if (vo is None) else int(vo.value)
        new_val = old_val + add_amt
        new_obj = LWWValue(new_val, time.time())
        await self.chord_node.replicate_locally(crdt_key, new_obj)
        logging.info(f"[CubTekera] increase_plain_balance => addr={address}, old={old_val}, new={new_val}")

    async def attempt_ml_reward(self, reward_tx: dict, ml_proof: dict) -> bool:
        sender = reward_tx.get("sender")
        recipient_addr = reward_tx.get("recipient")
        amt = reward_tx.get("amount_terabit", 0)
        if sender != "COINBASE":
            logging.warning("[CubTekera] attempt_ml_reward => not coinbase => reject.")
            return False
        if not await self._verify_ml_proof(ml_proof):
            logging.warning("[CubTekera] attempt_ml_reward => invalid proof => reject.")
            return False

        minted = await self._internal_mint(recipient_addr, amt)
        return (minted > 0)

    async def attempt_partial_reward(self, distribution_map: Dict[str, int]) -> bool:
        total_need = sum(distribution_map.values())
        if total_need <= 0:
            logging.warning("[CubTekera] partial_reward => total_need=0 => skip.")
            return False

        minted_so_far = await self._load_minted_total()
        leftover = self.max_supply_terabit - minted_so_far
        if leftover <= 0:
            logging.warning("[CubTekera] partial_reward => supply exhausted => 0 minted.")
            return False

        minted_total = 0
        for (addr, amt) in distribution_map.items():
            if amt <= 0:
                continue
            minted_now = await self._internal_mint(addr, amt)
            minted_total += minted_now

        logging.info(f"[CubTekera] partial_reward => minted={minted_total}, recipients={len(distribution_map)}")
        return True

    # ----------------------------------------------------------------
    # Proof check
    # ----------------------------------------------------------------
    async def _verify_ml_proof(self, ml_proof: dict) -> bool:
        minted_terabits = await self._load_minted_total()
        minted_tekera = minted_terabits / self.TEKERA_TO_TERABIT
        expected_diff = int(minted_tekera // 50_000_000)

        got_diff = ml_proof.get("difficulty", -1)
        if got_diff != expected_diff:
            return False

        acc = ml_proof.get("accuracy", 0.0)
        needed = 0.80 + 0.02 * expected_diff
        if acc < needed:
            return False

        model_hash = ml_proof.get("model_hash")
        if not model_hash:
            return False
        weights_data = ml_proof.get("weights_data", "")
        import hashlib
        local_h = hashlib.sha256(weights_data.encode('utf-8')).hexdigest()
        if local_h != model_hash:
            return False

        return self._zkp_verify(ml_proof)

    def _zkp_verify(self, ml_proof: dict) -> bool:
        # Заглушка под Zero-Knowledge
        return True

    # ----------------------------------------------------------------
    # Stake
    # ----------------------------------------------------------------
    async def stake_dataset(self, dataset_id: str, stake_amount_terabit: int) -> bool:
        """
        Локально уменьшаем баланс, потом вызываем stake_for_dataset(...) в ledger.
        """
        if not self.stake_ledger:
            logging.warning("[CubTekera] stake_dataset => no stake_ledger => skip.")
            return False

        async with self._lock:
            have = await self._load_balance()
            if stake_amount_terabit <= 0 or stake_amount_terabit > have:
                logging.warning(f"[CubTekera] insufficient => have={have}, need={stake_amount_terabit}")
                return False
            new_bal = have - stake_amount_terabit
            await self._save_balance(new_bal)
            logging.info(f"[CubTekera] stake_dataset => node_id={self.node_id}, minus {stake_amount_terabit}, newLocal={new_bal}")

        st_tekera = stake_amount_terabit / self.TEKERA_TO_TERABIT
        ok = self.stake_ledger.stake_for_dataset(dataset_id, self.node_id, st_tekera)
        if not ok:
            # Откат
            async with self._lock:
                revert_bal = await self._load_balance()
                revert_new = revert_bal + stake_amount_terabit
                await self._save_balance(revert_new)
            logging.warning("[CubTekera] stake_dataset => ledger fail => rollback local balance")
            return False

        logging.info(f"[CubTekera] stake_dataset => ds={dataset_id}, user={self.node_id}, staked={st_tekera} TEKERA")
        return True

    async def unstake_dataset(self, dataset_id: str) -> bool:
        if not self.stake_ledger:
            logging.warning("[CubTekera] unstake_dataset => no stake_ledger => skip.")
            return False

        staked_amt = self.stake_ledger.get_dataset_stake_amount(dataset_id, self.node_id)
        if staked_amt <= 0:
            logging.warning(f"[CubTekera] unstake_dataset => no stake => ds={dataset_id}")
            return False

        success = self.stake_ledger.unstake_dataset_amount(dataset_id, self.node_id, staked_amt)
        if not success:
            logging.warning("[CubTekera] unstake_dataset => ledger fail => skip.")
            return False

        ret_terabits = int(staked_amt * self.TEKERA_TO_TERABIT)
        async with self._lock:
            oldb = await self._load_balance()
            newb = oldb + ret_terabits
            await self._save_balance(newb)
            logging.info(f"[CubTekera] unstake_dataset => ds={dataset_id}, +{ret_terabits}, newBal={newb}")

        return True

    # ----------------------------------------------------------------
    #  BFT transfers via TransactionManager
    # ----------------------------------------------------------------
    async def propose_transfer_bft(self, amount_terabit: int, recipient_address: str):
        """
        Вместо прямого hotstuff_consensus.propose_block, 
        вызываем TransactionManager (если есть).
        """
        if not self.transaction_manager:
            logging.warning("[CubTekera] propose_transfer_bft => no transaction_manager => skip.")
            return

        async with self._lock:
            my_bal = await self._load_balance()
            if amount_terabit <= 0 or amount_terabit > my_bal:
                logging.warning(
                    f"[CubTekera] propose_transfer_bft => invalid => have={my_bal}, need={amount_terabit}"
                )
                return

        self.logger.info(
            f"[CubTekera] propose_transfer_bft => from={self.address}, to={recipient_address}, amt={amount_terabit}"
        )
        tx_id = await self.transaction_manager.propose_bft_transfer(
            recipient_id=recipient_address,
            amount_terabit=amount_terabit
        )
        if not tx_id:
            logging.warning("[CubTekera] propose_transfer_bft => fail => no tx_id returned.")
        else:
            logging.info(f"[CubTekera] propose_transfer_bft => tx_id={tx_id}")

    async def propose_stake_increase(self, amount: float, signature: Optional[str] = None):
      
        if not self.stake_ledger or not self.transaction_manager:
            logging.warning("[CubTekera] propose_stake_increase => missing stake_ledger / transaction_manager => skip.")
            return

        self.logger.info(f"[CubTekera] propose_stake_increase => node={self.node_id}, amt={amount}")

        
        tx_id = await self.transaction_manager.propose_stake_tx(
            node_id=self.node_id,
            amount=amount,
            signature=signature
        )
        if not tx_id:
            logging.warning("[CubTekera] propose_stake_increase => no tx_id => fail.")
        else:
            logging.info(f"[CubTekera] propose_stake_increase => tx_id={tx_id}")

    # ----------------------------------------------------------------
    # Метод исполнения (вызывается при DECIDE в HotStuff)
    # ----------------------------------------------------------------
    async def _commit_transfer(self, tx_data: dict):
        """
        HotStuff вызывает это при финализации блока, 
        чтобы списать/зачислить локальный баланс.
        """
        sender_addr = tx_data.get("sender")
        recipient_addr = tx_data.get("recipient")
        amt = tx_data.get("amount_terabit")
        if not amt or amt <= 0:
            return

        async with self._lock:
            if sender_addr == self.address:
                myb = await self._load_balance()
                if myb < amt:
                    logging.warning("[CubTekera] _commit_transfer => insufficient => skip.")
                    return
                newb = myb - amt
                await self._save_balance(newb)
                logging.info(f"[CubTekera] _commit_transfer => sent => newBal={newb}")

            if recipient_addr == self.address:
                myb = await self._load_balance()
                newb = myb + amt
                await self._save_balance(newb)
                logging.info(f"[CubTekera] _commit_transfer => received => newBal={newb}")