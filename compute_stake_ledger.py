import time
import json
import logging
import sqlite3
import asyncio
import hashlib
from typing import Optional, Dict, List, Tuple, Any

from sealevel_engine import BaseTransaction

logging.basicConfig(level=logging.INFO)

class StakeTransaction:


    def __init__(self, tx_id: str, owner_address: str, amount: float, timestamp: float, signature: Optional[str]):
        self.tx_id = tx_id
        self.owner_address = owner_address
        self.amount = amount
        self.timestamp = timestamp
        self.signature = signature

    def to_dict(self) -> dict:
       
        return {
            "tx_id": self.tx_id,
            "target_node": self.owner_address,
            "amount": self.amount,
            "timestamp": self.timestamp,
            "signature": self.signature
        }

    @staticmethod
    def from_dict(d: dict) -> "StakeTransaction":
        """
        Обратно: считаем, что d["target_node"] = owner_address.
        """
        return StakeTransaction(
            tx_id=d["tx_id"],
            owner_address=d["target_node"],
            amount=float(d["amount"]),
            timestamp=float(d["timestamp"]),
            signature=d.get("signature")
        )


class StakeTxAdapter(BaseTransaction):
   

    def __init__(self, stx: StakeTransaction, ledger: "ComputeStakeLedger"):
        super().__init__(stx.tx_id)
        self.stx = stx
        self.ledger = ledger
        # Для Sealevel нужно указать, какие ключи затрагивает транзакция:
        self.write_keys.add(f"stake_{stx.owner_address}")

    async def execute(self, global_state: dict):
        # Прямо вызываем локальное применение стейк-транзакции
        self.ledger._apply_stake_tx_local(self.stx)
        logging.info(f"[StakeTxAdapter] stx={self.stx.tx_id} => stake change={self.stx.amount}")


class ComputeStakeLedger:
   

    def __init__(
        self,
        local_alias: str,
        local_db_path: str = "stake_ledger.db",
        key_manager=None,
        batch_interval: float = 0.5,
        chord_node=None
    ):
      
        self.local_alias = local_alias
        self.local_db_path = local_db_path
        self.key_manager = key_manager
        self.batch_interval = batch_interval
        self.chord_node = chord_node

        self._init_db()

        self._pending_stx: List[StakeTransaction] = []
        self._batch_lock = asyncio.Lock()
        self._batch_task: Optional[asyncio.Task] = None

        loop = asyncio.get_event_loop()
        self._batch_task = loop.create_task(self._batch_loop())

        logging.info(f"[ComputeStakeLedger] alias={local_alias}, db={local_db_path} init OK.")

    def _init_db(self):
       
        conn = sqlite3.connect(self.local_db_path)
        c = conn.cursor()

        c.execute("""
        CREATE TABLE IF NOT EXISTS stake_balance(
            node_id TEXT PRIMARY KEY,
            stake_value REAL NOT NULL
        )""")

        c.execute("""
        CREATE TABLE IF NOT EXISTS stake_txs(
            tx_id TEXT PRIMARY KEY,
            target_node TEXT NOT NULL,
            amount REAL NOT NULL,
            timestamp REAL NOT NULL,
            signature TEXT,
            status TEXT DEFAULT 'new'
        )""")

        c.execute("""
        CREATE TABLE IF NOT EXISTS dataset_stakes(
            dataset_id TEXT NOT NULL,
            node_id TEXT NOT NULL,
            staked_amount REAL NOT NULL,
            PRIMARY KEY(dataset_id, node_id)
        )""")

        conn.commit()
        conn.close()

    # --------------------------------------------------------------
    # 1) Методы чтения stake
    # --------------------------------------------------------------
    def get_stake(self, owner_address: str) -> float:
        """
        Возвращает общий стейк (stake_balance[node_id]).
        """
        conn = sqlite3.connect(self.local_db_path)
        c = conn.cursor()
        c.execute("SELECT stake_value FROM stake_balance WHERE node_id=?", (owner_address,))
        row = c.fetchone()
        conn.close()
        if row:
            return float(row[0])
        return 0.0

    def total_stake(self) -> float:
        """
        Суммарный stake по всем узлам.
        """
        conn = sqlite3.connect(self.local_db_path)
        c = conn.cursor()
        c.execute("SELECT SUM(stake_value) FROM stake_balance")
        row = c.fetchone()
        conn.close()
        if row and row[0]:
            return float(row[0])
        return 0.0

    def all_stakes(self) -> dict:
        
        out = {}
        conn = sqlite3.connect(self.local_db_path)
        c = conn.cursor()
        c.execute("SELECT node_id, stake_value FROM stake_balance")
        rows = c.fetchall()
        conn.close()
        for nd, val in rows:
            out[nd] = float(val)
        return out

    # --------------------------------------------------------------
    # 2) Методы стейка для конкретного dataset_id
    # --------------------------------------------------------------
    def stake_for_dataset(self, dataset_id: str, owner_address: str, amount: float) -> bool:
        
        if amount <= 0:
            logging.warning("[ComputeStakeLedger] stake_for_dataset => amount<=0 => skip")
            return False

        old_val = self.get_stake(owner_address)
        new_val = old_val + amount

        conn = sqlite3.connect(self.local_db_path)
        c = conn.cursor()

        # Обновляем stake_balance
        c.execute("""
          INSERT OR REPLACE INTO stake_balance(node_id, stake_value)
          VALUES(?,?)
        """, (owner_address, new_val))

        # dataset_stakes
        c.execute("""
          SELECT staked_amount
          FROM dataset_stakes
          WHERE dataset_id=? AND node_id=?
        """, (dataset_id, owner_address))
        row = c.fetchone()
        if row:
            old_ds_val = float(row[0])
            new_ds_val = old_ds_val + amount
            c.execute("""
              UPDATE dataset_stakes
              SET staked_amount=?
              WHERE dataset_id=? AND node_id=?
            """, (new_ds_val, dataset_id, owner_address))
        else:
            c.execute("""
              INSERT INTO dataset_stakes(dataset_id, node_id, staked_amount)
              VALUES(?,?,?)
            """, (dataset_id, owner_address, amount))

        conn.commit()
        conn.close()

        logging.info(f"[ComputeStakeLedger] stake_for_dataset => ds={dataset_id}, owner={owner_address}, +{amount}, newTotal={new_val}")
        return True

    def get_dataset_stake_amount(self, dataset_id: str, owner_address: str) -> float:
        conn = sqlite3.connect(self.local_db_path)
        c = conn.cursor()
        c.execute("""
          SELECT staked_amount
          FROM dataset_stakes
          WHERE dataset_id=? AND node_id=?
        """, (dataset_id, owner_address))
        row = c.fetchone()
        conn.close()
        if row:
            return float(row[0])
        return 0.0

    def unstake_dataset_amount(self, dataset_id: str, owner_address: str, amount: float) -> bool:
       
        if amount <= 0:
            logging.warning("[ComputeStakeLedger] unstake_dataset_amount => amount<=0 => skip.")
            return False

        # читаем dataset_stakes
        conn = sqlite3.connect(self.local_db_path)
        c = conn.cursor()
        c.execute("""
          SELECT staked_amount
          FROM dataset_stakes
          WHERE dataset_id=? AND node_id=?
        """, (dataset_id, owner_address))
        row = c.fetchone()
        if not row:
            conn.close()
            logging.warning(f"[ComputeStakeLedger] unstake_dataset_amount => no stake => ds={dataset_id}, user={owner_address}")
            return False
        ds_val = float(row[0])
        if ds_val < amount:
            conn.close()
            logging.warning(f"[ComputeStakeLedger] unstake_dataset_amount => not enough => ds_val={ds_val}, need={amount}")
            return False

        new_ds_val = ds_val - amount

        # Уменьшаем общий stake_balance
        old_bal = self.get_stake(owner_address)
        new_bal = old_bal - amount
        if new_bal < 0:
            new_bal = 0

        c.execute("""
          INSERT OR REPLACE INTO stake_balance(node_id, stake_value)
          VALUES(?,?)
        """, (owner_address, new_bal))

        # dataset_stakes
        if new_ds_val <= 0:
            c.execute("""
              DELETE FROM dataset_stakes
              WHERE dataset_id=? AND node_id=?
            """, (dataset_id, owner_address))
        else:
            c.execute("""
              UPDATE dataset_stakes
              SET staked_amount=?
              WHERE dataset_id=? AND node_id=?
            """, (new_ds_val, dataset_id, owner_address))

        conn.commit()
        conn.close()

        logging.info(f"[ComputeStakeLedger] unstake_dataset_amount => ds={dataset_id}, user={owner_address}, unstaked={amount}, remain={new_ds_val}, newOwnerStake={new_bal}")
        return True

    def slash_dataset_stake(self, dataset_id: str) -> bool:
       
        conn = sqlite3.connect(self.local_db_path)
        c = conn.cursor()

        c.execute("""
          SELECT node_id, staked_amount
          FROM dataset_stakes
          WHERE dataset_id=?
        """, (dataset_id,))
        row = c.fetchone()
        if not row:
            conn.close()
            logging.warning(f"[ComputeStakeLedger] slash_dataset_stake => no stake => ds={dataset_id}")
            return False

        owner_address, staked_amt = row
        staked_amt = float(staked_amt)
        if staked_amt <= 0:
            conn.close()
            logging.warning(f"[ComputeStakeLedger] slash_dataset_stake => staked=0 => skip => ds={dataset_id}")
            return False

        old_stake = self.get_stake(owner_address)
        new_stake = old_stake - staked_amt
        if new_stake < 0:
            new_stake = 0

        c.execute("""
          INSERT OR REPLACE INTO stake_balance(node_id, stake_value)
          VALUES(?,?)
        """, (owner_address, new_stake))

        c.execute("""
          UPDATE dataset_stakes
          SET staked_amount=0
          WHERE dataset_id=? AND node_id=?
        """, (dataset_id, owner_address))

        conn.commit()
        conn.close()

        logging.warning(f"[ComputeStakeLedger] slash_dataset_stake => ds={dataset_id}, owner={owner_address}, slashed={staked_amt}, newOwnerStake={new_stake}")
        return True

    def slash_stake(self, owner_address: str):
        """
        Сжигаем весь stake пользователя (в т.ч. dataset_stakes).
        """
        old_val = self.get_stake(owner_address)
        if old_val > 0:
            conn = sqlite3.connect(self.local_db_path)
            c = conn.cursor()

            c.execute("""
              INSERT OR REPLACE INTO stake_balance(node_id, stake_value)
              VALUES(?,?)
            """, (owner_address, 0.0))

            c.execute("""
              UPDATE dataset_stakes
              SET staked_amount=0
              WHERE node_id=?
            """, (owner_address,))

            conn.commit()
            conn.close()
            logging.warning(f"[ComputeStakeLedger] slash_stake => user={owner_address}, old={old_val}, new=0 => all ds=0")

    # --------------------------------------------------------------
    # propose_stake_change => (без dataset_id) + BFT
    # --------------------------------------------------------------
    def propose_stake_change(
        self,
        owner_address: str,
        amount: float,
        bft_consensus=None,
        signature: Optional[str] = None
    ):
        """
        Старый способ: если amount>0 => прибавляем к stake_balance,
        если <0 => вычитаем.
        """
        if amount == 0:
            logging.warning("[ComputeStakeLedger] propose_stake_change => 0 => skip.")
            return
        tx_id = self._make_tx_id(owner_address, amount)
        now_ts = time.time()
        stx = StakeTransaction(tx_id, owner_address, amount, now_ts, signature)

        block_data = {"stakeTx": stx.to_dict()}
        if bft_consensus:
            import asyncio
            asyncio.create_task(bft_consensus.propose_block(block_data))
        else:
            logging.warning("[ComputeStakeLedger] no BFT => local apply => apply_stake_tx.")
            self.apply_stake_tx(stx)

    def apply_stake_tx(self, stx: StakeTransaction):
        """
        Применить (увеличить/уменьшить) stake без dataset_id.
        Если key_manager есть — используем batch (с проверкой подписи).
        """
        if not self.key_manager:
            # Применяем сразу
            self._apply_stake_tx_local(stx)
        else:
            # Ставим в очередь на batch‐проверку
            self._schedule_batch_stake(stx)

    def _apply_stake_tx_local(self, stx: StakeTransaction):
        
        conn = sqlite3.connect(self.local_db_path)
        c = conn.cursor()

        # Проверяем, не было ли tx_id
        c.execute("SELECT status FROM stake_txs WHERE tx_id=?", (stx.tx_id,))
        row = c.fetchone()
        if row:
            old_status = row[0]
            if old_status in ('applied','confirmed','rejected'):
                conn.close()
                logging.info(f"[ComputeStakeLedger] stx={stx.tx_id} => already {old_status} => skip")
                return

        old_val = self.get_stake(stx.owner_address)
        new_val = old_val + stx.amount
        if new_val < 0:
            new_val = 0
            logging.warning("[ComputeStakeLedger] negative => set=0")

        c.execute("""
          INSERT OR REPLACE INTO stake_balance(node_id, stake_value)
          VALUES(?,?)
        """, (stx.owner_address, new_val))

        c.execute("""
          INSERT OR REPLACE INTO stake_txs(tx_id, target_node, amount, timestamp, signature, status)
          VALUES(?,?,?,?,?,?)
        """, (stx.tx_id, stx.owner_address, stx.amount, stx.timestamp, stx.signature, 'applied'))

        conn.commit()
        conn.close()

        logging.info(f"[ComputeStakeLedger] APPLIED stakeTx={stx.tx_id}, user={stx.owner_address}, amt={stx.amount}, newStake={new_val}")

    # --------------------------------------------------------------
    # Batch проверка Schnorr-подписи (через key_manager.verify_transaction)
    # --------------------------------------------------------------
    def _schedule_batch_stake(self, stx: StakeTransaction):
        self._pending_stx.append(stx)

    async def _batch_loop(self):
        try:
            while True:
                await asyncio.sleep(self.batch_interval)
                await self._flush_batch()
        except asyncio.CancelledError:
            logging.info("[ComputeStakeLedger] batch_loop canceled.")
        except Exception as e:
            logging.error(f"[ComputeStakeLedger] batch_loop error => {e}")

    async def _flush_batch(self):
        if not self._pending_stx:
            return
        async with self._batch_lock:
            st_list = self._pending_stx
            self._pending_stx = []

        # batch-верификация
        stxs_ok = self._batch_verify(st_list)

        # Применяем локально только те, что прошли подпись
        for (ok, stx) in stxs_ok:
            if ok:
                self._apply_stake_tx_local(stx)
            else:
                logging.warning(f"[ComputeStakeLedger] stakeTx={stx.tx_id} => FAIL signature => skip")

    def _batch_verify(self, stx_list: List[StakeTransaction]) -> List[Tuple[bool, StakeTransaction]]:
       
        out = []
        for stx in stx_list:
            if (not stx.signature) or (not self.key_manager):
                out.append((False, stx))
                continue

            sign_data = {
                "tx_id": stx.tx_id,
                "target_node": stx.owner_address,
                "amount": stx.amount,
                "timestamp": stx.timestamp
            }
            ok = self.key_manager.verify_transaction(stx.owner_address, sign_data, stx.signature)
            out.append((ok, stx))
        return out

    # --------------------------------------------------------------
    # Sealevel batch
    # --------------------------------------------------------------
    async def run_sealevel_batch(self, sealevel_engine, stx_list: List[StakeTransaction]):
        adapters = []
        for stx in stx_list:
            adapter = StakeTxAdapter(stx, self)
            adapters.append(adapter)
        await sealevel_engine.process_batch(adapters)
        logging.info(f"[ComputeStakeLedger] run_sealevel_batch => done => {len(stx_list)} stakeTx")

    # --------------------------------------------------------------
    # Генерация tx_id
    # --------------------------------------------------------------
    def _make_tx_id(self, owner_address: str, amount: float) -> str:
        raw = f"{owner_address}-{amount}-{time.time()}"
        return hashlib.sha256(raw.encode('utf-8')).hexdigest()

    # --------------------------------------------------------------
    # Остановка (отмена фоновой задачи)
    # --------------------------------------------------------------
    async def stop(self):
        if self._batch_task and not self._batch_task.done():
            self._batch_task.cancel()
            try:
                await self._batch_task
            except asyncio.CancelledError:
                pass
            logging.info("[ComputeStakeLedger] stopped.")

    # --------------------------------------------------------------
    # Хранение в Chord (CRDT)
    # --------------------------------------------------------------
    async def store_ledger_in_chord(self):
        if not self.chord_node:
            logging.warning("[ComputeStakeLedger] no chord_node => skip store_ledger.")
            return

        st_map = self.all_stakes()
        tx_list = self._get_all_txs_from_db()
        ds_stakes = self._get_dataset_stakes_from_db()

        out_obj = {
            "stake_balance": st_map,
            "stake_txs": [t.to_dict() for t in tx_list],
            "dataset_stakes": ds_stakes
        }
        data_js = json.dumps(out_obj, sort_keys=True)
        from chordnode import LWWValue
        vo = LWWValue(data_js, time.time())
        key = f"stake_ledger_{self.local_alias}"
        await self.chord_node.replicate_locally(key, vo)
        logging.info(f"[ComputeStakeLedger] store_ledger_in_chord => key={key}, st_count={len(st_map)}, tx_count={len(tx_list)}, ds_stakes={len(ds_stakes)}")

    async def load_ledger_from_chord(self):
        if not self.chord_node:
            logging.warning("[ComputeStakeLedger] no chord_node => skip load_ledger.")
            return
        key = f"stake_ledger_{self.local_alias}"
        vo = self.chord_node.get_local(key)
        if not vo:
            logging.info(f"[ComputeStakeLedger] chord => no ledger => skip => {key}")
            return

        raw_val = vo.value
        if isinstance(raw_val, dict) and raw_val.get("deleted") is True:
            logging.warning(f"[ComputeStakeLedger] chord => tombstone => skip load => {key}")
            return
        if not isinstance(raw_val, str):
            logging.warning(f"[ComputeStakeLedger] chord => data not str => skip => {key}")
            return

        try:
            data = json.loads(raw_val)
        except:
            logging.error("[ComputeStakeLedger] chord => fail parse => skip.")
            return

        st_map = data.get("stake_balance", {})
        tx_list = data.get("stake_txs", [])
        ds_stakes = data.get("dataset_stakes", [])

        conn = sqlite3.connect(self.local_db_path)
        c = conn.cursor()

        # чистим
        c.execute("DELETE FROM stake_balance")
        c.execute("DELETE FROM stake_txs")
        c.execute("DELETE FROM dataset_stakes")

        # stake_balance
        for addr, stval in st_map.items():
            c.execute("INSERT INTO stake_balance(node_id, stake_value) VALUES(?,?)", (addr, float(stval)))

        # stake_txs
        for txd in tx_list:
            stx = StakeTransaction.from_dict(txd)
            c.execute("""
              INSERT INTO stake_txs(tx_id, target_node, amount, timestamp, signature)
              VALUES(?,?,?,?,?)
            """, (stx.tx_id, stx.owner_address, stx.amount, stx.timestamp, stx.signature))

        # dataset_stakes
        if ds_stakes and isinstance(ds_stakes, list):
            for ds_item in ds_stakes:
                ds_id = ds_item["dataset_id"]
                owner_addr = ds_item["node_id"]
                amt = float(ds_item["staked_amount"])
                c.execute("""
                  INSERT INTO dataset_stakes(dataset_id, node_id, staked_amount)
                  VALUES(?,?,?)
                """, (ds_id, owner_addr, amt))

        conn.commit()
        conn.close()

        logging.info(f"[ComputeStakeLedger] load_ledger_from_chord => replaced DB => st_count={len(st_map)}, tx_count={len(tx_list)}, ds_stakes={len(ds_stakes)}")

    async def delete_ledger_in_chord(self):
        if not self.chord_node:
            logging.warning("[ComputeStakeLedger] no chord_node => skip delete.")
            return
        from chordnode import LWWValue
        tomb = {"deleted": True}
        vo = LWWValue(tomb, time.time())
        key = f"stake_ledger_{self.local_alias}"
        await self.chord_node.replicate_locally(key, vo)
        logging.info(f"[ComputeStakeLedger] delete_ledger_in_chord => key={key}, tombstone.")

    # ----------------------------------------------------------------
    # Helpers (чтение tx_list, dataset_stakes напрямую из DB)
    # ----------------------------------------------------------------
    def _get_all_txs_from_db(self) -> List[StakeTransaction]:
        conn = sqlite3.connect(self.local_db_path)
        c = conn.cursor()
        c.execute("SELECT tx_id, target_node, amount, timestamp, signature FROM stake_txs")
        rows = c.fetchall()
        conn.close()
        out = []
        for (tx_id, addr, amt, ts, sig) in rows:
            out.append(StakeTransaction(tx_id, addr, float(amt), float(ts), sig))
        return out

    def _get_dataset_stakes_from_db(self) -> List[Dict[str,Any]]:
        conn = sqlite3.connect(self.local_db_path)
        c = conn.cursor()
        c.execute("SELECT dataset_id, node_id, staked_amount FROM dataset_stakes")
        rows = c.fetchall()
        conn.close()
        out = []
        for (ds_id, owner_addr, amt) in rows:
            out.append({
                "dataset_id": ds_id,
                "node_id": owner_addr,
                "staked_amount": float(amt)
            })
        return out