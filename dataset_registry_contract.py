import aiosqlite
import time
import logging
from typing import Optional, Dict, Any

logging.basicConfig(level=logging.INFO)

class DatasetRegistryContract:

    def __init__(
        self,
        stake_ledger,            
        cub_tekera,              
        db_path: str = "dataset_registry.db",
        min_stake_required: float = 10.0,
        max_baseline_acc: float = 0.90
    ):
        """
        :param stake_ledger: экземпляр ComputeStakeLedger
        :param cub_tekera:   экземпляр CubTekera (с полем self.address)
        :param db_path:      путь к SQLite для хранения dataset_registry
        :param min_stake_required: минимально допустимый stake, TEKERA
        :param max_baseline_acc:   если baseline_acc > этого порога => reject
        """
        self.stake_ledger = stake_ledger
        self.cub_tekera = cub_tekera
        self.db_path = db_path
        self.min_stake_required = min_stake_required
        self.max_baseline_acc = max_baseline_acc

        self.logger = logging.getLogger("DatasetRegistryContract")
        self._db_initialized = False

    async def init_db(self):
    
        if self._db_initialized:
            return
        self.logger.info(f"[DatasetRegistry] init_db => {self.db_path}")
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("PRAGMA journal_mode=WAL;")
            # owner_address храним как текст (например, "addr_abc123...").
            await db.execute("""
            CREATE TABLE IF NOT EXISTS dataset_registry(
                dataset_id TEXT PRIMARY KEY,
                owner_address TEXT NOT NULL,
                stake_amount REAL NOT NULL,   -- TEKERA
                status TEXT NOT NULL,
                baseline_acc REAL NOT NULL DEFAULT 0,
                created_ts REAL NOT NULL
            )
            """)
            await db.commit()
        self._db_initialized = True


    async def mark_dataset_mined(self, dataset_id: str, final_acc: float) -> bool:
  
        await self.init_db()
        async with aiosqlite.connect(self.db_path) as db:
            row = await db.execute_fetchone(
                """
                SELECT owner_address, stake_amount, status
                FROM dataset_registry
                WHERE dataset_id=?
                """,
                (dataset_id,)
            )
            if not row:
                self.logger.warning(f"[DatasetRegistry] mark_dataset_mined => ds={dataset_id} not found => skip.")
                return False

            (owner_addr, stake_amt, old_status) = row
            if old_status not in ("approved", "proposed"):
                self.logger.warning(f"[DatasetRegistry] ds={dataset_id}, status={old_status} => skip mining_proved.")
                return False

            # Проверка acc >0.99 или <0.80 => suspicious => частично слэшим
            if final_acc > 0.99 or final_acc < 0.80:
                self.logger.warning(
                    f"[DatasetRegistry] ds={dataset_id}, final_acc={final_acc} => suspicious => slash or skip."
                )
                
                await self.slash_dataset(dataset_id, slash_ratio=0.5,
                                         reason="Trivial or worthless dataset in mining")
                return False

            # Если всё норм => ставим статус='mining_proved' (пример)
            await db.execute(
                "UPDATE dataset_registry SET status='mining_proved' WHERE dataset_id=?",
                (dataset_id,)
            )
            await db.commit()

        self.logger.info(f"[DatasetRegistry] ds={dataset_id} => mining_proved => final_acc={final_acc}")
        return True


    async def propose_dataset(self, dataset_id: str, owner_address: str, stake_amount_tekera: float) -> bool:
       
        await self.init_db()

       
        if stake_amount_tekera < self.min_stake_required:
            self.logger.warning(
                f"[DatasetRegistry] propose_dataset => stake={stake_amount_tekera} < min={self.min_stake_required}"
            )
            return False

        
        if owner_address != self.cub_tekera.address:
            self.logger.warning(
                f"[DatasetRegistry] propose_dataset => mismatch address => given={owner_address}, "
                f"but cub_tekera.address={self.cub_tekera.address} => skip."
            )
            return False

        
        async with aiosqlite.connect(self.db_path) as db:
            row = await db.execute_fetchone(
                "SELECT dataset_id FROM dataset_registry WHERE dataset_id=?",
                (dataset_id,)
            )
        if row:
            self.logger.warning(f"[DatasetRegistry] dataset_id={dataset_id} exists => skip propose.")
            return False

        
        stake_amount_terabit = int(stake_amount_tekera * self.cub_tekera.TEKERA_TO_TERABIT)
        ok = await self.cub_tekera.stake_dataset(dataset_id, stake_amount_terabit)
        if not ok:
            self.logger.warning("[DatasetRegistry] propose_dataset => stake_dataset failed => stop.")
            return False

        
        now_ts = time.time()
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
            INSERT INTO dataset_registry(dataset_id, owner_address, stake_amount, status, baseline_acc, created_ts)
            VALUES(?,?,?,?,?,?)
            """, (dataset_id, owner_address, stake_amount_tekera, "proposed", 0.0, now_ts))
            await db.commit()

        self.logger.info(
            f"[DatasetRegistry] proposed => ds={dataset_id}, owner={owner_address}, stake={stake_amount_tekera}"
        )
        return True

  
    async def approve_dataset(self, dataset_id: str) -> bool:
      
        await self.init_db()
        async with aiosqlite.connect(self.db_path) as db:
            row = await db.execute_fetchone(
                """
                SELECT owner_address, stake_amount, status, baseline_acc
                FROM dataset_registry
                WHERE dataset_id=?
                """,
                (dataset_id,)
            )
            if not row:
                self.logger.warning(f"[DatasetRegistry] approve_dataset => ds={dataset_id} not found => skip.")
                return False

            (owner_addr, stake_amt, old_status, bacc) = row
            if old_status in ("approved", "slashed", "rejected", "closed"):
                self.logger.warning(
                    f"[DatasetRegistry] ds={dataset_id} => status={old_status} => skip approve."
                )
                return False

            if bacc > self.max_baseline_acc:
                
                self.logger.warning(
                    f"[DatasetRegistry] ds={dataset_id}, baseline_acc={bacc} > max={self.max_baseline_acc} => REJECT"
                )
                await db.execute(
                    "UPDATE dataset_registry SET status='rejected' WHERE dataset_id=?",
                    (dataset_id,)
                )
                await db.commit()
                return False

            
            await db.execute(
                "UPDATE dataset_registry SET status='approved' WHERE dataset_id=?",
                (dataset_id,)
            )
            await db.commit()

        self.logger.info(f"[DatasetRegistry] APPROVED => ds={dataset_id}")
        return True

  
    async def slash_dataset(self, dataset_id: str, slash_ratio: float=1.0, reason: str="fake") -> bool:
      
        if slash_ratio <= 0:
            self.logger.warning(f"[DatasetRegistry] slash_dataset => ratio={slash_ratio} <=0 => skip.")
            return False

        await self.init_db()
        async with aiosqlite.connect(self.db_path) as db:
            row = await db.execute_fetchone(
                """
                SELECT owner_address, stake_amount, status
                FROM dataset_registry
                WHERE dataset_id=?
                """,
                (dataset_id,)
            )
            if not row:
                self.logger.warning(f"[DatasetRegistry] slash_dataset => ds={dataset_id} not found => skip.")
                return False

            (owner_addr, stake_amt, old_status) = row
            if old_status == "slashed":
                self.logger.warning(f"[DatasetRegistry] ds={dataset_id} => already slashed => skip.")
                return False

            # partial slash ?
            if slash_ratio < 1.0:
                # Узнаём, сколько реально застейкано
                staked_full = self.stake_ledger.get_dataset_stake_amount(dataset_id, owner_addr)
                slash_amt = staked_full * slash_ratio

                self.logger.warning(
                    f"[DatasetRegistry] partial slash => ds={dataset_id}, ratio={slash_ratio}, slash_amt={slash_amt}, reason={reason}"
                )

                
                self.stake_ledger.unstake_dataset_amount(dataset_id, owner_addr, staked_full)
              

                new_stake = stake_amt * (1 - slash_ratio)
                await db.execute(
                    "UPDATE dataset_registry SET stake_amount=?, status='slashed' WHERE dataset_id=?",
                    (new_stake, dataset_id)
                )
            else:
                # Full slash
                self.stake_ledger.slash_dataset_stake(dataset_id)  # Обнуляет stake (в ledger)
                await db.execute(
                    "UPDATE dataset_registry SET stake_amount=0, status='slashed' WHERE dataset_id=?",
                    (dataset_id,)
                )

            await db.commit()

        self.logger.warning(f"[DatasetRegistry] slash_dataset => ds={dataset_id}, ratio={slash_ratio}, reason={reason}")
        return True

    # ---------------------------------------------------------
    # 4) return_stake
    # ---------------------------------------------------------
    async def return_stake(self, dataset_id: str) -> bool:
 
        await self.init_db()
        async with aiosqlite.connect(self.db_path) as db:
            row = await db.execute_fetchone(
                """
                SELECT owner_address, stake_amount, status
                FROM dataset_registry
                WHERE dataset_id=?
                """,
                (dataset_id,)
            )
            if not row:
                self.logger.warning(f"[DatasetRegistry] return_stake => ds={dataset_id} not found => skip.")
                return False
            (owner_addr, stake_amt, old_status) = row
            if old_status not in ("approved","proposed"):
                self.logger.warning(
                    f"[DatasetRegistry] return_stake => ds={dataset_id}, status={old_status} => skip."
                )
                return False

            
            ok = await self.cub_tekera.unstake_dataset(dataset_id)
            if not ok:
                self.logger.warning(f"[DatasetRegistry] return_stake => ds={dataset_id}, fail on unstake.")
                return False

            # Обновляем в локальной БД
            await db.execute(
                "UPDATE dataset_registry SET status='closed' WHERE dataset_id=?",
                (dataset_id,)
            )
            await db.commit()

        self.logger.info(f"[DatasetRegistry] return_stake => ds={dataset_id}, => closed => done.")
        return True

    # ---------------------------------------------------------
    # 5) set_baseline_acc
    # ---------------------------------------------------------
    async def set_baseline_acc(self, dataset_id: str, baseline_acc: float) -> bool:
        await self.init_db()
        async with aiosqlite.connect(self.db_path) as db:
            row = await db.execute_fetchone(
                "SELECT dataset_id FROM dataset_registry WHERE dataset_id=?",
                (dataset_id,)
            )
            if not row:
                self.logger.warning(f"[DatasetRegistry] set_baseline_acc => no dataset => {dataset_id}")
                return False
            await db.execute(
                "UPDATE dataset_registry SET baseline_acc=? WHERE dataset_id=?",
                (baseline_acc, dataset_id)
            )
            await db.commit()
        self.logger.info(f"[DatasetRegistry] ds={dataset_id}, baseline_acc={baseline_acc}")
        return True

    # ---------------------------------------------------------
    # 6) is_approved
    # ---------------------------------------------------------
    async def is_approved(self, dataset_id: str) -> bool:
        await self.init_db()
        async with aiosqlite.connect(self.db_path) as db:
            row = await db.execute_fetchone(
                "SELECT status FROM dataset_registry WHERE dataset_id=?",
                (dataset_id,)
            )
        if row and row[0] == "approved":
            return True
        return False

    # ---------------------------------------------------------
    # 7) get_dataset_info + list_datasets
    # ---------------------------------------------------------
    async def get_dataset_info(self, dataset_id: str) -> Optional[Dict[str,Any]]:
        await self.init_db()
        async with aiosqlite.connect(self.db_path) as db:
            row = await db.execute_fetchone(
                """
                SELECT owner_address, stake_amount, status, baseline_acc, created_ts
                FROM dataset_registry
                WHERE dataset_id=?
                """,
                (dataset_id,)
            )
        if not row:
            return None
        (addr, st_amt, st, bacc, cts) = row
        return {
            "dataset_id": dataset_id,
            "owner_address": addr,
            "stake_amount": st_amt,
            "status": st,
            "baseline_acc": bacc,
            "created_ts": cts
        }

    async def list_datasets(self) -> Dict[str,Dict[str,Any]]:
        await self.init_db()
        out = {}
        async with aiosqlite.connect(self.db_path) as db:
            rows = await db.execute_fetchall("""
                SELECT dataset_id, owner_address, stake_amount, status, baseline_acc, created_ts
                FROM dataset_registry
            """)
        for ds_id,addr,st_amt,st,bacc,cts in rows:
            out[ds_id] = {
                "owner_address": addr,
                "stake_amount": st_amt,
                "status": st,
                "baseline_acc": bacc,
                "created_ts": cts
            }
        return out
