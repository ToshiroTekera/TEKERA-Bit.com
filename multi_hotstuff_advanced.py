#multi_hotstuff_advanced.py


import asyncio
import aiosqlite
import logging
import time
import json
import hashlib
from typing import Dict, Any, List, Optional, Set, Tuple
from sealevel_engine import AdvancedSealevelEngine
from multi import MultiSigTransaction

from cryptography.hazmat.primitives import hashes

logging.basicConfig(level=logging.INFO)

PHASE_PREPARE   = "PREPARE"
PHASE_PRECOMMIT = "PRECOMMIT"
PHASE_COMMIT    = "COMMIT"
PHASE_DECIDE    = "DECIDE"

DEFAULT_PROTOCOL_VERSION = "2.0"

class AdvancedBlockStore:
    def __init__(self, db_path: str = "multi_hs_advanced.db", enable_wal: bool = True):
        self.db_path = db_path
        self.enable_wal = enable_wal
        self._db_initialized = False
        self.logger = logging.getLogger("AdvancedBlockStore")

    async def init_db(self):
        if self._db_initialized:
            return
        self.logger.info(f"Initializing DB at {self.db_path}, WAL={self.enable_wal}")
        async with aiosqlite.connect(self.db_path) as db:
            if self.enable_wal:
                await db.execute("PRAGMA journal_mode=WAL;")
            await db.execute("""
            CREATE TABLE IF NOT EXISTS adv_blocks(
                block_id TEXT PRIMARY KEY,
                parent_id TEXT,
                height INTEGER,
                phase TEXT,
                status TEXT,
                data TEXT,
                sum_votes REAL DEFAULT 0,
                partial_sigs TEXT,
                complaints TEXT,
                create_ts REAL,
                final_ts REAL
            )
            """)
            await db.execute("CREATE INDEX IF NOT EXISTS idx_adv_blocks_height ON adv_blocks(height);")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_adv_blocks_parent ON adv_blocks(parent_id);")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_adv_blocks_status ON adv_blocks(status);")
            await db.commit()
        self._db_initialized = True

    async def save_block(self, block_id: str, parent_id: str, height: int, block_data: dict):
        raw_data = json.dumps(block_data, sort_keys=True)
        now_ts = time.time()
        sql = """
          INSERT OR REPLACE INTO adv_blocks(
            block_id, parent_id, height, phase, status, data, create_ts
          ) VALUES(?,?,?,?,?,?,?)
        """
        args = (block_id, parent_id, height, PHASE_PREPARE, "prepare", raw_data, now_ts)
        async with aiosqlite.connect(self.db_path) as db:
            if self.enable_wal:
                await db.execute("PRAGMA journal_mode=WAL;")
            await db.execute(sql, args)
            await db.commit()

    async def update_phase(self, block_id: str, new_phase: str, new_status: str):
        sql = """
          UPDATE adv_blocks
          SET phase=?, status=?
          WHERE block_id=?
        """
        async with aiosqlite.connect(self.db_path) as db:
            if self.enable_wal:
                await db.execute("PRAGMA journal_mode=WAL;")
            await db.execute(sql, (new_phase, new_status, block_id))
            await db.commit()

    async def mark_sum_votes(self, block_id: str, sum_votes: float):
        sql = """
          UPDATE adv_blocks
          SET sum_votes=?
          WHERE block_id=?
        """
        async with aiosqlite.connect(self.db_path) as db:
            if self.enable_wal:
                await db.execute("PRAGMA journal_mode=WAL;")
            await db.execute(sql, (sum_votes, block_id))
            await db.commit()

    async def update_partial_sigs(self, block_id: str, partial_sigs: Dict[str,str]):
        p_js = json.dumps(partial_sigs, sort_keys=True)
        sql = """
          UPDATE adv_blocks
          SET partial_sigs=?
          WHERE block_id=?
        """
        async with aiosqlite.connect(self.db_path) as db:
            if self.enable_wal:
                await db.execute("PRAGMA journal_mode=WAL;")
            await db.execute(sql, (p_js, block_id))
            await db.commit()

    async def update_complaints(self, block_id: str, complaints_list: List[str]):
        c_js = json.dumps(complaints_list, sort_keys=True)
        sql = """
          UPDATE adv_blocks
          SET complaints=?
          WHERE block_id=?
        """
        async with aiosqlite.connect(self.db_path) as db:
            if self.enable_wal:
                await db.execute("PRAGMA journal_mode=WAL;")
            await db.execute(sql, (c_js, block_id))
            await db.commit()

    async def mark_final(self, block_id: str):
        now_ts = time.time()
        sql = """
          UPDATE adv_blocks
          SET phase=?, status='final', final_ts=?
          WHERE block_id=?
        """
        async with aiosqlite.connect(self.db_path) as db:
            if self.enable_wal:
                await db.execute("PRAGMA journal_mode=WAL;")
            await db.execute(sql, (PHASE_DECIDE, now_ts, block_id))
            await db.commit()

    async def load_unfinished_blocks(self) -> Dict[str, dict]:
        out = {}
        sql = """
        SELECT block_id, parent_id, height, phase, status, data, sum_votes, partial_sigs, complaints
        FROM adv_blocks
        WHERE status<>'final'
        """
        async with aiosqlite.connect(self.db_path) as db:
            if self.enable_wal:
                await db.execute("PRAGMA journal_mode=WAL;")
            async with db.execute(sql) as cursor:
                rows = await cursor.fetchall()
        for (bid, par, h, ph, st, raw_d, sumv, ps_js, compl_js) in rows:
            try:
                bd = json.loads(raw_d) if raw_d else {}
            except:
                bd = {}
            try:
                p_sigs = json.loads(ps_js) if ps_js else {}
            except:
                p_sigs = {}
            try:
                c_list = json.loads(compl_js) if compl_js else []
            except:
                c_list = []
            out[bid] = {
                "parent_id": par,
                "height": h,
                "phase": ph,
                "status": st,
                "data": bd,
                "sum_votes": sumv,
                "partial_sigs": p_sigs,
                "complaints": c_list
            }
        return out

    async def load_last_final(self) -> Optional[str]:
        sql = """
          SELECT block_id
          FROM adv_blocks
          WHERE status='final'
          ORDER BY final_ts DESC
          LIMIT 1
        """
        async with aiosqlite.connect(self.db_path) as db:
            if self.enable_wal:
                await db.execute("PRAGMA journal_mode=WAL;")
            async with db.execute(sql) as cursor:
                row = await cursor.fetchone()
        if row:
            return row[0]
        return None


class MultiLeaderHotStuffAdvanced:
    def __init__(
        self, 
        node_id: str,
        stake_ledger,          
        network,               
        all_nodes: List[str],
        cub_tekera=None,
        validator_registry=None,        
        dataset_registry=None,          
        task_registry=None,             
        db_store: Optional[AdvancedBlockStore] = None,
        protocol_version: str = DEFAULT_PROTOCOL_VERSION,
        f: int = 1,
        n: int = 4,
        t: int = 3,
        phase_timeout: float = 5.0,
        poh=None,
        chord_node=None,
        cubic_matrix=None,
        transaction_manager=None,
        key_manager=None                
    ):
        self.node_id = node_id
        self.stake_ledger = stake_ledger
        self.network = network
        self.all_nodes = all_nodes
        self.cub_tekera = cub_tekera

        # Новые поля:
        self.validator_registry = validator_registry
        self.dataset_registry = dataset_registry
        self.task_registry = task_registry
        self.key_manager = key_manager

        self.protocol_version = protocol_version
        self.f = f
        self.n = n
        self.t = t
        self.phase_timeout = phase_timeout
        self.poh = poh
        self.chord_node = chord_node
        self.cubic_matrix = cubic_matrix
        self.sealevel_engine = AdvancedSealevelEngine()
        self.transaction_manager = transaction_manager

        self.block_proposer_task = None
        self.block_proposer_interval = 5.0
        self._proposer_is_running = True
        self.block_counter = 0
        self.global_difficulty = 1

        self.block_store = db_store or AdvancedBlockStore()

        self.threshold_ratio = 2.0 / 3.0
        self.logger = logging.getLogger(f"[MultiAdvHS-{node_id}]")

        self.proposals: Dict[str, Dict[str, Any]] = {}
        self.complaint_count: Dict[str, int] = {}

        self.sign_records = {}
        self.msg_records = {}
        self.my_votes_at_height: Dict[int, str] = {}
        self.locked_block_at_height: Dict[int, str] = {}

        self.current_view = 0
        self.view_change_in_progress = False
        self.view_change_msgs: Dict[int, Dict[str, dict]] = {}
        self.highest_qc: Dict[str, Any] = {"block_id": None, "height": -1, "agg_sig": None}
        self.locked_block = None
        self.timeout_votes = {}
        self.timeout_certificate = {}

        self._initialized = False

    # ----------------------------------------------------------------
    # VALIDATE block_data
    # ----------------------------------------------------------------
    async def _validate_block_data(self, block_data: dict) -> bool:
     
        # 1) stakeTx
        stx_data = block_data.get("stakeTx")
        if stx_data:
            try:
                from compute_stake_ledger import StakeTransaction
                stx = StakeTransaction.from_dict(stx_data)
                if stx.amount <= 0:
                    self.logger.warning("[Validate] StakeTx => amount<=0 => reject")
                    return False
               
                if stx.signature and stx.target_node and self.key_manager:
                    sign_data = {
                        "tx_id": stx.tx_id,
                        "target_node": stx.target_node,
                        "amount": stx.amount,
                        "timestamp": stx.timestamp
                    }
                    if not self.key_manager.verify_transaction(stx.target_node, sign_data, stx.signature):
                        self.logger.warning("[Validate] StakeTx => invalid signature => reject")
                        return False
            except Exception as e:
                self.logger.warning(f"[Validate] StakeTx parse error => {e}")
                return False

        # 2) TekeraTx
        tekera_data = block_data.get("tekeraTx")
        if tekera_data and self.cub_tekera:
            sender = tekera_data.get("sender")
            amt = tekera_data.get("amount_terabit", 0)
            if amt <= 0:
                self.logger.warning("[Validate] TekeraTx => amount<=0 => reject")
                return False
            try:
                bal = await self.cub_tekera.load_balance_of(sender)
            except Exception as e:
                self.logger.warning(f"[Validate] TekeraTx => error loading balance => {e}")
                return False
            if amt > bal and sender != "COINBASE":
                self.logger.warning(f"[Validate] TekeraTx => insufficient: sender={sender}, have={bal}, need={amt}")
                return False
            # Проверка подписи
            tx_id = tekera_data.get("tx_id")
            sign_hex = tekera_data.get("signature")
            if tx_id and sign_hex and sender != "COINBASE" and self.key_manager:
                data_obj = dict(tekera_data)
                data_obj.pop("signature", None)
                if not self.key_manager.verify_transaction(sender, data_obj, sign_hex):
                    self.logger.warning("[Validate] TekeraTx => invalid signature => reject")
                    return False

        # 3) MultiSigTx
        multi_sig_data = block_data.get("multiSigTx")
        if multi_sig_data:
            try:
                from multi import MultiSigTransaction
                mst = MultiSigTransaction.from_dict(multi_sig_data, self.key_manager)
                if not mst.is_valid():
                    self.logger.warning("[Validate] MultiSigTx => not valid => reject")
                    return False
            except Exception as e:
                self.logger.warning(f"[Validate] MultiSig parse error => {e}")
                return False

        # 4) mlRewardTx + mlProof
        ml_reward_tx = block_data.get("mlRewardTx")
        ml_proof = block_data.get("mlProof")
        if ml_reward_tx and ml_proof and self.cub_tekera:
            test_ok = await self._test_ml_reward(ml_reward_tx, ml_proof)
            if not test_ok:
                self.logger.warning("[Validate] mlRewardTx => proof invalid or limit => reject")
                return False

        # ---------------- NEW FIELDS ----------------
        # 5) ValidatorTx
        val_tx = block_data.get("validatorTx")
        if val_tx and self.validator_registry and self.key_manager:
            tx_type = val_tx.get("type")
            node_id = val_tx.get("node_id")
            sig_hex = val_tx.get("signature")
            if not (tx_type and node_id and sig_hex):
                self.logger.warning("[Validate] validatorTx => missing fields => reject")
                return False
            # Проверяем подпись
            sign_data = dict(val_tx)
            sign_data.pop("signature", None)
            ok = self.key_manager.verify_transaction(self.node_id, sign_data, sig_hex)
            if not ok:
                self.logger.warning("[Validate] validatorTx => invalid signature => reject")
                return False
            # Прочие проверки (например, stake_amount>0 при 'validator_join')
            if tx_type == "validator_join":
                st = val_tx.get("stake_amount", 0.0)
                if st <= 0:
                    self.logger.warning("[Validate] validator_join => stake<=0 => reject")
                    return False
            self.logger.info("[Validate] validatorTx => pass")

        # 6) DatasetTx
        ds_tx = block_data.get("datasetTx")
        if ds_tx and self.dataset_registry and self.key_manager:
            tx_type = ds_tx.get("type")
            ds_id   = ds_tx.get("dataset_id")
            sig_hex = ds_tx.get("signature")
            if not (tx_type and ds_id and sig_hex):
                self.logger.warning("[Validate] datasetTx => missing fields => reject")
                return False
            sign_data = dict(ds_tx)
            sign_data.pop("signature", None)
            ok = self.key_manager.verify_transaction(self.node_id, sign_data, sig_hex)
            if not ok:
                self.logger.warning("[Validate] datasetTx => invalid signature => reject")
                return False
            self.logger.info(f"[Validate] datasetTx => type={tx_type}, ds={ds_id} => pass")

        
        task_tx = block_data.get("taskTx")
        if task_tx and self.task_registry and self.key_manager:
            ttype = task_tx.get("type")
            tid   = task_tx.get("task_id")
            s_hex = task_tx.get("signature")
            if not (ttype and tid and s_hex):
                self.logger.warning("[Validate] taskTx => missing fields => reject")
                return False
            # Проверяем подпись
            sign_data = dict(task_tx)
            sign_data.pop("signature", None)
            if not self.key_manager.verify_transaction(self.node_id, sign_data, s_hex):
                self.logger.warning("[Validate] taskTx => invalid signature => reject")
                return False
            self.logger.info(f"[Validate] taskTx => type={ttype}, task_id={tid} => pass")

        
        shard_op = block_data.get("cubic_shard_op")
        if shard_op:
            if "shard_index" not in shard_op:
                self.logger.warning("[Validate] cubic_shard_op => no shard_index => reject")
                return False

        reconfig_data = block_data.get("reconfig")
        if reconfig_data:
            pass  

       
        return True


    # ----------------------------------------------------------------
    # APPLY BLOCK
    # ----------------------------------------------------------------
    async def _apply_block(self, block_id: str, block_data: dict):
        

        # 1) stakeTx
        stx_data = block_data.get("stakeTx")
        if stx_data:
            from compute_stake_ledger import StakeTransaction
            stx = StakeTransaction.from_dict(stx_data)
            self.stake_ledger.apply_stake_tx(stx)
            self.stake_ledger.mark_stake_tx_confirmed(stx.tx_id)

        # 2) TekeraTx
        tekera_data = block_data.get("tekeraTx")
        if tekera_data and self.cub_tekera:
            self.logger.info(f"[Debug] Attempt commit TekeraTx => {tekera_data}")
            await self.cub_tekera._commit_transfer(tekera_data)
            tx_id = tekera_data.get("tx_id")
            if tx_id and self.transaction_manager:
                self.transaction_manager.mark_tx_confirmed(tx_id)

        # 3) MultiSigTx
        multi_sig_data = block_data.get("multiSigTx")
        if multi_sig_data and self.cub_tekera:
            from multi import MultiSigTransaction
            await MultiSigTransaction.commit_multi_sig(multi_sig_data, self.cub_tekera)

        # 4) mlRewardTx
        ml_reward_tx = block_data.get("mlRewardTx")
        ml_proof = block_data.get("mlProof")
        if ml_reward_tx and ml_proof and self.cub_tekera:
            ok = await self.cub_tekera.attempt_ml_reward(ml_reward_tx, ml_proof)
            if not ok:
                self.logger.warning(f"[MultiAdvHS] _apply_block => single mlRewardTx => fail, block={block_id}")
            else:
                c_txid = ml_reward_tx.get("tx_id")
                if c_txid and self.transaction_manager:
                    self.transaction_manager.mark_tx_confirmed(c_txid)

        # ------- NEW: validatorTx ------
        val_tx = block_data.get("validatorTx")
        if val_tx and self.validator_registry:
            await self.validator_registry.apply_validator_tx(val_tx)
            self.logger.info(f"[MultiAdvHS] _apply_block => validatorTx => done => block={block_id}")

        # ------- NEW: datasetTx ------
        ds_tx = block_data.get("datasetTx")
        if ds_tx and self.dataset_registry:
            await self.dataset_registry.apply_dataset_tx(ds_tx)
            self.logger.info(f"[MultiAdvHS] _apply_block => datasetTx => done => block={block_id}")

        # ------- NEW: taskTx ------
        task_tx = block_data.get("taskTx")
        if task_tx and self.task_registry:
            await self.task_registry.apply_task_tx(task_tx)
            self.logger.info(f"[MultiAdvHS] _apply_block => taskTx => done => block={block_id}")

        # 5) reconfig
        reconfig_data = block_data.get("reconfig")
        if reconfig_data:
            self._apply_reconfig(reconfig_data)

        # 6) shard_op
        shard_op = block_data.get("cubic_shard_op")
        if shard_op and self.cubic_matrix:
            idx = shard_op["shard_index"]
            new_data = shard_op["shard_payload"]
            new_ver = shard_op.get("version", 0)
            new_sig = shard_op.get("signature", "")
            self.cubic_matrix.merge_shard_if_newer(idx, new_data, new_ver, new_sig)
            await self.cubic_matrix.store_shard_in_chord(idx)

        # Done
        self.logger.info(f"[MultiAdvHS] block={block_id} => final => done => all ops applied.")

       
        self.block_counter += 1
        if (self.block_counter % 46000) == 0:
            self.global_difficulty += 1
            self.logger.warning(
                f"[MultiAdvHS] Reached block_count={self.block_counter} => global_difficulty={self.global_difficulty}"
            )

    async def _test_ml_reward(self, reward_tx: dict, ml_proof: dict) -> bool:
       
       
        if reward_tx.get("sender") != "COINBASE":
            return False
        amt = reward_tx.get("amount_terabit", 0)
       
        proof_ok = await self.cub_tekera._verify_ml_proof(ml_proof)
        if not proof_ok:
            return False
       
        minted_so_far = await self.cub_tekera._load_minted_total()
        if minted_so_far + amt > self.cub_tekera.max_supply_terabit:
            return False
        return True


    async def propose_block(self, block_data: dict):
        parent_id = block_data.get("parent_id", "")
        height = block_data.get("height", 0)
        block_id = self._make_block_id(block_data)
        
        
        for b_id, prop in self.proposals.items():
            if prop["height"] == height and prop["status"] != "final":
           
                if self.node_id in prop["votes"][PHASE_PREPARE]:
                    self.logger.warning(
                        f"[ProposeBlock] Уже подписан другой блок {b_id} на height={height}, status={prop['status']}."
                        " Пропускаем повторное предложение."
                    )
                    return       

        if block_id in self.proposals:
            self.logger.warning(f"[MultiAdvHS] Block re-propose => {block_id}")
            return

        
        if height in self.locked_block_at_height:
            locked_bid = self.locked_block_at_height[height]
            if locked_bid != parent_id:
                self.logger.warning(
                    f"[MultiAdvHS] Propose conflict => locked another block at height={height}, => viewChange"
                )
                await self._start_view_change(reason="Locked conflict", forced_view=None)
                return

        
        self.proposals[block_id] = {
            "parent_id": parent_id,
            "height": height,
            "phase": PHASE_PREPARE,
            "status": "prepare",
            "data": block_data,
            "complaints": set(),
            "votes": {
                PHASE_PREPARE: {},
                PHASE_PRECOMMIT: {},
                PHASE_COMMIT: {}
            },
            "timeout_task": None,
            "aggregated_sigs": {}
        }

        await self.block_store.save_block(block_id, parent_id, height, block_data)

        # Свой голос
        my_stake = self._get_stake(self.node_id)
        self.proposals[block_id]["votes"][PHASE_PREPARE][self.node_id] = my_stake

        
        msg = {
            "type": "hotstuff_chain_multi",
            "protocol_version": self.protocol_version,
            "phase": PHASE_PREPARE,
            "block_id": block_id,
            "block_data": block_data,
            "view": self.current_view,
            "sender": self.node_id
        }
        
        sig = self.network._sign_message(msg, self.node_id)
        msg["signature"] = sig

        # Для double-sign detection (локально)
        self._record_sign(self.node_id, PHASE_PREPARE, height, block_id, msg, sig)

        # Рассылаем
        await self.network.broadcast_transaction(msg)
        self.logger.info(f"[MultiAdvHS] Propose => block={block_id}, h={height}, view={self.current_view}")

        # Таймер
        self._schedule_timeout(block_id)

        # Проверка кворума (вдруг у нас локально большой stake)
        await self._check_threshold(block_id, PHASE_PREPARE)  
   
   
 
    async def _check_threshold(self, block_id: str, phase: str):
        if block_id not in self.proposals:
            return
        prop = self.proposals[block_id]

        sum_st = sum(prop["votes"][phase].values())
        await self.block_store.mark_sum_votes(block_id, sum_st)

        total = self._total_stake()
        if total <= 0:
            return
        if sum_st < total * self.threshold_ratio:
            return

        # --- PHASE: PREPARE -> PRECOMMIT ---
        if phase == PHASE_PREPARE and prop["phase"] == PHASE_PREPARE:
            
            is_valid = await self._validate_block_data(prop["data"])
            if not is_valid:
                self.logger.warning(f"[HotStuff] Block={block_id} invalid => skip precommit.")
                return

           
            prop["phase"] = PHASE_PRECOMMIT
            prop["status"] = "precommit"
            await self.block_store.update_phase(block_id, PHASE_PRECOMMIT, "precommit")

            h = prop["height"]
            if h > self.highest_qc["height"]:
                self.highest_qc = {"block_id": block_id, "height": h, "agg_sig": b""}

            
            msg = {
                "type": "hotstuff_chain_multi",
                "phase": PHASE_PRECOMMIT,
                "block_id": block_id,
                "view": self.current_view,
                "sender": self.node_id
            }
            s = self.network._sign_message(msg, self.node_id)
            msg["signature"] = s

            await self.network.broadcast_transaction(msg)
            self._schedule_timeout(block_id)

        # --- PHASE: PRECOMMIT -> COMMIT ---
        elif phase == PHASE_PRECOMMIT and prop["phase"] == PHASE_PRECOMMIT:
            # Набрали кворум на PRECOMMIT => переходим в COMMIT
            prop["phase"] = PHASE_COMMIT
            prop["status"] = "commit"
            await self.block_store.update_phase(block_id, PHASE_COMMIT, "commit")

            h = prop["height"]
            self.locked_block_at_height[h] = block_id
            if h > self.highest_qc["height"]:
                self.highest_qc = {"block_id": block_id, "height": h, "agg_sig": b""}

            # Рассылаем COMMIT
            msg = {
                "type": "hotstuff_chain_multi",
                "phase": PHASE_COMMIT,
                "block_id": block_id,
                "view": self.current_view,
                "sender": self.node_id
            }
            s = self.network._sign_message(msg, self.node_id)
            msg["signature"] = s

            await self.network.broadcast_transaction(msg)
            self._schedule_timeout(block_id)

        # --- PHASE: COMMIT -> DECIDE (final) ---
        elif phase == PHASE_COMMIT and prop["phase"] == PHASE_COMMIT:
            prop["phase"] = PHASE_DECIDE
            prop["status"] = "final"
            await self.block_store.mark_final(block_id)

            
            if prop["timeout_task"] and not prop["timeout_task"].done():
                prop["timeout_task"].cancel()

           )
            await self._apply_block(block_id, prop["data"])
            self.logger.info(f"[HotStuff] block={block_id} => final => done")

           
            del self.proposals[block_id]         
 

    def mark_stake_tx_confirmed(self, tx_id: str):
        conn = sqlite3.connect(self.local_db_path)
        c = conn.cursor()
        c.execute("""
          UPDATE stake_txs
          SET status='confirmed'
          WHERE tx_id=? AND status<>'rejected'
        """, (tx_id,))
        conn.commit()
        conn.close()
        logging.info(f"[ComputeStakeLedger] stakeTx={tx_id} => confirmed.")
  
    async def init_state(self):
        if self._initialized:
            return
        await self.block_store.init_db()
        unfin = await self.block_store.load_unfinished_blocks()
        for bid, inf in unfin.items():
            par = inf["parent_id"]
            hh = inf["height"]
            ph = inf["phase"]
            st = inf["status"]
            bd = inf["data"]
            sumv = inf["sum_votes"]
            ps = inf["partial_sigs"]
            cpls = inf["complaints"]

            self.proposals[bid] = {
                "parent_id": par,
                "height": hh,
                "phase": ph,
                "status": st,
                "data": bd,
                "partial_sigs": dict(ps),
                "complaints": set(cpls),
                "votes": {
                    PHASE_PREPARE: {},
                    PHASE_PRECOMMIT: {},
                    PHASE_COMMIT: {}
                },
                "timeout_task": None,
                "aggregated_sigs": {}
            }
            self.logger.info(
                f"Recover block={bid}, p={par}, h={hh}, phase={ph}, status={st}, sum_votes={sumv}"
            )

            if st in ("precommit", "commit") and hh > self.highest_qc["height"]:
                self.highest_qc = {"block_id": bid, "height": hh, "agg_sig": None}
        self._initialized = True

    async def start(self):
        if not self._initialized:
            await self.init_state()
        self.logger.info(f"Node={self.node_id} => start => version={self.protocol_version}")
   
        for bid, prp in self.proposals.items():
            if prp["status"] != "final":
                self._schedule_timeout(bid)
       
       

    async def stop(self):
        self.logger.info(f"Node={self.node_id} => stop.")
    
        self._proposer_is_running = True
        if self.block_proposer_task and not self.block_proposer_task.done():
            self.block_proposer_task.cancel()
        self.block_proposer_task = None

        for bid, prp in self.proposals.items():
            if prp["timeout_task"] and not prp["timeout_task"].done():
                prp["timeout_task"].cancel()

  
    async def maybe_propose_new_block(self):
   
        if not self.transaction_manager:
       
            return
    
        unconf = self.transaction_manager.get_unconfirmed_txs(limit=10)
        if not unconf:
            self.logger.info(f"Found 0 tx => propose empty block on height ?")
            unconf = []
   
        last_bid = self.highest_qc["block_id"] or "GENESIS"
        last_h   = self.highest_qc["height"] or 0

        h_new = last_h + 1
        block_data = {
            "parent_id": last_bid,
            "height": h_new,
            "timestamp": time.time(),
            "tx_list": unconf,  
            
                  
        }

        self.logger.info(f"[maybe_propose_new_block] found {len(unconf)} tx => propose block h={h_new}")
   
        await self.propose_block(block_data)

    def _apply_reconfig(self, rc_data: dict):
        add_list = rc_data.get("add_nodes", [])
        remove_list = rc_data.get("remove_nodes", [])
        slash_list = rc_data.get("slash_nodes", [])

        for s in slash_list:
            self.logger.warning(f"Slash node={s}")
            self.stake_ledger.slash_stake(s)
            if s in self.pub_keys:
                self.pub_keys.pop(s, None)
            if s in self.all_nodes:
                self.all_nodes.remove(s)

        for r in remove_list:
            if r in self.all_nodes:
                self.all_nodes.remove(r)
            if r in self.pub_keys:
                self.pub_keys.pop(r, None)

        for a in add_list:
            self.logger.info(f"Add node={a}, pubkey must be added externally.")
            if a not in self.all_nodes:
                self.all_nodes.append(a)

        # Пересчитываем n,f,t
        self.n = len(self.all_nodes)
        self.f = (self.n - 1) // 3
        # t (порог BLS) = f+1 или вручную
        self.t = self.f + 1
        self.logger.warning(f"[Reconfig] new n={self.n}, f={self.f}, t={self.t}")

    def _make_block_id(self, block_data: dict) -> str:
        raw = json.dumps(block_data, sort_keys=True)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    # ----------------------------------------------------------------
    # HANDLE PHASE MESSAGE
    # ----------------------------------------------------------------


    async def handle_phase_message(self, data: dict, sender_id: str):
        ph = data.get("phase", "")
        block_id = data.get("block_id", "")
        bdata = data.get("block_data")
        msg_view = data.get("view", 0)

        # Если (msg_view < self.current_view), 
        if msg_view < self.current_view:
            return

        # Для double-sign detection
        height = bdata.get("height", 0) if bdata else 0
        signature = data.get("signature", "")
        self._record_sign(sender_id, ph, height, block_id, data, signature)

       
        if block_id not in self.proposals:
            if ph == PHASE_PREPARE and bdata:
                # Проверяем lock
                if height in self.locked_block_at_height:
                    if self.locked_block_at_height[height] != bdata.get("parent_id"):
                        self.logger.warning("Lock conflict => viewchange.")
                        await self._start_view_change(reason="Locked mismatch", forced_view=None)
                        return

              
                self.proposals[block_id] = {
                    "parent_id": bdata.get("parent_id",""),
                    "height": height,
                    "phase": PHASE_PREPARE,
                    "status": "prepare",
                    "data": bdata,
                    "partial_sigs": {},
                    "complaints": set(),
                    "votes": {
                        PHASE_PREPARE: {},
                        PHASE_PRECOMMIT: {},
                        PHASE_COMMIT: {}
                    },
                    "timeout_task": None,
                    "aggregated_sigs": {}
                }
                await self.block_store.save_block(block_id, bdata.get("parent_id",""), height, bdata)
                self._schedule_timeout(block_id)
            else:
                
                return

       
        prop = self.proposals[block_id]
        stv = self._get_stake(sender_id)

       
        if sender_id == self.node_id and ph in (PHASE_PREPARE, PHASE_PRECOMMIT, PHASE_COMMIT):
            old_block = self.my_votes_at_height.get(height)
            if old_block and old_block != block_id:
                self.logger.warning(
                    f"[DoubleSignPrevent] Ignoring block={block_id} at height={height}, "
                    f"already voted for {old_block}"
                )
                return
            
            self.my_votes_at_height[height] = block_id
  

        if ph == PHASE_PREPARE:
            prop["votes"][PHASE_PREPARE][sender_id] = stv
            await self._check_threshold(block_id, PHASE_PREPARE)

        elif ph == PHASE_PRECOMMIT:
            if prop["phase"] not in (PHASE_PRECOMMIT, PHASE_PREPARE):
                self.logger.warning("Out-of-order PRECOMMIT => complaint.")
                await self._issue_complaint(block_id, f"OutOfOrder precommit from {sender_id}")
                return
            prop["votes"][PHASE_PRECOMMIT][sender_id] = stv
            await self._check_threshold(block_id, PHASE_PRECOMMIT)

        elif ph == PHASE_COMMIT:
            if prop["phase"] not in (PHASE_COMMIT, PHASE_PRECOMMIT):
                self.logger.warning("Out-of-order COMMIT => complaint.")
                await self._issue_complaint(block_id, f"OutOfOrder commit from {sender_id}")
                return
            prop["votes"][PHASE_COMMIT][sender_id] = stv
            await self._check_threshold(block_id, PHASE_COMMIT)

        elif ph == "timeout_partial":
            await self._handle_timeout_partial(data, sender_id)

        elif ph == "hotstuff_view_change":
            await self._handle_view_change_message(data, sender_id)

        elif ph == "hotstuff_new_view":
            await self._handle_new_view_message(data, sender_id)

        elif ph == "hotstuff_chain_complaint":
            await self.handle_complaint_message(data, sender_id)

        else:
            self.logger.warning(f"Unknown hotstuff phase={ph} => skip.")


    def _schedule_timeout(self, block_id: str):
        if block_id not in self.proposals:
            return
        p = self.proposals[block_id]
        if p["timeout_task"] and not p["timeout_task"].done():
            p["timeout_task"].cancel()

        async def on_timeout():
            try:
                await asyncio.sleep(self.phase_timeout)
                if block_id not in self.proposals:
                    return
                if self.proposals[block_id]["status"] == "final":
                    return
                ph = self.proposals[block_id]["phase"]
                self.logger.warning(f"Timeout block={block_id}, phase={ph} => broadcast partial timeout.")
                await self._broadcast_timeout_partial()
            except asyncio.CancelledError:
                pass

        p["timeout_task"] = asyncio.create_task(on_timeout())


    async def _broadcast_timeout_partial(self):
        # Если уже есть TimeoutCertificate на текущий view, то не дублируем.
        if self.timeout_certificate.get(self.current_view):
            return

        msg = {
            "type": "hotstuff_chain_multi",
            "phase": "timeout_partial",
            "view": self.current_view,
            "sender": self.node_id
        }
        sig = self.network._sign_message(msg, self.node_id)
        msg["signature"] = sig

        await self.network.broadcast_transaction(msg)
        self.logger.warning(f"[BroadcastTimeoutPartial] => node={self.node_id}, view={self.current_view}")


    async def _handle_timeout_partial(self, data: dict, sender_id: str):
        view_num = data.get("view", 0)
        if view_num < self.current_view:
            return

        if view_num not in self.timeout_votes:
            self.timeout_votes[view_num] = {}

        if sender_id in self.timeout_votes[view_num]:
            return

        signature = data.get("signature", "")
        self.timeout_votes[view_num][sender_id] = signature

        self.logger.info(
            f"[TimeoutPartial] node={sender_id}, view={view_num}, count={len(self.timeout_votes[view_num])}"
        )

        if len(self.timeout_votes[view_num]) >= (2*self.f + 1):
            self.timeout_certificate[view_num] = {
                "signatures": dict(self.timeout_votes[view_num]),
                "count": len(self.timeout_votes[view_num]),
                "created_at": time.time()
            }
            self.logger.warning(
                f"[TimeoutCertificate] => view={view_num}, start ViewChange => forced_view={view_num + 1}"
            )
            await self._start_view_change(
                reason=f"TimeoutCertificate at view={view_num}",
                forced_view=view_num + 1
            )


    async def _issue_complaint(self, block_id: str, reason: str):
        msg = {
            "type": "hotstuff_chain_complaint",
            "protocol_version": self.protocol_version,
            "block_id": block_id,
            "reason": reason,
            "phase": "hotstuff_chain_complaint",
            "view": self.current_view,
            "sender": self.node_id
        }
        sg = self.network._sign_message(msg, self.node_id)
        msg["signature"] = sg

        await self.network.broadcast_transaction(msg)
        self.logger.warning(f"Complaint => block={block_id}, reason={reason}")

    async def handle_complaint_message(self, data: dict, sender_id: str):
        bid = data.get("block_id", "")
        rsn = data.get("reason", "")
        self.logger.warning(f"Got complaint => block={bid}, from={sender_id}, reason={rsn}")

   
        if bid in self.proposals:
            self.proposals[bid]["complaints"].add(sender_id)
            clist = list(self.proposals[bid]["complaints"])
            await self.block_store.update_complaints(bid, clist)

        # Если это double-sign proof => проверяем
        if "double-sign" in rsn and "/ proof=" in rsn:
            try:
                splitted = rsn.split("/ proof=",1)
                proof_json = splitted[1].strip()
                proof_obj = json.loads(proof_json)
                if self._verify_double_sign_proof(proof_obj):
                    mal = proof_obj.get("malicious_node")
                    self._punish_malicious(mal)
            except:
                pass

  
        if " from " in rsn:
            arr = rsn.split(" from ")
            if len(arr) >= 2:
                nd = arr[1].strip()
                cnt = self.complaint_count.get(nd, 0) + 1
                self.complaint_count[nd] = cnt
                if cnt >= self.f + 1:
                    self.logger.warning(f"Slashing node={nd} => by majority complaints.")
                    self.stake_ledger.slash_stake(nd)

        if bid in self.proposals:
            self.proposals[bid]["complaints"].add(sender_id)
            clist = list(self.proposals[bid]["complaints"])
            await self.block_store.update_complaints(bid, clist)


    def _punish_malicious(self, node_id: str):
        self.logger.warning(f"Punish malicious node={node_id}")
        self.stake_ledger.slash_stake(node_id)
        if node_id in self.pub_keys:
            self.pub_keys.pop(node_id, None)
        if node_id in self.all_nodes:
            self.all_nodes.remove(node_id)


    def _record_sign(self, sender_id: str, phase: str, height: int,
                     block_id: str, raw_msg: dict, signature: str):
        self.msg_records[(sender_id, block_id, phase)] = (raw_msg, signature)
        key = (sender_id, phase, height)
        exist = self.sign_records.get(key)
        if not exist:
            self.sign_records[key] = (block_id, raw_msg, signature)
            return
        old_bid, old_msg, old_sig = exist
        if old_bid == block_id:
            return
        # double-sign
        self.logger.warning(f"[DoubleSign] node={sender_id}, old_block={old_bid}, new_block={block_id}, phase={phase}")
        oldp, olds = self.msg_records.get((sender_id, old_bid, phase), (None, None))
        newp, news = self.msg_records.get((sender_id, block_id, phase), (None, None))
        proof = {
            "phase": phase,
            "height": height,
            "malicious_node": sender_id,
            "blockA_id": old_bid,
            "blockA_msg": oldp or {},
            "blockA_sig": olds or "",
            "blockB_id": block_id,
            "blockB_msg": newp or {},
            "blockB_sig": news or ""
        }
        reason = f"double-sign from {sender_id} at height={height} / proof={json.dumps(proof, sort_keys=True)}"
        asyncio.create_task(self._issue_complaint(block_id, reason))

    async def _start_view_change(self, reason: str, forced_view: Optional[int]):
        if self.view_change_in_progress:
            self.logger.warning("ViewChange already in progress => skip.")
            return

        old_view = self.current_view
        new_view = forced_view if forced_view is not None else (old_view + 1)
        self.current_view = new_view
        self.view_change_in_progress = True

        locked_h = -1
        locked_bid = None
        if self.locked_block_at_height:
            locked_h = max(self.locked_block_at_height.keys())
            locked_bid = self.locked_block_at_height[locked_h]

        self.logger.warning(f"[ViewChange] reason={reason}, {old_view}=>{new_view}, locked={locked_bid}")

        msg = {
            "type": "hotstuff_chain_multi",
            "phase": "hotstuff_view_change",
            "protocol_version": self.protocol_version,
            "view": new_view,
            "locked_height": locked_h,
            "locked_block_id": locked_bid,
            "reason": reason,
            "sender": self.node_id
        }
        s = self.network._sign_message(msg, self.node_id)
        msg["signature"] = s

        if new_view not in self.view_change_msgs:
            self.view_change_msgs[new_view] = {}
        self.view_change_msgs[new_view][self.node_id] = {
            "locked_height": locked_h,
            "locked_block_id": locked_bid,
            "signature": s
        }

        await self.network.broadcast_transaction(msg)
        await self._try_form_new_view(new_view)


    async def _handle_view_change_message(self, data: dict, sender_id: str):
        view_num = data.get("view", 0)
        locked_h = data.get("locked_height", -1)
        locked_bid = data.get("locked_block_id", None)
        reason = data.get("reason","")

        if view_num < self.current_view:
            return

        if view_num not in self.view_change_msgs:
            self.view_change_msgs[view_num] = {}
        self.view_change_msgs[view_num][sender_id] = {
            "locked_height": locked_h,
            "locked_block_id": locked_bid,
            "signature": data.get("signature","")
        }

        self.logger.info(f"view_change from={sender_id}, view={view_num}, locked={locked_bid}, reason={reason}")
        await self._try_form_new_view(view_num)


    async def _try_form_new_view(self, view_num: int):
        if view_num < self.current_view:
            return
        if view_num not in self.view_change_msgs:
            return

        vc_data = self.view_change_msgs[view_num]
        if len(vc_data) < (2*self.f + 1):
            return

        # Собрали 2f+1 => формируем hotstuff_new_view
        highest_h = -1
        highest_bid = None
        for nd, info in vc_data.items():
            lh = info["locked_height"]
            lbid = info["locked_block_id"]
            if lh > highest_h:
                highest_h = lh
                highest_bid = lbid

        msg = {
            "type": "hotstuff_chain_multi",
            "phase": "hotstuff_new_view",
            "protocol_version": self.protocol_version,
            "view": view_num,
            "highest_locked_height": highest_h,
            "highest_locked_block": highest_bid,
            "vc_proofs": {},
            "sender": self.node_id
        }

        # При желании добавить первые 2f+1 подписей
        c = 0
        for nd,inf in vc_data.items():
            if c<(2*self.f+1):
                msg["vc_proofs"][nd] = {
                    "locked_height": inf["locked_height"],
                    "locked_block_id": inf["locked_block_id"],
                    "signature": inf["signature"]
                }
                c+=1

        sg = self.network._sign_message(msg, self.node_id)
        msg["signature"] = sg

        await self.network.broadcast_transaction(msg)
        self.logger.warning(f"[TryFormNewView] => broadcast hotstuff_new_view, view={view_num}, locked={highest_bid}")

        self.view_change_in_progress = False

        # Если мы лидер => предлагаем новый блок
        leader = self._get_leader_for_view(view_num)
        if leader == self.node_id:
            # parent=locked_bid, height=highest_h+1
            h = highest_h+1 if highest_h>=0 else 1
            parent = highest_bid or "GENESIS"
            new_data = {
                "parent_id": parent,
                "height": h,
                "view": view_num,
                "payload": f"NewView block from {self.node_id}"
            }
            await self.propose_block(new_data)


    async def _handle_new_view_message(self, data: dict, sender_id: str):
        view_num = data.get("view",0)
        hh = data.get("highest_locked_height", -1)
        hb = data.get("highest_locked_block", None)
        if view_num < self.current_view:
            return

        self.current_view = view_num
        self.view_change_in_progress = False
        self.logger.warning(f"Got new_view => from={sender_id}, view={view_num}, locked={hb}, locked_h={hh}")

        # (опционально) вычищаем старые пропозалы
        for b_id in list(self.proposals.keys()):
            old_view = self.proposals[b_id]["data"].get("view", 0)
            if old_view < self.current_view and self.proposals[b_id]["status"] != "final":
                self.logger.warning(f"[ViewChange CleanUp] removing old proposal block={b_id}, view={old_view}")
                del self.proposals[b_id]

 
    def _get_leader_for_view(self, view_num: int) -> str:
        if not self.all_nodes:
            return self.node_id
        idx = view_num % len(self.all_nodes)
        return self.all_nodes[idx]

    def _get_node_index(self, node_id: str)->int:
        if node_id in self.all_nodes:
            return self.all_nodes.index(node_id)
        return 0

    def _my_index(self)->int:
        return self._get_node_index(self.node_id)

    def _total_stake(self)->float:
        return self.stake_ledger.total_stake()

    def _get_stake(self, node_id: str)->float:
        return self.stake_ledger.get_stake(node_id)


