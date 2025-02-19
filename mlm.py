import logging
import asyncio
import uuid
import numpy as np
import os
import json
import time
from typing import Any, Optional, Dict, List
from collections import defaultdict
import random
from numpy import ndarray

logging.basicConfig(level=logging.INFO)


from mltrainer import MLTrainer, Task
from tranmen import TransactionManager
from networknod import NodeNetwork
from chordnode import ChordNode
from POH import ProofOfHistory
from dataset_registry_contract import DatasetRegistryContract
from tekeracub import CubTekera
from real_datasets import RealDatasets


class MiningModule:
    def __init__(
        self,
        node_id: str,
        ml_trainer: MLTrainer,
        tx_manager: TransactionManager,
        network: NodeNetwork,
        poh: Optional[ProofOfHistory] = None,
        chord_node: Optional[ChordNode] = None,
        data_file: str = "mining_module.json",
        ephemeral_mode: bool = False,
        encrypt_data: bool = False,
        passphrase: Optional[str] = None,
        max_concurrent_train: int = 2,
        partial_steps: int = 3,
        hotstuff_consensus=None,
        dataset_registry: Optional[DatasetRegistryContract] = None,
        cub_tekera: Optional[CubTekera] = None,
    ):
        self.node_id = node_id
        self.ml_trainer = ml_trainer
        self.tx_manager = tx_manager
        self.network = network
        self.poh = poh
        self.chord_node = chord_node
        self.hotstuff = hotstuff_consensus
        self.jackpot_terabit = 1_000_000_000_000  # 1000 TEKERA
        self.partial_terabit = 4_000_000_000_000  # 4000 TEKERA

        # Храним задачи, результаты, секретные тесты
        self.active_tasks: Dict[str, Task] = {}
        self.task_shares = defaultdict(lambda: defaultdict(float))
        self.task_winner: Dict[str, Optional[str]] = {}
        # NOTE: У каждого узла — свой X_secret_test (здесь храним)!
        self.secret_tests: Dict[str, dict] = {}
        self.pending_solutions: Dict[str, dict] = {}

        self._lock = asyncio.Lock()

        self.data_file = data_file
        self.ephemeral_mode = ephemeral_mode
        self.encrypt_data = encrypt_data and (not ephemeral_mode)
        self.secret_key: Optional[bytes] = None
        if passphrase and self.encrypt_data:
            self.secret_key = self._derive_key_from_passphrase(passphrase)

        self._train_sema = (
            asyncio.Semaphore(max_concurrent_train) if max_concurrent_train > 0 else None
        )

        self.logger = logging.getLogger(f"MiningModule-{node_id}")
        self.subscribed = False
        self.partial_steps = partial_steps

        self.dataset_registry = dataset_registry
        self.cub_tekera = cub_tekera

       
        self.real_ds = RealDatasets()

        if not ephemeral_mode:
            self._load_local_data()
        else:
            self.logger.warning("[MiningModule] ephemeral_mode => skip load from disk.")

    async def start(self):
        
        if not self.subscribed:
            self.subscribed = True
            if hasattr(self.network, "on_message_callbacks"):
                self.network.on_message_callbacks.append(self.on_network_message)
        self.logger.info(f"[MiningModule] started => node={self.node_id}")

    async def stop(self):
        """Остановка MiningModule (с сохранением данных, если нужно)."""
        self.logger.info(f"[MiningModule] stop => node={self.node_id}")
        if not self.ephemeral_mode:
            self._save_local_data()

    async def run_mining_loop(self):
        
        while True:
            try:
                # Пример: создаём задачу (датасет iris)
                task = self.generate_task(
                    task_type="classification",
                    test_threshold=0.8,
                    shard_index=0,
                    shard_size=50,
                    dataset_id="iris"
                )
                if task:
                    self.logger.info(f"[MiningModule] run_mining_loop => created task={task.task_id}")

                    all_peers = list(self.network.connections.keys())
                    subset_size = min(len(all_peers), 20)
                    recipients = (
                        random.sample(all_peers, subset_size)
                        if subset_size > 0 else []
                    )
                    if recipients:
                        self.logger.info(f"[MiningModule] run_mining_loop => distributing => {recipients}")
                        await self.distribute_task(task, recipients)

                    # Запускаем локальное обучение
                    await self._solve_local_task(task)

                await asyncio.sleep(60.0)

            except asyncio.CancelledError:
                self.logger.info("[MiningModule] run_mining_loop => cancelled => exit.")
                break
            except Exception as e:
                self.logger.error(f"[MiningModule] run_mining_loop => error => {e}")
                await asyncio.sleep(5.0)

    def generate_task(
        self,
        task_type="classification",
        test_threshold: float = 0.8,
        shard_index: int = 0,
        shard_size: int = 300,
        dataset_id: Optional[str] = None
    ) -> Optional[Task]:
       
        if not dataset_id:
            self.logger.warning("[MiningModule] generate_task => no dataset_id => skip => no reward.")
            return None

        
        if self.dataset_registry:
            loop = asyncio.get_event_loop()
            approved = loop.run_until_complete(self.dataset_registry.is_approved(dataset_id))
            if not approved:
                self.logger.warning(f"[MiningModule] generate_task => dataset={dataset_id} not approved => skip.")
                return None

        task_id = f"ml_{uuid.uuid4().hex}"
        if task_type != "classification":
            self.logger.warning("[MiningModule] generate_task => only classification logic => skip.")
            return None

        
        try:
            real_data = self.real_ds.get_dataset_shard(dataset_id, shard_index, shard_size)
        except ValueError as ex:
            self.logger.error(f"[MiningModule] real dataset error => {ex} => skip.")
            return None

        data_dict = {
            "X_train": real_data["X_train"],
            "y_train": real_data["y_train"],
            "X_val":   real_data["X_val"],
            "y_val":   real_data["y_val"],
            "target_acc": test_threshold
        }

       
        t = Task(
            task_id=task_id,
            data=data_dict,
            task_type="classification",
            difficulty=5
        )

        
        X_val = data_dict["X_val"]
        y_val = data_dict["y_val"]
        n = min(20, len(y_val))
        idx = np.random.choice(len(y_val), n, replace=False)
        X_test = X_val[idx]
        y_test = y_val[idx]

        
        self.secret_tests[task_id] = {
            "X_test": X_test,
            "y_test": y_test,
            "threshold": test_threshold,
            "dataset_id": dataset_id
        }

        self.active_tasks[task_id] = t
        self.logger.info(f"[MiningModule] generate_task => {task_id}, ds={dataset_id}, thr={test_threshold}")
        return t

    async def distribute_task(self, task: Task, recipients: List[str]):
        
        data_obj = {}
        if isinstance(task.data, dict):
            for k, v in task.data.items():
                if isinstance(v, ndarray):
                    data_obj[k] = v.tolist()
                else:
                    data_obj[k] = v
            data_obj["task_type"] = task.task_type
            data_obj["difficulty"] = task.difficulty
        else:
            data_obj = {}

        msg = {
            "type": "ml_task",
            "task_id": task.task_id,
            "task_data": data_obj,
            "sender": self.node_id
        }
        for rid in recipients:
            await self.network.send_transaction(msg, rid)
        self.logger.info(f"[MiningModule] distribute_task => {task.task_id} => recips={recipients}")

    def on_network_message(self, msg: dict):
        
        mtype = msg.get("type")
        if mtype == "ml_task":
            asyncio.create_task(self._handle_incoming_task(msg))
        elif mtype == "ml_partial_solution":
            asyncio.create_task(self._handle_incoming_partial(msg))
        elif mtype == "ml_solution":
            asyncio.create_task(self._handle_incoming_solution(msg))
        elif mtype == "ml_challenge_response":
            asyncio.create_task(self._handle_challenge_response(msg))
        elif mtype == "ml_challenge":
            asyncio.create_task(self._handle_challenge(msg))
        else:
            self.logger.debug(f"[MiningModule] unknown msg => {mtype}")

    async def _handle_incoming_task(self, msg: dict):
    
        task_id = msg.get("task_id")
        sender = msg.get("sender")
        task_data = msg.get("task_data", {})

        if not task_id:
            self.logger.warning("[MiningModule] incoming_task => no task_id => skip.")
            return

        t = self._build_task_from_dict(task_id, task_data)

        async with self._lock:
            self.active_tasks[task_id] = t

        self.logger.info(f"[MiningModule] got ml_task={task_id} from sender={sender}")

        
        await self._solve_local_task(t)

    async def _handle_incoming_partial(self, msg: dict):
        """Учтём частичный результат обучения (acc) от какого-то узла."""
        task_id = msg.get("task_id")
        sender = msg.get("sender")
        if not task_id or not sender:
            self.logger.warning("[MiningModule] partial => missing => skip.")
            return

        acc = msg.get("accuracy", 0.0)
        epoch = msg.get("epoch", 0)
        async with self._lock:
            if task_id not in self.active_tasks:
                self.logger.warning(f"[MiningModule] partial => unknown task={task_id}")
                return
            self.task_shares[task_id][sender] += acc

        self.logger.info(f"[MiningModule] partial => task={task_id}, from={sender}, ep={epoch}, acc={acc}")

    async def _handle_incoming_solution(self, msg: dict):
        
        task_id = msg.get("task_id")
        solver = msg.get("solver_node")
        result = msg.get("result")
        if not task_id or not solver:
            self.logger.warning("[MiningModule] ml_solution => missing => skip.")
            return

        async with self._lock:
            if task_id not in self.active_tasks:
                self.logger.warning(f"[MiningModule] no active task => {task_id}")
                return
            if (task_id in self.task_winner) and (self.task_winner[task_id] is not None):
                self.logger.info(f"[MiningModule] solution => but task={task_id} already has winner => skip.")
                return

            self.pending_solutions[task_id] = {
                "solver": solver,
                "result": result
            }

        
        cmsg = {
            "type": "ml_challenge",
            "task_id": task_id,
            "note": "Please provide predictions on secret test",
            "sender": self.node_id
        }

        
        if task_id in self.secret_tests:
            secret_data = self.secret_tests[task_id]
            X_secret_list = secret_data["X_test"].tolist()  # numpy => list
            cmsg["X_secret_test"] = X_secret_list
            self.logger.info(f"[MiningModule] adding X_secret_test => len={len(X_secret_list)}")
        else:
            
            self.logger.warning("[MiningModule] no X_secret_test => sending empty => likely no reward.")
            cmsg["X_secret_test"] = []

        await self.network.send_transaction(cmsg, solver)
        self.logger.info(
            f"[MiningModule] challenge => solver={solver}, task={task_id}, X_test_size={len(cmsg['X_secret_test'])}"
        )

    async def _handle_challenge(self, msg: dict):
       
        self.logger.info(f"[MiningModule] handle ml_challenge => {msg}")

        task_id = msg.get("task_id")
        sender = msg.get("sender")
        if not task_id or not sender:
            self.logger.warning("[MiningModule] _handle_challenge => no task_id or sender => skip.")
            return

        if task_id not in self.active_tasks:
            self.logger.warning(f"[MiningModule] _handle_challenge => unknown task={task_id}")
            return

        sol_data = self.pending_solutions.get(task_id)
        if not sol_data or ("result" not in sol_data):
            self.logger.warning(f"[MiningModule] no model_state => using random predictions => task={task_id}")
            model_state = None
        else:
            model_state = sol_data["result"]

        X_test = msg.get("X_secret_test")
        if not X_test:
            X_test = []
            self.logger.warning("[MiningModule] no X_secret_test => fallback empty list")

        predictions = []
        if model_state and hasattr(self.ml_trainer, "predict"):
            # Если массив непустой, вызываем predict
            if len(X_test) > 0:
                arr = np.array(X_test, dtype=np.float32)
                predictions = self.ml_trainer.predict(model_state, arr)
            else:
                
                predictions = []
        else:
            
            if len(X_test) > 0:
                predictions = np.random.randint(0, 3, size=len(X_test)).tolist()
            else:
                predictions = []

        
        resp_msg = {
            "type": "ml_challenge_response",
            "task_id": task_id,
            "predictions": predictions,
            "sender": self.node_id
        }
        self.logger.info(f"[MiningModule] sending ml_challenge_response => to={sender}, task={task_id}")
        await self.network.send_transaction(resp_msg, sender)

    async def _handle_challenge_response(self, msg: dict):
       
        task_id = msg.get("task_id")
        solver = msg.get("sender")
        preds = msg.get("predictions", [])
        if not task_id or not solver:
            self.logger.warning("[MiningModule] challenge_resp => missing => skip.")
            return

        async with self._lock:
            if task_id not in self.secret_tests:
                self.logger.warning(f"[MiningModule] no secret test => {task_id}")
                return
            st = self.secret_tests[task_id]

        X_test = st["X_test"]
        y_test = st["y_test"]
        thr = st["threshold"]
        dataset_id = st.get("dataset_id")

        if len(preds) != len(y_test):
            self.logger.warning("[MiningModule] challenge => mismatch => no reward.")
            return

        correct = sum(1 for i in range(len(y_test)) if preds[i] == y_test[i])
        acc = correct / len(y_test)
        self.logger.info(f"[MiningModule] challenge => solver={solver}, final acc={acc:.3f}, need>={thr}")

        # Если acc > 0.99 => считаем датасет подозрительным
        if acc > 0.99 and self.dataset_registry and dataset_id:
            self.logger.warning(f"[MiningModule] dataset={dataset_id} => suspicious => slash!")
            await self.dataset_registry.slash_dataset(dataset_id, reason="Trivial dataset => acc>0.99")

        if acc < thr:
            self.logger.warning("[MiningModule] challenge => fail => no reward.")
            return

        
        async with self._lock:
            sol_data = self.pending_solutions.get(task_id)
            if (not sol_data) or (sol_data["solver"] != solver):
                self.logger.warning("[MiningModule] mismatch solver => skip.")
                return
            self.task_winner[task_id] = solver

        self.logger.info(f"[MiningModule] challenge => solver={solver} => success! acc={acc:.3f}")

        
        if self.hotstuff:
            
            parent_bid = self.hotstuff.highest_qc.get("block_id") or "GENESIS"
            parent_h   = self.hotstuff.highest_qc.get("height", 0)
            new_h = parent_h + 1

            reward_tx_id = f"ml_reward_{task_id}_{int(time.time())}"
            block_data = {
                "parent_id": parent_bid,
                "height": new_h,
                "timestamp": time.time(),
                # Сам reward:
                "mlRewardTx": {
                    "sender":        "COINBASE",
                    "receiver":      solver,
                    "amount_terabit": self.jackpot_terabit,
                    "tx_id":         reward_tx_id
                },
                
                "mlProof": {
                    "task_id":  task_id,
                    "accuracy": acc,
                    "comment":  "ML-challenge success"
                }
            }
            self.logger.info(
                f"[MiningModule] Proposing HotStuff block => reward solver={solver}, block_height={new_h}"
            )
            try:
                await self.hotstuff.propose_block(block_data)
            except Exception as e:
                self.logger.error(f"[MiningModule] propose_block error => {e}, fallback => _give_jackpot.")
                await self._give_jackpot(task_id, solver)
        else:
            
            self.logger.info("[MiningModule] no hotstuff => fallback => direct _give_jackpot.")
            await self._give_jackpot(task_id, solver)

        
           await self._distribute_partial(task_id)   

    def _build_task_from_dict(self, task_id: str, data_dict: dict) -> Task:
        
        ttype = data_dict.get("task_type", "classification")
        diff = data_dict.get("difficulty", 5)
        if ttype == "classification":
            local_d = {}
            for k, v in data_dict.items():
                if k in ["X_train", "y_train", "X_val", "y_val"]:
                    local_d[k] = np.array(v)
                else:
                    local_d[k] = v
            return Task(task_id=task_id, data=local_d, task_type=ttype, difficulty=diff)
        else:
            return Task(task_id=task_id, data={}, task_type=ttype, difficulty=diff)

    async def _solve_local_task(self, t: Task):
        """Запускаем локальную (partial) тренировку задачи."""
        if self._train_sema:
            async with self._train_sema:
                await self._do_train_multistep(t)
        else:
            await self._do_train_multistep(t)

    async def _do_train_multistep(self, t: Task):
        
        if t.task_type != "classification":
            self.logger.warning(f"[MiningModule] only classification => skip => {t.task_id}")
            return

        X_train = t.data["X_train"].astype(np.float32)
        y_train = t.data["y_train"].astype(np.int32)
        total_epochs = self.ml_trainer.epochs
        step_ep = max(1, total_epochs // self.partial_steps)

        model_state = None
        accum = 0.0
        for step_i in range(1, self.partial_steps + 1):
            try:
                out = await self.ml_trainer.train_partial(
                    X_train, y_train,
                    epochs=step_ep,
                    initial_state=model_state,
                    task_id=t.task_id
                )
                model_state = out["state"]
                acc = out["accuracy"]
                lo = out["loss"]
                accum += acc
                self.logger.info(
                    f"[MiningModule] partial => step={step_i}/{self.partial_steps}, acc={acc:.3f}, loss={lo:.3f}"
                )
                
                pmsg = {
                    "type": "ml_partial_solution",
                    "task_id": t.task_id,
                    "sender": self.node_id,
                    "epoch": step_i,
                    "accuracy": float(acc),
                    "loss": float(lo)
                }
                await self.network.broadcast_transaction(pmsg)
            except Exception as e:
                self.logger.error(f"[MiningModule] do_train_multistep => {e}")
                return

        
        final_msg = {
            "type": "ml_solution",
            "task_id": t.task_id,
            "solver_node": self.node_id,
            "result": model_state
        }
        await self.network.broadcast_transaction(final_msg)
        self.logger.info(
            f"[MiningModule] final local => {t.task_id}, total partialAcc={accum/self.partial_steps:.3f}"
        )

    async def _give_jackpot(self, task_id: str, solver: str):
       
        tinfo = self.active_tasks.get(task_id)
        if not tinfo:
            return

       
        if self.cub_tekera:
            try:
                await self.cub_tekera.propose_transfer_bft(self.jackpot_terabit, solver)
                self.logger.info(
                    f"[MiningModule] jackpot => solver(address)={solver}, amt={self.jackpot_terabit} => via CubTekera(BFT)"
                )
                if self.poh:
                    ev = {
                        "type": "mining_jackpot",
                        "task_id": task_id,
                        "winner": solver,
                        "amount_terabit": self.jackpot_terabit,
                        "timestamp": time.time()
                    }
                    await self.poh.record_event(ev)

            except Exception as e:
                self.logger.error(f"[MiningModule] _give_jackpot => cub_tekera => error => {e}, fallback old approach.")
                await self._fallback_txmgr_jackpot(task_id, solver)
        else:
            # fallback
            await self._fallback_txmgr_jackpot(task_id, solver)

        #
        await self._distribute_partial(task_id)

    async def _fallback_txmgr_jackpot(self, task_id: str, solver: str):
        
        try:
            txid = await self.tx_manager.propose_ml_reward(
                solver_id=solver,
                reward_terabit=self.jackpot_terabit,
                proof_data={"reason": "jackpot", "task_id": task_id}
            )
            if txid:
                self.logger.info(
                    f"[MiningModule] jackpot => solver={solver}, amt={self.jackpot_terabit}, tx_id={txid}"
                )
                if self.poh:
                    ev = {
                        "type": "mining_jackpot",
                        "task_id": task_id,
                        "winner": solver,
                        "amount_terabit": self.jackpot_terabit,
                        "timestamp": time.time()
                    }
                    await self.poh.record_event(ev)
            else:
                self.logger.warning("[MiningModule] jackpot => propose_jackpot => no tx_id")
        except Exception as e:
            self.logger.error(f"[MiningModule] jackpot => error => {e}")

    async def _distribute_partial(self, task_id: str):
        share_map = self.task_shares.get(task_id)
        if not share_map:
            self.logger.info(f"[MiningModule] partial => no shares => skip => {task_id}")
            return

        total_sh = sum(share_map.values())
        if total_sh <= 0:
            self.logger.info(f"[MiningModule] partial => zero sum => skip => {task_id}")
            return

        partial_pool = self.partial_terabit
        for nd, sh in share_map.items():
            portion = int((sh / total_sh) * partial_pool)
            if portion <= 0:
                continue

        
            if self.cub_tekera:
                try:
                    await self.cub_tekera.propose_transfer_bft(portion, nd)
                    self.logger.info(f"[MiningModule] partial => node={nd}, portion={portion} => via CubTekera.")
                    if self.poh:
                        ev = {
                            "type": "mining_partial_reward",
                            "task_id": task_id,
                            "node_id": nd,
                            "portion": portion,
                            "shares": sh,
                            "timestamp": time.time()
                        }
                        await self.poh.record_event(ev)
                    continue  # успешно => переходим к следующему узлу
                except Exception as e:
                    self.logger.error(f"[MiningModule] partial => fail cubTekera => {e} => fallback tx_manager")
       
            try:
           
                ptx = await self.tx_manager.propose_ml_reward(
                    solver_id=nd,
                    reward_terabit=portion,
                    proof_data={"reason": "partial", "task_id": task_id}
                )
                if ptx:
                    self.logger.info(f"[MiningModule] partial => node={nd}, portion={portion}, tx_id={ptx}")
                    if self.poh:
                        ev = {
                            "type": "mining_partial_reward",
                            "task_id": task_id,
                            "node_id": nd,
                            "portion": portion,
                            "shares": sh,
                            "timestamp": time.time()
                        }
                        await self.poh.record_event(ev)
                else:
                    self.logger.warning(f"[MiningModule] partial => propose_ml_reward fail => {nd}")
            except Exception as e:
                self.logger.error(f"[MiningModule] partial => node={nd}, e={e}")
    
        del self.task_shares[task_id]  
   
    async def store_mining_data_in_chord(self):
        
        if not self.chord_node:
            self.logger.warning("[MiningModule] no chord => skip store.")
            return
        obj = {
            "task_shares": {},
            "active_tasks": {}
        }
        for tid, mp in self.task_shares.items():
            obj["task_shares"][tid] = dict(mp)
        for tid, tv in self.active_tasks.items():
            obj["active_tasks"][tid] = {
                "task_type": tv.task_type,
                "difficulty": tv.difficulty
            }
        val_js = json.dumps(obj, sort_keys=True)
        from chordnode import LWWValue
        vo = LWWValue(val_js, time.time())
        key = f"mining_module_{self.node_id}"
        await self.chord_node.replicate_locally(key, vo)
        self.logger.info(f"[MiningModule] store_mining_data_in_chord => {key}")

    async def load_mining_data_from_chord(self):
        
        if not self.chord_node:
            self.logger.warning("[MiningModule] no chord => skip.")
            return
        key = f"mining_module_{self.node_id}"
        vo = self.chord_node.get_local(key)
        if not vo:
            self.logger.info("[MiningModule] chord => no data => skip.")
            return
        if isinstance(vo.value, dict) and vo.value.get("deleted") is True:
            self.logger.warning("[MiningModule] chord => tombstone => skip.")
            return
        if not isinstance(vo.value, str):
            self.logger.warning("[MiningModule] chord => not str => skip.")
            return
        try:
            data = json.loads(vo.value)
        except:
            self.logger.error("[MiningModule] chord => parse fail => skip.")
            return

        tsh = data.get("task_shares", {})
        for tid, mp in tsh.items():
            self.task_shares[tid] = defaultdict(float, mp)

        atv = data.get("active_tasks", {})
        for tid, tinfo in atv.items():
            tk = Task(
                task_id=tid,
                data={},
                task_type=tinfo.get("task_type", "classification"),
                difficulty=tinfo.get("difficulty", 5)
            )
            self.active_tasks[tid] = tk

        self.logger.info("[MiningModule] load_mining_data_from_chord => done")

    async def delete_mining_data_in_chord(self):
        
        if not self.chord_node:
            self.logger.warning("[MiningModule] no chord => skip delete.")
            return
        from chordnode import LWWValue
        tomb = {"deleted": True}
        vo = LWWValue(tomb, time.time())
        key = f"mining_module_{self.node_id}"
        await self.chord_node.replicate_locally(key, vo)
        self.logger.info(f"[MiningModule] delete_mining_data_in_chord => {key} => tombstone")

    def _save_local_data(self):
       
        if self.ephemeral_mode:
            return
        out = {
            "task_shares": {},
            "active_tasks": {}
        }
        for tid, mp in self.task_shares.items():
            out["task_shares"][tid] = dict(mp)
        for tid, tv in self.active_tasks.items():
            out["active_tasks"][tid] = {
                "task_type": tv.task_type,
                "difficulty": tv.difficulty
            }
        try:
            js = json.dumps(out, indent=2)
            raw = js.encode("utf-8")
            if self.encrypt_data and self.secret_key:
                raw = self._aes_encrypt(raw)
            tmp_path = self.data_file + ".tmp"
            with open(tmp_path, "wb") as f:
                f.write(raw)
            os.replace(tmp_path, self.data_file)
            self.logger.info(f"[MiningModule] saved => {self.data_file}, enc={self.encrypt_data}")
        except Exception as e:
            self.logger.error(f"[MiningModule] _save_local_data => {e}")

    def _load_local_data(self):
       
        if not os.path.isfile(self.data_file):
            self.logger.info(f"[MiningModule] no file => skip => {self.data_file}")
            return
        try:
            with open(self.data_file, "rb") as f:
                raw = f.read()
            if self.encrypt_data and self.secret_key:
                raw = self._aes_decrypt(raw)
            js_str = raw.decode("utf-8")
            data = json.loads(js_str)

            tsh = data.get("task_shares", {})
            for tid, mp in tsh.items():
                self.task_shares[tid] = defaultdict(float, mp)

            for tid, tinfo in data.get("active_tasks", {}).items():
                tk = Task(
                    task_id=tid,
                    data={},
                    task_type=tinfo.get("task_type", "classification"),
                    difficulty=tinfo.get("difficulty", 5)
                )
                self.active_tasks[tid] = tk

            self.logger.info(f"[MiningModule] loaded => tasks={len(self.active_tasks)}")
        except Exception as e:
            self.logger.error(f"[MiningModule] load error => {e}")

    def _aes_encrypt(self, plain: bytes) -> bytes:
       
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aes = AESGCM(self.secret_key)
        nonce = os.urandom(12)
        return nonce + aes.encrypt(nonce, plain, None)

    def _aes_decrypt(self, enc: bytes) -> bytes:
       
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aes = AESGCM(self.secret_key)
        if len(enc) < 12:
            raise ValueError("encrypted data too short")
        nonce = enc[:12]
        cipher = enc[12:]
        return aes.decrypt(nonce, cipher, None)

    def _derive_key_from_passphrase(self, passphrase: str) -> bytes:
       
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        salt = (self.node_id + "_mining_module").encode("utf-8")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000
        )
        return kdf.derive(passphrase.encode("utf-8"))
