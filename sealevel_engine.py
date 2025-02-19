import asyncio
import logging
import time
from collections import defaultdict
from typing import Dict, Any, List, Optional, Set

class BaseTransaction:
 
    def __init__(self, tid: str, fee: int = 0, compute_units: int = 0):
        self.tid = tid
        self.fee = fee
        self.compute_units = compute_units

        self.read_keys: Set[str] = set()
        self.write_keys: Set[str] = set()

    async def execute(self, global_state: Dict[str, Any]):
     
        raise NotImplementedError("BaseTransaction.execute(...) not implemented.")


class AdvancedSealevelEngine:
  
    def __init__(
        self,
        max_parallel: int = 0,
        layer_cu_limit: Optional[int] = None,
        use_processes: bool = False
    ):
        
        self.logger = logging.getLogger("AdvSealevelEngine")
        self.global_state: Dict[str, Any] = {}
        self._engine_lock = asyncio.Lock()

        self.max_parallel = max_parallel
        self.layer_cu_limit = layer_cu_limit
        self.use_processes = use_processes
        self._proc_executor = None

        if use_processes:
            import concurrent.futures
            workers = max_parallel if max_parallel > 0 else None
            self._proc_executor = concurrent.futures.ProcessPoolExecutor(workers)

    async def process_batch(self, tx_list: List[BaseTransaction]):
        
        async with self._engine_lock:
            n = len(tx_list)
            if n == 0:
                self.logger.info("[AdvSealevelEngine] process_batch => empty => skip.")
                return

            
            tx_list = sorted(tx_list, key=lambda t: t.fee, reverse=True)

           
           
            adj = [[] for _ in range(n)]
            write_map = defaultdict(list) 

            
            for i, txA in enumerate(tx_list):
                for wkey in txA.write_keys:
                    write_map[wkey].append(i)

           
            for i, txA in enumerate(tx_list):
                conflict_set = set()
                for wkey in txA.write_keys:
                    conflict_set |= set(write_map[wkey])
               
                conflict_set.discard(i)

              
                for j in conflict_set:
                    txB = tx_list[j]
                    if self._is_conflict(txA, txB):
                        adj[i].append(j)
                        adj[j].append(i)

            
            assigned_color = self._graph_coloring(adj)
            max_color = max(assigned_color)
            self.logger.info(f"[AdvSealevelEngine] graph => {n} tx, max_color={max_color}")

           
            
            layers: List[List[int]] = []
            for color_id in range(max_color + 1):
                # все tx с assigned_color == color_id
                same_color = [i for i, c in enumerate(assigned_color) if c == color_id]
                if not same_color:
                    continue

                if not self.layer_cu_limit:
                   
                    layers.append(same_color)
                else:
                   
                    sublayer = []
                    sub_cu = 0
                    for idx in same_color:
                        cu = tx_list[idx].compute_units
                        if sub_cu + cu > self.layer_cu_limit and sublayer:
                           
                            layers.append(sublayer)
                            sublayer = [idx]
                            sub_cu = cu
                        else:
                            sublayer.append(idx)
                            sub_cu += cu
                    if sublayer:
                        layers.append(sublayer)

           
            layer_count = len(layers)
            self.logger.info(f"[AdvSealevelEngine] total_layers={layer_count}, total_tx={n}")

            if self.max_parallel > 0:
                sem = asyncio.Semaphore(self.max_parallel)
            else:
                sem = None

            async def run_tx(tx: BaseTransaction):
                if self._proc_executor:
                    # Запуск в ProcessPool (демо)
                    loop = asyncio.get_running_loop()
                    await loop.run_in_executor(self._proc_executor, self._sync_execute, tx)
                else:
                    
                    if sem:
                        async with sem:
                            await tx.execute(self.global_state)
                    else:
                        await tx.execute(self.global_state)

            for layer_id, subindexes in enumerate(layers):
                sub_txs = [tx_list[i] for i in subindexes]
                self.logger.info(f"[AdvSealevelEngine] layer={layer_id}, tx_count={len(sub_txs)} => run.")

                if sub_txs:
                    await asyncio.gather(*(run_tx(t) for t in sub_txs))

                self.logger.info(f"[AdvSealevelEngine] layer={layer_id} => done => {len(sub_txs)} tx.")

            self.logger.info(f"[AdvSealevelEngine] process_batch => total={n} => used {layer_count} layers.")

    def _is_conflict(self, txA: BaseTransaction, txB: BaseTransaction) -> bool:
        # write-write
        if txA.write_keys & txB.write_keys:
            return True
        # write-read
        if txA.write_keys & txB.read_keys:
            return True
        # read-write
        if txB.write_keys & txA.read_keys:
            return True
        return False

    def _graph_coloring(self, adj: List[List[int]]) -> List[int]:
        
        n = len(adj)
        color_of = [-1]*n
        for i in range(n):
            used = set()
            for nei in adj[i]:
                if color_of[nei] != -1:
                    used.add(color_of[nei])
            c = 0
            while c in used:
                c += 1
            color_of[i] = c
        return color_of

    def _sync_execute(self, tx: BaseTransaction):
        
              
        pass

    async def apply_block(self, tx_list: List[BaseTransaction]):
       
        if not tx_list:
            self.logger.info("[AdvSealevelEngine] apply_block => no tx => skip.")
            return
        self.logger.info(f"[AdvSealevelEngine] apply_block => {len(tx_list)} tx.")
        await self.process_batch(tx_list)
        self.logger.info("[AdvSealevelEngine] apply_block => done.")

    async def stop(self):
       
        self.logger.info("[AdvSealevelEngine] stop => shutting down.")
        if self._proc_executor:
            self._proc_executor.shutdown(wait=True)
            self._proc_executor = None
        self.logger.info("[AdvSealevelEngine] stop => done.")
