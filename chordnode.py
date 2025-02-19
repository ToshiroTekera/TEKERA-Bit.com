import logging
import asyncio
import json
import hashlib
import random
import time
import os
from typing import Optional, Dict, Tuple, List, Any

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def sha1_hash(value: str) -> int:
    return int(hashlib.sha1(value.encode('utf-8')).hexdigest(), 16)

class LWWValue:
    """
    CRDT (Last-Write-Wins) значение: (value, ts).
    """
    __slots__ = ('value','ts')

    def __init__(self, value: Any, ts: float):
        self.value = value
        self.ts = ts

    def to_dict(self) -> dict:
        return {"value": self.value, "ts": self.ts}

    @staticmethod
    def from_dict(d: dict) -> "LWWValue":
        return LWWValue(d["value"], d["ts"])


class ChordNode:
 
    RPC_TIMEOUT = 20.0
    BAN_DURATION = 120.0
    TTL_FIND_SUCCESSOR = 15.0
    DEFAULT_GOSSIP_PROB = 0.4


    def __init__(
        self,
        my_address: str,
        replication_factor: int = 1,
        m_bits: int = 10,
        data_file: Optional[str] = None,
        stabilize_interval: float = 5.0,
        resync_interval: float = 25.0,
        max_predecessors: int = 2,
        max_successors: int = 3,
        rejoin_on_failure: bool = True,
        gossip_interval: float = 10.0
    ):
        self.my_address = my_address
        self.my_hash = sha1_hash(my_address)
        self.replication_factor = replication_factor
        self.m_bits = m_bits
        self.ring_size = 2 ** m_bits

        self.data_store: Dict[str, LWWValue] = {}

        self.predecessors: List[Tuple[str, int]] = []
        self.max_predecessors = max_predecessors

        self.successors: List[Tuple[str,int]] = [(self.my_address, self.my_hash)] * max_successors
        self.max_successors = max_successors

        self.fingers: List[Tuple[int, str, int]] = []

        self.ban_list: Dict[str, float] = {}
        self.seen_nodes: Dict[str, float] = {}

        self.data_file = data_file or f"chord_{my_address}.json"
        self._data_lock = asyncio.Lock()

       
        self.network = None
        self._bg_task: Optional[asyncio.Task] = None
        self._stop_bg = False

        self._stabilize_interval = stabilize_interval
        self._resync_interval = resync_interval
        self._iteration_counter = 0
        self._rejoin_on_failure = rejoin_on_failure

        self._gossip_interval = gossip_interval
        self._last_gossip_time = 0.0
        self._last_big_change = 0.0

        # Кэш для find_successor
        self._fs_cache: Dict[int, Tuple[str,int,float]] = {}

        logger.info(
            f"[ChordNode] init => address={my_address}, hash={self.my_hash}, "
            f"rep={replication_factor}, m_bits={m_bits}, st={stabilize_interval}, rejoin={rejoin_on_failure}"
        )
        self._load_data()

    def set_network(self, network):             
        self.network = network    
        if network is not None:
            network.chord_node = self

        logger.info(f"[ChordNode {self.my_address}] set_network => done")

 
    def _is_self(self, addr: str) -> bool:
        return (addr == self.my_address)

    async def join(self, other_address: Optional[str] = None):
       
        if (other_address is None) or self._is_self(other_address):
            self.predecessors.clear()
            self.successors = [(self.my_address, self.my_hash)] * self.max_successors
            self.fingers.clear()
            logger.info(f"[ChordNode {self.my_address}] single-node ring => no join needed.")
            return

        if self.is_banned(other_address):
            logger.warning(
                f"[ChordNode {self.my_address}] join => target {other_address} is banned => skip."
            )
            return

        if (self.network is None) or (other_address not in self.network.connections):
            logger.warning(
                f"[ChordNode {self.my_address}] join => address={other_address} not in network => abort."
            )
            return

        try:
            # RPC: find_successor(my_hash)
            s_addr, s_hash = await asyncio.wait_for(
                self.network.send_chord_find_successor(other_address, self.my_hash),
                timeout=self.RPC_TIMEOUT
            )
        except asyncio.TimeoutError:
            logger.error(f"[ChordNode {self.my_address}] join => Timeout from {other_address}")
            return
        except Exception as e:
            logger.error(f"[ChordNode {self.my_address}] join => error => {e}")
            self.ban_node(other_address)
            return

        self.predecessors.clear()
        self.successors[0] = (s_addr, s_hash)
        for i in range(1, self.max_successors):
            self.successors[i] = (self.my_address, self.my_hash)

        self.fingers.clear()
        self._last_big_change = time.time()
        logger.info(
            f"[ChordNode {self.my_address}] => joined => successor={self.successors[0]}"
        )

        await self.init_finger_table()
        await self.stabilize()
        await self.fix_fingers()

    # ----------------------------------------------------------------
    # FIND SUCCESSOR
    # ----------------------------------------------------------------
    async def chord_find_successor(self, hkey: int) -> Tuple[str,int]:
       
        now = time.time()
        # Кэш
        if hkey in self._fs_cache:
            (sid,sh,exp) = self._fs_cache[hkey]
            if now < exp:
              
                if self._in_range(hkey, self.my_hash, self.successors[0][1], inclusive=True):
                    return self.successors[0]
                return (sid, sh)

       
        if self._in_range(hkey, self.my_hash, self.successors[0][1], inclusive=True):
            self._update_cache(hkey, self.successors[0])
            return self.successors[0]

       
        cf = self.closest_preceding_finger(hkey)
        if cf[0] == self.my_address:
            self._update_cache(hkey, self.successors[0])
            return self.successors[0]

        # RPC
        if self._is_self(cf[0]):
            return self.successors[0]

        try:
            ret_addr, ret_hash = await asyncio.wait_for(
                self.network.send_chord_find_successor(cf[0], hkey),
                timeout=self.RPC_TIMEOUT
            )
            self._update_cache(hkey, (ret_addr, ret_hash))
            return (ret_addr, ret_hash)
        except Exception as e:
            logger.error(f"[ChordNode {self.my_address}] chord_find_successor => error => {e}")
            return self.successors[0]

    def _update_cache(self, hkey: int, successor: Tuple[str,int]):
        now = time.time()
        self._fs_cache[hkey] = (successor[0], successor[1], now + self.TTL_FIND_SUCCESSOR)
        logger.debug(f"[ChordNode {self.my_address}] _update_cache => hkey={hkey}, succ={successor}")

    def closest_preceding_finger(self, hkey: int) -> Tuple[str,int]:
        for i in reversed(range(len(self.fingers))):
            (_, f_addr, f_hash) = self.fingers[i]
            if self._in_range(f_hash, self.my_hash, hkey):
                return (f_addr, f_hash)
        return self.successors[0]

    # ----------------------------------------------------------------
    # chord_notify
    # ----------------------------------------------------------------
    async def chord_notify(self, pred_address: str, pred_hash: int):
        if self._is_self(pred_address):
            return
        if self.is_banned(pred_address):
            return

        existing = [p for p in self.predecessors if p[0] == pred_address]
        if not existing:
            self.predecessors.append((pred_address, pred_hash))
            self.predecessors = sorted(self.predecessors, key=lambda x:x[1])[:self.max_predecessors]
            logger.info(f"[ChordNode {self.my_address}] chord_notify => add predecessor={pred_address}")

        if (not self.predecessors) or (self.predecessors[0][0] == pred_address):
            await self._transfer_keys_to_predecessor(pred_address, pred_hash)

    async def _transfer_keys_to_predecessor(self, pred_addr: str, pred_hash: int):
        if self._is_self(pred_addr):
            return
        start_h = pred_hash
        end_h   = self.my_hash
        to_transfer = []
        async with self._data_lock:
            for k,v in self.data_store.items():
                kh = sha1_hash(k)
                if not self._in_range(kh, start_h, end_h, inclusive=True):
                    to_transfer.append((k,v))
        if not to_transfer:
            return
        c=0
        for (k,v) in to_transfer:
            try:
                await asyncio.wait_for(
                    self.network.send_chord_store_req(pred_addr, k, v),
                    timeout=self.RPC_TIMEOUT
                )
                c+=1
            except:
                pass
        if c>0:
            async with self._data_lock:
                for (k,_) in to_transfer:
                    self.data_store.pop(k, None)
        logger.info(
            f"[ChordNode {self.my_address}] => transferred {c} keys => pred={pred_addr}"
        )

    # ----------------------------------------------------------------
    # Store + replicate
    # ----------------------------------------------------------------
    async def chord_store_req(self, key: str, val_dict: dict):
        val_obj = LWWValue.from_dict(val_dict)
        async with self._data_lock:
            old = self.data_store.get(key)
            if (not old) or (val_obj.ts > old.ts):
                self.data_store[key] = val_obj
                logger.debug(f"[ChordNode {self.my_address}] chord_store_req => key={key}, ts={val_obj.ts}")
                col = self.check_key_collisions()
                if col:
                    logger.warning(
                        f"[ChordNode {self.my_address}] collisions => {col}"
                    )
            else:
                logger.debug(f"[ChordNode {self.my_address}] chord_store_req => older => skip key={key}")

    async def replicate_locally(self, key: str, val_obj: LWWValue):
        async with self._data_lock:
            old = self.data_store.get(key)
            if (not old) or (val_obj.ts>old.ts):
                self.data_store[key] = val_obj
                col = self.check_key_collisions()
                if col:
                    logger.warning(
                        f"[ChordNode {self.my_address}] collisions => {col}"
                    )

        if self.replication_factor <=1 or not self.network:
            await self._save_data()
            return

        replic=1
        for i in range(1, self.max_successors):
            s = self.successors[i]
            if s[0] == self.my_address:
                break
            try:
                await asyncio.wait_for(
                    self.network.send_chord_store_req(s[0], key, val_obj),
                    timeout=self.RPC_TIMEOUT
                )
                replic+=1
                if replic>=self.replication_factor:
                    break
            except:
                pass
        logger.info(f"[ChordNode {self.my_address}] replicate_locally => key={key}, total replicas={replic}")
        await self._save_data()

    def get_local(self, key: str) -> Optional[LWWValue]:
        return self.data_store.get(key)

    # ----------------------------------------------------------------
    # init_finger_table / fix_fingers
    # ----------------------------------------------------------------
    async def init_finger_table(self):
        self.fingers.clear()
        for i in range(self.m_bits):
            start_h = (self.my_hash + 2**i) % self.ring_size
            s_addr, s_hash = await self.chord_find_successor(start_h)
            self.fingers.append((start_h, s_addr, s_hash))
        self._last_big_change = time.time()
        logger.debug(
            f"[ChordNode {self.my_address}] init_finger_table => {len(self.fingers)} entries"
        )

    async def fix_fingers(self):
        if (time.time() - self._last_big_change)<5:
            return
        if not self.fingers:
            return
        i = random.randint(0, self.m_bits-1)
        start_h = (self.my_hash + 2**i) % self.ring_size
        s_addr, s_hash = await self.chord_find_successor(start_h)
        self.fingers[i] = (start_h, s_addr, s_hash)
        logger.debug(f"[ChordNode {self.my_address}] fix_fingers => i={i}, succ={s_addr}")

    # ----------------------------------------------------------------
    # STABILIZE
    # ----------------------------------------------------------------
    async def stabilize(self):
        alive_succ = []
        for s in self.successors:
            if s[0] == self.my_address:
                alive_succ.append(s)
            else:
                if await self._ping_node(s[0]):
                    alive_succ.append(s)

        if not alive_succ:
            logger.warning(f"[ChordNode {self.my_address}] all successors dead => check rejoin.")
            if self._rejoin_on_failure and (len(self.seen_nodes)>0):
                await self._attempt_rejoin()
            else:
                self.successors = [(self.my_address, self.my_hash)]*self.max_successors
            return

        self.successors = alive_succ + [(self.my_address,self.my_hash)]*self.max_successors
        self.successors = self.successors[: self.max_successors]

        main_succ = self.successors[0]
        if main_succ[0] != self.my_address:
            try:
                await self.network.send_chord_notify(main_succ[0], self.my_address, self.my_hash)
            except:
                pass

        now = time.time()
        if (now - self._last_gossip_time) > self._gossip_interval:
            if random.random() < self.DEFAULT_GOSSIP_PROB:
                await self._gossip_fingers()
            self._last_gossip_time = now

    async def _attempt_rejoin(self):
        items = sorted(self.seen_nodes.items(), key=lambda x: x[1], reverse=True)
        for (addr,_) in items:
            if addr == self.my_address:
                continue
            if self.is_banned(addr):
                continue
            if (not self.network) or (addr not in self.network.connections):
                continue
            logger.info(f"[ChordNode {self.my_address}] attempt_rejoin => {addr}")
            await self.join(addr)
            if self.successors[0][0] != self.my_address:
                logger.info(
                    f"[ChordNode {self.my_address}] rejoin => success => succ={self.successors[0]}"
                )
                return

    async def _ping_node(self, addr: str)->bool:
        if self._is_self(addr):
            return True
        try:
            pong = await self.network.send_chord_ping(addr)
            return bool(pong)
        except:
            return False

    # ----------------------------------------------------------------
    # BAN
    # ----------------------------------------------------------------
    def is_banned(self, addr: str) -> bool:
        if addr == self.my_address:
            return False
        ban_info = self.ban_list.get(addr)
        if not ban_info:
            return False
        expire, reason = ban_info
        now = time.time()
        if now<expire:
            return True
        else:
            del self.ban_list[addr]
            return False

    def ban_node(self, addr: str, reason: str="unknown"):
        if addr == self.my_address:
            return
        expire_time = time.time() + self.BAN_DURATION
        self.ban_list[addr] = (expire_time, reason)
        logger.warning(
            f"[ChordNode {self.my_address}] ban_node => addr={addr}, reason={reason}, until={expire_time:.1f}"
        )

    # ----------------------------------------------------------------
    # GOSSIP
    # ----------------------------------------------------------------
    async def _gossip_fingers(self):
        if not self.fingers or not self.network:
            return
        if len(self.fingers) == 1:
            target = self.fingers[0][1]
        else:
            idx = random.randint(0, len(self.fingers)-1)
            target = self.fingers[idx][1]

        if (not target) or self._is_self(target):
            return

        local_fingers = self.fingers[:5]
        try:
            remotefingers = await self.network.send_chord_gossip_fingers(target, local_fingers)
            logger.debug(
                f"[ChordNode {self.my_address}] _gossip_fingers => from={target}, got={len(remotefingers)}"
            )
        except Exception as e:
            logger.debug(f"[ChordNode {self.my_address}] _gossip_fingers => fail => {e}")

    # ----------------------------------------------------------------
    # GRACEFUL LEAVE
    # ----------------------------------------------------------------
    async def graceful_leave(self):
        if self.successors[0][0] == self.my_address:
            logger.info(f"[ChordNode {self.my_address}] single-node => skip leave.")
            return
        succ_addr = self.successors[0][0]
        if self._is_self(succ_addr):
            logger.info(f"[ChordNode {self.my_address}] can't leave => we are alone.")
            return

        async with self._data_lock:
            items = list(self.data_store.items())

        cnt=0
        for (k,v) in items:
            try:
                await asyncio.wait_for(
                    self.network.send_chord_store_req(succ_addr, k, v),
                    timeout=self.RPC_TIMEOUT
                )
                cnt+=1
            except Exception as e:
                logger.error(
                    f"[ChordNode {self.my_address}] graceful_leave => store_req => {e}"
                )

        logger.info(f"[ChordNode {self.my_address}] graceful_leave => transferred {cnt} => succ={succ_addr}")

    # ----------------------------------------------------------------
    # BG
    # ----------------------------------------------------------------
    def start_background_tasks(self):
        if self._bg_task and not self._bg_task.done():
            return
        self._stop_bg = False
        self._bg_task = asyncio.create_task(self._bg_loop())
        logger.info(f"[ChordNode {self.my_address}] background tasks started.")

    async def stop_background_tasks(self):
        if self._bg_task:
            self._stop_bg = True
            self._bg_task.cancel()
            try:
                await self._bg_task
            except asyncio.CancelledError:
                pass
            self._bg_task = None
            logger.info(f"[ChordNode {self.my_address}] background tasks stopped.")

    async def _bg_loop(self):
        try:
            while not self._stop_bg:
                await self.stabilize()
                await self.fix_fingers()
                self._iteration_counter+=1

                if (self._iteration_counter*self._stabilize_interval)>= self._resync_interval:
                    self._iteration_counter=0
                    await self._resync_data()

                await self._save_data()
                await asyncio.sleep(self._stabilize_interval)

        except asyncio.CancelledError:
            logger.info(f"[ChordNode {self.my_address}] bg_loop => canceled.")
        except Exception as e:
            logger.error(f"[ChordNode {self.my_address}] bg_loop => error => {e}")
        finally:
            await self._save_data()
            logger.info(f"[ChordNode {self.my_address}] bg_loop => exited.")

    # ----------------------------------------------------------------
    # RESYNC
    # ----------------------------------------------------------------
    async def _resync_data(self):
        async with self._data_lock:
            items = list(self.data_store.items())
        cnt=0
        for k,v in items:
            await self.replicate_locally(k,v)
            cnt+=1
        logger.info(f"[ChordNode {self.my_address}] _resync_data => re-sent {cnt} items")

    # ----------------------------------------------------------------
    # in_range
    # ----------------------------------------------------------------
    def _in_range(self, x: int, start: int, end: int, inclusive=False) -> bool:
        rs = self.ring_size
        sm = start % rs
        em = end % rs
        xm = x % rs

        if sm < em:
            if inclusive:
                return (sm < xm <= em)
            else:
                return (sm < xm < em)
        else:
            # Заворот по кольцу
            if inclusive:
                return (xm > sm or xm <= em)
            else:
                return (xm > sm or xm < em)

    def check_key_collisions(self):
        hash_map = {}
        collisions = []
        for key in self.data_store:
            kh = sha1_hash(key)
            if kh in hash_map:
                collisions.append((hash_map[kh], key))
            else:
                hash_map[kh] = key
        return collisions

    # ----------------------------------------------------------------
    # LOAD/SAVE
    # ----------------------------------------------------------------
    def _load_data(self):
        if not os.path.isfile(self.data_file):
            logger.info(f"[ChordNode {self.my_address}] no local file => skip => {self.data_file}")
            return
        try:
            with open(self.data_file,"r",encoding="utf-8") as f:
                raw=json.load(f)
            loaded=0
            for k,vd in raw.items():
                val = LWWValue.from_dict(vd)
                self.data_store[k] = val
                loaded+=1
            logger.info(f"[ChordNode {self.my_address}] load => {loaded} keys from {self.data_file}")
            col=self.check_key_collisions()
            if col:
                logger.warning(f"[ChordNode {self.my_address}] collisions => {col}")
        except Exception as e:
            logger.error(f"[ChordNode {self.my_address}] load error => {e}")

    async def _save_data(self):
        async with self._data_lock:
            dct = {k:v.to_dict() for (k,v) in self.data_store.items()}
        tmp_path = self.data_file+".tmp"
        try:
            with open(tmp_path,"w",encoding="utf-8") as f:
                json.dump(dct,f,indent=4)
            os.replace(tmp_path, self.data_file)
        except Exception as e:
            logger.error(f"[ChordNode {self.my_address}] save error => {e}")
