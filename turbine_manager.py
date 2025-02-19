import asyncio
import logging
import random
import time
from typing import Dict, Tuple, Any, List, Optional, Union
import lz4.frame
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

DEFAULT_CHUNK_SIZE = 8192

TYPE_TURBINE_DATA = 1
TYPE_TURBINE_NACK = 2

class TurbineManager:
    SEND_TIMEOUT = 5.0
    NACK_RESEND_DELAY = 2.0
    COMPRESSION_TIMEOUT = 10.0

    def __init__(
        self,
        network: Any,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        max_flow_age: float = 120.0,
        resend_interval: float = 5.0,
        do_compress: bool = True
    ):
        self.network = network
        self.node_id = getattr(network, "node_id", "localNode")
        self.chunk_size = chunk_size
        self.max_flow_age = max_flow_age
        self.resend_interval = resend_interval
        self.do_compress = do_compress
        self._flows: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self.assembled_callback = None
        self._stop_bg = False
        self._bg_task: Optional[asyncio.Task] = None
        self._flows_lock = asyncio.Lock()
        self._compression_executor = ThreadPoolExecutor(max_workers=2)

   
    def start(self):
        if self._bg_task and not self._bg_task.done():
            return
        self._stop_bg = False
        self._bg_task = asyncio.create_task(self._bg_loop())
        logger.info("[TurbineManager] started background resend-check loop.")

    async def stop(self):
        self._stop_bg = True
        if self._bg_task:
            self._bg_task.cancel()
            try:
                await self._bg_task
            except asyncio.CancelledError:
                pass
        self._bg_task = None
        self._compression_executor.shutdown(wait=False)
        logger.info("[TurbineManager] stopped.")

    def _compute_layer_map(self, all_peers: List[str], fanout: int) -> List[List[str]]:
        shuffled = all_peers[:]
        random.shuffle(shuffled)
        layers = []
        start = 0
        while start < len(shuffled):
            end = start + fanout
            layer = shuffled[start:end]
            layers.append(layer)
            start = end
        return layers

    async def handle_incoming_packet(self, sender_id: str, data: dict):
        mtype = data.get("type")
        if mtype == "turbine_packet":
            await self._on_data_packet(sender_id, data)
        elif mtype == "turbine_nack":
            await self._on_nack_packet(sender_id, data)
        else:
            logger.debug(f"[TurbineManager] unknown msg_type={mtype}")

    async def _on_nack_packet(self, sender_id: str, data: dict):
        flow_id = data.get("flow_id")
        from_source = data.get("from_source")
        missing = data.get("missing_packets")
        
        if not flow_id or missing is None:
            return

        flow_key = (flow_id, from_source)
        logger.info(f"[TurbineManager] NACK from={sender_id}, flow={flow_id}, missing={missing}")

        async with self._flows_lock:
            entry = self._flows.get(flow_key)
            if not entry:
                return
            sub_hex = entry["subpackets"]
            entry["nack_requests"] += 1

        tasks = []
        for idx in missing:
            if 0 <= idx < len(sub_hex) and sub_hex[idx]:
                msg = {
                    "type": "turbine_packet",
                    "flow_id": flow_id,
                    "from_source": from_source,
                    "num_packets": entry["num_packets"],
                    "packet_idx": idx,
                    "packet_bytes": sub_hex[idx],
                    "current_layer": entry["current_layer"],
                    "layer_map": entry["layer_map"]
                }
                tasks.append(self._send_to_node_with_retry(sender_id, msg))

        if tasks:
            await asyncio.sleep(self.NACK_RESEND_DELAY)
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _bg_loop(self):
        try:
            while not self._stop_bg:
                now = time.time()
                await self._clean_flows(now)
                await asyncio.sleep(self.resend_interval)
        except asyncio.CancelledError:
            logger.info("[TurbineManager] _bg_loop => canceled.")
        except Exception as e:
            logger.error(f"[TurbineManager] _bg_loop => error => {e}")

    async def _clean_flows(self, now: float):
        to_delete = []
        async with self._flows_lock:
            for (fkey, flow) in self._flows.items():
                age = now - flow["start_ts"]
                if (flow["done"] and age > self.max_flow_age) or (not flow["done"] and age > 2 * self.max_flow_age):
                    to_delete.append(fkey)
            for d in to_delete:
                del self._flows[d]

    
    async def _compress_async(self, data: bytes) -> bytes:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self._compression_executor, 
            lz4.frame.compress, 
            data
        )

    async def _decompress_async(self, data: bytes) -> bytes:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self._compression_executor,
            lz4.frame.decompress,
            data
        )

    async def _send_to_node_with_retry(self, peer_id: str, msg: dict, retries: int = 3):
        for attempt in range(retries):
            try:
                await asyncio.wait_for(
                    self.network._send_to_node(peer_id, msg),
                    timeout=self.SEND_TIMEOUT
                )
                return
            except (asyncio.TimeoutError, ConnectionError) as e:
                logger.warning(f"Send error ({type(e).__name__}), attempt {attempt+1}/{retries}")
                await asyncio.sleep(1 * (attempt + 1))

    async def _safe_callback(self, flow_id: str, from_source: str, raw: bytes):
        try:
            if self.assembled_callback:
                self.assembled_callback(flow_id, from_source, raw)
        except Exception as e:
            logger.error(f"Callback error: {e}")

    
    async def start_broadcast_data(self, flow_id: str, data_bytes: bytes, all_peers: List[str], fanout: int = 3):
        real_peers = [p for p in all_peers if p != self.node_id]
        if not real_peers:
            return

        layer_map = self._compute_layer_map(real_peers, fanout)
        if not layer_map:
            return

        sub_chunks = []
        start = 0
        while start < len(data_bytes):
            end = start + self.chunk_size
            chunk_data = data_bytes[start:end]
            start = end
            if self.do_compress:
                try:
                    chunk_data = await asyncio.wait_for(
                        self._compress_async(chunk_data),
                        timeout=self.COMPRESSION_TIMEOUT
                    )
                except asyncio.TimeoutError:
                    logger.error("Compression timeout, using raw data")
            sub_chunks.append(chunk_data)

        async with self._flows_lock:
            self._flows[(flow_id, self.node_id)] = {
                "subpackets": [ch.hex() for ch in sub_chunks],
                "count": len(sub_chunks),
                "num_packets": len(sub_chunks),
                "assembled": True,
                "layer_map": layer_map,
                "current_layer": -1,
                "start_ts": time.time(),
                "done": False,
                "nack_requests": 0
            }

        await self._send_subpackets(flow_id, self.node_id, [ch.hex() for ch in sub_chunks], 0, layer_map)

    async def _send_subpackets(self, flow_id: str, from_source: str, sub_hex_list: List[str], current_layer: int, layer_map: List[List[str]]):
        if current_layer >= len(layer_map):
            return

        recipients = layer_map[current_layer]
        tasks = []
        for idx, pkt_hex in enumerate(sub_hex_list):
            msg = {
                "type": "turbine_packet",
                "flow_id": flow_id,
                "from_source": from_source,
                "num_packets": len(sub_hex_list),
                "packet_idx": idx,
                "packet_bytes": pkt_hex,
                "current_layer": current_layer,
                "layer_map": layer_map
            }
            for peer_id in recipients:
                tasks.append(self._send_to_node_with_retry(peer_id, msg))

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _on_data_packet(self, sender_id: str, data: dict):
        flow_id = data.get("flow_id")
        from_source = data.get("from_source")
        num_packets = data.get("num_packets")
        pkt_idx = data.get("packet_idx")
        pkt_hex = data.get("packet_bytes")
        current_layer = data.get("current_layer", 0)
        layer_map = data.get("layer_map")

        if None in (flow_id, from_source, num_packets, pkt_idx, pkt_hex, layer_map):
            return

        flow_key = (flow_id, from_source)
        async with self._flows_lock:
            if flow_key not in self._flows:
                self._flows[flow_key] = {
                    "subpackets": [None] * num_packets,
                    "count": 0,
                    "num_packets": num_packets,
                    "assembled": False,
                    "layer_map": layer_map,
                    "current_layer": current_layer,
                    "start_ts": time.time(),
                    "done": False,
                    "nack_requests": 0
                }

            entry = self._flows[flow_key]
            if num_packets > entry["num_packets"]:
                entry["subpackets"] += [None] * (num_packets - entry["num_packets"])
                entry["num_packets"] = num_packets

            if entry["subpackets"][pkt_idx] is None:
                entry["subpackets"][pkt_idx] = pkt_hex
                entry["count"] += 1

            if not entry["assembled"] and entry["count"] == entry["num_packets"]:
                entry["assembled"] = True
                full_compressed = b"".join(bytes.fromhex(c) for c in entry["subpackets"])
                try:
                    raw = await self._decompress_async(full_compressed)
                except Exception as e:
                    logger.error(f"Decompress failed: {e}")
                    return
                asyncio.create_task(self._safe_callback(flow_id, from_source, raw))
                entry["done"] = True

        if not entry["done"] and current_layer < len(layer_map) - 1:
            next_layer = current_layer + 1
            await self._send_subpackets(flow_id, from_source, entry["subpackets"], next_layer, layer_map)
