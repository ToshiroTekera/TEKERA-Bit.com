import asyncio
import json
import time
import logging
import hashlib
import numpy as np
from typing import Optional, Dict, Any

logging.basicConfig(level=logging.INFO)

from chordnode import ChordNode, LWWValue

class ProofOfHistory:

    def __init__(
        self,
        chord_node: Optional[ChordNode] = None,
        difficulty_iterations: int = 100_000,  # Можно уменьшить, скажем, 50_000 или 20_000
        ml_trainer=None
    ):
        """
        :param chord_node: ссылка на ChordNode (для хранения events).
        :param difficulty_iterations: кол-во повторов SHA256 (если нет ml_trainer).
        :param ml_trainer: если есть — мы можем вместо repeated hashing сделать ML puzzle.
                           Но здесь показываем пример chunked-hash.
        """
        self.chord_node = chord_node
        self.difficulty_iterations = difficulty_iterations
        self.ml_trainer = ml_trainer

        self.head_hash_key = "poh_head_hash"
        self._poh_lock = asyncio.Lock()
        self.current_head: Optional[str] = None  # Будет загружено в init_poh

        logging.info("[ProofOfHistory] Created. (call await init_poh() to load head)")

    async def init_poh(self):
        """
        Асинхронная инициализация: загружаем current_head из Chord, если есть.
        """
        async with self._poh_lock:
            self.current_head = await self._load_str_from_chord(self.head_hash_key)
            logging.info(f"[ProofOfHistory] init => current_head={self.current_head}")

    # ------------------------------------------------
    # record_event
    # ------------------------------------------------
    async def record_event(self, event_data: dict) -> str:
        """
        Добавляем новое событие PoH: 
          - prev_hash = self.current_head
          - вычисляем vdf_result (async)
          - event_hash = sha256(...), chord => poh_{event_hash} 
          - Обновляем head=event_hash
        """
        async with self._poh_lock:
            # Загружаем актуальный head (если не загружен)
            if self.current_head is None:
                self.current_head = await self._load_str_from_chord(self.head_hash_key)

            now_ts = time.time()
            event_data["timestamp"] = now_ts
            prev_hash = self.current_head

            event = {
                "prev_hash": prev_hash,
                "data": event_data
            }

            # Вычисляем VDF (async)
            base_bytes = json.dumps(event, sort_keys=True).encode('utf-8')
            vdf_result = await self._fake_vdf_async(base_bytes, self.difficulty_iterations)
            event["hash_n"] = vdf_result

            # финальный event_hash
            encoded_event = json.dumps(event, sort_keys=True).encode('utf-8')
            event_hash = hashlib.sha256(encoded_event).hexdigest()

            # сохраняем
            key_event = f"poh_{event_hash}"
            await self._store_value_in_chord(key_event, event)

            # обновляем current_head
            self.current_head = event_hash
            await self._store_str_in_chord(self.head_hash_key, event_hash)

            logging.info(f"[ProofOfHistory] record_event => event_hash={event_hash}, prev={prev_hash}")
            return event_hash

    async def record_consensus_block(self, block_id: str, block_data: dict, final_votes: dict = None):
        """
        Записываем commit блока в PoH-цепочку (как &laquo;тип=...block&raquo;).
        """
        event_data = {
            "type": "C4C_block",
            "block_id": block_id,
            "block_data": block_data
        }
        if final_votes:
            event_data["final_votes"] = final_votes
        return await self.record_event(event_data)

    async def record_block_received(self, block_id: str):
        """
        Фиксируем получение/принятие block_id.
        """
        event_data = {
            "type": "block_received",
            "block_id": block_id
        }
        await self.record_event(event_data)
        logging.info(f"[ProofOfHistory] block_received => {block_id}")

    # ------------------------------------------------
    # verify_history
    # ------------------------------------------------
    async def verify_history(self) -> bool:
        """
        Идём от current_head вниз, проверяя hash_n + sha256.
        """
        async with self._poh_lock:
            if not self.current_head:
                self.current_head = await self._load_str_from_chord(self.head_hash_key)
            if not self.current_head:
                logging.info("[ProofOfHistory] no events => verify OK (empty).")
                return True

            current_hash = self.current_head

        while current_hash:
            key_event = f"poh_{current_hash}"
            event = await self._load_value_from_chord(key_event)
            if not event or not isinstance(event, dict):
                logging.error(f"[ProofOfHistory] verify => missing/invalid event => {current_hash}")
                return False

            original_vdf = event.get("hash_n")
            if not original_vdf:
                logging.error(f"[ProofOfHistory] no hash_n => {current_hash}")
                return False

            event_copy = dict(event)
            del event_copy["hash_n"]
            base_bytes = json.dumps(event_copy, sort_keys=True).encode('utf-8')

            # Пересчитываем vdf (синхронно? или также chunked?)
            # Для верификации можно либо chunked, либо синхронно (короче).
            recalculated_vdf = self._fake_vdf_sync(base_bytes, self.difficulty_iterations)
            if recalculated_vdf != original_vdf:
                logging.error(f"[ProofOfHistory] vdf mismatch => {current_hash}")
                return False

            # пересчитываем sha256
            re_encoded = json.dumps(event, sort_keys=True).encode('utf-8')
            re_hash = hashlib.sha256(re_encoded).hexdigest()
            if re_hash != current_hash:
                logging.error(f"[ProofOfHistory] hash mismatch => {current_hash}")
                return False

            current_hash = event.get("prev_hash")

        logging.info("[ProofOfHistory] verify_history => success, all events match.")
        return True

    # ------------------------------------------------
    # Asynchronous chunked VDF
    # ------------------------------------------------
    async def _fake_vdf_async(self, data: bytes, total_iters: int) -> str:
        """
        Асинхронная &laquo;chunked&raquo; версия repeated SHA256.
        Делим на чанки (chunk_size=1000), между чанками => await asyncio.sleep(0).
        """
        # Если есть ml_trainer — используйте ML puzzle? 
        # Для примера оставим repeated hashing.
        chunk_size = 1000
        current = data
        done = 0
        while done < total_iters:
            batch = min(chunk_size, total_iters - done)
            for _ in range(batch):
                current = hashlib.sha256(current).digest()
            done += batch
            # Позволяем event-loop отработать:
            await asyncio.sleep(0)
        return current.hex()

    def _fake_vdf_sync(self, data: bytes, total_iters: int) -> str:
        """
        Синхронная версия для verify_history (не обязательно делать chunk).
        """
        current = data
        for _ in range(total_iters):
            current = hashlib.sha256(current).digest()
        return current.hex()

    # ------------------------------------------------
    # Storage in chord
    # ------------------------------------------------
    async def _load_value_from_chord(self, key: str) -> Optional[Any]:
        if not self.chord_node:
            return None
        val_obj = self.chord_node.get_local(key)
        if val_obj is None:
            return None
        return val_obj.value

    async def _store_value_in_chord(self, key: str, data: Any):
        if not self.chord_node:
            return
        now_ts = time.time()
        val_obj = LWWValue(data, now_ts)
        await self.chord_node.replicate_locally(key, val_obj)

    async def _load_str_from_chord(self, key: str) -> Optional[str]:
        val = await self._load_value_from_chord(key)
        if isinstance(val, str):
            return val
        return None

    async def _store_str_in_chord(self, key: str, text: str):
        await self._store_value_in_chord(key, text)