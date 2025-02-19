import argparse
import asyncio
import base64
import json
import logging
import math
import os
import random
import sys
import time
from typing import Dict, List, Optional

import lz4.frame
from zfec import Encoder, Decoder

from aiortc import RTCDataChannel

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

TYPE_DATA = 1
TYPE_NACK = 2

DEFAULT_CHUNK_SIZE = 2_000_000

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    import hmac, hashlib
    return hmac.new(key, data, hashlib.sha256).digest()


class SenderChunk:
    def __init__(self, chunk_idx: int, shares: List[bytes], K: int, M: int):
        self.chunk_idx = chunk_idx
        self.shares = shares   # список байтов каждого шарда
        self.K = K
        self.M = M
        self.N = K + M

        self.received_mask = [False] * self.N  # если нужно
        self.done = False
        self.resend_count = [0] * self.N      # ограничение resend

class SenderFlow:
    def __init__(self, flow_id: bytes, chunk_count: int):
        self.flow_id = flow_id
        self.chunk_count = chunk_count
        self.chunks: Dict[int, SenderChunk] = {}
        self.start_ts = time.time()
        self.done = False
        # Добавим счётчик NACK для защиты
        self.nack_count = 0

class ReceiverFlow:
    def __init__(self, flow_id: bytes, chunk_count: int, K: int, M: int):
        self.flow_id = flow_id
        self.chunk_count = chunk_count
        self.K = K
        self.M = M
        self.N = K + M

        self.chunks_data = [[None]*self.N for _ in range(chunk_count)]
        self.chunk_done = [False]*chunk_count
        self.done = False
        self.start_ts = time.time()
        self.last_nack_ts = 0.0   # когда последний раз слали NACK


class FecChannel:
 

    ACK_INTERVAL = 2.0           # как часто проверять receiver flows
    FLOW_TIMEOUT = 120.0         # через сколько секунд удалить (receiver) flow, если не собран
    MAX_RESEND_ATTEMPTS = 5      # cколько раз можно пересылать 1 share
    MAX_NACK_PER_FLOW = 20       # лимит NACK
    INFLIGHT_LIMIT = 50_000_000  # 50MB “в полёте”

    def __init__(
        self,
        datachannel: RTCDataChannel,
        # Параметры FEC (если не adaptive):
        K: int = 10,
        M: int = 2,
        do_compress: bool = True,
        secret_key: Optional[bytes] = None,
        ack_interval: float = ACK_INTERVAL,
        max_resend_attempts: int = MAX_RESEND_ATTEMPTS,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        assembled_cb=None,
        adaptive_fec: bool = False
    ):
        """
        :param datachannel: RTCDataChannel для отправки/приёма
        :param K, M: базовые параметры, если adaptive_fec=False
        :param do_compress: lz4-сжатие
        :param secret_key: HMAC-ключ (или None)
        :param ack_interval: как часто bg-loop
        :param max_resend_attempts: лимит resend
        :param chunk_size: размер чанка
        :param assembled_cb: callback(flow_id, raw_data), когда собран весь файл
        :param adaptive_fec: если True, при send_file(...) K,M берём из _choose_fec_params
        """
        self.dc = datachannel
        self.K = K
        self.M = M
        self.N = K + M
        self.do_compress = do_compress
        self.secret_key = secret_key
        self.ack_interval = ack_interval
        self.max_resend_attempts = max_resend_attempts
        self.chunk_size = chunk_size
        self.assembled_cb = assembled_cb
        self.adaptive_fec = adaptive_fec

        self.sender_flows: Dict[bytes, SenderFlow] = {}
        self.rx_flows: Dict[bytes, ReceiverFlow] = {}

        # Фоновая задача
        self._bg_task = asyncio.create_task(self._bg_loop())

        # Подписка на сообщения
        self.dc.on("message", self._on_message)
        logger.info("[FecChannel] created => listening datachannel messages...")

        # Лок, чтобы не было гонок
        self._lock = asyncio.Lock()

        # Flow control semaphore
        self._flow_sem = asyncio.Semaphore(self.INFLIGHT_LIMIT)

    # ---------------------------------------------------------------
    # BG loop
    # ---------------------------------------------------------------
    def stop(self):
 
        if self._bg_task and not self._bg_task.done():
            self._bg_task.cancel()

    async def _bg_loop(self):
       
        try:
            while True:
                await asyncio.sleep(self.ack_interval)
                now = time.time()
                async with self._lock:
                    # 1) пробегаемся по receiver_flows
                    for fid, rf in list(self.rx_flows.items()):
                        if rf.done:
                            # remove if old
                            if now - rf.start_ts> self.FLOW_TIMEOUT:
                                del self.rx_flows[fid]
                                logger.debug(f"[FecChannel] remove old receiver flow={fid.hex()}")
                            continue

                      
                        missing_any = False
                        for cidx in range(rf.chunk_count):
                            if not rf.chunk_done[cidx]:
                                arr = rf.chunks_data[cidx]
                                missing_list= []
                                for i, sd in enumerate(arr):
                                    if sd is None:
                                        missing_list.append(i)
                                if missing_list:
                                    missing_any= True
                                    self._send_nack(fid, cidx, missing_list)
                        if missing_any:
                            rf.last_nack_ts= now

                    # 2) чистим sender_flows
                    for fid, sf in list(self.sender_flows.items()):
                        if sf.done and (now - sf.start_ts> self.FLOW_TIMEOUT):
                            del self.sender_flows[fid]
                            logger.debug(f"[FecChannel] remove old sender flow={fid.hex()}")

        except asyncio.CancelledError:
            logger.info("[FecChannel] _bg_loop => canceled.")
        except Exception as e:
            logger.error(f"[FecChannel] _bg_loop => error => {e}")


    def _choose_fec_params(self, data_len: int) -> (int,int):
      
        if data_len < 10_000_000:
            return (8,2)
        elif data_len < 100_000_000:
            return (16,4)
        else:
            return (32,6)


    def send_file(self, raw_data: bytes):
      
        flow_id = os.urandom(16)

       
        if self.adaptive_fec:
            K,M = self._choose_fec_params(len(raw_data))
        else:
            K,M= self.K,self.M
        N= K+M

        
        chunks=[]
        start=0
        while start< len(raw_data):
            end= start+ self.chunk_size
            cdata= raw_data[start:end]
            start= end
            if self.do_compress:
                cdata= lz4.frame.compress(cdata)
            chunks.append(cdata)

        sf = SenderFlow(flow_id, len(chunks))

        
        enc = Encoder(K,N)
        for cidx, cd in enumerate(chunks):
            shares= enc.encode(cd)
            sc= SenderChunk(cidx, shares, K,M)
            sf.chunks[cidx]= sc

        async def do_send():
            async with self._lock:
                self.sender_flows[flow_id]= sf

            
            for cidx, sc in sf.chunks.items():
                for share_idx, shard_data in enumerate(sc.shares):
                    await self._send_one_share(sf, cidx, share_idx, shard_data)

            logger.info(f"[FecChannel] send_file => flow={flow_id.hex()}, chunks={len(chunks)}, totalSize={len(raw_data)}, (K={K},M={M}).")

        asyncio.create_task(do_send())

    async def _send_one_share(self, sf: SenderFlow, chunk_idx: int, share_idx: int, shard_data: bytes):
        sc= sf.chunks[chunk_idx]
        N= sc.N
        flow_id= sf.flow_id

        # Собираем пакет
        # packet = [TYPE_DATA] + flow_id(16) + chunk_idx(2) + share_idx(2) + N(2) + shard_data + [hmac?]
        header= bytearray([TYPE_DATA])
        header+= flow_id
        header+= chunk_idx.to_bytes(2,'big')
        header+= share_idx.to_bytes(2,'big')
        header+= N.to_bytes(2,'big')
        packet= bytes(header)+ shard_data

        if self.secret_key:
            sig= hmac_sha256(self.secret_key, packet)
            packet+= sig

        # FLOW CONTROL => 1 slot
        await self._flow_sem.acquire()
        try:
            self.dc.send(packet)
        except Exception as e:
            logger.warning(f"[FecChannel] send_file => error => {e}")
        finally:
            self._flow_sem.release()

   
    def _send_nack(self, flow_id: bytes, chunk_idx: int, missing_idx: List[int]):
        """
        NACK => [TYPE_NACK] + flow_id(16) + chunk_idx(2) + missing_count(2) + each missing(2) + [hmac?]
        """
        body= flow_id + chunk_idx.to_bytes(2,'big') + len(missing_idx).to_bytes(2,'big')
        for mi in missing_idx:
            body+= mi.to_bytes(2,'big')
        packet= bytes([TYPE_NACK]) + body

        if self.secret_key:
            sig= hmac_sha256(self.secret_key, packet)
            packet+= sig

        try:
            self.dc.send(packet)
            logger.debug(f"[FecChannel] send NACK => fid={flow_id.hex()}, chunk={chunk_idx}, missing={missing_idx}")
        except Exception as e:
            logger.warning(f"[FecChannel] send NACK => error => {e}")

    async def _resend_share(self, sf: SenderFlow, chunk_idx: int, share_idx: int):
        sc= sf.chunks[chunk_idx]
        if share_idx<0 or share_idx>= sc.N:
            logger.warning("[FecChannel] invalid share_idx => skip resend.")
            return
        if sc.resend_count[share_idx]>= self.max_resend_attempts:
            logger.warning(f"[FecChannel] share_idx={share_idx} exceed resend limit => skip.")
            return

        sc.resend_count[share_idx]+=1
        shard_data= sc.shares[share_idx]
      
        header= bytearray([TYPE_DATA])
        header+= sf.flow_id
        header+= chunk_idx.to_bytes(2,'big')
        header+= share_idx.to_bytes(2,'big')
        header+= sc.N.to_bytes(2,'big')
        packet= bytes(header)+ shard_data

        if self.secret_key:
            sig= hmac_sha256(self.secret_key, packet)
            packet+= sig

        # flow control
        await self._flow_sem.acquire()
        try:
            self.dc.send(packet)
            logger.debug(f"[FecChannel] resend => chunk={chunk_idx}, share={share_idx}, total resend={sc.resend_count[share_idx]}")
        except Exception as e:
            logger.warning(f"[FecChannel] resend error => {e}")
        finally:
            self._flow_sem.release()

    # ---------------------------------------------------------------
    # Receive (Data/NACK)
    # ---------------------------------------------------------------
    def _on_message(self, raw: bytes):
        if not raw:
            return
        msg_type= raw[0]
        body= raw[1:]

        if msg_type not in (TYPE_DATA, TYPE_NACK):
            logger.debug("[FecChannel] unknown msg_type => skip")
            return

        # HMAC check
        if self.secret_key:
            if len(body)<32:
                logger.warning("[FecChannel] message too short => no HMAC => skip.")
                return
            main_part= body[:-32]
            sig_part= body[-32:]
            import hmac
            check_data= bytes([msg_type])+ main_part
            calc= hmac_sha256(self.secret_key, check_data)
            if not hmac.compare_digest(sig_part, calc):
                logger.warning("[FecChannel] invalid HMAC => skip.")
                return
            body= main_part

        if msg_type==TYPE_DATA:
            self._on_data_packet(body)
        elif msg_type==TYPE_NACK:
            self._on_nack_packet(body)

    def _on_data_packet(self, body: bytes):
        if len(body)<22:
            return
        flow_id= body[:16]
        chunk_idx= int.from_bytes(body[16:18],'big')
        share_idx= int.from_bytes(body[18:20],'big')
        totalN= int.from_bytes(body[20:22],'big')
        shard_data= body[22:]

        async def handle_data():
            rf= self.rx_flows.get(flow_id)
            if not rf:
                # Предположим chunk_count=1
                chunk_count=1
                K= max(1, totalN-2)
                M= totalN-K
                rf= ReceiverFlow(flow_id, chunk_count, K,M)
                self.rx_flows[flow_id]= rf

            if rf.done:
                return
            if chunk_idx>= rf.chunk_count:
                logger.warning("[FecChannel] chunk_idx out-of-range => skip.")
                return
            if share_idx<0 or share_idx>= rf.N:
                logger.warning("[FecChannel] share_idx out-of-range => skip.")
                return

            arr= rf.chunks_data[chunk_idx]
            if arr[share_idx] is None:
                arr[share_idx]= shard_data
                got_cnt= sum(1 for x in arr if x)
                if got_cnt>= rf.K and not rf.chunk_done[chunk_idx]:
                    # decode
                    dec= Decoder(rf.N, rf.K)
                    good_data=[]
                    good_idx=[]
                    for i,sd in enumerate(arr):
                        if sd:
                            good_data.append(sd)
                            good_idx.append(i)
                    try:
                        raw_dec= dec.decode(good_data, good_idx)
                        if self.do_compress:
                            raw_dec= lz4.frame.decompress(raw_dec)
                        rf.chunk_done[chunk_idx]= True
                        rf.done= True # single chunk
                        if self.assembled_cb:
                            try:
                                self.assembled_cb(flow_id, raw_dec)
                            except Exception as e:
                                logger.error(f"[FecChannel] assembled_cb => {e}")
                        logger.info(f"[FecChannel] flow={flow_id.hex()} => chunk={chunk_idx} => assembled => size={len(raw_dec)}")

                    except Exception as e:
                        logger.warning(f"[FecChannel] decode error => {e}")

        asyncio.create_task(self._process_with_lock(handle_data))

    def _on_nack_packet(self, body: bytes):
        if len(body)<20:
            return
        flow_id= body[:16]
        chunk_idx= int.from_bytes(body[16:18],'big')
        mc= int.from_bytes(body[18:20],'big')
        offset=20
        missing=[]
        for _ in range(mc):
            if offset+2> len(body):
                break
            mid= int.from_bytes(body[offset:offset+2],'big')
            offset+=2
            missing.append(mid)

        async def handle_nack():
            sf= self.sender_flows.get(flow_id)
            if not sf:
                return
            # Защита от NACK-флуда
            sf.nack_count+=1
            if sf.nack_count> self.MAX_NACK_PER_FLOW:
                logger.warning(f"[FecChannel] flow={flow_id.hex()} => too many NACK => skip further.")
                return

            sc= sf.chunks.get(chunk_idx)
            if not sc:
                logger.debug(f"[FecChannel] NACK => unknown chunk={chunk_idx}")
                return

            # resend
            for mi in missing:
                if 0<=mi< sc.N:
                    if sc.resend_count[mi]< self.max_resend_attempts:
                        asyncio.create_task(self._resend_share(sf, chunk_idx, mi))
                else:
                    logger.warning("[FecChannel] invalid share idx in NACK => skip")

        asyncio.create_task(self._process_with_lock(handle_nack))

    async def _process_with_lock(self, coro):
        async with self._lock:
            await coro()
