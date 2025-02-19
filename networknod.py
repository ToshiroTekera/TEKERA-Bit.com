import asyncio
import json
import os
import ssl
import time
import logging
import tempfile
from uuid import uuid4
from typing import Optional, Dict, Tuple, Any, List

import websockets
from websockets.server import serve
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

from chordnode import ChordNode
from multi_hotstuff_advanced import MultiLeaderHotStuffAdvanced  # <-- ваш HotStuff без threshold
from key import KeyManager
from turbine_manager import TurbineManager
from erasure_udp_zfec_ack_advanced import FecChannel

try:
    import miniupnpc
except ImportError:
    miniupnpc = None

try:
    import stun
except ImportError:
    stun = None

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class NodeNetwork:
    SEND_TIMEOUT = 20.0

    def __init__(
        self,
        my_address: str,           
        host: str = "0.0.0.0",
        port: int = 8765,
        data_dir: Optional[str] = None,
        enable_tls: bool = False,
        ssl_context: Optional[ssl.SSLContext] = None,
        auto_tls_generate: bool = True,
        max_msg_size: int = 2_000_000,

        require_auth: bool = False,
        require_signature: bool = False,
        key_manager: Optional[KeyManager] = None,
        auth_tokens: Dict[str, str] = None,
        mining_module=None,

        enable_nat_traversal: bool = False,
        upnp_lease_duration: int = 3600,
        stun_server: str = "stun.l.google.com",
        stun_port: int = 19302,

        rate_limit_capacity: int = 200,
        rate_limit_refill_rate: float = 2.0,
        replay_protect_window: int = 300,

        datachannel=None,
        fec_K: int = 10,
        fec_M: int = 2,
        fec_do_compress: bool = True,
        fec_secret_key: Optional[bytes] = None,

        turbine_chunk_size: int = 8192,
        turbine_max_flow_age: float = 120.0,
        turbine_resend_interval: float = 5.0,
        turbine_do_compress: bool = True
    ):
        self.my_address = my_address
        self.host = host
        self.port = port
        self.data_dir = data_dir

        self.logger = logging.getLogger(f"NodeNetwork-{self.my_address}")
        self.logger.setLevel(logging.DEBUG)
        self.logger.debug(f">>> NodeNetwork file: {__file__} / address={my_address}")

        self.enable_tls = enable_tls
        self.auto_tls_generate = auto_tls_generate
        self.ssl_context = ssl_context
        self.max_msg_size = max_msg_size

        self.require_auth = require_auth
        self.require_signature = require_signature
        self.key_manager = key_manager
        self.auth_tokens = auth_tokens or {}

        self.enable_nat_traversal = enable_nat_traversal
        self.upnp_lease_duration = upnp_lease_duration
        self.stun_server = stun_server
        self.stun_port = stun_port

        self.public_host = host
        self.public_port = port

        self.rate_limit_capacity = rate_limit_capacity
        self.rate_limit_refill_rate = rate_limit_refill_rate
        self.replay_protect_window = replay_protect_window

        self._server = None
        self.connections: Dict[str, websockets.WebSocketClientProtocol] = {}
        self._connections_lock = asyncio.Lock()

      
        self.token_buckets: Dict[str, Dict[str, float]] = {}
       
        self._recent_msg_ids: Dict[str, float] = {}

        # Chord / HotStuff / Mining
        self.chord_node: Optional[ChordNode] = None
        self.hotstuff_consensus: Optional[MultiLeaderHotStuffAdvanced] = None
        self.mining_module = mining_module

        # FEC-канал
        self.fec_channel: Optional[FecChannel] = None
        if datachannel is not None:
            self.fec_channel = FecChannel(
                datachannel=datachannel,
                K=fec_K,
                M=fec_M,
                do_compress=fec_do_compress,
                secret_key=fec_secret_key,
                assembled_cb=self._on_fec_assembled
            )
            logger.info("[NodeNetwork] FecChannel => created.")
        else:
            logger.info("[NodeNetwork] datachannel=None => skip FecChannel.")

        # Turbine
        self.turbine_manager = TurbineManager(
            network=self,
            chunk_size=turbine_chunk_size,
            max_flow_age=turbine_max_flow_age,
            resend_interval=turbine_resend_interval,
            do_compress=turbine_do_compress
        )

        self.rpc_futures: Dict[str, asyncio.Future] = {}

        if self.enable_tls and (self.ssl_context is None) and self.auto_tls_generate:
            self.ssl_context = self._generate_self_signed_ssl()

        scheme = "wss" if (self.enable_tls and self.ssl_context) else "ws"
        logger.info(
            f"[NodeNetwork] address={my_address}, listening on {scheme}://{host}:{port}, "
            f"auth={require_auth}, sign={require_signature}, "
            f"rateLimit={rate_limit_capacity}, replay={replay_protect_window}"
        )

        self._stop_flag = False

        
        self.outgoing_endpoints: Dict[str, Dict[str,Any]] = {}
        self._reconnect_task: Optional[asyncio.Task] = None

    # -------------------------------------------------------
    # NAT + start/stop
    # -------------------------------------------------------
    async def setup_nat_traversal(self):
        if not self.enable_nat_traversal:
            return
        await self._enable_upnp()
        ip, prt = await self._discover_stun()
        if ip:
            self.public_host = ip
            self.public_port = prt
            logger.info(f"[NodeNetwork] NAT => discovered public={ip}:{prt}")

    async def _enable_upnp(self):
        if not miniupnpc:
            logger.warning("[NodeNetwork] miniupnpc not installed => skip.")
            return
        try:
            upnp = miniupnpc.UPnP()
            upnp.discoverdelay = 200
            upnp.discover()
            upnp.selectigd()
            lan_ip = upnp.lanaddr
            ext_ip = upnp.externalipaddress()
            logger.info(f"[NodeNetwork] UPNP => localIP={lan_ip}, externalIP={ext_ip}")
            upnp.addportmapping(
                self.port, 'TCP',
                lan_ip, self.port,
                f"{self.my_address}-WS",
                ''
            )
            logger.info(f"[NodeNetwork] UPNP => mapped {self.port} => OK")
        except Exception as e:
            logger.warning(f"[NodeNetwork] UPNP => fail => {e}")

    async def _discover_stun(self) -> Tuple[Optional[str], Optional[int]]:
        if not stun:
            return None, None
        try:
            nat_type, external_ip, external_port = stun.get_ip_info(
                source_ip=self.host,
                source_port=self.port,
                stun_host=self.stun_server,
                stun_port=self.stun_port
            )
            logger.info(f"[NodeNetwork] STUN => nat_type={nat_type}, ext={external_ip}:{external_port}")
            return external_ip, external_port
        except Exception as e:
            logger.warning(f"[NodeNetwork] STUN => fail => {e}")
        return None, None

    async def start_server(self):
        await self.setup_nat_traversal()

        self._server = await serve(
            ws_handler=self.handle_connection,
            host=self.host,
            port=self.port,
            ssl=self.ssl_context,
            max_size=self.max_msg_size
        )
        scheme = "wss" if self.ssl_context else "ws"
        self.logger.info(f"[NodeNetwork] {scheme}://{self.host}:{self.port} started => waiting for clients...")

        self.turbine_manager.start()
        asyncio.create_task(self._clean_old_msg_ids())

        # Запускаем фоновый reconnect (для outgoing_endpoints)
        self._reconnect_task = asyncio.create_task(self._reconnect_loop())

    async def run_forever(self):
        while not self._stop_flag:
            await asyncio.sleep(1.0)
        await self.stop_server()

    async def stop_server(self):
        self._stop_flag = True
        if self._reconnect_task:
            self._reconnect_task.cancel()
            try:
                await self._reconnect_task
            except asyncio.CancelledError:
                pass
            self._reconnect_task = None

        await self.turbine_manager.stop()
        if self.fec_channel:
            self.fec_channel.stop()
            self.logger.info("[NodeNetwork] fec_channel => stopped")

        if self._server:
            self.logger.info("[NodeNetwork] stopping WS server...")
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        async with self._connections_lock:
            for addr, ws in list(self.connections.items()):
                if not ws.closed:
                    await ws.close(reason="NodeNetwork shutting down.")
            self.connections.clear()

        self.logger.info("[NodeNetwork] server stopped.")

    def request_stop(self):
        self._stop_flag = True

    async def _clean_old_msg_ids(self):
        while not self._stop_flag:
            await asyncio.sleep(30)
            cutoff = time.time() - self.replay_protect_window
            old_keys = [k for (k,ts) in self._recent_msg_ids.items() if ts < cutoff]
            for k in old_keys:
                del self._recent_msg_ids[k]
            self.logger.debug(f"[NodeNetwork] _clean_old_msg_ids => removed {len(old_keys)} old msg_ids")

    # -------------------------------------------------------
    # OUTGOING + RECONNECT
    # -------------------------------------------------------
    def add_outgoing_node(self, other_address: str, host: str, port: int, max_retries: int=5):
        self.logger.debug(f"[NodeNetwork {self.my_address}] add_outgoing_node => {other_address} => {host}:{port}")
        if other_address == self.my_address:
            return
        self.outgoing_endpoints[other_address] = {
            "host": host,
            "port": port,
            "max_retries": max_retries,
            "retries_left": max_retries,
            "backoff": 1.0
        }



    async def connect_to_node(self, other_address: str, host: str, port: int) -> bool:
  
        self.logger.debug(f"[NodeNetwork {self.my_address}] connect_to_node => address={other_address}, host={host}, port={port}")
    
        
        async with self._connections_lock:
            if other_address in self.connections:
                self.logger.warning(f"[{self.my_address}] connect_to_node => already have ws => {other_address}")
                return True

   
        url = f"ws://{host}:{port}" if not self.ssl_context else f"wss://{host}:{port}"
        self.logger.info(f"[{self.my_address}] connect_to_node => trying {url}")
    
        try:
            ws = await websockets.connect(url, max_size=self.max_msg_size, ssl=self.ssl_context)

       
            init_msg = {
                "type": "register",
                "address": self.my_address
            }

       
            if self.require_auth and self.auth_tokens.get(self.my_address):
                init_msg["auth_token"] = self.auth_tokens[self.my_address]

          
            if self.require_signature:
                pubkey = self.key_manager.get_ec_pubkey(self.my_address)
                if pubkey:
                    init_msg["pubkey"] = pubkey.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ).decode("utf-8")
                else:
                    self.logger.error(f"[{self.my_address}] connect_to_node => missing pubkey for registration!")
                    return False 

            self.logger.debug(f"[{self.my_address}] sending register => {init_msg}")
            await ws.send(json.dumps(init_msg))

           
            async with self._connections_lock:
                self.connections[other_address] = ws

            self.logger.info(f"[{self.my_address}] connected => address={other_address} => {url}")

           
            asyncio.create_task(self._client_reader_loop(other_address, ws))
            return True

        except Exception as e:
            self.logger.error(f"[{self.my_address}] connect_to_node => address={other_address}, error => {e}")
            return False

    async def _client_reader_loop(self, other_addr: str, ws: websockets.WebSocketClientProtocol):
        self.logger.debug(f"[{self.my_address}] _client_reader_loop START => address={other_addr}")
        try:
            while True:
                raw = await ws.recv()
                self.logger.info(
                    f"[NodeNetwork {self.my_address}] _client_reader_loop => got msg from {other_addr} => {raw[:200]}"
                )
                if not raw:
                    continue
                if not self._check_rate_limit_token(other_addr):
                    await self._close_with_error(ws, "Rate limit exceeded (outgoing).")
                    break
                msg_in = self._safe_json_parse(raw)
                if not msg_in:
                    await self._close_with_error(ws, "Invalid JSON msg (outgoing).")
                    continue
                if not self._check_replay(msg_in):
                    await self._close_with_error(ws, "Replay or missing msg_id.")
                    break
                if self.require_signature:
                    if not self._verify_message_signature(msg_in):
                        await self._close_with_error(ws, "Signature check fail (outgoing).")
                        break

                await self.process_incoming_message(other_addr, msg_in)

        except websockets.ConnectionClosed:
            self.logger.warning(f"[{self.my_address}] ws closed => address={other_addr}")
        except Exception as e:
            self.logger.error(f"[{self.my_address}] client_reader => {other_addr}, error => {e}", exc_info=True)
        finally:
            self.logger.info(f"[{self.my_address}] _client_reader_loop FINALLY => {other_addr}")
            async with self._connections_lock:
                if other_addr in self.connections and self.connections[other_addr] is ws:
                    del self.connections[other_addr]
                    self.logger.info(f"[{self.my_address}] address={other_addr} => removed from connections.")

    async def _reconnect_loop(self):
        self.logger.debug(f"[{self.my_address}] _reconnect_loop => start")
        while not self._stop_flag:
            await asyncio.sleep(5.0)
            endpoints_copy = list(self.outgoing_endpoints.items())

            for addr, info in endpoints_copy:
                if addr == self.my_address:
                    continue
                async with self._connections_lock:
                    already_connected = (addr in self.connections)

                if already_connected:
                    info["retries_left"] = info["max_retries"]
                    info["backoff"] = 1.0
                else:
                    if info["retries_left"] <= 0:
                        continue
                    self.logger.info(f"[{self.my_address}] => reconnect => address={addr}, left={info['retries_left']}")
                    ok = await self.connect_to_node(addr, info["host"], info["port"])
                    if ok:
                        info["retries_left"] = info["max_retries"]
                        info["backoff"] = 1.0
                    else:
                        info["retries_left"] -= 1
                        self.logger.warning(f"[{self.my_address}] => reconnect fail => address={addr}, backoff={info['backoff']}s")
                        await asyncio.sleep(info["backoff"])
                        info["backoff"] *= 2.0
                        if info["backoff"]>30:
                            info["backoff"] = 30

    # ----------------------------------------------------------------
    # TLS self-signed
    # ----------------------------------------------------------------
    def _generate_self_signed_ssl(self) -> ssl.SSLContext:
        import ssl
        import datetime
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        if self.data_dir:
            os.makedirs(self.data_dir, exist_ok=True)
            cert_path = os.path.join(self.data_dir, f"{self.my_address}_cert.pem")
            key_path = os.path.join(self.data_dir, f"{self.my_address}_key.pem")
        else:
            cert_path = None
            key_path = None

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"{self.my_address}-SelfSigned")
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                critical=False
            )
            .sign(key, hashes.SHA256())
        )

        pem_cert = cert.public_bytes(serialization.Encoding.PEM)
        pem_key = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )

        if cert_path and key_path:
            try:
                with open(cert_path, "wb") as f:
                    f.write(pem_cert)
                with open(key_path, "wb") as f:
                    f.write(pem_key)
                logger.info(f"[NodeNetwork] self-signed => {cert_path}, {key_path}")
            except Exception as e:
                logger.warning(f"[NodeNetwork] can't save TLS cert => {e}")

        with tempfile.NamedTemporaryFile(delete=False) as cf:
            cf.write(pem_cert)
            certf = cf.name
        with tempfile.NamedTemporaryFile(delete=False) as kf:
            kf.write(pem_key)
            keyf = kf.name

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=certf, keyfile=keyf)

        try:
            os.remove(certf)
            os.remove(keyf)
        except:
            pass
        return ctx

    # ----------------------------------------------------------------
    # SERVER-SIDE
    # ----------------------------------------------------------------


    async def handle_connection(self, websocket: websockets.WebSocketServerProtocol, path: str):
   
        ip_addr = self._extract_ip(websocket)
        remote_address = None

        try:
            # Получаем первое сообщение
            raw_msg = await websocket.recv()
            self.logger.info(f"[NodeNetwork {self.my_address}] handle_connection => first msg => {raw_msg[:200]}")
        
            # Проверка лимита частоты запросов
            if not self._check_rate_limit_token(ip_addr):
                await self._close_with_error(websocket, "Rate limit exceeded (initial).")
                return

       
            data = self._safe_json_parse(raw_msg)
            if (not data) or data.get("type") != "register":
                await self._close_with_error(websocket, "First message must be 'register'")
                return

            remote_address = data.get("address")
            if not remote_address:
                await self._close_with_error(websocket, "Missing 'address' in register")
                return

       
            if self.require_signature:
                pubkey = data.get("pubkey")
                if not pubkey:
                    await self._close_with_error(websocket, "Missing 'pubkey' in register message")
                    return

           
                existing_pubkey = self.key_manager.get_ec_pubkey(remote_address)
                if not existing_pubkey:
                    # Сохраняем публичный ключ нового узла
                    self.key_manager.keys[remote_address] = {"public_key": pubkey}
                    self.key_manager._save_keys()
                    self.logger.info(f"[KeyManager] Stored pubkey for {remote_address}")
                else:
               
                    existing_pub_pem = existing_pubkey.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ).decode("utf-8")
                
                    if existing_pub_pem != pubkey:
                        self.logger.warning(f"[KeyManager] Mismatch in pubkey for {remote_address}, updating.")
                        self.key_manager.keys[remote_address]["public_key"] = pubkey
                        self.key_manager._save_keys()

       
            if self.require_auth:
                provided_token = data.get("auth_token", "")
                valid_token = self.auth_tokens.get(remote_address)
                if (not valid_token) or (provided_token != valid_token):
                    await self._close_with_error(websocket, "Auth token invalid.")
                    return

       
            async with self._connections_lock:
                if remote_address in self.connections:
                    await self._close_with_error(websocket, f"Address {remote_address} already connected.")
                    return
                self.connections[remote_address] = websocket

            self.logger.info(f"[NodeNetwork] address={remote_address} connected from IP={ip_addr}")

           
            async for raw_msg2 in websocket:
                self.logger.info(f"[NodeNetwork {self.my_address}] handle_connection => next msg => {raw_msg2[:200]}")
            
           
                if not self._check_rate_limit_token(remote_address):
                    await self._close_with_error(websocket, "Rate limit exceeded.")
                    break

           
                msg_in = self._safe_json_parse(raw_msg2)
                if not msg_in:
                    await self._close_with_error(websocket, "Invalid JSON msg.")
                    continue

            
                if not self._check_replay(msg_in):
                    await self._close_with_error(websocket, "Replay or missing msg_id.")
                    break

           
                if self.require_signature:
                    if not self._verify_message_signature(msg_in):
                        await self._close_with_error(websocket, "Signature check fail.")
                        break

                # Передаём сообщение на обработку
                await self.process_incoming_message(remote_address, msg_in)

        except websockets.ConnectionClosed as cc:
            self.logger.info(f"[NodeNetwork] Connection closed: address={remote_address}, ip={ip_addr}, code={cc.code}")
        except Exception as e:
            self.logger.error(f"[NodeNetwork] handle_connection error => {type(e).__name__}: {e}")
        finally:
       
            async with self._connections_lock:
                if remote_address and remote_address in self.connections:
                    del self.connections[remote_address]
                    self.logger.info(f"[NodeNetwork] address={remote_address} disconnected => {len(self.connections)} left.")


    async def process_incoming_message(self, sender_address: str, data: dict):
        self.logger.info(f"[NodeNetwork {self.my_address}] process_incoming_message => from={sender_address}, data={data}")
        msg_type = data.get("type","")
        if not msg_type:
            self.logger.warning(f"[NodeNetwork {self.my_address}] no 'type' => skip => data={data}")
            return

        rpc_id = data.get("rpc_id")
        if rpc_id and (rpc_id in self.rpc_futures):
            fut = self.rpc_futures[rpc_id]
            if not fut.done():
                fut.set_result(data)
            del self.rpc_futures[rpc_id]
            return

        # ----- turbine/chord/hotstuff -----
        if msg_type == "turbine_packet":
            await self.turbine_manager.handle_incoming_packet(sender_address, data)
            return
        elif msg_type.startswith("chord_"):
            await self._handle_chord_message(sender_address, data)
            return
        elif msg_type.startswith("hotstuff_chain_"):
            await self._handle_hotstuff_message(sender_address, data)
            return

        # ----- ML / PoML -----
        merged_msg = data.copy()
        merged_msg["sender"] = sender_address

        if msg_type == "ml_task":
            if self.mining_module:
                await self.mining_module._handle_incoming_task(merged_msg)
            else:
                self.logger.warning("[NodeNetwork] no mining_module => skip ml_task")

        elif msg_type == "ml_partial_solution":
            if self.mining_module:
                await self.mining_module._handle_incoming_partial(merged_msg)
            else:
                self.logger.warning("[NodeNetwork] no mining_module => skip ml_partial_solution")

        elif msg_type == "ml_solution":
            if self.mining_module:
                await self.mining_module._handle_incoming_solution(merged_msg)
            else:
                self.logger.warning("[NodeNetwork] no mining_module => skip ml_solution")

        elif msg_type == "ml_challenge":
            if self.mining_module:
                await self.mining_module._handle_challenge(merged_msg)
            else:
                self.logger.warning("[NodeNetwork] no mining_module => skip ml_challenge")

        elif msg_type == "ml_challenge_response":
            if self.mining_module:
                await self.mining_module._handle_challenge_response(merged_msg)
            else:
                self.logger.warning("[NodeNetwork] no mining_module => skip ml_challenge_response")

        else:
            # Если сообщение неизвестного типа
            self.logger.info(f"[NodeNetwork {self.my_address}] unknown msg => type={msg_type}")

    # ----------------------------------------------------------------
    # CHORD
    # ----------------------------------------------------------------
    async def _handle_chord_message(self, sender_address: str, data: dict):
        if not self.chord_node:
            logger.warning("[NodeNetwork] no chord_node => skip chord msg.")
            return
        msg_type = data["type"]
        if msg_type == "chord_find_successor":
            hkey = data.get("hkey")
            if hkey is not None:
                s_id, s_hash = await self.chord_node.chord_find_successor(hkey)
                rep = {
                    "type": "chord_find_successor_reply",
                    "successor_id": s_id,
                    "successor_hash": s_hash
                }
                if "rpc_id" in data:
                    rep["rpc_id"] = data["rpc_id"]
                await self._send_to_node(sender_address, rep)

        elif msg_type == "chord_notify":
            pred_id = data.get("pred_id")
            pred_hash = data.get("pred_hash",0)
            if pred_id:
                await self.chord_node.chord_notify(pred_id, pred_hash)

        elif msg_type == "chord_store_req":
            key = data.get("key")
            val_dict = data.get("val_dict")
            if key and val_dict:
                await self.chord_node.chord_store_req(key, val_dict)

        elif msg_type == "chord_get_predecessor":
            if self.chord_node.predecessors:
                p_id, p_hash = self.chord_node.predecessors[0]
            else:
                p_id, p_hash = "", 0
            rep = {
                "type": "chord_get_predecessor_reply",
                "pred_id": p_id,
                "pred_hash": p_hash
            }
            if "rpc_id" in data:
                rep["rpc_id"] = data["rpc_id"]
            await self._send_to_node(sender_address, rep)

        elif msg_type == "chord_get_successor":
            if self.chord_node.successors:
                s_id, s_hash = self.chord_node.successors[0]
            else:
                s_id, s_hash = (self.chord_node.node_id, self.chord_node.node_hash)
            rep = {
                "type": "chord_get_successor_reply",
                "succ_id": s_id,
                "succ_hash": s_hash
            }
            if "rpc_id" in data:
                rep["rpc_id"] = data["rpc_id"]
            await self._send_to_node(sender_address, rep)

        elif msg_type == "chord_get_predecessor_list":
            pl = self.chord_node.predecessors
            arr = [(p[0],p[1]) for p in pl]
            rep = {
                "type": "chord_get_predecessor_list_reply",
                "predecessors": arr
            }
            if "rpc_id" in data:
                rep["rpc_id"] = data["rpc_id"]
            await self._send_to_node(sender_address, rep)

        elif msg_type == "chord_get_successor_list":
            sl = self.chord_node.successors
            arr = [(s[0],s[1]) for s in sl]
            rep = {
                "type": "chord_get_successor_list_reply",
                "successors": arr
            }
            if "rpc_id" in data:
                rep["rpc_id"] = data["rpc_id"]
            await self._send_to_node(sender_address, rep)

        elif msg_type == "chord_gossip_fingers":
            remote_fingers = data.get("fingers", [])
            local_fingers = self.chord_node.fingers[:5] if self.chord_node.fingers else []
            reply_fingers = [(f[0],f[1],f[2]) for f in local_fingers]
            rep = {
                "type": "chord_gossip_fingers_reply",
                "fingers": reply_fingers
            }
            if "rpc_id" in data:
                rep["rpc_id"] = data["rpc_id"]
            await self._send_to_node(sender_address, rep)

        elif msg_type == "chord_ping":
            rep = {"type": "chord_ping_reply", "pong": True}
            if "rpc_id" in data:
                rep["rpc_id"] = data["rpc_id"]
            await self._send_to_node(sender_address, rep)
        else:
            logger.warning(f"[NodeNetwork] unhandled chord msg => {msg_type}")

    # ----------------------------------------------------------------
    # HOTSTUFF
    # ----------------------------------------------------------------
    async def _handle_hotstuff_message(self, sender_addr: str, data: dict):
     
        if not self.hotstuff_consensus:
            logger.warning("[NodeNetwork] no hotstuff_consensus => skip.")
            return

        msg_type = data.get("type", "")

       
        if not self._verify_message_signature(data):
            logger.warning(f"[NodeNetwork] Invalid ECDSA signature => skip hotstuff msg.")
            return

        # Дальше передаём в hotstuff_consensus
        if msg_type == "hotstuff_chain_multi":
            phase = data.get("phase", "")
            if phase == "hotstuff_view_change":
                # специальная ветка: запустить viewChange
                await self.hotstuff_consensus._start_view_change(
                    reason=data.get("reason"),
                    forced_view=data.get("view")
                )
            else:
              
                await self.hotstuff_consensus.handle_phase_message(data, sender_addr)

        elif msg_type == "hotstuff_chain_complaint":
            await self.hotstuff_consensus.handle_complaint_message(data, sender_addr)

        elif msg_type == "hotstuff_chain_timeout":
           
            await self.hotstuff_consensus._handle_timeout(data)

        else:
            logger.warning(f"[NodeNetwork] unknown hotstuff message => {msg_type}")

    async def broadcast_bft_proposal(self, sender_id: str, block_id: str, msg: dict, signature: str):
        """
        Отправка HotStuff-сообщения (PREPARE/COMMIT/ViewChange/etc.) 
        по ECDSA-схеме (без partial_sign).
        """
        msg["sender"] = sender_id
        msg["signature"] = signature
        # Нет вызова threshold_bls.partial_sign(...)!

        async with self._connections_lock:
            addrs = list(self.connections.keys())

        # Рассылаем всем
        for peer in addrs:
            try:
                await self._send_to_node(peer, msg)
            except Exception as e:
                logger.warning(f"[NodeNetwork] Failed to send BFT proposal to {peer}: {e}")

    # ----------------------------------------------------------------
    # FEC
    # ----------------------------------------------------------------
    def _on_fec_assembled(self, flow_id: bytes, full_data: bytes):
        try:
            block_data = json.loads(full_data.decode('utf-8'))
            logger.info(f"[NodeNetwork] fec_assembled => flow_id={flow_id.hex()}, keys={list(block_data.keys())}")
        except Exception as e:
            logger.warning(f"[NodeNetwork] fec_assembled => parse error => {e}")

    # ----------------------------------------------------------------
    # Send methods
    # ----------------------------------------------------------------
    async def broadcast_transaction(self, msg: dict):
        msg["msg_id"] = str(uuid4())
        raw = json.dumps(msg)
        async with self._connections_lock:
            tasks = []
            for addr, ws in self.connections.items():
                tasks.append(self._send_raw(ws, raw, node_id=addr))
            await asyncio.gather(*tasks, return_exceptions=True)

    async def send_transaction(self, msg: dict, recipient_address: str):
        msg["msg_id"] = str(uuid4())
        raw = json.dumps(msg)
        async with self._connections_lock:
            ws = self.connections.get(recipient_address)
            if not ws:
                self.logger.warning(f"[NodeNetwork] no ws => {recipient_address}, skip send.")
                return
        await self._send_raw(ws, raw, node_id=recipient_address)

    async def _send_to_node(self, address: str, msg: dict):
        msg["msg_id"] = msg.get("msg_id") or str(uuid4())
        raw = json.dumps(msg)
        async with self._connections_lock:
            ws = self.connections.get(address)
            if not ws:
                self.logger.warning(f"[NodeNetwork] _send_to_node => no ws => {address}")
                return
        try:
            await self._send_raw(ws, raw, node_id=address)
        except Exception as e:
            self.logger.error(f"[NodeNetwork {self.my_address}] _send_to_node => {address}, error => {e}")

    async def _send_raw(self, ws: websockets.WebSocketServerProtocol, raw: str, node_id: str):
        self.logger.debug(f"[NodeNetwork {self.my_address}] _send_raw => to={node_id}, raw[:200]={raw[:200]}")
        try:
            await asyncio.wait_for(ws.send(raw), timeout=self.SEND_TIMEOUT)
        except asyncio.TimeoutError:
            self.logger.warning(f"[NodeNetwork] _send_raw => timeout => {node_id}")
        except asyncio.CancelledError as ce:
            self.logger.error(f"[NodeNetwork] _send_raw => CANCELLED => {ce}", exc_info=True)
            raise
        except Exception as e:
            self.logger.warning(f"[NodeNetwork] _send_raw => error => {node_id}, e={e}")

   
    def _extract_ip(self, ws: websockets.WebSocketServerProtocol) -> str:
        if ws.remote_address:
            return ws.remote_address[0]
        return "unknown"

    async def _close_with_error(self, ws: websockets.WebSocketServerProtocol, reason: str):
        self.logger.warning(f"[NodeNetwork {self.my_address}] _close_with_error => reason={reason}")
        resp = {"type": "error", "message": reason}
        try:
            await asyncio.wait_for(ws.send(json.dumps(resp)), timeout=3.0)
        except:
            pass
        await ws.close(reason=reason)

    def _safe_json_parse(self, raw: str) -> Optional[dict]:
        try:
            return json.loads(raw)
        except:
            return None

    def _check_rate_limit_token(self, client_id: str) -> bool:
        now = time.time()
        bucket = self.token_buckets.get(client_id)
        if not bucket:
            bucket = {"tokens": float(self.rate_limit_capacity), "last_time": now}
            self.token_buckets[client_id] = bucket

        elapsed = now - bucket["last_time"]
        refill = elapsed * self.rate_limit_refill_rate
        new_tokens = bucket["tokens"] + refill
        if new_tokens > self.rate_limit_capacity:
            new_tokens = float(self.rate_limit_capacity)
        if new_tokens < 1.0:
            return False

        bucket["tokens"] = new_tokens - 1.0
        bucket["last_time"] = now
        return True

    def _check_replay(self, msg: dict) -> bool:
        msg_id = msg.get("msg_id")
        if not msg_id:
            return False
        now = time.time()
        if msg_id in self._recent_msg_ids:
            return False
        self._recent_msg_ids[msg_id] = now
        return True

    def _verify_message_signature(self, msg: dict) -> bool:
    
        msg_type = msg.get("type", "")
    
        CRITICAL_TYPES = ["hotstuff_chain_multi", "transaction_broadcast", "stakeTx"]
        if msg_type in CRITICAL_TYPES:
            sender_addr = msg.get("sender")
            signature_hex = msg.get("signature")
        
       
            if not sender_addr or not signature_hex:
                self.logger.warning("[NodeNetwork] signature => missing sender or signature.")
                return False
        
        
            if not self.key_manager:
                self.logger.warning("[NodeNetwork] signature => no key_manager => fail.")
                return False
        
       
            msg_cpy = dict(msg)
            for f in ("signature", "msg_id", "rpc_id", "type", "phase"):
                msg_cpy.pop(f, None)

        
            ok = self.key_manager.verify_transaction(sender_addr, msg_cpy, signature_hex)
            if not ok:
                self.logger.warning("[NodeNetwork] signature => invalid signature.")
                return False
        
       
            return True
        else:
        
            return True
      
    async def send_chord_find_successor(self, target_addr: str, hkey: int) -> Tuple[str,int]:
        rpc_id = str(uuid4())
        fut = asyncio.get_event_loop().create_future()
        self.rpc_futures[rpc_id] = fut
        req = {
            "type": "chord_find_successor",
            "rpc_id": rpc_id,
            "hkey": hkey,
            "msg_id": str(uuid4())
        }
        await self._send_to_node(target_addr, req)
        try:
            reply = await asyncio.wait_for(fut, timeout=self.SEND_TIMEOUT)
        except asyncio.TimeoutError:
            raise RuntimeError(f"Timeout chord_find_successor => {target_addr}")

        succ_id = reply.get("successor_id")
        succ_hash = reply.get("successor_hash")
        return succ_id, succ_hash
      
    def _sign_message(self, msg: dict, sender_addr: str) -> str:
        
        if not self.key_manager:
            raise ValueError("[NodeNetwork] _sign_message => no key_manager configured.")

       
        msg_cpy = dict(msg)

        
        for f in ("signature", "msg_id", "rpc_id", "type", "phase"):
            msg_cpy.pop(f, None)

       
        raw = json.dumps(msg_cpy, sort_keys=True).encode("utf-8")

        
        privkey = self.key_manager.get_ec_privkey(sender_addr)
        if not privkey:
            raise ValueError(f"[NodeNetwork] _sign_message => no EC privkey for {sender_addr}")

      
        signature_bin = privkey.sign(raw, ec.ECDSA(hashes.SHA256()))
        signature_hex = signature_bin.hex()

        return signature_hex            
