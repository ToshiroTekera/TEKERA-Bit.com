import logging
import asyncio
import json
import hashlib
import time
import os
from typing import Optional, Dict, Any, List

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logging.basicConfig(level=logging.INFO)

class CRDTCell:
    """
    Ячейка 3D-CRDT, хранит (value, timestamp).
    """
    def __init__(self, value: Any = None, timestamp: float = 0.0):
        self.value = value
        self.timestamp = timestamp

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "timestamp": self.timestamp
        }

    @staticmethod
    def from_dict(d: dict) -> "CRDTCell":
        return CRDTCell(
            value=d.get("value"),
            timestamp=d.get("timestamp", 0.0)
        )



class CubicMatrix:
    def __init__(
        self,
        node_id: str,
        chord_node=None,   # ChordNode
        network=None,      # NodeNetwork (для TurbineManager, FecChannel)
        key_manager=None,  
        poh=None,
        dimension: (int,int,int) = (8,8,8),
        shard_size: int = 4,
        use_encryption: bool = False,
        data_file: Optional[str] = None
    ):
        self.node_id = node_id
        self.chord_node = chord_node
        self.network = network
        self.key_manager = key_manager
        self.poh = poh
        self.dimension = dimension
        self.shard_size = shard_size
        self.use_encryption = use_encryption

        x, y, z = dimension
        # Инициализируем 3D-матрицу CRDTCell
        self.matrix: List[List[List[CRDTCell]]] = [
            [
                [CRDTCell() for _ in range(z)]
                for _ in range(y)
            ]
            for _ in range(x)
        ]

        # shard_info: индекс шарда -> {version, nonce, signature, hash}
        self.shard_info: Dict[int, Dict[str, Any]] = {}

        # Генерируем aes_key, если use_encryption
        self.aes_key = None
        if self.use_encryption:
            self.aes_key = AESGCM.generate_key(bit_length=256)

        # Локальный файл
        if not data_file:
            self.data_file = f"cubic_matrix_{node_id}.json"
        else:
            self.data_file = data_file

        # Блокировка (асинхронная) для операций с self.matrix
        self._matrix_lock = asyncio.Lock()

        logging.info(f"[CubicMatrix] init => node={node_id}, dimension={dimension}, "
                     f"shard_size={shard_size}, encryption={use_encryption}")

        # Пытаемся загрузить локальные данные (demo)
        self._load_local_data()

    # ----------------------------------------------------------------
    # set_value / get_value
    # ----------------------------------------------------------------
    async def set_value(self, x: int, y: int, z: int, value: Any):
        ts = time.time()
        async with self._matrix_lock:
            self._apply_local(x, y, z, value, ts)
        # При желании можно auto-save

    def _apply_local(self, x: int, y: int, z: int, value: Any, ts: float):
        if not (0 <= x < self.dimension[0] and 0 <= y < self.dimension[1] and 0 <= z < self.dimension[2]):
            logging.error(f"[CubicMatrix {self.node_id}] out-of-range coords => ({x},{y},{z})")
            return
        cell = self.matrix[x][y][z]
        if ts > cell.timestamp:
            cell.value = value
            cell.timestamp = ts
            logging.info(f"[CubicMatrix {self.node_id}] set_value({x},{y},{z}) => {value}, ts={ts}")

    async def get_value(self, x: int, y: int, z: int) -> Any:
        if not (0 <= x < self.dimension[0] and 0 <= y < self.dimension[1] and 0 <= z < self.dimension[2]):
            raise IndexError("Coordinates out of range.")
        async with self._matrix_lock:
            return self.matrix[x][y][z].value

    # ----------------------------------------------------------------
    # Shard operations
    # ----------------------------------------------------------------
    def get_shard_data(self, shard_index: int) -> Dict:
        """
        Извлекаем срез [x_start..x_end) по X.
        """
        x_start = shard_index * self.shard_size
        x_end = min((shard_index + 1)*self.shard_size, self.dimension[0])
        shard_3d = []

        for xx in range(x_start, x_end):
            row_2d = []
            for yy in range(self.dimension[1]):
                row_1d = []
                for zz in range(self.dimension[2]):
                    c = self.matrix[xx][yy][zz]
                    row_1d.append(c.to_dict())
                row_2d.append(row_1d)
            shard_3d.append(row_2d)

        return {
            "node_id": self.node_id,
            "shard_index": shard_index,
            "x_range": [x_start, x_end],
            "dimension": self.dimension,
            "shard_data": shard_3d
        }

    def apply_shard_data(self, shard_payload: dict):
        shard_index = shard_payload["shard_index"]
        x_start, x_end = shard_payload["x_range"]
        shard_3d = shard_payload["shard_data"]

        for local_x, block_2d in enumerate(shard_3d):
            real_x = x_start + local_x
            for yy, row_1d in enumerate(block_2d):
                for zz, cell_dict in enumerate(row_1d):
                    incoming = CRDTCell.from_dict(cell_dict)
                    local_cell = self.matrix[real_x][yy][zz]
                    # CRDT merge => Last-Write-Wins
                    if incoming.timestamp > local_cell.timestamp:
                        self.matrix[real_x][yy][zz] = incoming

        logging.info(f"[CubicMatrix {self.node_id}] apply_shard_data => shard={shard_index} merged")

    def compute_shard_hash(self, shard_index: int) -> str:
        shard_data = self.get_shard_data(shard_index)
        raw = json.dumps(shard_data, sort_keys=True).encode('utf-8')
        return hashlib.sha256(raw).hexdigest()

    def sign_shard(self, shard_index: int):
        info = self.shard_info.get(shard_index, {
            "version": 0, "nonce": None, "signature": None, "hash": None
        })
        info["version"] += 1

        if self.use_encryption:
            nonce = os.urandom(12)
            info["nonce"] = nonce
        else:
            info["nonce"] = None

        shard_hash = self.compute_shard_hash(shard_index)
        info["hash"] = shard_hash

        if self.key_manager and (self.node_id in self.key_manager.keys):
            sign_data = {
                "node_id": self.node_id,
                "shard_index": shard_index,
                "version": info["version"],
                "hash": shard_hash
            }
            sig_hex = self.key_manager.sign_transaction(self.node_id, sign_data)
            info["signature"] = sig_hex

        self.shard_info[shard_index] = info
        logging.info(f"[CubicMatrix] shard={shard_index} signed => ver={info['version']}, hash={shard_hash}")

    def verify_shard_signature(self, shard_index: int) -> bool:
        info = self.shard_info.get(shard_index)
        if not info:
            logging.warning(f"[CubicMatrix] no shard_info for idx={shard_index}")
            return False
        if not info.get("signature") or not self.key_manager:
            logging.warning(f"[CubicMatrix] shard={shard_index}, no signature or no key_manager.")
            return False

        sign_data = {
            "node_id": self.node_id,
            "shard_index": shard_index,
            "version": info["version"],
            "hash": info["hash"]
        }
        sig_hex = info["signature"]
        ok = self.key_manager.verify_transaction(self.node_id, sign_data, sig_hex)
        logging.info(f"[CubicMatrix] verify_shard => idx={shard_index}, valid={ok}")
        return ok

    def _encrypt_bytes(self, shard_index: int, data_bytes: bytes) -> bytes:
        if not self.use_encryption:
            return data_bytes
        info = self.shard_info.get(shard_index)
        if not info or not info["nonce"]:
            return data_bytes

        aesgcm = AESGCM(self.aes_key)
        return aesgcm.encrypt(info["nonce"], data_bytes, None)

    def _decrypt_bytes(self, shard_index: int, enc_bytes: bytes) -> bytes:
        if not self.use_encryption:
            return enc_bytes
        info = self.shard_info.get(shard_index)
        if not info or not info["nonce"]:
            return enc_bytes

        aesgcm = AESGCM(self.aes_key)
        return aesgcm.decrypt(info["nonce"], enc_bytes, None)


    async def load_shard_from_chord(self, shard_index: int):
        if not self.chord_node:
            logging.warning("[CubicMatrix] load_shard_from_chord => no chord_node => skip.")
            return

        key = f"cubic_matrix_{self.node_id}_shard_{shard_index}"
        lww_val = self.chord_node.get_local(key)
        if not lww_val:
            logging.warning(f"[CubicMatrix] no shard data => shard={shard_index} => skip.")
            return

        data_hex = lww_val.value
        if not isinstance(data_hex, str):
            logging.error("[CubicMatrix] load_shard_from_chord => data not str => skip.")
            return

        try:
            enc_bytes = bytes.fromhex(data_hex)
        except ValueError:
            logging.error("[CubicMatrix] load_shard_from_chord => invalid hex => skip.")
            return

        dec_bytes = self._decrypt_bytes(shard_index, enc_bytes)
        record = json.loads(dec_bytes.decode('utf-8'))

        new_ver = record["version"]
        old_info = self.shard_info.get(shard_index, {"version":0,"nonce":None,"signature":None,"hash":None})
        if new_ver <= old_info["version"]:
            logging.warning(f"[CubicMatrix] shard={shard_index} older ver={new_ver} <= local={old_info['version']} => skip.")
            return

        # 1) apply_shard_data
        shard_data = record["shard_data"]
        await self._apply_shard_data_async(shard_data)

        # 2) обновляем shard_info
        shard_hash = self.compute_shard_hash(shard_index)
        self.shard_info[shard_index] = {
            "version": new_ver,
            "nonce": bytes.fromhex(record["nonce"]) if record["nonce"] else None,
            "signature": record["signature"],
            "hash": shard_hash
        }
        logging.info(f"[CubicMatrix] load_shard_from_chord => shard={shard_index}, ver={new_ver}")

    async def _apply_shard_data_async(self, shard_data: dict):
        async with self._matrix_lock:
            self.apply_shard_data(shard_data)

    # ----------------------------------------------------------------
    # PoH support
    # ----------------------------------------------------------------
    def get_shard_indices(self) -> range:
        total_x = self.dimension[0]
        num_shards = (total_x + self.shard_size - 1) // self.shard_size
        return range(num_shards)

    def compute_global_root(self) -> str:
        shard_hashes = []
        for idx in self.get_shard_indices():
            info = self.shard_info.get(idx)
            if info and info.get("hash"):
                shard_hashes.append(info["hash"])
        shard_hashes.sort()
        joined = "".join(shard_hashes).encode('utf-8')
        return hashlib.sha256(joined).hexdigest()

    def record_in_poh(self, description="CRDT CubicMatrix global"):
        if not self.poh:
            return
        root = self.compute_global_root()
        event_data = {
            "type": "crdt_matrix_merkle",
            "node_id": self.node_id,
            "root_hash": root,
            "description": description
        }
        self.poh.record_event(event_data)
        logging.info(f"[CubicMatrix] record_in_poh => root={root}, desc={description}")

    async def consensus_commit(self, shard_index: int):
        self.sign_shard(shard_index)
        info = self.shard_info[shard_index]
        if self.poh:
            shard_hash = info["hash"]
            event_data = {
                "type": "crdt_shard_commit",
                "shard_index": shard_index,
                "hash": shard_hash,
                "node_id": self.node_id
            }
            self.poh.record_event(event_data)
            logging.info(f"[CubicMatrix] shard={shard_index} committed in PoH, hash={shard_hash}")

    # ----------------------------------------------------------------
    # Локальное сохранение всей 3D-матрицы (demo)
    # ----------------------------------------------------------------
    async def save_local_data(self):
        """
        Сохраняем весь 3D-массив (matrix) + shard_info в JSON-файл.
        """
        try:
            async with self._matrix_lock:
                matrix_list = []
                for xx in range(self.dimension[0]):
                    row_2d = []
                    for yy in range(self.dimension[1]):
                        row_1d = []
                        for zz in range(self.dimension[2]):
                            c = self.matrix[xx][yy][zz]
                            row_1d.append(c.to_dict())
                        row_2d.append(row_1d)
                    matrix_list.append(row_2d)

                data = {
                    "dimension": self.dimension,
                    "matrix": matrix_list,
                    "shard_info": {}
                }
                for idx, info in self.shard_info.items():
                    rec = {
                        "version": info["version"],
                        "nonce": info["nonce"].hex() if info["nonce"] else None,
                        "signature": info["signature"],
                        "hash": info["hash"]
                    }
                    data["shard_info"][str(idx)] = rec

            with open(self.data_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)

            logging.info(f"[CubicMatrix] save_local_data => wrote {self.data_file}")
        except Exception as e:
            logging.error(f"[CubicMatrix] save_local_data => error => {e}")

    def _load_local_data(self):
        """
        Загружаем из файла, восстанавливаем matrix + shard_info.
        """
        if not os.path.isfile(self.data_file):
            logging.info(f"[CubicMatrix] no local file => skip => {self.data_file}")
            return

        try:
            with open(self.data_file, "r", encoding="utf-8") as f:
                raw = json.load(f)

            dim = raw.get("dimension", (8,8,8))
            if tuple(dim) != self.dimension:
                logging.warning(f"[CubicMatrix] loaded dimension={dim} != current={self.dimension}")

            mat = raw.get("matrix", [])
            if len(mat) != self.dimension[0]:
                logging.warning("[CubicMatrix] loaded matrix size mismatch => skip load.")
                return

            for xx in range(self.dimension[0]):
                row_2d = mat[xx]
                for yy in range(self.dimension[1]):
                    row_1d = row_2d[yy]
                    for zz in range(self.dimension[2]):
                        c_dict = row_1d[zz]
                        cell_obj = CRDTCell.from_dict(c_dict)
                        self.matrix[xx][yy][zz] = cell_obj

            loaded_shard_info = raw.get("shard_info", {})
            for k,v in loaded_shard_info.items():
                idx = int(k)
                rec = {
                    "version": v["version"],
                    "nonce": bytes.fromhex(v["nonce"]) if v["nonce"] else None,
                    "signature": v["signature"],
                    "hash": v["hash"]
                }
                self.shard_info[idx] = rec

            logging.info(f"[CubicMatrix] _load_local_data => loaded from {self.data_file}")

        except Exception as e:
            logging.error(f"[CubicMatrix] _load_local_data => error => {e}")
                  
    # ----------------------------------------------------------------
    # Шард -> Chord
    # ----------------------------------------------------------------
    async def store_shard_in_chord(self, shard_index: int):
        """
        (Без изменений, но можно добавить вызов TurbineManager перед CRDT)
        """
        if not self.chord_node:
            logging.warning("[CubicMatrix] store_shard_in_chord => no chord_node => skip.")
            return

        # 1) sign_shard
        if shard_index not in self.shard_info:
            self.shard_info[shard_index] = {"version": 0,"nonce":None,"signature":None,"hash":None}
        self.sign_shard(shard_index)

        info = self.shard_info[shard_index]
        record = {
            "version": info["version"],
            "nonce": info["nonce"].hex() if info["nonce"] else None,
            "signature": info["signature"],
            "shard_data": self.get_shard_data(shard_index)
        }

        raw = json.dumps(record, sort_keys=True).encode('utf-8')
        enc_data = self._encrypt_bytes(shard_index, raw)

        from chordnode import LWWValue
        now_ts = time.time()
        val_obj = LWWValue(enc_data.hex(), now_ts)

        key = f"cubic_matrix_{self.node_id}_shard_{shard_index}"
        await self.chord_node.replicate_locally(key, val_obj)
        logging.info(f"[CubicMatrix] store_shard_in_chord => shard={shard_index}, ver={info['version']} saved")

    # ----------------------------------------------------------------
    # Передача шарда через Network (Turbine / FEC)
    # ----------------------------------------------------------------
    async def broadcast_shard(self, shard_index: int):
        """
        Старый метод: просто network.broadcast_transaction(...) => JSON.
        Если шард большой, могут быть проблемы.
        """
        if not self.network:
            logging.error("[CubicMatrix] broadcast_shard => no network => skip.")
            return
        if shard_index not in self.shard_info:
            self.shard_info[shard_index] = {"version":0,"nonce":None,"signature":None,"hash":None}
        self.sign_shard(shard_index)

        info = self.shard_info[shard_index]
        shard_data = self.get_shard_data(shard_index)
        msg = {
            "type": "cubic_matrix_shard_crdt",
            "node_id": self.node_id,
            "shard_index": shard_index,
            "version": info["version"],
            "signature": info["signature"],
            "shard_payload": shard_data
        }
        await self.network.broadcast_transaction(self.node_id, msg)
        logging.info(f"[CubicMatrix] broadcast_shard => shard={shard_index}, ver={info['version']}")

    async def turbine_broadcast_shard(self, shard_index: int, all_peers: List[str], fanout: int = 3):
        """
        Пример chunk+lz4 через TurbineManager
        """
        if not self.network or not hasattr(self.network, "turbine_manager"):
            logging.error("[CubicMatrix] turbine_broadcast_shard => no turbine_manager => skip.")
            return

        if shard_index not in self.shard_info:
            self.shard_info[shard_index] = {"version":0,"nonce":None,"signature":None,"hash":None}
        self.sign_shard(shard_index)

        info = self.shard_info[shard_index]
        # Если шард большой => chunk
        shard_dict = {
            "type": "cubic_matrix_shard_crdt",
            "node_id": self.node_id,
            "shard_index": shard_index,
            "version": info["version"],
            "signature": info["signature"],
            "shard_payload": self.get_shard_data(shard_index)
        }
        data_bytes = json.dumps(shard_dict).encode('utf-8')

        flow_id = f"{self.node_id}_shard_{shard_index}"
        await self.network.turbine_manager.start_broadcast_data(
            flow_id=flow_id,
            data_bytes=data_bytes,
            all_peers=all_peers,
            fanout=fanout
        )
        logging.info(f"[CubicMatrix] turbine_broadcast_shard => shard={shard_index}, flow_id={flow_id}, fanout={fanout}")

    def fec_broadcast_shard(self, shard_index: int):
        """
        Пример использования FecChannel (WebRTC).
        """
        if not self.network or not hasattr(self.network, "fec_channel") or not self.network.fec_channel:
            logging.error("[CubicMatrix] fec_broadcast_shard => no fec_channel => skip.")
            return

        if shard_index not in self.shard_info:
            self.shard_info[shard_index] = {"version":0,"nonce":None,"signature":None,"hash":None}
        self.sign_shard(shard_index)

        info = self.shard_info[shard_index]
        shard_dict = {
            "type": "cubic_matrix_shard_crdt",
            "node_id": self.node_id,
            "shard_index": shard_index,
            "version": info["version"],
            "signature": info["signature"],
            "shard_payload": self.get_shard_data(shard_index)
        }
        raw_js = json.dumps(shard_dict)
        self.network.fec_channel.send_file(raw_js.encode("utf-8"))
        logging.info(f"[CubicMatrix] fec_broadcast_shard => shard={shard_index}, size={len(raw_js)}")

   
    def merge_shard_if_newer(self, shard_index: int, new_data: dict, new_version: int, new_signature: str):
        """
        Сравниваем версию, если новее - применяем, пересчитываем hash, обновляем shard_info.
        """
        old_info = self.shard_info.get(shard_index, {"version":0,"nonce":None,"signature":None,"hash":None})
        if new_version <= old_info["version"]:
            logging.info(f"[CubicMatrix] ignoring shard={shard_index}, new_ver={new_version} <= local={old_info['version']}")
            return

        self.apply_shard_data(new_data)

        new_hash = self.compute_shard_hash(shard_index)
        self.shard_info[shard_index] = {
            "version": new_version,
            "nonce": None,
            "signature": new_signature,
            "hash": new_hash
        }
        logging.info(f"[CubicMatrix] merge_shard_if_newer => shard={shard_index}, ver={new_version}, new_hash={new_hash}")

    