import logging
import asyncio
import os
import json
import time
import numpy as np
import matplotlib.pyplot as plt
import tensorflow as tf

from dataclasses import dataclass
from typing import Optional, Any, Dict, List
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logging.basicConfig(level=logging.INFO)

@dataclass
class Task:
    """
    Задача для PoML (classification).
    """
    task_id: str
    data: Dict[str, Any]
    task_type: str
    difficulty: int
    labels: Optional[np.ndarray] = None
    solved: bool = False
    solved_by: str = ""

    def mark_solved(self, result, solved_by: str):
        self.solved = True
        self.solved_by = solved_by


class MLTrainer:
    

    def __init__(
        self,
        learning_rate: float = 0.001,
        epochs: int = 10,
        model_file: str = "ml_trainer_model.bin",
        passphrase: Optional[str] = None,
        use_encryption: bool = True,
        ephemeral_mode: bool = False,
        task_manager=None,
        cubic_matrix=None
    ):
       
        self.learning_rate = learning_rate
        self.epochs = epochs
        self.model_file = model_file
        self.use_encryption = use_encryption and (not ephemeral_mode)
        self.ephemeral_mode = ephemeral_mode

        
        self.task_manager = task_manager
        self.cubic_matrix = cubic_matrix

        
        self.model: Optional[tf.keras.Model] = None
        self._ml_lock = asyncio.Lock()

        
        self.secret_key: Optional[bytes] = None
        if passphrase and self.use_encryption:
            self.secret_key = self._derive_key_from_passphrase(passphrase, salt="MLTrainerSalt")

        
        self._training_logs: Dict[str, List[Dict[str, float]]] = {}

        
        self.real_X: Optional[np.ndarray] = None
        self.real_y: Optional[np.ndarray] = None

        logging.info(f"[MLTrainer] init => ephemeral={self.ephemeral_mode}, encryption={self.use_encryption}")

        if not self.ephemeral_mode:
            self._load_model_weights()

 
    def load_real_dataset(self, X: np.ndarray, y: np.ndarray):
      
        if len(X) != len(y):
            logging.error("[MLTrainer] load_real_dataset => mismatch len(X), len(y)")
            return
        self.real_X = X
        self.real_y = y
        logging.info(f"[MLTrainer] load_real_dataset => loaded real data => samples={len(X)}")

 
    def build_neural_network(self, input_dim: int, layers: list) -> tf.keras.Model:
       
        model = tf.keras.Sequential()
        model.add(tf.keras.layers.InputLayer(shape=(input_dim,)))
        for (size, activation) in layers:
            model.add(tf.keras.layers.Dense(size, activation=activation))

        loss_fn = "sparse_categorical_crossentropy"
        opt = tf.keras.optimizers.Adam(learning_rate=self.learning_rate)
        model.compile(optimizer=opt, loss=loss_fn, metrics=['accuracy'])
        return model

    def train(
        self,
        X: np.ndarray,
        y: np.ndarray,
        input_dim: int,
        layers: list,
        epochs: int = 10,
        batch_size: int = 32,
        visualize: bool = False
    ):
     
        self.model = self.build_neural_network(input_dim, layers)
        history = self.model.fit(X, y, epochs=epochs, batch_size=batch_size, verbose=1)
        if visualize:
            self._plot_training(history)
        return history


    async def train_partial(
        self,
        X: np.ndarray,
        y: np.ndarray,
        epochs: int = 5,
        batch_size: int = 32,
        initial_state: Optional[list] = None,
        task_id: Optional[str] = None
    ) -> Dict[str, Any]:
    
        async with self._ml_lock:
           
            if not self.model:
                default_layers = [(64,'relu'), (10,'softmax')]
                self.model = self.build_neural_network(X.shape[1], default_layers)

            
            if initial_state is not None:
                self._set_flat_weights(self.model, initial_state)

            hist = self.model.fit(X, y, epochs=epochs, batch_size=batch_size, verbose=0)
            final_acc = float(hist.history['accuracy'][-1])
            final_loss = float(hist.history['loss'][-1])

            # Логи:
            if task_id:
                if task_id not in self._training_logs:
                    self._training_logs[task_id] = []
                for ep_i in range(epochs):
                    ep_acc = float(hist.history['accuracy'][ep_i])
                    ep_loss = float(hist.history['loss'][ep_i])
                    self._training_logs[task_id].append({"epoch": ep_i+1, "acc": ep_acc, "loss": ep_loss})

            
            wlist = [w.flatten().tolist() for w in self.model.get_weights()]
            await self._save_model_weights()

            return {
                "state": wlist,
                "accuracy": final_acc,
                "loss": final_loss,
                "epochs_trained": epochs
            }


    def predict(self, model_state: list, X_array: np.ndarray) -> list:
   
        if self.model is None:
            if len(X_array.shape) < 2:
                raise ValueError(f"X_array shape={X_array.shape} not suitable for a NN input.")
            input_dim = X_array.shape[1]
            default_layers = [(64, 'relu'), (10, 'softmax')]
            self.model = self.build_neural_network(input_dim, default_layers)
  
        self._set_flat_weights(self.model, model_state)
   
        preds_prob = self.model.predict(X_array)
        preds = np.argmax(preds_prob, axis=1).tolist()

        return preds

    async def solve_task(
        self,
        task: "Task",
        layers: list = None,
        node_id: str = "",
        partial_mode: bool = True
    ) -> Any:
        
        ttype = task.task_type
        if ttype != "classification":
            logging.error(f"[MLTrainer] solve_task => only classification. Got {ttype}")
            return None

        X_train = np.array(task.data["X_train"], dtype=np.float32)
        y_train = np.array(task.data["y_train"], dtype=np.int32)
        set_layers = task.data.get("layers", [(64,'relu'),(10,'softmax')])
        input_dim = X_train.shape[1]

        try:
            if partial_mode:
                out = await self.train_partial(X_train, y_train, epochs=self.epochs)
                final_state = out["state"]
                task.mark_solved(final_state, f"trainer_node={node_id}")
                logging.info(f"[MLTrainer] solve_task(partial) => acc={out['accuracy']:.3f}")
                return final_state
            else:
                # Синхронная
                self.train(
                    X_train, y_train,
                    input_dim=input_dim,
                    layers=set_layers,
                    epochs=self.epochs
                )
                final_state = [w.flatten() for w in self.model.get_weights()]
                task.mark_solved(final_state, f"trainer_node={node_id}")
                logging.info("[MLTrainer] solve_task(sync) => done")
                return final_state
        except Exception as e:
            logging.error(f"[MLTrainer] solve_task => error => {e}")
            return None

    
    def generate_classification_data_shard(self, shard_index: int = 0, shard_size: int = 300) -> dict:
      
        if self.real_X is None or self.real_y is None:
            logging.warning("[MLTrainer] no real dataset => fallback random shard.")
            return self.generate_classification_data(num_samples=shard_size)

        start = shard_index * shard_size
        end = min(len(self.real_X), start + shard_size)
        X_shard = self.real_X[start:end]
        y_shard = self.real_y[start:end]
        if len(X_shard) == 0:
            logging.warning("[MLTrainer] shard => empty => fallback random")
            return self.generate_classification_data(num_samples=shard_size)

        # Делим на train/val
        val_split = 0.2
        tr_sz = int(len(X_shard)*(1 - val_split))
        X_train, y_train = X_shard[:tr_sz], y_shard[:tr_sz]
        X_val,   y_val   = X_shard[tr_sz:], y_shard[tr_sz:]

        return {
            "X_train": X_train,
            "y_train": y_train,
            "X_val":   X_val,
            "y_val":   y_val
        }

   
    def generate_classification_data(
        self,
        seed: int = 0,
        num_samples: int = 300,
        input_dim: int = 10,
        num_classes: int = 3,
        val_split: float = 0.2
    ) -> dict:
        """
        Fallback: генерируем random, если нет self.real_X.
        """
        if self.real_X is not None and self.real_y is not None:
           
            logging.warning("[MLTrainer] fallback random data, though real dataset is present? Check usage.")
        np.random.seed(seed)
        X = np.random.randn(num_samples, input_dim)
        y = np.random.randint(0, num_classes, size=num_samples)
        train_size = int(num_samples*(1-val_split))
        X_train, y_train = X[:train_size], y[:train_size]
        X_val,   y_val   = X[train_size:], y[train_size:]
        return {
            "X_train": X_train,
            "y_train": y_train,
            "X_val":   X_val,
            "y_val":   y_val
        }

    def verify_classification_solution(self, data_dict, weights) -> bool:
     
        X_val = data_dict["X_val"]
        y_val = data_dict["y_val"]
        target_acc = data_dict.get("target_acc", 0.8)
        layers = data_dict.get("layers", [(64,'relu'),(10,'softmax')])

        model = self.build_neural_network(X_val.shape[1], layers)
        self._set_flat_weights(model, weights)
        loss, acc = model.evaluate(X_val, y_val, verbose=0)
        logging.info(f"[MLTrainer] verify => val_acc={acc:.3f}, need>={target_acc}")
        return (acc >= target_acc)


    async def _save_model_weights(self):
      
        if self.ephemeral_mode or not self.model:
            return
        try:
            weights = self.model.get_weights()
            arr_list = [w.tolist() for w in weights]
            data_js = json.dumps(arr_list)
            raw_bytes = data_js.encode('utf-8')

            if self.use_encryption and self.secret_key:
                raw_bytes = self._encrypt_aes(raw_bytes)

            tmp_file = self.model_file + ".tmp"
            with open(tmp_file, "wb") as f:
                f.write(raw_bytes)
            os.replace(tmp_file, self.model_file)
            logging.info(f"[MLTrainer] model weights saved => {self.model_file}, encrypt={self.use_encryption}")

        except Exception as e:
            logging.error(f"[MLTrainer] _save_model_weights => {e}")

    def _load_model_weights(self):
        if self.ephemeral_mode or (not os.path.isfile(self.model_file)):
            return
        try:
            with open(self.model_file, "rb") as f:
                enc_bytes = f.read()
            if self.use_encryption and self.secret_key:
                enc_bytes = self._decrypt_aes(enc_bytes)

            arr_list = json.loads(enc_bytes.decode('utf-8'))
            logging.info(f"[MLTrainer] loaded model weights => {self.model_file}, arrays={len(arr_list)}")
            # Не вставляем автоматически, т.к. не знаем shape/layers

        except Exception as e:
            logging.error(f"[MLTrainer] _load_model_weights => {e}")

    def _encrypt_aes(self, plain: bytes) -> bytes:
        aes = AESGCM(self.secret_key)
        nonce = os.urandom(12)
        ct = aes.encrypt(nonce, plain, None)
        return nonce + ct

    def _decrypt_aes(self, enc: bytes) -> bytes:
        aes = AESGCM(self.secret_key)
        if len(enc) < 12:
            raise ValueError("encrypted data too short")
        nonce = enc[:12]
        ciph = enc[12:]
        return aes.decrypt(nonce, ciph, None)

    def _derive_key_from_passphrase(self, passphrase: str, salt: str) -> bytes:
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt.encode('utf-8'),
            iterations=100_000
        )
        return kdf.derive(passphrase.encode('utf-8'))

    # ----------------------------------------------------------------
    # 10) Helpers
    # ----------------------------------------------------------------
    def _set_flat_weights(self, model: tf.keras.Model, flatted_weights: list):
       
        original = model.get_weights()
        new_w = []
        idx = 0
        for orig in original:
            shape = orig.shape
            flat_array = flatted_weights[idx]
            resh = np.reshape(flat_array, shape)
            new_w.append(resh)
            idx += 1
        model.set_weights(new_w)

    def _plot_training(self, history):
        loss = history.history['loss']
        acc = history.history.get('accuracy', None)

        plt.figure(figsize=(12,5))
        plt.subplot(1,2,1)
        plt.plot(loss, label="Loss")
        plt.title("Training Loss")
        plt.legend()

        if acc is not None:
            plt.subplot(1,2,2)
            plt.plot(acc, label="Accuracy")
            plt.title("Training Accuracy")
            plt.legend()

        plt.show()
