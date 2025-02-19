# federated_ray_module.py

import os
import json
import time
import random
import logging
from typing import Any, Dict, List, Optional

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim

import ray
from prometheus_client import start_http_server, Histogram

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("FederatedRayTraining")

# Prometheus 
TRAINING_LOSS = Histogram("training_loss", "Local training loss", ["actor_id"])
VALIDATION_ACCURACY = Histogram("validation_accuracy", "Local validation accuracy", ["actor_id"])
AGGREGATION_TIME = Histogram("aggregation_time", "Time spent aggregating weights")
start_http_server(8000)
logger.info("Prometheus HTTP server started on port 8000")


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
   
    default_config = {
        "ml_config": {
            "lr": 0.01,
            "batch_size": 64,
            "input_dim": 10,
            "output_dim": 2
        },
        "num_workers": 4,
        "num_rounds": 20,
        "checkpoint_dir": "./checkpoints",
        "timeouts": {
            "apply_weights": 10,
            "train_round": 30,
            "validation": 5,
        }
    }
    if config_path and os.path.exists(config_path):
        with open(config_path, "r") as f:
            file_conf = json.load(f)
        default_config.update(file_conf)
    return default_config


class SimpleMLP(nn.Module):
    def __init__(self, input_dim: int, output_dim: int):
        super().__init__()
        self.fc = nn.Linear(input_dim, output_dim)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.fc(x)


def get_flat_params(model: nn.Module) -> torch.Tensor:
    return torch.cat([p.data.view(-1) for p in model.parameters()])

def set_flat_params(model: nn.Module, flat_vector: torch.Tensor) -> None:
    pointer = 0
    for p in model.parameters():
        num_param = p.numel()
        new_param = flat_vector[pointer:pointer + num_param].view_as(p.data)
        p.data.copy_(new_param)
        pointer += num_param


class WeightsAggregator:
    @staticmethod
    def fed_avg(deltas: List[torch.Tensor]) -> torch.Tensor:
        if not deltas:
            raise ValueError("Нет дельт для агрегации")
        stacked = torch.stack(deltas, dim=0)
        return torch.mean(stacked, dim=0)


@ray.remote(num_gpus=1)
class MLTrainerActor:
    def __init__(self, ml_config: Dict[str, Any]):
        self.ml_config = ml_config
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        input_dim = ml_config["input_dim"]
        output_dim = ml_config["output_dim"]
        self.model = SimpleMLP(input_dim, output_dim).to(self.device)
        self.optimizer = optim.SGD(self.model.parameters(), lr=ml_config["lr"])
        self.loss_fn = nn.CrossEntropyLoss()

        self.weights_size = int(get_flat_params(self.model).numel())
        self.local_weights = get_flat_params(self.model).detach().clone()

        actor_id = ray.get_runtime_context().current_actor
        logging.info(f"Actor {actor_id}: model with weights_size={self.weights_size}")

    def train_local_batch(
        self,
        X: Any,
        y: Any,
        epochs_per_round: int = 5
    ) -> np.ndarray:
      
        actor_id = ray.get_runtime_context().current_actor
        old_w = get_flat_params(self.model).detach().clone()

        X_t = torch.tensor(X, dtype=torch.float32, device=self.device)
        y_t = torch.tensor(y, dtype=torch.long, device=self.device)
        self.model.train()

        total_delta = torch.zeros_like(old_w)
        for ep in range(epochs_per_round):
            # 1) Считаем delta до обучения
            before_w = get_flat_params(self.model).detach().clone()

            # 2) Обычный шаг train
            self.optimizer.zero_grad()
            out = self.model(X_t)
            loss = self.loss_fn(out, y_t)
            loss.backward()
            self.optimizer.step()

            # 3) partial delta
            after_w = get_flat_params(self.model).detach().clone()
            step_delta = after_w - before_w
            total_delta += step_delta

            # 4) partial accuracy
            pred = out.argmax(dim=1)
            correct = (pred == y_t).sum().item()
            acc = correct / len(y_t)

            
            TRAINING_LOSS.labels(actor_id=str(actor_id)).observe(loss.item())
            VALIDATION_ACCURACY.labels(actor_id=str(actor_id)).observe(acc)

            # **Опционально**: log partial solution
            logging.info(f"Actor {actor_id}: ep={ep+1}/{epochs_per_round}, partial_loss={loss.item():.4f}, acc={acc:.3f}")

        
        new_w = get_flat_params(self.model).detach().clone()
        self.local_weights = new_w
        logging.info(f"Actor {actor_id}: local train done => final accum delta norm={total_delta.norm():.4f}")

        
        return total_delta.cpu().numpy()

 
    def apply_global_weights(self, global_w: np.ndarray) -> None:
        actor_id = ray.get_runtime_context().current_actor
        g_w_t = torch.tensor(global_w, dtype=torch.float32, device=self.device)
        if g_w_t.numel() != self.weights_size:
            msg = (f"Global weights size mismatch => got {g_w_t.numel()}, expect {self.weights_size}")
            logging.error(f"Actor {actor_id}: {msg}")
            raise ValueError(msg)
        set_flat_params(self.model, g_w_t)
        self.local_weights = get_flat_params(self.model).detach().clone()
        logging.info(f"Actor {actor_id}: global weights applied")

    def get_local_metrics(self, X_val: Any, y_val: Any) -> Dict[str, float]:
        actor_id = ray.get_runtime_context().current_actor
        self.model.eval()
        with torch.no_grad():
            X_v = torch.tensor(X_val, dtype=torch.float32, device=self.device)
            y_v = torch.tensor(y_val, dtype=torch.long, device=self.device)
            out = self.model(X_v)
            loss = self.loss_fn(out, y_v).item()
            pred = out.argmax(dim=1)
            correct = (pred == y_v).sum().item()
            accuracy = correct / len(y_v)
            VALIDATION_ACCURACY.labels(actor_id=str(actor_id)).observe(accuracy)

        logging.info(f"Actor {actor_id}: validate => acc={accuracy:.3f}, loss={loss:.4f}")
        return {"accuracy": accuracy, "loss": loss}


def save_checkpoint(global_w: torch.Tensor, checkpoint_dir: str, round_i: int) -> None:
    import torch
    os.makedirs(checkpoint_dir, exist_ok=True)
    ckpt_path = os.path.join(checkpoint_dir, f"global_round_{round_i}.pth")
    data = {
        "global_weights": global_w.cpu(),
        "round": round_i
    }
    torch.save(data, ckpt_path)
    logging.info("Checkpoint saved => %s", ckpt_path)


def federated_training_loop(config: Dict[str, Any]) -> torch.Tensor:
  
    ml_config = config["ml_config"]
    num_workers = config["num_workers"]
    num_rounds = config["num_rounds"]
    ckp_dir = config["checkpoint_dir"]
    timeouts = config.get("timeouts", {})

    if not ray.is_initialized():
        ray.init()

    
    dummy_model = SimpleMLP(ml_config["input_dim"], ml_config["output_dim"])
    global_w = get_flat_params(dummy_model).detach().clone()

    
    trainers = [MLTrainerActor.remote(ml_config) for _ in range(num_workers)]
    logging.info(f"Created {len(trainers)} MLTrainerActor(s)")

    
    X_shards = [np.random.randn(100, ml_config["input_dim"]) for _ in range(num_workers)]
    y_shards = [np.random.randint(0, ml_config["output_dim"], size=100) for _ in range(num_workers)]
    X_val = np.random.randn(50, ml_config["input_dim"])
    y_val = np.random.randint(0, ml_config["output_dim"], size=50)

    for r in range(num_rounds):
        logging.info("===== Round %d / %d =====", r, num_rounds)

        # 1) Применяем глобальные веса в акторы
        up_futs = []
        for act in trainers:
            fut = act.apply_global_weights.remote(global_w.cpu().numpy())
            up_futs.append(fut)
        try:
            ray.get(up_futs, timeout=timeouts.get("apply_weights", 10))
        except Exception as e:
            logging.error(f"[Round={r}] apply_global_weights => {e}")
            continue

        
        train_futs = []
        for i, act in enumerate(trainers):
            fut = act.train_local_batch.remote(X_shards[i], y_shards[i], epochs=1)
            train_futs.append(fut)
        try:
            local_deltas_np = ray.get(train_futs, timeout=timeouts.get("train_round", 30))
        except Exception as e:
            logging.error(f"[Round={r}] train_local_batch => {e}")
            continue

        # 3) FedAvg
        with AGGREGATION_TIME.time():
            local_deltas = [torch.tensor(delta, dtype=torch.float32) for delta in local_deltas_np]
            if local_deltas:
                stacked = torch.stack(local_deltas, dim=0)
                mean_d = torch.mean(stacked, dim=0)
                global_w += mean_d
        logging.info(f"[Round={r}] Global weights updated")

        
        check_actor = random.choice(trainers)
        try:
            met = ray.get(check_actor.get_local_metrics.remote(X_val, y_val), timeout=timeouts.get("validation", 5))
            acc = met.get("accuracy", 0.0)
            if acc < 0.5:
                logging.warning(f"[Round={r}] Low accuracy => possible penalty or slash stake")
            else:
                logging.info(f"[Round={r}] accuracy ok => {acc:.3f}")
        except Exception as e:
            logging.error(f"[Round={r}] validation => {e}")

        
        save_checkpoint(global_w, ckp_dir, r)
        time.sleep(0.2)

    logging.info("Federated training done. final global_w size=%d", global_w.numel())
    return global_w
