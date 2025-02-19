# real_datasets.py

import numpy as np
from sklearn.datasets import load_iris

class RealDatasets:
    def __init__(self):
        # Пример: встроенный iris
        iris = load_iris()
        X = iris.data
        y = iris.target
        n = len(X)
        idx = np.arange(n)
        np.random.shuffle(idx)
        split = int(0.8*n)
        tr_idx, val_idx = idx[:split], idx[split:]
        self.datasets = {
            "iris": {
                "X_train": X[tr_idx],
                "y_train": y[tr_idx],
                "X_val": X[val_idx],
                "y_val": y[val_idx]
            }
        }

    def upload_custom_dataset(self, dataset_id: str, X_train, y_train, X_val, y_val):
        """
        Пользовательский датасет загружается в память.
        В реальном решении — хранение в БД / IPFS / Chord / etc.
        """
        if dataset_id in self.datasets:
            raise ValueError(f"Dataset {dataset_id} уже существует.")
        self.datasets[dataset_id] = {
            "X_train": X_train,
            "y_train": y_train,
            "X_val":   X_val,
            "y_val":   y_val
        }

    def get_dataset_shard(self, dataset_id: str, shard_index: int, shard_size: int):
        """
        Возвращаем фрагмент (шард) [shard_index : shard_index + shard_size]
        для train, а val целиком (или тоже шардим — по желанию).
        """
        if dataset_id not in self.datasets:
            raise ValueError(f"Unknown dataset_id={dataset_id}")

        pack = self.datasets[dataset_id]
        X_tr_full = pack["X_train"]
        y_tr_full = pack["y_train"]
        X_val_full= pack["X_val"]
        y_val_full= pack["y_val"]

        start = shard_index
        end = min(start + shard_size, len(X_tr_full))

        return {
            "X_train": X_tr_full[start:end],
            "y_train": y_tr_full[start:end],
            "X_val":   X_val_full,
            "y_val":   y_val_full
        }