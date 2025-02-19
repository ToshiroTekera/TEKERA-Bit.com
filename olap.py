# olap_aggregator.py
import json
import logging
import psycopg2
import redis

class OlapAggregator:
    """
    Класс, отвечающий за:
    1) Приём транзакций (on_new_transaction) и вставку их в SQL (OLAP) таблицу.
    2) Метод get_stats(...) для аналитики (с кэшированием в Redis).
    """
    def __init__(
        self,
        pg_dsn="dbname=olap user=postgres password=secret host=localhost port=5432",
        redis_host="localhost",
        redis_port=6379,
        cache_ttl=60
    ):
        """
        :param pg_dsn: строка подключения к PostgreSQL (или другой SQL). 
        :param redis_host: Хост Redis.
        :param redis_port: Порт Redis.
        :param cache_ttl: Время кэширования (секунды).
        """
        self.pg_dsn = pg_dsn
        self.redis_host = redis_host
        self.redis_port = redis_port
        self.cache_ttl = cache_ttl

        # Инициируем соединение PostgreSQL
        self._init_postgres()

        # Инициируем Redis
        self.r = redis.Redis(host=self.redis_host, port=self.redis_port, decode_responses=True)
        logging.info("[OlapAggregator] Connected to Redis at %s:%s", redis_host, redis_port)

        # Создаём таблицы, если нужно
        self._init_schema()

    def _init_postgres(self):
        """
        Создаём подключение к Postgres (в реальном коде можно пул коннектов).
        """
        self.pg_conn = psycopg2.connect(self.pg_dsn)
        self.pg_conn.autocommit = True  # Для упрощения

    def _init_schema(self):
        """
        Создаём таблицу transactions (если нет).
        """
        create_sql = """
        CREATE TABLE IF NOT EXISTS transactions (
            tx_id TEXT PRIMARY KEY,
            sender TEXT,
            recipient TEXT,
            amount BIGINT,
            timestamp DOUBLE PRECISION
        );
        """
        with self.pg_conn.cursor() as cur:
            cur.execute(create_sql)
        logging.info("[OlapAggregator] Schema ensured (transactions table).")

    def on_new_transaction(self, tx: dict):
        """
        Записываем транзакцию в таблицу. tx = { tx_id, sender, recipient, amount_terabit, timestamp,... }
        """
        # Пример: вставляем (tx_id, sender, recipient, amount, timestamp).
        # amount_terabit -> amount (BIGINT).
        # Если tx_id уже есть, пропускаем (INSERT ... ON CONFLICT DO NOTHING) или UPDATE.
        insert_sql = """
        INSERT INTO transactions (tx_id, sender, recipient, amount, timestamp)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (tx_id) DO NOTHING;
        """
        with self.pg_conn.cursor() as cur:
            cur.execute(
                insert_sql,
                (
                    tx["tx_id"],
                    tx["sender"],
                    tx["recipient"],
                    tx["amount_terabit"],
                    tx.get("timestamp", 0.0),
                )
            )
        logging.info("[OlapAggregator] Inserted tx_id=%s into OLAP DB.", tx["tx_id"])

        # (Опционально) можно сбрасывать кэш, если хотим, чтобы новые данные попадали немедленно
        # self._invalidate_cache()

    def get_stats(self, interval="day") -> dict:
        """
        Пример метода для запроса "сколько террабит перевели за interval=day/week?"
        Сначала проверяем Redis, если нет - идём в PostgreSQL, потом кладём в Redis.
        """
        cache_key = f"stats:{interval}"
        cached = self.r.get(cache_key)
        if cached:
            logging.info("[OlapAggregator] Cache HIT for %s", cache_key)
            return json.loads(cached)

        # Иначе Cache MISS
        logging.info("[OlapAggregator] Cache MISS for %s, querying Postgres...", cache_key)
        # Допустим, interval='day' => за последние 24 часа
        # (здесь всё упрощённо)
        query_sql = """
        SELECT COALESCE(SUM(amount),0)
        FROM transactions
        WHERE timestamp >= EXTRACT(EPOCH FROM (NOW() - INTERVAL '1 day'))
        """
        if interval == "week":
            query_sql = """
            SELECT COALESCE(SUM(amount),0)
            FROM transactions
            WHERE timestamp >= EXTRACT(EPOCH FROM (NOW() - INTERVAL '7 day'))
            """

        with self.pg_conn.cursor() as cur:
            cur.execute(query_sql)
            row = cur.fetchone()
            total_amount = row[0] if row else 0

        data = {"total_amount": total_amount, "interval": interval}
        self.r.setex(cache_key, self.cache_ttl, json.dumps(data))

        return data

    def _invalidate_cache(self):
        """
        При желании можно удалять ключи stats:*
        чтобы при новых транзакциях не было устаревших данных.
        """
        # keys = self.r.keys("stats:*")
        # for k in keys:
        #     self.r.delete(k)
        pass