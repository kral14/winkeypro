"""Pooled PostgreSQL storage for the gateway's existing transaction contract."""
from contextlib import contextmanager
from deploy.gateway_production_server import ProductionDatabase


class Connection:
    def __init__(self, raw):
        self.raw = raw

    def execute(self, query, parameters=()):
        # Only repository-owned SQL uses this adapter; values stay bound params.
        return self.raw.execute(query.replace('?', '%s'), parameters)

    def commit(self):
        self.raw.commit()


class PostgresDatabase(ProductionDatabase):
    def __init__(self, url):
        import os
        from psycopg.rows import dict_row
        from psycopg.conninfo import conninfo_to_dict
        from psycopg_pool import ConnectionPool
        # Never propagate a driver exception: its text can contain the DSN.
        self.pool = None
        try:
            options = conninfo_to_dict(url).get('options', '')
            pool_max = int(os.environ.get('WINKEY_PG_POOL_SIZE', '30'))
            pool_timeout = float(os.environ.get('WINKEY_PG_POOL_TIMEOUT', '15.0'))
            self.pool = ConnectionPool(
                conninfo=url, min_size=1, max_size=pool_max, timeout=pool_timeout,
                kwargs={'row_factory': dict_row, 'connect_timeout': 5,
                        'options': options + ' -c statement_timeout=5000 -c lock_timeout=4000'},
                open=False)
            self.pool.open(wait=True, timeout=10)
            self._init_db()
        except Exception:
            if self.pool:
                self.pool.close()
            raise RuntimeError('E_POSTGRES_STARTUP_FAILED: Check DATABASE_URL, TLS and database permissions') from None

    @contextmanager
    def get_conn(self):
        with self.pool.connection() as raw:
            yield Connection(raw)

    def close(self):
        self.pool.close()
