"""Run only against an explicitly supplied DISPOSABLE PostgreSQL database."""
import os
import unittest
from pathlib import Path
import sys
import secrets
import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import test_vm_gateway as contracts
import test_gateway_concurrency as concurrency
from deploy.postgres_database import PostgresDatabase


class IsolatedSchema:
    def setUp(self):
        self.schema = 'winkey_test_' + secrets.token_hex(8)
        with psycopg.connect(os.environ['WINKEY_TEST_DATABASE_URL'], autocommit=True) as conn:
            conn.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(self.schema)))
        super().setUp()

    def database_factory(self, _):
        return PostgresDatabase(make_conninfo(os.environ['WINKEY_TEST_DATABASE_URL'],
                                options='-c search_path=' + self.schema))

    def tearDown(self):
        try:
            super().tearDown()
        finally:
            with psycopg.connect(os.environ['WINKEY_TEST_DATABASE_URL'], autocommit=True) as conn:
                conn.execute(sql.SQL('DROP SCHEMA {} CASCADE').format(sql.Identifier(self.schema)))


@unittest.skipUnless(os.environ.get('WINKEY_TEST_DATABASE_URL'), 'Disposable PostgreSQL URL required')
class PostgresContract(IsolatedSchema, contracts.VMContract):
    pass


@unittest.skipUnless(os.environ.get('WINKEY_TEST_DATABASE_URL'), 'Disposable PostgreSQL URL required')
class PostgresConcurrency(IsolatedSchema, concurrency.Concurrency):
    pass


if __name__ == '__main__':
    unittest.main()
