from pathlib import Path
p=Path('tests/test_e2e_full_chain.py')
s=p.read_text(encoding='utf-8')
s=s.replace('def run_e2e(allow_real_input=False):\n','def run_e2e(allow_real_input=False):\n    # Read before any real LOCK action so the operator is not prompted on a locked screen.\n    operator_pin = getpass.getpass("Local Windows test PIN (never logged): ") if allow_real_input else None\n    if allow_real_input and not operator_pin:\n        raise ValueError("Real-input test requires a local operator credential")\n',1)
s=s.replace('local_pin = getpass.getpass("Local Windows test PIN (never logged): ") if allow_real_input else "123456"','local_pin = operator_pin if allow_real_input else "123456"',1)
s=s.replace('        local_pin = None\n','        local_pin = None\n        operator_pin = None\n',1)
p.write_text(s,encoding='utf-8')
