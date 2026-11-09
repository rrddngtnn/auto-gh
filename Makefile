export PYTHONPATH := packages
PY ?= /home/azuramaru/.hermes/tools/python-3.14.7+20260901-linux-x64/bin/python3

.PHONY: test hygiene status alloc-proxy inbox-create aging-queue export-sessions domain-check panel

test:
	PYTHONPATH=packages $(PY) tests/test_auto_gh.py

hygiene:
	$(PY) scripts/public-hygiene-gate.py --repo-root .

status:
	PYTHONPATH=packages $(PY) -m auto_gh.cli status

alloc-proxy:
	PYTHONPATH=packages $(PY) -m auto_gh.cli alloc-proxy --country $${CC:-sg} --ttl $${TTL:-30}

inbox-create:
	PYTHONPATH=packages $(PY) -m auto_gh.cli inbox-create

aging-queue:
	PYTHONPATH=packages $(PY) -m auto_gh.cli aging-queue

export-sessions:
	PYTHONPATH=packages $(PY) -m auto_gh.cli export-sessions

domain-check:
	PYTHONPATH=packages $(PY) -m auto_gh.cli domain-check

panel:
	PYTHONPATH=packages $(PY) -m auto_gh.cli panel --host $${HOST:-127.0.0.1} --port $${PORT:-8790}
