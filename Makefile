.PHONY: install demo run test

install:
	python3 -m venv .venv
	. .venv/bin/activate && pip install -r requirements.txt

demo:
	. .venv/bin/activate && python -m nids.demo --force

run:
	. .venv/bin/activate && python -m nids

test:
	. .venv/bin/activate && python -m unittest tests/test_smoke.py
