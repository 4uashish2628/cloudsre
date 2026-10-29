PY ?= .venv/bin/python

.PHONY: setup test experiments quick demo paper all

setup:
	python3 -m venv .venv && $(PY) -m pip install -r requirements.txt

test:
	$(PY) -m pytest -q

quick:
	$(PY) experiments/run_all.py --quick

experiments:
	$(PY) experiments/run_all.py

demo:
	$(PY) -m cloudforensix.cli simulate --seed 7 --out data
	$(PY) -m cloudforensix.cli investigate --seed 7 --out cases

paper:
	cd paper && tectonic main.tex

all: test experiments paper
