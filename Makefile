.PHONY: test bench run demo

test:
	python3 tests/test_adf.py

bench:
	python3 -m adf bench

run:
	python3 -m adf run fixtures/snortml_beachhead.json fixtures/splunk_notables.json

demo: test bench run
