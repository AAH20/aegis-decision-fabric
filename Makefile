.PHONY: test bench run serve demo

test:
	python3 tests/test_adf.py
	python3 tests/test_api.py

bench:
	python3 -m adf bench

run:
	python3 -m adf run fixtures/snortml_beachhead.json fixtures/splunk_notables.json fixtures/ocsf_dual_signal.json

serve:
	python3 -m adf serve --host 0.0.0.0 --port 8080

demo: test bench run
