.PHONY: test bench run serve demo package-splunk

test:
	python3 tests/test_adf.py
	python3 tests/test_api.py
	python3 tests/test_splunk_app.py

bench:
	python3 -m adf bench

run:
	python3 -m adf run fixtures/snortml_beachhead.json fixtures/splunk_notables.json fixtures/ocsf_dual_signal.json

serve:
	python3 -m adf serve --host 0.0.0.0 --port 8080

package-splunk:
	mkdir -p artifacts
	COPYFILE_DISABLE=1 tar -C splunk_app --exclude='*.pyc' --exclude='__pycache__' --exclude='.DS_Store' -czf artifacts/TA-aegis-decision-fabric.tar.gz TA-aegis-decision-fabric

demo: test bench run package-splunk
