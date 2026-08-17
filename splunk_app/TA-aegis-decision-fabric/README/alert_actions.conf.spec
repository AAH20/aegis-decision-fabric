[adf_gate_contain]
adf_url = HTTP(S) URL of ADF serve (example: http://adf.internal:8080)
adapter = Event adapter (splunk | snort | sentinel | soar | copilot | ocsf | auto)
tool = Contain tool (block_ip | contain_host | quarantine | fmc_block)
mode = Gate mode (simulate | allow | deny). allow still requires ADF_PROVE_TOKEN and is denied on ML-only
prove_token = Optional ADF prove token. Never send this if you only want SIMULATE
