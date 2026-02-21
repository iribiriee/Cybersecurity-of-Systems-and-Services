# 1. Command used to monitor for file changes (Behavioral Detection)
inotifywait -m -e modify /lib/python3.12/site-packages/paramiko/__init__.py

# 2. Command used to run the attack
python3 test.py

# 3. Command used to scan with YARA (Static Analysis)
./yara-4.5.5/yara -r detect_pwned.yara /lib/python3.12/site-packages/paramiko
