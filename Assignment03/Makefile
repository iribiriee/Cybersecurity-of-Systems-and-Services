all: audit_logger.so audit_monitor test_audit


audit_logger.so: audit_logger.c
	gcc -Wall -fPIC -shared -o audit_logger.so audit_logger.c -lcrypto -ldl 


audit_monitor: audit_monitor.c 
	gcc -Wall audit_monitor.c -o audit_monitor


test_audit: test_audit.c 
	gcc -Wall test_audit.c -o test_audit


run: audit_logger.so test_audit
	LD_PRELOAD=./audit_logger.so ./test_audit


clean:
	rm -f audit_logger.so
	rm -f test_audit
	rm -f audit_monitor
	rm -f /tmp/access_audit.log

