SHELL := /bin/bash

app: 
	cd application/sdn/ && make start

topo:
	cd topology/ && sudo make topo

clean:
	@echo -n "[MAKE] Killing POX..      " 
	@(sudo kill -s SIGINT $$(ps aux | grep pox | grep root | head -n 1 | awk '{print $$2}') 2>/dev/null  && echo "OK") || echo "POX not running!"
	@#([ $$(sudo kill -s SIGINT $$(ps aux | grep pox | grep root | head -n 1 | awk '{print $$2}') 2>/dev/null; echo $$?) -eq 0 ] && echo "yes" || echo "no")
	@echo -n "[MAKE] Killing Click..    "
	@sudo pkill --signal SIGINT click && echo "OK" || echo "Click not running!"
	@echo -n "[MAKE] Killing SDN App..  "
	@(sudo kill -s SIGTERM $$(ps aux | grep sdn | grep root | head -n 1 | awk '{print $$2}')  2>/dev/null && echo "OK") || echo "SDN not running!"
	@cd topology/ && make clean