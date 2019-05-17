SHELL := /bin/bash

app: 
	cd application/sdn/ && make start

topo:
	cd topology/ && sudo make topo

clean:
	@echo "[MAKE] Killing pox.. $$(sudo kill -s SIGINT $$(echo $$(ps aux | grep pox | grep root | head -n 1 | awk '{print $$2}')) 2>/dev/null ; echo $$?)"
	@sleep 1
	@echo "[MAKE] Killing click.. $$(sudo pkill --signal SIGINT click; echo $$?)"
	@echo "[MAKE] Killing sdn app.. $$(sudo kill -s SIGTERM $$(echo $$(ps aux | grep sdn | head -n 1 | awk '{print $$2}')); echo $$?)"
	@cd topology/ && make clean