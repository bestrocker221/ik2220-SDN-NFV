SHELL := /bin/bash

app: 
	cd application/sdn/ && make start

topo:
	cd topology/ && sudo make topo

clean:
	kill -s SIGINT $$(echo $$(ps aux | grep pox | head -n 1 | awk '{print $$2}'))
	sleep 1
	sudo pkill --signal SIGINT click
	sleep 1
	sudo kill -s SIGTERM $$(echo $$(ps aux | grep sdn | head -n 1 | awk '{print $$2}'))
	cd topology/ && make clean