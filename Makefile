all: gen_key program

program: mitm_attack pharm_attack

gen_key:
	openssl rand -writerand ~/.rnd
	openssl genrsa -out ca.key 4096
	openssl req -new -x509 -days 30 -key ca.key -out ca.crt -subj "/C=TW/ST=Taiwan/L=Hsinchu/O=NYCU/OU=HSINCHU/CN=*.NYCU.EDU.TW"

mitm_attack:
	cp mitm_attack.py mitm_attack
	chmod +x mitm_attack

pharm_attack:
	cp pharm_attack.py pharm_attack
	chmod +x pharm_attack

clean:
	sudo rm -f tmp/logdir/*
	sudo rm -f connections.log
	rm -f mitm_attack pharm_attack
	rm -f ca.key ca.crt