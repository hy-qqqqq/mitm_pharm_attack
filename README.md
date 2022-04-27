<h1> MITM & Pharming Attacks in Wi-Fi Networks </h1>

*Project in Computer Security Capstone.*

<h2> Concepts </h2>

* Redirect victim's traffic to attacker
    * **MITM** - ARP spoofing - requires IP, MAC.
* Encrypted sessions - sslsplit
    * **MITM** - sslsplit - do ARP spoofing first.
    * **PHARM** - redirect HTTP requests to a phishing web page.

<h2> Scenario </h2>

![Attack scenario](/images/scenario.drawio.svg)

<h2> Implementation </h2>

<h3> Man-in-the-middle attack </h3>

1. Scan interfaces
    * `scapy` or `netifaces`
    * Send ARP request packets to subnet, get MAC from the answered responses.
2. ARP spoofing (consider both uplink and downlink)
    * Send ARP reply packets to all possible victims. (modify the below fields)
        * Source MAC: Attacker MAC
        * Souce IP: AP IP
    * Send ARP reply packets to AP. (modify the below fields)
        * Source MAC: Attacker MAC
        * Source IP: Victim IP
3. Split SSL/TLS session
    * Generate RSA key and certificate by `openssl`
    * Enable IP forwarding
        * `sysctl -w net.ipv4.ip_forward=1`
    * Set NAT rules to redirect connections to ports: 8080, 8443
    * `sslsplit` command
4. Intercept username and password
    * parse HTTP content (input box)

<h3> Pharming attack </h3>

1. Scan interfaces
2. ARP spoofing
    * In order to do DNS spoofing, we need to become the middle man first, so that we can intercept the packet and then forward it.
3. DNS spoofing
    * Since we have the ability to intercept and forward packets, we can modify the values in the packet when capturing it, and then forward it.
    * `scapy` + `netfilterqueue`
        * Add a rule in iptables, so that whenever a packet is forwarded, redirect it to the netfilter queue with number 0.
        * `iptables -I FORWARD -j NFQUEUE --queue-num 0`
    * DNS format
        * Check if the packet is in `IP + UDP + DNS + DNSRR` structure
        * Keep the original IP + UDP layers
        * Replace the original DNS layer with self created DNS layer with only one qd + one an

<h2> Usage </h2>

Build mitm_attack & pharm_attack & generate key, certificate
```
make
```

Clean
```
make clean
```

Run programs
```
./mitm_attack
```
```
./pharm_attack
```
