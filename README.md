# Thread-based-TCP-Three-way-handshake-with-Scapy
This file demonstrates thread-based TCP connection along with handling of all incoming packets using scapy. 

Instructions to run:
Before running this file, install IPTABLES rule as given below:


$ IPTABLES -A OUTPUT -p tcp --tcp-flags RST RST -s <your-ip-address(src-ip)> -j DROP

as when scapy sends first TCP SYN packet, linux kernel doesn't know anything about it, 
hence when a SYN-ACK packet is received from remote host, kernel sends an RST packet back suspecting 
no SYN packet has been sent from the machine, so this IPTABLES rule blocks any outgoing RST packet thus
allowing TCP handshake to complete.
