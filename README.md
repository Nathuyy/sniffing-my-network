# 🛰️ Sniffer de Rede em Java com Npcap + Pcap4J

Este projeto é um sniffer de rede feito em Java utilizando Pcap4J sobre o driver Npcap.

O objetivo é capturar pacotes da interface de rede e permitir visualizar, estudar e entender como a comunicação na rede realmente acontece.

Este projeto é educacional e voltado para aprendizado de redes, protocolos e segurança. Por esse motivo, você irá ver muitos comentários explicando certos comportamentos

## 📚 O que é um Sniffer de Rede?

Um sniffer é um programa capaz de capturar os pacotes que trafegam na rede da sua máquina.

Com isso, é possível observar na prática:

Requisições DNS
Handshake TCP (SYN, ACK…)
Tráfego HTTP/HTTPS
Comunicação entre aplicações
Headers, portas, IPs, MAC Address
Funcionamento real do modelo OSI / TCP-IP

### 🌐 O que é uma Interface de Rede?

Uma interface de rede é o ponto de conexão entre seu dispositivo e a rede.

Ela pode ser:

Física → placa Ethernet, Wi-Fi
Lógica → loopback, VPN, Docker bridge

O sniffer precisa escolher qual interface observar, pois os pacotes passam por elas.