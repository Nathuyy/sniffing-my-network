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

### Estudos e notas:

Ao usar este sniffer, vários conceitos de redes deixam de ser “teoria” e passam a ser coisas visíveis nos bytes.

🧩 O que é o OSI model

O OSI não é um protocolo.
É um modelo mental para entender onde cada parte do pacote atua.

Quando você captura um pacote bruto (getRawData()), você está vendo as camadas, 2, 3, 4, 7

🧱 O que é um Frame Ethernet

O que chega primeiro na sua placa de rede é um frame Ethernet (camada 2).

Ele contém:
MAC de origem
MAC de destino
EtherType
Payload (que normalmente é um pacote IP)

🔎 O que é EtherType

Campo nos bytes 12 e 13 do frame Ethernet.

Ele diz o que vem depois do header Ethernet:

EtherType	Significa
0x0800	IPv4
0x86DD	IPv6
0x0806	ARP

É assim que você descobre se o payload é IP ou ARP.

🤝 Como o TCP mostra SYN, ACK, etc.

No header TCP existem flags (bits de controle):

SYN
ACK
FIN
RST
PSH

São esses bits que permitem enxergar o 3-way handshake acontecendo ao vivo.
