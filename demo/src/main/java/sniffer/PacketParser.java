package sniffer;

import org.pcap4j.packet.*;

public class PacketParser {

    public void parse(Packet packet) {

        // Camada 2 do modelo OSI - Enlace - pega os bytes brutos do frame completo.
        byte[] raw = packet.getRawData();

        // Um header Ethernet tem exatamente 14 bytes:
        //   bytes 0-5:  MAC de destino
        //   bytes 6-11: MAC de origem
        //   bytes 12-13: EtherType (qual protocolo vem a seguir)
        // Se o frame for menor que 14 bytes, está corrompido — ignora.
        if (raw.length < 14) return;

        // EtherType fica nos bytes 12 e 13 - é o campo do frame Ethernet que diz o que vem dentro dele.
        // Como Java não tem tipo "unsigned byte", usamos & 0xFF
        // para tratar o byte como valor de 0-255 antes de montar
        // o inteiro de 16 bits com shift.
        // Ex: 0x08 0x00 → 0x0800 = IPv4
        //     0x86 0xDD → 0x86DD = IPv6
        int etherType = ((raw[12] & 0xFF) << 8) | (raw[13] & 0xFF);

        // Tudo depois dos 14 bytes do header Ethernet é o payload - o pacote IP (camada 3 - Rede).
        byte[] ipRaw = new byte[raw.length - 14];
        System.arraycopy(raw, 14, ipRaw, 0, ipRaw.length);

        String srcIp, dstIp;
        byte protocol;       // número do protocolo de transporte (6=TCP, 17=UDP, 1=ICMP)
        byte[] transportRaw; // bytes do segmento TCP ou UDP (camada 4 - transporte)

        if (etherType == 0x0800) {

            // Menor header possível do ipv4 é 20 bytes
            if (ipRaw.length < 20) return;

            // Byte 9 do header IPv4 é o campo "Protocol" - define qual protocolo de camada 4 está encapsulado.
            protocol = ipRaw[9];

            // IHL = Internet Header Length. Bits 0-3 do primeiro byte.
            // Multiplicamos por 4 para converter de palavras para bytes.
            int ihl = (ipRaw[0] & 0x0F) * 4; // “Onde o header termina e onde começam os dados (TCP/UDP)?”

            // Bytes 12-15: IP de origem. Bytes 16-19: IP de destino.
            // Cada grupo de 4 bytes vira um octeto do endereço (ex: 192.168.0.1).
            srcIp = formatIpV4(ipRaw, 12);
            dstIp = formatIpV4(ipRaw, 16);

            transportRaw = new byte[ipRaw.length - ihl];
            System.arraycopy(ipRaw, ihl, transportRaw, 0, transportRaw.length);

        } else if (etherType == 0x86DD) {
            // ── IPv6 ──────────────────────────────────────────────
            // O header IPv6 é FIXO: sempre 40 bytes. Não há IHL.
            if (ipRaw.length < 40) return;

            // Byte 6 do header IPv6 é o "Next Header",
            protocol = ipRaw[6];

            // Bytes 8-23: endereço IPv6 de origem (16 bytes).
            // Bytes 24-39: endereço IPv6 de destino (16 bytes).
            srcIp = formatIpV6(ipRaw, 8);
            dstIp = formatIpV6(ipRaw, 24);

            // Payload começa no byte 40 (logo após o header fixo).
            transportRaw = new byte[ipRaw.length - 40];
            System.arraycopy(ipRaw, 40, transportRaw, 0, transportRaw.length);

        } else {
            return;
        }

        StringBuilder sb = new StringBuilder();
        sb.append(String.format("%-42s → %-42s", srcIp, dstIp));


        if (transportRaw.length >= 4) {

            // Nos headers TCP e UDP, os primeiros 4 bytes são sempre:
            //   bytes 0-1: porta de origem  (16 bits)
            //   bytes 2-3: porta de destino (16 bits)
            int srcPort = ((transportRaw[0] & 0xFF) << 8) | (transportRaw[1] & 0xFF);
            int dstPort = ((transportRaw[2] & 0xFF) << 8) | (transportRaw[3] & 0xFF);

            if (protocol == 6) {
                // ── TCP (protocolo 6)
                // TCP é orientado à conexão. Tem flags de controle (SYN, ACK...)
                // que formam o 3-way handshake e gerenciam o ciclo de vida da conexão.
                String flags = parseTcpFlags(transportRaw);
                sb.append(String.format("  TCP  %5d → %-5d [%-11s] [%s]",
                        srcPort, dstPort, resolveService(dstPort), flags));

            } else if (protocol == 17) {
                // ── UDP (protocolo 17)
                // UDP é sem conexão, sem handshake, sem garantia de entrega.
                sb.append(String.format("  UDP  %5d → %-5d [%s]",
                        srcPort, dstPort, resolveService(dstPort)));

                // DNS usa a porta 53. Pode ser query (cliente → 53)
                // ou resposta (53 → cliente).
                if (dstPort == 53 || srcPort == 53) {
                    sb.append(parseDnsFromUdp(transportRaw));
                }

            } else if (protocol == 1)  { sb.append("  ICMPv4"); }
              else if (protocol == 58)  { sb.append("  ICMPv6"); }
        }

        System.out.println(sb);
    }


    // O header UDP tem SEMPRE 8 bytes:
    //   bytes 0-1: porta de origem
    //   bytes 2-3: porta de destino
    //   bytes 4-5: comprimento total do segmento UDP
    //   bytes 6-7: checksum
    // O payload DNS começa no byte 8.
    private String parseDnsFromUdp(byte[] udp) {
        if (udp.length <= 8) return "  DNS [payload vazio]";
        byte[] dns = new byte[udp.length - 8];
        System.arraycopy(udp, 8, dns, 0, dns.length);
        return parseDnsBytes(dns);
    }

    // Estrutura do header DNS (12 bytes fixos):
    //
    //  0-1:  Transaction ID  — número aleatório para casar query/reply
    //  2-3:  Flags           — bit 15 = QR (0=query, 1=response),
    //                          bits 11-14 = opcode, bit 10 = AA,
    //                          bit 9 = TC, bit 8 = RD, bit 7 = RA,
    //                          bits 0-3 = RCODE (0=ok, 3=NXDOMAIN...)
    //  4-5:  QDCOUNT         — número de perguntas
    //  6-7:  ANCOUNT         — número de respostas
    //  8-9:  NSCOUNT         — registros de autoridade (ignoramos)
    //  10-11: ARCOUNT        — registros adicionais (ignoramos)
    private String parseDnsBytes(byte[] dns) {
        if (dns.length < 12) return "  DNS [header incompleto]";

        StringBuilder sb = new StringBuilder();

        // Byte 2, bit mais significativo (bit 7 do byte, ou bit 15 do word
        // de flags): QR flag. 0 = pergunta, 1 = resposta.
        boolean isResponse = (dns[2] & 0x80) != 0;

        // Bits 0-3 do byte 3 = RCODE.
        // 0 = sem erro, 3 = NXDOMAIN (domínio não existe).
        int rcode = dns[3] & 0x0F;

        // QDCOUNT: quantas perguntas tem neste pacote (quase sempre 1).
        int qdCount = ((dns[4] & 0xFF) << 8) | (dns[5] & 0xFF);

        // ANCOUNT: quantas respostas tem (0 nas queries).
        int anCount = ((dns[6] & 0xFF) << 8) | (dns[7] & 0xFF);

        // Offset atual na leitura. Avança conforme parseamos os campos.
        // Começa em 12 (depois do header fixo).
        int offset = 12;

        if (!isResponse) {
            sb.append("  DNS query");
        } else {
            sb.append("  DNS reply");
            // RCODE 0 = NOERROR, 3 = NXDOMAIN ("domínio não existe")
            if (rcode == 3) sb.append(" [NXDOMAIN]");
            else if (rcode != 0) sb.append(" [rcode=").append(rcode).append("]");
        }

        // Cada question tem: QNAME (nome comprimido), QTYPE (2 bytes),
        // QCLASS (2 bytes, quase sempre 0x0001 = IN = Internet).
        for (int i = 0; i < qdCount && offset < dns.length; i++) {
            // readName retorna o domínio em texto e avança `offset`
            // através do mecanismo de labels (ver método abaixo).
            String[] result = readName(dns, offset);
            String name = result[0];
            offset = Integer.parseInt(result[1]);

            if (offset + 4 > dns.length) break;

            // QTYPE: tipo do registro consultado.
            // 1=A (IPv4), 28=AAAA (IPv6), 15=MX, 5=CNAME, 65=HTTPS...
            int qtype = ((dns[offset] & 0xFF) << 8) | (dns[offset + 1] & 0xFF);
            offset += 4; // pula QTYPE (2) + QCLASS (2)

            sb.append(" → ").append(name).append(" (").append(qtypeName(qtype)).append(")");
        }

        // Cada answer tem: NAME (pode ser ponteiro comprimido),
        // TYPE (2), CLASS (2), TTL (4), RDLENGTH (2), RDATA (variável).
        for (int i = 0; i < anCount && offset < dns.length; i++) {
            String[] result = readName(dns, offset);
            String name = result[0];
            offset = Integer.parseInt(result[1]);

            if (offset + 10 > dns.length) break;

            int type     = ((dns[offset]     & 0xFF) << 8) | (dns[offset + 1] & 0xFF);
            int ttl      = ((dns[offset + 4] & 0xFF) << 24)
                         | ((dns[offset + 5] & 0xFF) << 16)
                         | ((dns[offset + 6] & 0xFF) << 8)
                         |  (dns[offset + 7] & 0xFF);
            int rdLength = ((dns[offset + 8] & 0xFF) << 8) | (dns[offset + 9] & 0xFF);
            offset += 10;

            if (offset + rdLength > dns.length) break;

            String rdata = parseRData(dns, offset, rdLength, type);
            offset += rdLength;

            sb.append(" | ").append(name).append("=").append(rdata)
              .append(" ttl=").append(ttl).append("s");
        }

        return sb.toString();
    }


    // Um domínio é codificado como uma sequência de labels:
    //   3 w w w  6 g o o g l e  3 c o m  0
    //   ↑length  ↑6 chars       ↑3 chars ↑fim
    //
    // Para compressão, um "ponteiro" substitui um label:
    //   os dois bits mais significativos do byte são 11 (0xC0),
    //   e os 14 bits restantes apontam para outro offset no pacote.
    //   Isso evita repetir "google.com" em cada registro.
    // ───────────────────────────────────────────────────────────────
    private String[] readName(byte[] dns, int offset) {
        StringBuilder name = new StringBuilder();
        int jumped = -1;

        while (offset < dns.length) {
            int len = dns[offset] & 0xFF;

            if (len == 0) {
                offset++;
                break;
            }

            if ((len & 0xC0) == 0xC0) {
                if (jumped == -1) jumped = offset + 2;
                offset = ((len & 0x3F) << 8) | (dns[offset + 1] & 0xFF);
                continue;
            }

            offset++;
            if (name.length() > 0) name.append(".");
            for (int i = 0; i < len && offset < dns.length; i++, offset++) {
                name.append((char) dns[offset]);
            }
        }

        int finalOffset = jumped != -1 ? jumped : offset;
        return new String[]{ name.toString(), String.valueOf(finalOffset) };
    }

    private String parseRData(byte[] dns, int offset, int length, int type) {
        return switch (type) {
            case 1 -> { // A — endereço IPv4 (4 bytes)
                if (length == 4)
                    yield (dns[offset] & 0xFF) + "." + (dns[offset+1] & 0xFF)
                        + "." + (dns[offset+2] & 0xFF) + "." + (dns[offset+3] & 0xFF);
                yield "A[?]";
            }
            case 28 -> { // AAAA — endereço IPv6 (16 bytes)
                if (length == 16) yield formatIpV6(dns, offset);
                yield "AAAA[?]";
            }
            case 5 -> { // CNAME — nome canônico (alias)
                yield readName(dns, offset)[0];
            }
            case 15 -> { // MX — mail exchanger
                // 2 bytes de preferência (prioridade) + nome do servidor de e-mail
                int pref = ((dns[offset] & 0xFF) << 8) | (dns[offset+1] & 0xFF);
                yield "pref=" + pref + " " + readName(dns, offset + 2)[0];
            }
            case 16 -> { // TXT — texto livre (usado por SPF, DKIM, etc.)
                StringBuilder txt = new StringBuilder("\"");
                int end = offset + length;
                int pos = offset;
                // TXT é uma série de strings, cada uma precedida por 1 byte de comprimento
                while (pos < end) {
                    int slen = dns[pos++] & 0xFF;
                    for (int i = 0; i < slen && pos < end; i++, pos++)
                        txt.append((char) dns[pos]);
                }
                txt.append("\"");
                yield txt.toString();
            }
            default -> {
                // Para tipos desconhecidos (HTTPS=65, SVCB=64, etc.),
                // mostramos o número em vez de lançar exceção como o pcap4j fazia.
                yield "[type=" + type + " len=" + length + "]";
            }
        };
    }

    private String qtypeName(int t) {
        return switch (t) {
            case 1  -> "A";
            case 2  -> "NS";
            case 5  -> "CNAME";
            case 6  -> "SOA";
            case 15 -> "MX";
            case 16 -> "TXT";
            case 28 -> "AAAA";
            case 33 -> "SRV";
            case 65 -> "HTTPS";
            case 64 -> "SVCB";
            default -> "type" + t;
        };
    }

    // O header TCP tem estrutura fixa nos primeiros 13 bytes:
    //   0-1:  porta origem    2-3:  porta destino
    //   4-7:  sequence number (ISN no SYN, incrementa com os dados)
    //   8-11: acknowledgment number (próximo byte esperado do outro lado)
    //   12:   data offset (tamanho do header TCP em palavras de 32 bits)
    //   13:   flags (1 bit cada): CWR ECE URG ACK PSH RST SYN FIN
    //
    // O 3-way handshake usa:
    //   → SYN            cliente propõe ISN, quer conectar
    //   ← SYN + ACK      servidor aceita, propõe seu ISN, confirma o do cliente
    //   → ACK            cliente confirma o ISN do servidor — conexão aberta
    private String parseTcpFlags(byte[] tcp) {
        if (tcp.length < 14) return "?";
        int flags = tcp[13] & 0xFF;
        StringBuilder sb = new StringBuilder();
        // Testamos cada bit com máscara. A ordem é da mais relevante
        // para leitura: SYN e ACK são os mais comuns no handshake.
        if ((flags & 0x02) != 0) sb.append("SYN ");
        if ((flags & 0x10) != 0) sb.append("ACK ");
        if ((flags & 0x01) != 0) sb.append("FIN ");
        if ((flags & 0x04) != 0) sb.append("RST ");
        if ((flags & 0x08) != 0) sb.append("PSH ");
        if ((flags & 0x20) != 0) sb.append("URG ");
        return sb.isEmpty() ? "-" : sb.toString().trim();
    }

    private String formatIpV4(byte[] raw, int offset) {
        return (raw[offset]   & 0xFF) + "." + (raw[offset+1] & 0xFF) + "."
             + (raw[offset+2] & 0xFF) + "." + (raw[offset+3] & 0xFF);
    }

    private String formatIpV6(byte[] raw, int offset) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i += 2) {
            if (i > 0) sb.append(":");
            sb.append(String.format("%02x%02x", raw[offset+i], raw[offset+i+1]));
        }
        return sb.toString();
    }

    private String resolveService(int port) {
        return switch (port) {
            case 80   -> "HTTP";
            case 443  -> "HTTPS";
            case 53   -> "DNS";
            case 22   -> "SSH";
            case 25   -> "SMTP";
            case 587  -> "SMTP/TLS";
            case 143  -> "IMAP";
            case 993  -> "IMAPS";
            case 110  -> "POP3";
            case 3306 -> "MySQL";
            case 5432 -> "PostgreSQL";
            case 6379 -> "Redis";
            case 8080 -> "HTTP-alt";
            case 123  -> "NTP";
            case 67, 68 -> "DHCP";
            default   -> "port " + port;
        };
    }
}