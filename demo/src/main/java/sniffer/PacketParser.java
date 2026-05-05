package sniffer;

import org.pcap4j.packet.*;

public class PacketParser {

public void parse(Packet packet) {
    byte[] raw = packet.getRawData();
    if (raw.length < 14) return;

    // lê o EtherType dos bytes 12-13
    int etherType = ((raw[12] & 0xFF) << 8) | (raw[13] & 0xFF);

    // payload começa no byte 14 (depois do header Ethernet)
    byte[] ipRaw = new byte[raw.length - 14];
    System.arraycopy(raw, 14, ipRaw, 0, ipRaw.length);

    String srcIp = null, dstIp = null;
    byte protocol = 0;
    byte[] transportRaw = null;

    if (etherType == 0x0800) {
        // IPv4
        if (ipRaw.length < 20) return;
        protocol = ipRaw[9];
        int ihl = (ipRaw[0] & 0x0F) * 4; // tamanho do header IP em bytes
        srcIp = (ipRaw[12] & 0xFF) + "." + (ipRaw[13] & 0xFF) + "." + (ipRaw[14] & 0xFF) + "." + (ipRaw[15] & 0xFF);
        dstIp = (ipRaw[16] & 0xFF) + "." + (ipRaw[17] & 0xFF) + "." + (ipRaw[18] & 0xFF) + "." + (ipRaw[19] & 0xFF);
        transportRaw = new byte[ipRaw.length - ihl];
        System.arraycopy(ipRaw, ihl, transportRaw, 0, transportRaw.length);

    } else if (etherType == 0x86DD) {
        // IPv6 — header fixo de 40 bytes
        if (ipRaw.length < 40) return;
        protocol = ipRaw[6]; // next header
        srcIp = formatIpV6(ipRaw, 8);
        dstIp = formatIpV6(ipRaw, 24);
        transportRaw = new byte[ipRaw.length - 40];
        System.arraycopy(ipRaw, 40, transportRaw, 0, transportRaw.length);

    } else {
        return; // ARP ou outro, ignora
    }

    StringBuilder sb = new StringBuilder();
    sb.append(String.format("%-40s  →  %s", srcIp, dstIp));

    if (transportRaw.length >= 4) {
        int srcPort = ((transportRaw[0] & 0xFF) << 8) | (transportRaw[1] & 0xFF);
        int dstPort = ((transportRaw[2] & 0xFF) << 8) | (transportRaw[3] & 0xFF);

        if (protocol == 6) { // TCP
            sb.append(String.format("  TCP  %d → %d  [%s]", srcPort, dstPort, resolveService(dstPort)));
        } else if (protocol == 17) { // UDP
            sb.append(String.format("  UDP  %d → %d  [%s]", srcPort, dstPort, resolveService(dstPort)));

            if (dstPort == 53 || srcPort == 53) {
                // tenta parsear DNS
                try {
                    byte[] dnsRaw = new byte[transportRaw.length - 8];
                    System.arraycopy(transportRaw, 8, dnsRaw, 0, dnsRaw.length);
                    DnsPacket dns = DnsPacket.newPacket(dnsRaw, 0, dnsRaw.length);
                    sb.append(parseDns(dns));
                } catch (Exception ignored) {}
            }
        } else if (protocol == 1 || protocol == 58) {
            sb.append(protocol == 1 ? "  ICMPv4" : "  ICMPv6");
        }
    }

    System.out.println(sb);
}

private String formatIpV6(byte[] raw, int offset) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < 16; i += 2) {
        if (i > 0) sb.append(":");
        sb.append(String.format("%02x%02x", raw[offset + i], raw[offset + i + 1]));
    }
    return sb.toString();
}

    // Resolve o número de porta para o nome do protocolo
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

    // Extrai domínios do pacote DNS
    private String parseDns(DnsPacket dns) {
        StringBuilder sb = new StringBuilder();
        DnsPacket.DnsHeader header = dns.getHeader();

        if (!header.getQuestions().isEmpty()) {
            sb.append("  DNS query → ");
            header.getQuestions().forEach(q ->
                sb.append(q.getQName().getName()).append(" ")
            );
        }

        if (!header.getAnswers().isEmpty()) {
            sb.append("  DNS reply ← ");
            header.getAnswers().forEach(a ->
                sb.append(a.getName().getName()).append("=").append(a.getRData()).append(" ")
            );
        }

        return sb.toString();
    }

    private String bytesToHex(byte[] bytes, int limit) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(limit, bytes.length); i++) {
            sb.append(String.format("%02x ", bytes[i]));
        }
        return sb.toString();
    }
}