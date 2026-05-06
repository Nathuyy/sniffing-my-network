package sniffer;

import java.util.List;
import java.util.Scanner;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;

public class Sniffer {
    private final PacketParser parser = new PacketParser();
    // quantos pacotes vc quer capturar - zero é infinito
    private static final int PACKETS_TO_CAPTURE = 0;

    private static final int READ_TIMEOUT_MS = 10;

    private static final int MAX_PACKET_SIZE_BYTES = 65536;

    public static void main(String[] args) throws PcapNativeException, InterruptedException, NotOpenException {
        Sniffer sniffer = new Sniffer();
        PcapNetworkInterface interfaceToSniff = sniffer.chooseTheNetworkInterface();

        if (interfaceToSniff == null) {
            System.out.println("No interface to sniff");
            return;
        }

        sniffer.startCapture(interfaceToSniff);
    }

    private PcapNetworkInterface chooseTheNetworkInterface() throws PcapNativeException{
        FindNetworkInterface finder = new FindNetworkInterface();
        List<PcapNetworkInterface> interfaces = finder.listNetworkInterfaces();

        if (interfaces.isEmpty()) {
            System.out.println("No interfaces found");
            return null;
        }
    
        System.out.println("Choose wich network interface you want to sniff: ");
        Scanner scanner = new Scanner(System.in);
        int choice = scanner.nextInt();

        if (choice < 0 || choice >= interfaces.size()) {
            System.out.println("invalid");
            scanner.close();
            return null;
        }

        scanner.close();

        PcapNetworkInterface selectedInterface = interfaces.get(choice);
        System.out.println("Selected interface: " + selectedInterface.getDescription());
        return selectedInterface;

    }

    private void startCapture(PcapNetworkInterface netInterface) throws PcapNativeException, InterruptedException, NotOpenException {
        // PROMISCUOUS captura todos os pacotes
        PcapHandle handle = netInterface.openLive(MAX_PACKET_SIZE_BYTES, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT_MS);

        handle.loop(PACKETS_TO_CAPTURE, (PacketListener) packet -> processPacket(packet));

        handle.close();
    }

    private void processPacket(Packet packet) {
        parser.parse(packet);
    }
}
