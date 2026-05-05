package sniffer;

import java.util.List;

import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

public class FindNetworkInterface {
    /*
        Interface de rede é o ponto por onde os pacotes entram e saem do computador.
        O pc pode ter várias placas de rede ao mesmo tempo, por exemplo, ao rodar isso eu descobri: 

        -- interfaces internas do windows
        WAN Miniport (Network Monitor) 
        WAN Miniport (IPv6)
        WAN Miniport (IP)

        -- estou usando um usb de wifi - vamos sniffar essa
        Realtek RTL8188FTV Wireless LAN 802.11n USB 2.0 Network Adapter

        -- isso só é usado quando compartilhamos internet/hostspots
        Microsoft Wi-Fi Direct Virtual Adapter #2
        Microsoft Wi-Fi Direct Virtual Adapter

        -- e aqui é o localhost, podemos sniffar isso para ver o tráfedo interno também
        Adapter for loopback traffic capture

        -- cabo de rede
        Realtek PCIe GbE Family Controller

    */
    public List<PcapNetworkInterface> listNetworkInterfaces() throws PcapNativeException {
        List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();

        for(int i = 0; i < interfaces.size(); i++){
            PcapNetworkInterface nif = interfaces.get(i);
            System.out.printf("[%d] %s - %s%n", i, nif.getName(), nif.getDescription());
        }

        return interfaces;
    }
        

}
