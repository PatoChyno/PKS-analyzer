package pack;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.swing.JTextArea;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

public class PacketAnalysis {
	
	private int power(int x, int n) {
		int i, p = 1;
		for (i = 0; i < n; i++)
			p *= x;
		return p;
	}
	
	private int maxByteCount = 0;
	private String maxIP = "";
	private Map<String, Integer> ipCounts = new HashMap<String, Integer>();
	
	public void analyze(File f, JTextArea textArea) {

		StringBuilder errbuf = new StringBuilder(); // For any error msgs
		String filePath = f.getAbsolutePath();

		//System.out.printf("Opening file for reading: %s%n", file);
		
		Pcap pcap = Pcap.openOffline(filePath, errbuf);
		textArea.setText("");
		try {
			Runtime.getRuntime().exec("clear");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		if (pcap == null) {
			textArea.append("Error while opening device for capture: " + errbuf.toString());
			return;
		}
		
		class MyHandler implements PcapPacketHandler<String> {

			int i = 1;
			
			private StringBuffer stringBuffer = new StringBuffer();
			
			public String toString() {
				return stringBuffer.toString();
			}
			
			private String getEthType(String[] frame) {
				String type;
				if (typeLengthSum(frame) > 1500) {
					type = "Ethernet II";
				}
				else
					if (frame[15].equals("ff") &&
					frame[16].equals("ff"))
						type = "IEEE 802.3 - Raw";
					else if (frame[15].equals("aa") &&
							frame[16].equals("aa"))
						type = "IEEE 802.3 SNAP";
					else
						type = "IEEE 802.3 / 802.2 (LLC)";
				return type;
			}
			
			private String getMacDest(String[] frame) {
				return (frame[1] + " " + frame[2] + " " + frame[3] + " " +
						frame[4] + " " + frame[5] + " " + frame[6]).toUpperCase();
			}
			
			private String getMacSrc(String[] frame) {
				return (frame[7] + " " + frame[8] + " " + frame[9] + " " +
						frame[10] + " " + frame[11] + " " + frame[12]).toUpperCase();
			} 
			
			private void saveIPstats(String[] frame, int byteCount) {
				if (getEthType(frame).equals("Ethernet II") && frame[13].equals("08") && frame[14].equals("00")) {
					String s1 = String.valueOf(Integer.parseInt(frame[27], 16));
					String s2 = String.valueOf(Integer.parseInt(frame[28], 16));
					String s3 = String.valueOf(Integer.parseInt(frame[29], 16));
					String s4 = String.valueOf(Integer.parseInt(frame[30], 16));
					String s = s1 + "." + s2 + "." + s3 + "." + s4;
					int count = 0;
					if (ipCounts.containsKey(s))
						count = ipCounts.get(s);
					count += byteCount;
					ipCounts.put(s, count);
					if (count > maxByteCount) {
						maxByteCount = count;
						maxIP = s;
					}
				}
			}
			
			private int typeLengthSum(String[] frame) {
				return Integer.parseInt(frame[13], 16) * power(16, 2) +
						Integer.parseInt(frame[14], 16);
			}
			
			public void nextPacket(PcapPacket packet, String user) {
				
				int caplen = packet.getCaptureHeader().caplen();
				int wirelen;
				String buffer = new String(packet.toHexdump(packet.size(), false, false, true));
				String[] frame = buffer.split("\\s+");
				stringBuffer.append("rámec " + i++ + "\n");
				stringBuffer.append("dĺžka rámca poskytnutá paketovým drajverom - " + caplen + " B\n");
				wirelen = (caplen < 60 ? 64 : caplen + 4);
				stringBuffer.append("dĺžka rámca prenášaného po médiu - " + wirelen + " B\n");
				stringBuffer.append(getEthType(frame) + '\n');
				stringBuffer.append("Zdrojová MAC adresa: " + getMacSrc(frame) + '\n');
				stringBuffer.append("Cieľová MAC adresa: " + getMacDest(frame) + '\n');
				stringBuffer.append(buffer.toUpperCase() + "\n");
				saveIPstats(frame, wirelen);
			}
		};

		PcapPacketHandler<String> jpacketHandler = new MyHandler();
		
		pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, "");
		pcap.close();
		textArea.append(jpacketHandler.toString()); 
		printIPs(textArea);
		textArea.append("\nAdresa uzla s najväčším počtom odvysielaných bajtov:\n" + maxIP + "\t" + maxByteCount + " bajtov");
		textArea.setCaretPosition(0);
	}
	
	private void printIPs(JTextArea textArea) {
		textArea.append("IP adresy vysielajúcich uzlov:\n");
		for (Map.Entry<String, Integer> entry : ipCounts.entrySet())
			textArea.append(entry.getKey() + "\n");
	}

}