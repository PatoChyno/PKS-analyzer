package pack;

import java.io.File;

import javax.swing.JTextArea;
import java.math.BigInteger;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

public class CommsConn {
	
	private int charToDec(char c) {
		return (c - 'a' >= 0 ? c - 'a' : c - '0');
	}
	
	private int power(int x, int n) {
		int i, p = 1;
		for (i = 0; i < n; i++)
			p *= x;
		return p;
	}
	
	public void analyze(File f, JTextArea textArea) {

		StringBuilder errbuf = new StringBuilder(); // For any error msgs
		String filePath = f.getAbsolutePath();

		//System.out.printf("Opening file for reading: %s%n", file);
		
		Pcap pcap = Pcap.openOffline(filePath, errbuf);
		textArea.setText("");
		if (pcap == null) {
			textArea.append("Error while opening device for capture: " + errbuf.toString());
			return;
		}
		
		class MyHandler implements PcapPacketHandler<String> {

			int i = 1, commCount = 0;
			boolean syn, ack, fin, rst;
			
			private StringBuffer stringBuffer = new StringBuffer();
			
			public String toString() {
				return stringBuffer.toString();
			}
			
			public int commCount() {
				return commCount;
			}
			
			private String getEthType(int sum, String buffer) {
				String type;
				if (sum > 1500) {
					type = "Ethernet II";
				}
				else
					if (buffer.charAt(46) == 'f' && buffer.charAt(47) == 'f' &&
					buffer.charAt(49) == 'f' && buffer.charAt(50) == 'f')
						type = "IEEE 802.3 - Raw";
					else if (buffer.charAt(46) == 'a' && buffer.charAt(47) == 'a' &&
							buffer.charAt(49) == 'a' && buffer.charAt(50) == 'a')
						type = "IEEE 802.3 SNAP";
					else
						type = "IEEE 802.3 / 802.2 (LLC)";
				return type;
			}
			
			private String toIP(char a, char b, char c, char d, char e, char f, char g, char h) {
				return Integer.parseInt(a + "" + b + "", 16) + "." + 
						Integer.parseInt(c + "" + d + "", 16) + "." +
						Integer.parseInt(e + "" + f + "", 16) + "." +
						Integer.parseInt(g + "" + h + "", 16);
			}
			
			private String toPort(char a, char b, char c, char d) {
				return Integer.parseInt(a + "" + b + "" + c + "" + d, 16) + "";
			}			
			
			private String getFlags(String s) {
				return (new BigInteger(s, 16)).toString(2);
				//return s;
			}

			private boolean boolify(char c) {
				return (c == '0') ? false : true; 
			}
			
			private void analyzeFlags(String s) {
				int len = s.length();
				for (int i = 0; i < (5 - len); i++) {
					s = '0' + s;
				}
				syn = boolify(s.charAt(3));
				ack = boolify(s.charAt(0));
				fin = boolify(s.charAt(4));
				System.out.println(syn + "" + ack);
				System.out.println(s);
			}
			
			public void nextPacket(PcapPacket packet, String user) {
				
				int caplen = packet.getCaptureHeader().caplen();
				int wirelen;
				String buffer = new String(packet.toHexdump(packet.size(),
						false, false, true));
				int sumType = charToDec(buffer.charAt(40)) * power(16, 3)
						+ charToDec(buffer.charAt(41)) * power(16, 2)
						+ charToDec(buffer.charAt(43)) * power(16, 1)
						+ charToDec(buffer.charAt(44)) * power(16, 0); // IP
				String type = getEthType(sumType, buffer);
				
				if (type == "Ethernet II" // Ethernet II 
					&& sumType == 2048 // IP
					&& buffer.charAt(76) == '0' && buffer.charAt(77) == '6') {// TCP
					
					String prevSrcIP = "", prevDestIP = "";
					int frmCount = 1;
					String srcIP = toIP(buffer.charAt(86), buffer.charAt(87),
							buffer.charAt(89), buffer.charAt(90),
							buffer.charAt(93), buffer.charAt(94),
							buffer.charAt(96), buffer.charAt(97));
					String destIP = toIP(buffer.charAt(99), buffer.charAt(100),
							buffer.charAt(102), buffer.charAt(103),
							buffer.charAt(107), buffer.charAt(108),
							buffer.charAt(110), buffer.charAt(111));
					analyzeFlags(getFlags(buffer.charAt(155) + "" + buffer.charAt(156)));
					if (srcIP == prevDestIP && destIP == prevSrcIP) {
						if (syn && !ack && frmCount == 1)
							;
					}
					prevSrcIP = srcIP;
					prevDestIP = destIP;
					
					if (buffer.charAt(120) == '0' && buffer.charAt(121) == '0'
					&& buffer.charAt(123) == '5' && buffer.charAt(124) == '0') { // Telnet
						
						String srcPort = toPort(buffer.charAt(113), buffer.charAt(114),
								buffer.charAt(116), buffer.charAt(117));
						String destPort = toPort(buffer.charAt(120), buffer.charAt(121),
								buffer.charAt(123), buffer.charAt(124));
						//System.out.println(getFlags(buffer.charAt()));
						stringBuffer.append("Komunikácia č. " + commCount++ + "\n");
						stringBuffer.append("Zdrojová IP: " + srcIP + " : " + srcPort
								+ ", Cieľová IP: " + destIP  + " : " + destPort + "\n");
						stringBuffer.append("rámec " + i + "\n");
						stringBuffer.append("dĺžka rámca zachyteného paketovým drajverom: "
								+ caplen + " B\n");
						wirelen = (caplen < 60 ? 64 : caplen + 4);
						stringBuffer.append("dĺžka rámca prenášaného po médiu: "
								+ wirelen + " B\n");
						stringBuffer.append(type + '\n');
						stringBuffer.append(buffer.toUpperCase() + "\n");
					}
				}
				i++;
			}
		}

		PcapPacketHandler<String> jpacketHandler = new MyHandler();
		
		pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, "");
		pcap.close();
		textArea.append(jpacketHandler.toString());
		textArea.append("Po�et komunik�ci�: " + ((MyHandler) jpacketHandler).commCount() + "\n");
		textArea.setCaretPosition(0);
	}

}