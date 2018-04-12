//
// main.c
//
#include <uspienv.h>
#include <uspi.h>
#include <uspios.h>
#include <uspienv/util.h>
#include <uspienv/macros.h>
#include <uspienv/types.h>

#define	OWN_IP_ADDRESS		{192, 168, 178, 241}	// must be a valid IP address on your LAN

#define MAC_ADDRESS_SIZE	6
#define IP_ADDRESS_SIZE		4

#define UDP_MAX_DATA_SIZE 1400
#define ETHERNET_MAX_SIZE 1542

typedef struct EthernetHeader
{
	u8	MACReceiver[MAC_ADDRESS_SIZE];
	u8	MACSender[MAC_ADDRESS_SIZE];
	u16	nProtocolType;
}
PACKED EthernetHeader;

typedef struct TARPPacket
{
	u16		nHWAddressSpace;
#define HW_ADDR_ETHER		1
	u16		nProtocolAddressSpace;
#define PROT_ADDR_IP		0x800
	u8		nHWAddressLength;
	u8		nProtocolAddressLength;
	u16		nOPCode;
#define ARP_REQUEST		1
#define ARP_REPLY		2
	u8		HWAddressSender[MAC_ADDRESS_SIZE];
	u8		ProtocolAddressSender[IP_ADDRESS_SIZE];
	u8		HWAddressTarget[MAC_ADDRESS_SIZE];
	u8		ProtocolAddressTarget[IP_ADDRESS_SIZE];
}
PACKED TARPPacket;

typedef struct TARPFrame
{
    EthernetHeader Ethernet;
	TARPPacket	ARP;
}
PACKED TARPFrame;

typedef struct IPV4Header
{
	u8	VersIHL;
	u8	TOS;
	u16	Length;
	u16 	ID;
	u16	FlagFragmentOffset;
	u8	TTL;
	u8 	Protocol;
	u16	HeaderChecksum;
	u8	IPSender[IP_ADDRESS_SIZE];
	u8 	IPReceiver[IP_ADDRESS_SIZE];
}
PACKED IPV4Header;
typedef struct UDPHeader
{
	u16	PortSender;
	u16	PortReceiver;
	u16	Length;
	u16	Checksum;
}
PACKED UDPHeader;

typedef struct UDPFrame
{
    EthernetHeader Ethernet;
    IPV4Header IPV4;
    UDPHeader UDP;
    char data[UDP_MAX_DATA_SIZE];
}
PACKED UDPFrame;

typedef struct SNTPHeader
{
 	u8 	li_vn_mode;      // Eight bits. li, vn, and mode.
                           // li.   Two bits.   Leap indicator.
                           // vn.   Three bits. Version number of the protocol.
                           // mode. Three bits. Client will pick mode 3 for client.

  	u8	stratum;         // Eight bits. Stratum level of the local clock.
  	u8	poll;            // Eight bits. Maximum interval between successive messages.
  	u8	precision;       // Eight bits. Precision of the local clock.
  	u32 	rootDelay;      // 32 bits. Total round trip delay time.
  	u32 	rootDispersion; // 32 bits. Max error aloud from primary clock source.
  	u32 	refId;          // 32 bits. Reference clock identifier.
  	u32 	refTm_s;        // 32 bits. Reference time-stamp seconds.
  	u32 	refTm_f;        // 32 bits. Reference time-stamp fraction of a second.
  	u32 	origTm_s;       // 32 bits. Originate time-stamp seconds.
  	u32 	origTm_f;       // 32 bits. Originate time-stamp fraction of a second.
  	u32 	rxTm_s;         // 32 bits. Received time-stamp seconds.
  	u32 	rxTm_f;         // 32 bits. Received time-stamp fraction of a second.
  	u32 	txTm_s;         // 32 bits and the most important field the client cares about. Transmit time-stamp seconds.
  	u32 	txTm_f;         // 32 bits. Transmit time-stamp fraction of a second.
}
PACKED SNTPHeader;

void replay_arp(TARPFrame *pARPFrame);
void send_udp_to(u8 ip[IP_ADDRESS_SIZE],char *data, int data_size, int port);
int receiveEthernetFrame();

static const u8 OwnIPAddress[] = OWN_IP_ADDRESS;
static const char FromSample[] = "sample";
u8 *ip_table[256]; // size for netmask 255.255.255.0

u16 addU16(u16 *check, u16 anzByte, u16 data)
{	// Addieren von 16Bit-Blöcken
    	u16 i = 0;
    	u32 sum = 0x0000ffff&data; //16u in 32u übertragen

    	for(i=0;i<anzByte/2;i++)
    	{
       		sum = sum+check[i];
    	}

	if(anzByte%2) // ungerade Anzahl an Bytes -> letztes Bytepaar mit 0x00 auffüllen
	{
		sum = sum + (check[i]&0xff00);
	}
	sum = (sum&0xffff) +(sum>>16);
	return (sum & 0xffff);
}
void checksumIPV4(IPV4Header *IPV4)
{	//checksumme für IPV4-Header
	IPV4->HeaderChecksum = addU16((u16 *)IPV4, 20, 0)^0xffff;	//20 Byte großer Header
}
void checksumUDP(UDPFrame * UDP, int anzDataByte)
{	//checksumme für UDP-Header
	u16 tmp = 0;
	u16 udp_prot = 0x1100;
	//add pseudo Header
	tmp = addU16((u16 *) &UDP->IPV4.IPSender,8,tmp); // IP-Adressen
	tmp = addU16(&udp_prot,1,tmp);
	tmp = addU16(&UDP->UDP.Length,1,tmp);
	//add Header
	tmp = addU16(&UDP->UDP,8,tmp);
	//add Data
	tmp = addU16(&UDP->data,anzDataByte,tmp);
	//komplement
	UDP->UDP.Checksum = tmp^0xffff;
}
//Debug-Message senden
void send_debug_message(char * message, int size){
    u8 test_ip[] = {192,168,178,25};		//IP von Laptop

    send_udp_to(test_ip, message, size, 3030);
}
//Ausgleich der Endianness
int switch_msb_lsb(int number){		
	int switched = (number%(16*16)*(16*16))+ (number /(16*16));
	return switched;
}
//speichern der eigenen MAC-Adresse in Array
void init_arp(){	
	int pos;
	for(pos = 0; pos < sizeof * ip_table;pos++) {
		ip_table[pos] = 0;
	}

	u8 OwnMACAddress[MAC_ADDRESS_SIZE];
	USPiGetMACAddress (OwnMACAddress);

	int own_ip[IP_ADDRESS_SIZE] = OWN_IP_ADDRESS;

	ip_table[own_ip[IP_ADDRESS_SIZE-1]] = OwnMACAddress;
}
//MAC-Adresse aus Array auslesen
int get_mac_address_of(u8 ip[IP_ADDRESS_SIZE], u8 * mac){

	if(ip_table[ip[IP_ADDRESS_SIZE-1]] != 0){	//MAC-Adresse zu IP vorhanden

		mac = ip_table[ip[IP_ADDRESS_SIZE-1]];
		return 0;
	}else{	//bisher keine MAC-Adresse zu IP vorhanden
		//Anfrage nach MAC versenden
		send_arp_to(ip);
		//auf Antwort warten
		int loops = 20000;
		int loop_counter = 0;
		while(receiveEthernetFrame() == -1 || loop_counter < loops){
		    loop_counter++;
		}
		//wenn keine Antwort erhalten-> Broadcast MAC-Adresse verwenden
		if(loop_counter == loops){
		    u8 MAC_BROADCAST[MAC_ADDRESS_SIZE] = {255, 255, 255, 255, 255, 255};
		    mac = MAC_BROADCAST;
		    return -1;
		}else{
		//MAC Adresse aus Antwort auslesen
		    mac = ip_table[ip[IP_ADDRESS_SIZE-1]];
		    return 0;
		}

	}

}
//MAC-Adresse in Array einfügen
void set_mac_address_of(u8 ip[IP_ADDRESS_SIZE], u8 mac[MAC_ADDRESS_SIZE]){
	ip_table[ip[IP_ADDRESS_SIZE-1]] = &mac[0];
}

//ARP-Request senden
void send_arp_to(u8 ip[IP_ADDRESS_SIZE]){	//ARP-Request versenden

    	u8 OwnMACAddress[MAC_ADDRESS_SIZE];
    	USPiGetMACAddress (OwnMACAddress);

	u8 MAC_BROADCAST[] 	= {255, 255, 255, 255, 255, 255};

	u8 Buffer[USPI_FRAME_BUFFER_SIZE];
	TARPFrame *pARPFrame = (TARPFrame *) Buffer;
	//Ethernet-Header
	memcpy (pARPFrame->Ethernet.MACReceiver, MAC_BROADCAST, MAC_ADDRESS_SIZE);
	memcpy (pARPFrame->Ethernet.MACSender, OwnMACAddress, MAC_ADDRESS_SIZE);
	pARPFrame->Ethernet.nProtocolType = switch_msb_lsb(0x806);
	//ARP-Protocol
	pARPFrame->ARP.nHWAddressSpace = switch_msb_lsb(HW_ADDR_ETHER);
	pARPFrame->ARP.nProtocolAddressSpace = switch_msb_lsb(PROT_ADDR_IP);

	pARPFrame->ARP.nHWAddressLength = 6;
	pARPFrame->ARP.nProtocolAddressLength = 4;

	pARPFrame->ARP.nOPCode = switch_msb_lsb(ARP_REQUEST);

	memcpy (pARPFrame->ARP.HWAddressSender, OwnMACAddress, MAC_ADDRESS_SIZE);
	memcpy (pARPFrame->ARP.ProtocolAddressSender, OwnIPAddress, IP_ADDRESS_SIZE);

	memcpy (pARPFrame->ARP.HWAddressTarget, MAC_BROADCAST, MAC_ADDRESS_SIZE);
	memcpy (pARPFrame->ARP.ProtocolAddressTarget, ip, IP_ADDRESS_SIZE);

	if (!USPiSendFrame (pARPFrame, sizeof * pARPFrame))
	{
		LogWrite (FromSample, LOG_ERROR, "USPiSendFrame failed");
		return;
	}
}

void gratuitous_arp(){
    u8 own_ip[IP_ADDRESS_SIZE] = OWN_IP_ADDRESS;
	send_arp_to(own_ip);
}
//ARP-Paket auswerten
void analyse_arp(TARPFrame * pARPFrame, u8* mac, u8* ip, u16 *operation){
	memcpy (mac, pARPFrame->ARP.HWAddressSender, MAC_ADDRESS_SIZE);
	memcpy (ip, pARPFrame->ARP.ProtocolAddressSender, IP_ADDRESS_SIZE);
	*operation = pARPFrame->ARP.nOPCode;
}
//IPV4-Header auswerten
void analyse_ipv4(UDPFrame * frame, u8 * mac, u8 * ip ){
	memcpy (mac, frame->Ethernet.MACSender, MAC_ADDRESS_SIZE);
	memcpy (ip, frame->IPV4.IPSender, IP_ADDRESS_SIZE);
}
//Auswerten eines Empfangenen Ethernet Frames
int analyse_uspi_receive_frame(u8 Buffer[USPI_FRAME_BUFFER_SIZE], unsigned nFrameLength){


	if(nFrameLength < ETHERNET_MAX_SIZE){
	    EthernetHeader *header = (EthernetHeader *) Buffer;
		//memcpy(header, Buffer, sizeof * header);
		u8 mac[MAC_ADDRESS_SIZE];
		u8 ip[IP_ADDRESS_SIZE];
		if(header->nProtocolType == switch_msb_lsb(0x806) && nFrameLength >= sizeof(TARPFrame)){
			TARPFrame *frame = (TARPFrame *) Buffer;
			u16 operation = 0;
		    analyse_arp(frame, mac, ip, &operation);
		    set_mac_address_of(ip, mac);
		    if(operation == switch_msb_lsb(ARP_REQUEST)){
		        send_debug_message("received arp request", 20);
		        replay_arp(frame);
		    }else if(operation == switch_msb_lsb(ARP_REPLY)){
		        send_debug_message("received arp replay", 20);
		    }
		}else if(header->nProtocolType == switch_msb_lsb(0x800) && nFrameLength <= sizeof(UDPFrame)){
		    	UDPFrame *frame = (UDPFrame *) Buffer;
            		send_debug_message("received udp", 14);

            		analyse_ipv4(frame, mac, ip);
            		set_mac_address_of(ip, mac);
		}else{
		    return -1;
		}
	}else{
	    return -1;
	}

	return 0;
}
//auf ARP antworten
void replay_arp(TARPFrame *pARPFrame){

    u8 OwnMACAddress[MAC_ADDRESS_SIZE];
    USPiGetMACAddress (OwnMACAddress);

	// prepare reply packet
	memcpy (pARPFrame->Ethernet.MACReceiver, pARPFrame->ARP.HWAddressSender, MAC_ADDRESS_SIZE);
	memcpy (pARPFrame->Ethernet.MACSender, OwnMACAddress, MAC_ADDRESS_SIZE);
	pARPFrame->ARP.nOPCode = BE (ARP_REPLY);

	memcpy (pARPFrame->ARP.HWAddressTarget, pARPFrame->ARP.HWAddressSender, MAC_ADDRESS_SIZE);
	memcpy (pARPFrame->ARP.ProtocolAddressTarget, pARPFrame->ARP.ProtocolAddressSender, IP_ADDRESS_SIZE);

	memcpy (pARPFrame->ARP.HWAddressSender, OwnMACAddress, MAC_ADDRESS_SIZE);
	memcpy (pARPFrame->ARP.ProtocolAddressSender, OwnIPAddress, IP_ADDRESS_SIZE);

	if (!USPiSendFrame (pARPFrame, sizeof *pARPFrame))
	{
		LogWrite (FromSample, LOG_ERROR, "USPiSendFrame failed");
		return;
	}
}
//Ethernet Header für IPV4 zusammenstellen
void set_ethernet_header(EthernetHeader *header, u8 mac_address_reciver[])
{
	u8 OwnMACAddress[MAC_ADDRESS_SIZE];
	USPiGetMACAddress (OwnMACAddress);
	u16 EthernetProtocol = 0x0008;

    	memcpy (header->MACReceiver, mac_address_reciver, MAC_ADDRESS_SIZE);
    	memcpy (header->MACSender, OwnMACAddress, MAC_ADDRESS_SIZE);
    	header->nProtocolType = EthernetProtocol;
}

//IPV4-Header zusammenstellen
void set_ip_header(IPV4Header *IPV4, u8 ip[IP_ADDRESS_SIZE], int size){
	//IPV4-Header
	IPV4->VersIHL 		= 0x45; //Vers=4, IHL = 5x32Bit
	IPV4->TOS 		= 0x0;	
	IPV4->Length		= switch_msb_lsb(20 + size); //20 Byte Header + size
	IPV4->ID		= 0x01;	
	IPV4->FlagFragmentOffset = 0x0040; //Keine Fragmente
	IPV4->TTL		= 0x20;
	IPV4->Protocol		= 0x11; //17->UDP-Code
	IPV4->HeaderChecksum	= 0x0;
	memcpy (IPV4->IPSender, OwnIPAddress, IP_ADDRESS_SIZE);
	memcpy (IPV4->IPReceiver, ip, IP_ADDRESS_SIZE);
	checksumIPV4(IPV4);
}

//UDP Paket zusammenstellen und versenden
void send_udp_to(u8 ip[IP_ADDRESS_SIZE],char *data, int data_size, int port){

	int udp_size = data_size + 8; // 8 byte for udp header
	int package_size = udp_size; //EhternetHeader size and IPV4 Header size are added later

	u8 Buffer[USPI_FRAME_BUFFER_SIZE];
	UDPFrame *pack = (UDPFrame *) Buffer;

	u8 MAC_BROADCAST[] 	= {255, 255, 255, 255, 255, 255};
	u8 MAC_Laptop[]		= {184, 136, 227, 51, 106, 91};
	u8 MAC_Router[]		= {56, 16, 213, 19, 202, 42};
	u8 mac[MAC_ADDRESS_SIZE];
	//get_mac_address_of(ip, mac); //could also be broadcast
	//set_ethernet_header(&pack->Ethernet, mac);
	set_ethernet_header(&pack->Ethernet, MAC_BROADCAST);
	set_ip_header(&pack->IPV4, ip, udp_size);

	package_size += sizeof (pack->Ethernet) + sizeof (pack->IPV4);

	pack->UDP.PortSender 	= switch_msb_lsb(port);
	pack->UDP.PortReceiver	= switch_msb_lsb(port);
	pack->UDP.Length		= switch_msb_lsb(udp_size);
	pack->UDP.Checksum	= 0x0;

	memcpy (pack->data, data, data_size);

	checksumUDP(pack, data_size);
	//pack->UDP.Checksum	=  checksum((u16 *) &pack->UDP, 4+data_size/2);

	if (!USPiSendFrame (pack, package_size))
	{
		LogWrite (FromSample, LOG_ERROR, "USPiSendFrame failed");

		return;
	}
}
//überprüfen ob empfangenes Ethernet-Frame vorhanden -> auswerten
int receiveEthernetFrame(){
    u8 Buffer[USPI_FRAME_BUFFER_SIZE];
    unsigned nFrameLength;
	if (USPiReceiveFrame (Buffer, &nFrameLength))
	{
	    analyse_uspi_receive_frame(Buffer, nFrameLength);
	    return 0;
	}else{
	    return -1;
	}
}
void send_SNTP_Frame(u8 *IP) // SNTP-Request zusammenstellen und senden
{
	u8 BufferSNTP[USPI_FRAME_BUFFER_SIZE];
	SNTPHeader *SNTP = (SNTPHeader *) BufferSNTP;

	// SNTP
	SNTP->li_vn_mode	= 0xE3;
	SNTP->stratum		= 0x0;
	SNTP->poll		= 0x06;
  	SNTP->precision		= 0xE9;
  	SNTP->rootDelay		= 0x0;
  	SNTP->rootDispersion 	= 0x0;
 	SNTP->refId		= 0x0;
   	SNTP->refTm_s		= 0x0;
  	SNTP->refTm_f		= 0x0;
  	SNTP->origTm_s		= 0x0;
  	SNTP->origTm_f		= 0x0;
  	SNTP->rxTm_s		= 0x0;
  	SNTP->rxTm_f		= 0x0;
  	SNTP->txTm_s		= 0x0;
  	SNTP->txTm_f		= 0x0;

	//SNTP Request senden
	send_udp_to(IP, SNTP, sizeof * SNTP, 123);
}

///////////////////////MAIN///////////////////////////////////////////////////////
int main (void)
{	
	//Umgebung, USB und Ethernet initialisieren
	if (!USPiEnvInitialize ())
	{
		return EXIT_HALT;
	}
	
	if (!USPiInitialize ())
	{
		LogWrite (FromSample, LOG_ERROR, "Cannot initialize USPi");

		USPiEnvClose ();

		return EXIT_HALT;
	}

	if (!USPiEthernetAvailable ())
	{
		LogWrite (FromSample, LOG_ERROR, "Ethernet device not found");

		USPiEnvClose ();

		return EXIT_HALT;
	}
	//Bekannte IP und MAC Addressen
	u8 MAC_BROADCAST[] 	= {255, 255, 255, 255, 255, 255};
	u8 IP_BROADCAST[] 	= {192, 168, 178, 255};
	u8 RECIVER_IP_ADDRESS_PC[] = {192, 168, 178, 25};
	u8 RECIVER_IP_ADDRESS_ROUTER[] = {192, 168, 178, 1};
	u8 IP_Router[] 		= {192, 168, 178, 1}; //Router
	u8 MAC_Router[]		= {56, 16, 213, 19, 202, 42};
	u8 IP_Laptop[] 		= {192, 168, 178, 25}; // Laptop
	u8 MAC_Laptop[]		= {184, 136, 227, 51, 106, 91};
	u16 EthernetProtocol = 0x0008;	

	char * message;

	u32 pause = 200000;
	u32 pause_loop = 0;	
	while (1)
	{
        	//locksup if there is new frame
        	receiveEthernetFrame();

		if(pause_loop < pause){
	        	pause_loop++;
	        	continue;
	    	}else{
	        	pause_loop = 0;
	    	}
		//SNTP-Request senden
		send_SNTP_Frame(IP_Laptop);
		message = "SNTP-Request gesendet";
		send_udp_to(IP_Laptop, message, 22, 3031);
		
		//ARP-Requests senden
        	gratuitous_arp();
		send_arp_to(RECIVER_IP_ADDRESS_ROUTER);
		send_arp_to(RECIVER_IP_ADDRESS_PC);
	}

	USPiEnvClose ();

	return EXIT_HALT;
}
