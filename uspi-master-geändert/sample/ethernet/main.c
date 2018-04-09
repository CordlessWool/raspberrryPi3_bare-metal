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

typedef struct EthernetHeader
{
	u8	MACReceiver[MAC_ADDRESS_SIZE];
	u8	MACSender[MAC_ADDRESS_SIZE];
	u16	nProtocolType;
#define ETH_PROT_ARP		0x806
}
PACKED EthernetHeader;
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

typedef struct SNTPFrame
{
	EthernetHeader 	Ethernet;
	IPV4Header	IPV4;
	UDPHeader	UDP;
	SNTPHeader	SNTP;
}
PACKED SNTPFrame;

static const u8 OwnIPAddress[] = OWN_IP_ADDRESS;

static const char FromSample[] = "sample";

void set_ethernet_header(EthernetHeader *header, u8 mac_address_reciver[])
{
	u8 OwnMACAddress[MAC_ADDRESS_SIZE];
	USPiGetMACAddress (OwnMACAddress);
	u16 EthernetProtocol = 0x0008;

    memcpy (header->MACReceiver, mac_address_reciver, MAC_ADDRESS_SIZE);
    memcpy (header->MACSender, OwnMACAddress, MAC_ADDRESS_SIZE);
    header->nProtocolType = EthernetProtocol;
}

void set_ip_header(IPV4Header *IPV4, u8 ip[IP_ADDRESS_SIZE], int size){

	//IPV4-Header
	IPV4->VersIHL 	= 0x45; //Vers=4, IHL = 5x32Bit
	IPV4->TOS 		= 0x0;
	IPV4->Length	= switch_msb_lsb(20 + size); //20 Byte Header + size
	IPV4->ID		= 0x01;
	IPV4->FlagFragmentOffset = 0x0040; //Keine Fragmente
	IPV4->TTL		= 0x20;
	IPV4->Protocol	= 0x11; //17->UDP-Code
	IPV4->HeaderChecksum	= 0x0;
	memcpy (IPV4->IPSender, OwnIPAddress, IP_ADDRESS_SIZE);
	memcpy (IPV4->IPReceiver, ip, IP_ADDRESS_SIZE);
}

int switch_msb_lsb(int number){
    int switched = (number%(16*16)*(16*16))+ (number /(16*16));

    return switched;
}

void send_udp_to(u8 ip[IP_ADDRESS_SIZE],char *data, int data_size, int port){

	int udp_size = data_size + 8; // 8 byte for udp header

	u8 Buffer[USPI_FRAME_BUFFER_SIZE];
	UDPFrame *pack = (UDPFrame *) Buffer;

	u8 MAC_BROADCAST[] 	= {255, 255, 255, 255, 255, 255};

	set_ethernet_header(&pack->Ethernet, MAC_BROADCAST);
	set_ip_header(&pack->IPV4, ip, udp_size);

	pack->UDP.PortSender 	= switch_msb_lsb(port);
	pack->UDP.PortReceiver	= switch_msb_lsb(port);
	pack->UDP.Length		= switch_msb_lsb(udp_size);
	pack->UDP.Checksum	= 0x0;

	memcpy (pack->data, data, data_size);


	if (!USPiSendFrame (pack, sizeof *pack))
	{
		LogWrite (FromSample, LOG_ERROR, "USPiSendFrame failed");

		return;
	}
}

int main (void)
{
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
	u8 MAC_BROADCAST[] 	= {255, 255, 255, 255, 255, 255};
	u8 IP_BROADCAST[] 	= {192, 168, 178, 255};
	u8 IP_NTP[] 		= {192, 168, 178, 1};
	u8 RECIVER_IP_ADDRESS[]  = {192, 168, 178, 36};
	u16 EthernetProtocol = 0x0008;
	//u8 OWN_IP_ADDRESS = {192, 168, 178, 251};	

	u8 Buffer[USPI_FRAME_BUFFER_SIZE];
	SNTPFrame *pSNTPFrame = (SNTPFrame *) Buffer;

	u8 OwnMACAddress[MAC_ADDRESS_SIZE];
	USPiGetMACAddress (OwnMACAddress);
	
	u32 pause = 2000000000;
	u32 i = 0;	
	while (1)
	{



		/*
		
		//Request zusammenstellen
		//Ethernet-Header
		memcpy (pSNTPFrame->Ethernet.MACReceiver, MAC_BROADCAST, MAC_ADDRESS_SIZE);
		memcpy (pSNTPFrame->Ethernet.MACSender, OwnMACAddress, MAC_ADDRESS_SIZE);
		pSNTPFrame->Ethernet.nProtocolType = EthernetProtocol;
		//IPV4-Header
		pSNTPFrame->IPV4.VersIHL 	= 0x45; //Vers=4, IHL = 5x32Bit
		pSNTPFrame->IPV4.TOS 		= 0x0;
		pSNTPFrame->IPV4.Length		= 0x4C00; //20Header+56Data
		pSNTPFrame->IPV4.ID		= 0x01;
		pSNTPFrame->IPV4.FlagFragmentOffset = 0x0040; //Keine Fragmente
		pSNTPFrame->IPV4.TTL		= 0x20;
		pSNTPFrame->IPV4.Protocol	= 0x11; //17->UDP-Code
		pSNTPFrame->IPV4.HeaderChecksum	= 0x0;
		memcpy (pSNTPFrame->IPV4.IPSender, OwnIPAddress, IP_ADDRESS_SIZE);
		memcpy (pSNTPFrame->IPV4.IPReceiver, IP_NTP, IP_ADDRESS_SIZE);
		//UDP		
		pSNTPFrame->UDP.PortSender 	= 0x7B00; //Port 123 für NTP
		pSNTPFrame->UDP.PortReceiver	= 0x7B00;
		pSNTPFrame->UDP.Length		= 0x3800;	//56Byte
		pSNTPFrame->UDP.Checksum	= 0x0;
		// SNTP
		pSNTPFrame->SNTP.li_vn_mode	= 0x1B;
		pSNTPFrame->SNTP.stratum	= 0x0;
		pSNTPFrame->SNTP.poll		= 0x0;
  		pSNTPFrame->SNTP.precision	= 0x0;
  	 	pSNTPFrame->SNTP.rootDelay	= 0x0;
  	 	pSNTPFrame->SNTP.rootDispersion = 0x0;
  	 	pSNTPFrame->SNTP.refId		= 0x0;
  	 	pSNTPFrame->SNTP.refTm_s	= 0x0;
  	 	pSNTPFrame->SNTP.refTm_f	= 0x0;
  	 	pSNTPFrame->SNTP.origTm_s	= 0x0;
  	 	pSNTPFrame->SNTP.origTm_f	= 0x0;
  	 	pSNTPFrame->SNTP.rxTm_s		= 0x0;
  	 	pSNTPFrame->SNTP.rxTm_f		= 0x0;
  	 	pSNTPFrame->SNTP.txTm_s		= 0x0;
  	 	pSNTPFrame->SNTP.txTm_f		= 0x0;

		// Request
		
		if (!USPiSendFrame (pSNTPFrame, sizeof *pSNTPFrame))
		{
			LogWrite (FromSample, LOG_ERROR, "USPiSendFrame failed");

			break;
		}

		LogWrite (FromSample, LOG_NOTICE, "ARP reply successfully sent");

		 */

		char * message = "Hello Philipp";

        send_udp_to(RECIVER_IP_ADDRESS, message, UDP_MAX_DATA_SIZE, 3030);

		for(i=0; i<pause;i++)
		{
			1+1;
		}



	}

	USPiEnvClose ();

	return EXIT_HALT;
}
