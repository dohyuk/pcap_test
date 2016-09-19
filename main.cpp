#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>


struct ether_addr
{
	unsigned char ether_addr_octet[6];
};

struct ether_header
{
	struct  ether_addr ether_dhost;
	struct  ether_addr ether_shost;
	unsigned short ether_type;
};

struct ip_header
{
	unsigned char ip_header_len : 4;
	struct in_addr ip_srcaddr;
	struct in_addr ip_destaddr;
};

struct tcp_header
{
	unsigned short source_port;
	unsigned short dest_port;
	unsigned char data_offset : 4;
};

void print_ether_header(const unsigned char *data);
int print_ip_header(const unsigned char *data);
int print_tcp_header(const unsigned char *data);

int main() 
{
	pcap_if_t *alldevs = NULL;

	char errbuf[PCAP_ERRBUF_SIZE];
	char *dev;
	int offset = 0;
	int i;
	int inum = 1;

	dev = pcap_lookupdev(errbuf);

	if(dev == NULL)
	{
		printf("%s\n", errbuf);
		return -1;
	}
															
	pcap_t *fp = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	struct pcap_pkthdr *header = NULL;
	const unsigned char *pkt_data = NULL;
	int res = 0;

	if (fp == NULL) 
	{
		printf("pcap open failed\n");
		return -1;
	}

	
	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0) 
	{
		if (res == 0)
			continue;

		print_ether_header(pkt_data); // ethernet 
		pkt_data += 14; 

		offset = print_ip_header(pkt_data); // ip
		pkt_data += offset; // offset = length(ipheader)

		offset = print_tcp_header(pkt_data); // tcp
		pkt_data += offset; // print_tcp_header *4

		break;
	}

	return 0;

}

void print_ether_header(const unsigned char *data)
{
	struct  ether_header *eh;
	unsigned short ether_type;
	eh = (struct ether_header *)data;

	ether_type = ntohs(eh->ether_type); // big -> little

	if (ether_type != 0x0800)
	{
		printf("ether type wrong\n");
		return;
	}

	printf("\n============ETHERNET HEADER==========\n");
	printf("Dst MAC Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n", // 6 byte
		eh->ether_dhost.ether_addr_octet[0],
		eh->ether_dhost.ether_addr_octet[1],
		eh->ether_dhost.ether_addr_octet[2],
		eh->ether_dhost.ether_addr_octet[3],
		eh->ether_dhost.ether_addr_octet[4],
		eh->ether_dhost.ether_addr_octet[5]);
	printf("Src MAC Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n", // 6 byte
		eh->ether_shost.ether_addr_octet[0],
		eh->ether_shost.ether_addr_octet[1],
		eh->ether_shost.ether_addr_octet[2],
		eh->ether_shost.ether_addr_octet[3],
		eh->ether_shost.ether_addr_octet[4],
		eh->ether_shost.ether_addr_octet[5]);
}

int print_ip_header(const unsigned char *data)
{
	struct  ip_header *ih;
	ih = (struct ip_header *)data;

	printf("\n============IP HEADER============\n");
	printf("Src IP Addr : %s\n", inet_ntoa(ih->ip_srcaddr));
	printf("Dst IP Addr : %s\n", inet_ntoa(ih->ip_destaddr));

	// return to ip header size
	return ih->ip_header_len * 4;
}

int print_tcp_header(const unsigned char *data)
{
	struct  tcp_header *th;
	th = (struct tcp_header *)data;

	printf("\n============TCP HEADER============\n");
	printf("Src Port Num : %d\n", ntohs(th->source_port));
	printf("Dest Port Num : %d\n", ntohs(th->dest_port));

	// return to tcp header size
	return th->data_offset * 4;
}
