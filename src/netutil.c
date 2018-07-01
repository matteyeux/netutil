#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <ctype.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <include/netutil.h>

char *get_iface(void)
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE];

	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		exit(-1);
	}
	return (char *)dev;
}

void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	struct ether_header *eth_header;
	eth_header = (struct ether_header *) packet;
	if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
		/* not an IP packet */
		return;
	}


	printf("Total packet available: %d bytes\n", header->caplen);
	printf("Expected packet size: %d bytes\n", header->len);

	const u_char *ip_header;
	const u_char *tcp_header;
	const u_char *payload;

	/* Header lengths in bytes */
	int ethernet_header_length = 14, ip_header_length, tcp_header_length, payload_length;

	/* Find beginning of IP header */
	ip_header = packet + ethernet_header_length;
	ip_header_length = ((*ip_header) & 0x0F);
	ip_header_length = ip_header_length * 4;

	// IP header length
	printf("IHL: %d bytes\n", ip_header_length);

	u_char protocol = *(ip_header + 9);

	if (protocol != IPPROTO_TCP)
		return;

	tcp_header = packet + ethernet_header_length + ip_header_length;
	tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
	tcp_header_length = tcp_header_length * 4;
	printf("TCP header length: %d bytes\n", tcp_header_length);

	int total_headers_size;
	total_headers_size = ethernet_header_length + ip_header_length + tcp_header_length;
	printf("Size of all headers combined: %d bytes\n", total_headers_size);

	payload_length = header->caplen - (ethernet_header_length + ip_header_length + tcp_header_length);
	printf("Payload size: %d bytes\n", payload_length);

	payload = packet + total_headers_size;
	hex_it(payload, payload_length);
	return;
}

int hex_it(const u_char *payload, int len)
{
	const int line_len = 16;
	int offset = 0;
	int nb_lines = len / line_len;
	int i, j;

	if(nb_lines * line_len < len)
		nb_lines++;

	for(i = 0; i < nb_lines; i++)
	{
		printf("%04X    ", offset);
		for(j = 0; j < line_len; j++)
		{
			if(offset + j >= len)
				printf("   ");
			else
				printf("%02X ", payload[offset + j]);
		}
		printf("   ");

		for(j = 0; j < line_len; j++)
		{
			if(offset + j >= len)
				printf(" ");
			else if(payload[offset + j] > 31 && payload[offset + j] < 127)
				printf("%c", payload[offset + j]);
			else
				printf(".");
		}

		offset += line_len;
		printf("\n");
	}
	return 0;
}