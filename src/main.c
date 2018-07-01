#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pcap.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <include/netutil.h>
#include <include/scanner.h>

void usage(char const *name){
	fprintf(stdout, "usage : %s [arg]\n", name);
	fprintf(stdout, "-s, --snif <number of packets>\t\t\t snif network packets\n");
	fprintf(stdout, "-p, --port <host> <start port> <end port>\t scan ports\n");
	fprintf(stdout, "-i, --interface <interface>\t\t specify network interface\n");
	fprintf(stdout, "-h, --help \t\t\t\t\t print this help\n");
}

int main(int argc, char const *argv[]){
	bool snif = false, port = false, iface = false;
	int result;
	int pkt_number = 0;
	int snapshot_length = 1024;
	int start_port = 0, end_port = 0;
	char *device;
	char error_buffer[PCAP_ERRBUF_SIZE];
	char *host = NULL;
	pcap_t *handler;
	struct bpf_program filterprog;

	if (argc < 2)
	{
		usage(argv[0]);
		return 0;
	}

	for(int i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "-s") || !strcmp(argv[i], "--snif"))
		{
			snif = true;
		} else if (!strcmp(argv[i], "-p") || !strcmp(argv[i], "--port")){
			port = true;
		} else if (!strcmp(argv[i], "-i") || !strcmp(argv[i], "--interface")){
			iface = true;
			device = (char *)argv[i + 1];
		}
		else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")){
			usage(argv[0]);
			return 0;
		}
	}

	if (snif){
		int uid = getuid();
		if (!iface){
			device = get_iface();
		}
		fprintf(stdout, "[i] interface : %s\n", device);

		if (uid != 0){
			fprintf(stdout, "[-] please, run this tool as root\n[i] UID : %d\n", uid);
			return -1;
		}

		if (argc == 3){
			pkt_number = atoi(argv[2]);
		}

		handler = pcap_open_live(device, snapshot_length, pkt_number, 10000, error_buffer);
		if (handler == NULL){
			fprintf(stderr, "[e] pcap_open_live failed: %s\n", error_buffer);
			return -1;
		}

		result = pcap_compile(handler, &filterprog, "ip", 0, PCAP_NETMASK_UNKNOWN);
		if(result != 0){
        	fprintf(stderr, "[e] pcap_compile failed: %s\n", pcap_geterr(handler));
			pcap_close(handler);
			return -1;
		}

		result = pcap_setfilter(handler, &filterprog);
		if(result != 0) {
			fprintf(stderr, "[e] pcap_setfilter failed: %s\n", pcap_geterr(handler));
			pcap_close(handler);
			return -1;
		}

		pcap_loop(handler, 0, handle_packet, NULL);
		pcap_close(handler);
	}
	else if (port){
		switch(argc){
			case 3:
				host = (char *)argv[argc - 1];
				break;
			case 4:
				host = (char *)argv[argc - 2];
				start_port = atoi(argv[argc - 1]);
				break;
			case 5:
				host = (char *)argv[argc - 3];
				start_port = atoi(argv[argc - 2]);
				end_port = atoi(argv[argc - 1]);
				break;
		}
		scan_ports(host, start_port, end_port);
	} 
	else {
		usage(argv[0]);
		return -1;
	}
	return 0;
}
