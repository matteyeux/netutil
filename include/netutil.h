char *get_iface(void);
int hex_it(const u_char *payload, int len);
void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);