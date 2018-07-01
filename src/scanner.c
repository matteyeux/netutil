#include <stdio.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <include/scanner.h>

char *hostname_to_ip(const char *hostname)
{
	struct hostent *host;
	struct in_addr **addr_list;
	int i;
	if ((host = gethostbyname(hostname)) == NULL)
	{
		herror("gethostbyname");
		return NULL;
	}
	addr_list = (struct in_addr **) host->h_addr_list;

	for(i = 0; addr_list[i] != NULL; i++) 
	{
		return (char *)inet_ntoa(*addr_list[i]);
	}

	return NULL;
}

int scan_ports(const char *hostname, int start, int end)
{
	int err,i, sock;
	struct hostent *host;
	struct sockaddr_in sa;

	strncpy((char*)&sa , "" , sizeof sa);
	sa.sin_family = AF_INET;

	if (hostname == NULL)
		hostname = "127.0.0.1";

	/* direct ip address */
	if(isdigit(hostname[0])) {
		sa.sin_addr.s_addr = inet_addr(hostname);
	} else if((host = gethostbyname(hostname)) != 0) {
		fprintf(stdout, "[i] IP : %s\n", hostname_to_ip(hostname));
		strncpy((char*)&sa.sin_addr , (char*)host->h_addr , sizeof sa.sin_addr);
	} else {
		herror(hostname);
		exit(2);
	}

	if (start == 0)
		start = 1;

	if (end == 0)
		end = 64738;

	printf("[i] scanning...\n");
	for(i = start ; i <= end ; i++) 
	{
		sa.sin_port = htons(i);
		sock = socket(AF_INET , SOCK_STREAM , 0);

		if(sock < 0) 
		{
			perror("\nSocket");
			exit(1);
		}

		err = connect(sock , (struct sockaddr*)&sa , sizeof sa);

		/* not connected */
		if( err < 0 ) {
			#ifdef DEBUG
			printf("%s %-5d %s\n" , hostname , i, strerror(errno));
			#endif
		}
		else
		{
			fprintf(stdout, "[+] %-5d open\n",  i);
		}
		close(sock);
	}
	return(0);
}