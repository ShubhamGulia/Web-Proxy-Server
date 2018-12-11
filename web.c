#include<stdio.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<string.h>
#include<netdb.h>
#include<unistd.h>
#include<sys/poll.h>
#include<signal.h>

int init(int);
int parse(char*,int,int,char*);
int blacklist(char*,int);
void errorpager(int,int);
int dnslookup(char*,char*);
int go(char*,int,int,int,char*,int);

//TEAM M2:
	//Ben, Neeha, Aman, Shubham, Shreyash, Arpitha
//Code Authors:
	//MAIN LOOP/POLLING: By Ben
	//INIT: By Aman, edited by Ben
	//ERRORPAGER: by Ben
	//PARSE: By Neeha and Ben
	//DNSLOOKUP: By Ben
	//BLACKLIST: By Shubham, edited by Ben
	//GO: By Shreyash, Arpitha, and Ben

int main(int argc, char **argv) {
	printf("CS656 project by Shubham Gulia (sg952@njit.edu)\n");
	
	signal(SIGPIPE, SIG_IGN);
	char client_request[65535];
	char temp_request[65535];
	char domain[200];
	char ip[16];
	int port;
	int browser_socket;
	int csize;
	int blacklisted;
	struct pollfd browserpoll[1];
	int polling;
	int dnserr;
	int success;
	int n;
	int tempsize = 0;
	int readsomething = 0;
	
	int ourport = atoi(argv[1]);
	int server_socket = init(ourport);
	

	while (1){
		listen(server_socket,5);
		browser_socket=accept(server_socket,NULL,NULL);
		
		browserpoll[0].fd = browser_socket;
		browserpoll[0].events = POLLIN;
	
		while (( polling = poll(browserpoll,1,3000)) < 2) {
			if (polling < 0) {
				printf("LOG: polling failed on browser socket.\n");
				break; }
			else if (polling == 0 ) {
				break; }
			else {
				n = read(browser_socket,temp_request,sizeof(temp_request));
				if (n == 0) {
					break;
				}
				readsomething = 1;
				tempsize += n;
				if (tempsize > 65535) {
					printf("LOG: Request exceeds 65535 bytes; dropping.\n");
					memset(client_request, 0, sizeof(client_request[0]) * 65535);
					tempsize = 0;
					errorpager(413,browser_socket);
					break;
				}
				else {
					strncat(client_request,temp_request,n);
					memset(temp_request, 0, sizeof(temp_request[0]) * 65535);
				}
			}
		}
			csize = tempsize;
			if (csize > 0) {
				port = parse(client_request,csize,browser_socket,domain);
				if (port > 0) {
					blacklisted = blacklist(domain,browser_socket);
					if (!blacklisted) {
						dnserr = dnslookup(domain,ip);
						if (dnserr == 0) {
							success = go(client_request,csize,port,browser_socket,ip,server_socket);
							if (success == 0) {
								printf("LOG: Request to (%s) processed.\n",domain);
							}
						}
						else {
							errorpager(404,browser_socket);
							//Is there something more specific for DNS failure?
						}
					}
				}
			}
		if (csize != 0 ) {
			memset(client_request, 0, sizeof(client_request[0]) * 65535);
		}
		tempsize = 0;
		if (!readsomething) {
			printf("LOG: Client disconnected for inactivity.\n");
			errorpager(408,browser_socket); }
		readsomething = 0;
		close(browser_socket);
	}
}
int init (int proxyport) {
	int server_socket;
	char ourhost[200];
	gethostname(ourhost,200);
	char ourip[16];
	dnslookup(ourhost,ourip);
	
	server_socket=socket(AF_INET,SOCK_STREAM,0);
	struct sockaddr_in server_address;
	server_address.sin_family = AF_INET;
	server_address.sin_port=htons(proxyport);
	inet_pton(AF_INET,ourip,&(server_address.sin_addr.s_addr));
	if(server_socket<0){
        printf("LOG: Failed connecting the initial server socket.\n");
        exit(1); }
	bind(server_socket,(struct sockaddr *) &server_address, sizeof(server_address));
	return(server_socket);
}
void errorpager(int errno, int servsock) {
	char error[8];
	int n;
	sprintf(error,"%d.html",errno);
	FILE *errpage = fopen(error,"rb");
	fseek(errpage, 0, SEEK_END);
	long errsize = ftell(errpage);
	rewind(errpage);
	char *errp = malloc(errsize+1);
	fread(errp,errsize,1,errpage);
	fclose(errpage);
	errp[errsize] = '\0';
	n = write(servsock,errp,errsize);
	if (n < 0) {
		free(errp);
		return; }
	free(errp);
}
int parse(char *clienttext, int csize, int servsock, char *dom) {
    char text[csize];
	strcpy(text,clienttext);
	int getlength = strcspn(text,"\n");
	getlength++;
	char request[getlength];
	strncpy(request,text,getlength);
	request[getlength-1] = '\0';
	int readerror = 0;
	
	char get[3];
	strncpy(get,text,3);
	get[3]='\0';
	
	char *hostp = strstr(text,"Host: ");
	if  ( hostp == NULL ) {//
		printf("LOG: Not a valid request (Missing Host line).\n");
		errorpager(400,servsock);
		readerror = -1;
		return readerror; } 
	int hostlen = strcspn(hostp,"\n");
	char host[hostlen];
	strncpy(host,hostp,hostlen);
	host[hostlen] = '\0';
	
	if (get == NULL || request == NULL || host == NULL ) {
		printf("LOG: Not a valid request (Missing Method/Host data).\n");
		errorpager(400,servsock);
		readerror = -1;
		return readerror; }
	
	if (strcmp("GET",get) != 0) {
		printf("LOG: Method denied (Not a GET).\n");
		errorpager(405,servsock);
		readerror = -1;
		return readerror; }
	
	if (getlength < 13) {
		printf("LOG: Not a valid request (Bad GET line).\n");
		errorpager(400,servsock);
		readerror = -1;
		return readerror;
	}
	else {
		char *httpver = request+getlength-10;
		if (httpver[0] == ' ' ) {
			httpver++;
		}
		if (strncmp(httpver,"HTTP/1.1",8) != 0) {
			printf("LOG: Refusing request (Not HTTP/1.1).\n");
			errorpager(505,servsock);
			return -1;
		}
	}	
	char *hostpointer = strchr(host, ' ');
	if (hostpointer == NULL) {
		errorpager(400,servsock);
		printf("LOG: Not a valid request (Bad/no HOST).\n");
		readerror = -1;
		return readerror; }
	else { hostpointer++; }
	
	char *portpointer = strchr(hostpointer, ':');
	char *tocut = portpointer;
	int portnum = 80;
	int portcut = 0;
	int cutlen;
	int badport;
	if (portpointer != NULL ) {
		portpointer++;
		portnum = atoi(portpointer);
		portcut = 1; }
	if (portnum == 0) {
		errorpager(400,servsock);
		printf("LOG: Not a valid request (Bad Port).\n");
		readerror = -1;
		return readerror; }
	if (portcut == 1) {
		cutlen = strlen(hostpointer) - strlen(tocut); }
	else {
		cutlen = strlen(hostpointer) -1; }
	hostpointer[cutlen] = '\0';
	
	strcpy(dom,hostpointer);
	memset(text, 0, sizeof(text[0]) * sizeof(text));
	memset(request, 0, sizeof(request[0]) * sizeof(request));
	memset(get, 0, sizeof(get[0]) * sizeof(get));
	return portnum;
}
int dnslookup(char *dom, char* ipaddr) {
	struct addrinfo hints, *ipp;
	memset(&hints,0,sizeof(hints));
	hints.ai_family = AF_INET;
	char ip[16];
	int error;
	
	error = getaddrinfo(dom, NULL, &hints, &ipp);
	if (error != 0) {
		printf("LOG: DNS lookup failed (could not resolve).\n");
		return -1; }
	getnameinfo(ipp->ai_addr, ipp->ai_addrlen, ip, sizeof(ip), NULL, 0, NI_NUMERICHOST);
	strcpy(ipaddr,ip);
    freeaddrinfo(ipp);
	return 0;
}
int blacklist(char *dom,int browser_socket) {
	char* fword = dom;
	if (strncmp(fword,"www.",4) == 0) {
		fword++;
		fword++;
		fword++;
		fword++;
	}

	char found = 0;
	if (strcmp(fword,"torrentz.eu") == 0 || strcmp(fword,"makemoney.com") == 0 || strcmp(fword,"lottoforever.com") == 0) {
		found = 1;
		printf("LOG: Domain (%s) is forbidden (blacklisted).\n",fword);
		errorpager(403,browser_socket); }
	return found;
}
int go(char* client_req,int csize,int portnum,int network_socket,char* ip,int server_socket) {
	char server_response[65535];
	char client_request[csize];
	size_t buffersize = 65535;
	strcpy(client_request,client_req);
	int polling;
	
	int n, writesize;
	int wrotesomething = 0;
	int client_socket,net_socket;
	struct sockaddr_in client_address;
	client_address.sin_family = AF_INET;
	client_address.sin_port=htons(portnum);
	inet_pton(AF_INET,ip,&(client_address.sin_addr.s_addr));
	client_socket=socket(AF_INET,SOCK_STREAM,0);
	if(client_socket<0){
        printf("LOG: Failed to create socket for webserver at (%s).\n",ip);
		errorpager(500,server_socket);
        return -1; }

	n = connect(client_socket,(struct sockaddr *) &client_address,sizeof(client_address));
	if (n<0) {
		printf("LOG: Connection to webserver at (%s) at port (%d) failed.\n",ip,portnum);
		errorpager(404,server_socket);
		return -1; }
	
	n = write(client_socket,client_request,csize);
	if(n<0){
		printf("LOG: Failed write to server's socket.\n");
		errorpager(500,server_socket);
		return -1; }

	struct pollfd topoll[1];
	topoll[0].fd = client_socket;
	topoll[0].events = POLLIN;
	
	while ((polling = poll(topoll,1,3000)) < 2) {
		if (polling < 0) {
			printf("LOG: polling failed on server socket.\n");
			errorpager(504,server_socket);
			memset(server_response, 0, sizeof(server_response[0]) * 65535);
			close(client_socket);
			return -1; }
		else if (polling == 0 ) {
			memset(server_response, 0, sizeof(server_response[0]) * 65535);
			close(client_socket);
			if (!wrotesomething) {
				printf("LOG: Web server at (%s) port (%d) failed to respond or client disconnected.\n",ip,portnum);
				errorpager(504,server_socket);
				return -1; }
			return 0; }
		else {
				n = read(client_socket,server_response,buffersize);
				if (n == 0) {
					break;
				}
				wrotesomething = 1;
				writesize = write(network_socket,server_response,n);
			}
	}
	return 0;
}