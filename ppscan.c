/**
 * parallel port scanner
 * Copyright (C) 2009, Aaron Conole <apconole@yahoo.com>
 * 
 * the latest version will always be at:
 * http://aconole.brad-x.com/programs/ppscan.c
 *
 * ppscan is a fast, threaded portscanner which attempts to check for open 
 * ports by relaying connections through different services. Use this only on
 * services that you are authorized to use, and only against targets you are
 * allowed to scan. This is not a _quiet_ scan. It makes full-blown TCP
 * connections to services, and scans pretty aggressively.
 *
 * build with:
 * gcc -o ppscan ppscan.c -lpthread
 *
 * run with:
 * ./ppscan -h
 * for more information
 *
 * This code is free, as in beer. Have fun with it. However, I'm not 
 * responsible if you break the law, or if this code runs wild and wrecks your
 * network, software, hardware, computer, marriage, life, etc. YOU and only
 * YOU the end user are responsible for the outcome of using this software.
 * You agree not to hold me responsible if any of these things happen as a
 * result of using this software.
 *
 * Current BUGS:
 * - None known.
 *
 * TODO:
 * - Add banner grabbing (for those services which report banners).
 * - Add FTP write check (imagine mass delivery of packetdata via anonFTP)
 */

#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#ifdef HAVE_STROPTS_H
#include <stropts.h>
#endif 
#include <getopt.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <ctype.h>
#include <pthread.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define FTP_PORT_SVC  1
#define HTTP_CONN_SVC 2
#define TCP_CONN_SVC  3
#define TCP_SYN_SVC   4

typedef int (*port_scan)(unsigned int ip, unsigned short port);
int portscan4_ftp(unsigned int ip, unsigned short port);
int portscan4_http_connect(unsigned int ip, unsigned short port);
int portscan4_http_get(unsigned int ip, unsigned short port);
int portscan4_tcp_connect(unsigned int ip, unsigned short port);
int portscan4_tcp_syn(unsigned int ip, unsigned short port);

static struct
{
    unsigned char  svc_id;
    char          *svc_name;
    port_scan      svc_scan;
    unsigned short svc_default_port;
} scanners[] =
{
    {FTP_PORT_SVC, "ftp-port", portscan4_ftp, 21},
    {HTTP_CONN_SVC, "http-connect", portscan4_http_connect, 8080},
    {HTTP_CONN_SVC, "http-get", portscan4_http_get, 8080},
    {TCP_CONN_SVC, "tcp-connect", portscan4_tcp_connect, 0},
    {TCP_SYN_SVC, "tcp-syn", portscan4_tcp_syn, 0},

    /* this must be last */
    {0, NULL, 0, 0}
};

/* rough - hardest scan to succeed is the one we can't perform */
int null_scan(unsigned int ip, unsigned short port)
{
    return -1;
}

unsigned int   proxy_server = 0;
char *         target_spec = 0;
char *         target_ports = 0;

unsigned char  verbose = 1;
unsigned char  banner  = 0;

unsigned int   subnet_start;

unsigned char  proxy_svc    = TCP_CONN_SVC;
unsigned short proxy_port   = 0;

unsigned short target_end   = 0;

unsigned int   cur_target = 0;
unsigned int   cur_port   = 0;

unsigned int   glob_id    = 0; /* used for tcp syn scanning. */

char ports[65535] = {0}; /* all ports unscanned */

char * svcuser = "anonymous";
char * svcpass = "ftp@you.com";

#define USHORT_SWAP(a,b) {unsigned short tmp; tmp=a; a=b; b=tmp;}

void add_range(unsigned short start, unsigned short end)
{
    unsigned int i;

    if((start > 65535) || (end > 65535))
    {
        fprintf(stderr, "[-] Invaild port range. Aborting.\n");
        exit(0);
    }
    
    if(start > end)
        USHORT_SWAP(start, end);

    for(i = start - 1; i < end; ++i)
    {
        ports[i] = 1;
    }

    if(end > target_end)
        target_end = end;

}

void port_range(char *range)
{
    char *rdelim;
    char *buffer;
    unsigned int i;

    if(!target_ports)
    {
        target_ports = malloc(strlen(range)+1);
        if(!target_ports)
        {
            fprintf(stderr, "[-] Error: OOM setting port range.\n");
            exit(0);
        }
        strcat(target_ports, range);
    }

    if(!strchr(range, ',') &&
       !strchr(range, '-'))
    {
        i = atoi(range);
        if(i >= 65535)
        {
            fprintf(stderr, "[-] Error: port range not in range!\n");
            exit(0);
        }
        ports[i-1] = 1;

        if(i > target_end)
            target_end = i;

        return;
    }
    
    buffer = strtok(range, ",");
    while(buffer)
    {
        if((rdelim = strchr(buffer, '-')))
        {
            add_range(atoi(buffer), atoi(rdelim+1));
        } else
        {
            port_range(buffer);
        }
        buffer = strtok(NULL, ",");
    }

    if(buffer && (rdelim = strchr(buffer, '-')))
    {
        add_range(atoi(buffer), atoi(rdelim+1));
    }
}

unsigned short first_port()
{
    unsigned short i = 0;
    while(ports[i++] == 0);
    return i;
}

unsigned short next_port(unsigned short cur_port)
{
    while(ports[cur_port++] == 0);
    return cur_port;
}

char *iptoa(const int ip, char *buf)
{
    int fmt = htonl(ip);
    snprintf(buf, 16,
             "%d.%d.%d.%d",
             (fmt>>24)& 0xff,
             (fmt>>16)& 0xff,
             (fmt>>8) & 0xff,
             fmt      & 0xff);
    return buf;
}

int atoip(const char *pIpStr)
{
    struct hostent *ent;
    struct sockaddr_in sa;
    int t;

    t = inet_addr(pIpStr);
    
    if(inet_addr(pIpStr) == -1)
    {
        ent = gethostbyname(pIpStr);
        if(ent != NULL)
        {
            if(ent->h_addrtype != AF_INET)
            {
                fprintf(stderr, 
			"[-] error: address/host '%s' not of AF_INET.\n",
                        pIpStr);
                exit(-1);
            }
            else
            {
                memcpy ((caddr_t) & sa.sin_addr, ent->h_addr, ent->h_length);
                t = sa.sin_addr.s_addr;
            }
        }
        else
        {
            fprintf(stderr, "[-] error: address/host '%s' unknown.\n",
                    pIpStr);
            exit(-1);
        }
    }
    
    return t;
}

/* this function calculates the checksum for the IP and TCP header */
/* note: this code is all over the internet. who knows where it first came
         from
*/
u_short in_cksum(u_short *addr, int len)
{
	u_short i = 0, *word = addr;
	u_long acc = 0;
	
	while(i++ < len / 2)
		acc += *(word++);
	
	return ~(*(u_short*)&acc + *((u_short*)&acc + 1));
}

u_short tcp_cksum(struct iphdr *ip, struct tcphdr *tcp)
{
	char header[32], *p = header;

	*(unsigned long*)p = ip->saddr;
	p += 4;
	*(unsigned long*)p = ip->daddr;
	p += 4;
	*p = 0;
	p++;
	*p = ip->protocol;
	p++;
	*(unsigned short*)p = htons(4 * tcp->doff);
	p += 2;
	memcpy(p, tcp, 4 * tcp->doff);

	return in_cksum((unsigned short*)header, 32);
}


int tcp_connect(unsigned int ip, unsigned short port)
{
    char buf[16];
    int sockfd;
    struct sockaddr_in server;
    int ret;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0)
    {
        fprintf(stderr,"[-] error: unable to acquire socket.\n");
        return -1;
    }
    server.sin_family = AF_INET;
    server.sin_port   = htons(port);
    server.sin_addr.s_addr = ip; /*should be in network order*/
  
    if(connect(sockfd, 
               (struct sockaddr *)&server, sizeof(struct sockaddr)) < 0)
    {
        if(proxy_server)
            fprintf(stderr,
                    "[-] error: unable to connect to remote system [%s:%d].\n",
                    iptoa(ip, buf), port);
        close(sockfd);
        return -1;
    }
  
    return sockfd;
}

int strrepl(char *buf, size_t buflen, char *old, char *new)
{
    char *f;
    char *str = buf;
    int   repls = 0;

    int   origl = strlen(buf);
    int   oldl  = strlen(old);
    int   newl  = strlen(new);

    if((buf == NULL) || (old == NULL) || (new == NULL) || (buflen == 0))
        return -1;

    while((f = strstr(str, old)) != NULL)
    {
        ++repls;

        origl -= oldl;

        if(origl < 0)
            origl = 0;

        origl += newl;

        memmove(f+newl, f+oldl, strlen(f+oldl)+1);
        memcpy(f, new, newl);

        str = f + oldl;
    }
    return origl;
}

int timed_recv(int fd, void *data, int data_len, int flags, unsigned int ms_to)
{
    struct timeval tv;
    fd_set fds;
    int ret;

    /* the timeout time */
    tv.tv_sec = ms_to / 1000;
    tv.tv_usec = (ms_to % 1000) * 1000;

    FD_ZERO(&fds);
    FD_SET(fd, &fds);

    ret = select(fd+1, &fds, NULL, NULL, &tv);
    if(ret > 0)
    {
        if(FD_ISSET(fd, &fds))
        {
            return recv(fd, data, data_len, flags);
        }
    }

    return 0;
}

int timed_read(int fd, void *data, int data_len, unsigned int ms_to)
{
    struct timeval tv;
    fd_set fds;
    int ret;

    /* the timeout time */
    tv.tv_sec = ms_to / 1000;
    tv.tv_usec = (ms_to % 1000) * 1000;

    FD_ZERO(&fds);
    FD_SET(fd, &fds);

    ret = select(fd+1, &fds, NULL, NULL, &tv);
    if(ret > 0)
    {
        if(FD_ISSET(fd, &fds))
        {
            return read(fd, data, data_len);
        }
    }

    return 0;
}

int portscan4_http_get(unsigned int ip, unsigned short port)
{
    /*HTTP GET proxy*/
    char buf[16];
    char scan_str[1024];
    const char *SUCCESS1 = "HTTP/1.1 200";
    const char *SUCCESS2 = "HTTP/1.0 200";
    int sockfd;
  
    snprintf(scan_str, 1024, "GET http://%s:%d/ HTTP/1.0\r\n\r\n",
             iptoa(ip, buf), port);

    sockfd = tcp_connect(proxy_server, proxy_port);
    if(sockfd < 0)
        return sockfd;

    send(sockfd, scan_str, strlen(scan_str), 0);
    timed_recv(sockfd, scan_str, 1024, 0, 2000);

    if(strstr(scan_str, SUCCESS1) ||
       strstr(scan_str, SUCCESS2))
    {
        printf("[+] %s: %d open\n", iptoa(ip, buf), port);
    }
    else
    {
        if(verbose > 1)
            printf("[+] %s: %d closed.\n", iptoa(ip, buf), port);
    }

    close(sockfd);

    return 0;
}

int portscan4_http_connect(unsigned int ip, unsigned short port)
{
    /*HTTP Connect proxy*/
    char buf[16];
    char scan_str[1024];
    const char *SUCCESS1 = "HTTP/1.1 200";
    const char *SUCCESS2 = "HTTP/1.0 200";
    int sockfd;
  
    snprintf(scan_str, 1024, "CONNECT %s:%d HTTP/1.0\r\n\r\n",
             iptoa(ip, buf), port);

    sockfd = tcp_connect(proxy_server, proxy_port);
    if(sockfd < 0)
        return sockfd;

    send(sockfd, scan_str, strlen(scan_str), 0);
    recv(sockfd, scan_str, 1024, 0);

    if(strstr(scan_str, SUCCESS1) ||
       strstr(scan_str, SUCCESS2))
    {
        printf("[+] %s: %d open\n", iptoa(ip, buf), port);
    }
    else
    {
        if(verbose > 1)
            printf("[+] %s: %d closed.\n", iptoa(ip, buf), port);
    }

    close(sockfd);

    return 0;
}

int portscan4_ftp(unsigned int ip, unsigned short port)
{
    /*FTP PORT proxy*/
    /* for this, we'll definitely want a recv timeout (TBD). */
    char buf[16];
    char scan_str[1024];
    const char *SUCCESS1 = "successful";
    const char *SUCCESS2 = "426"; /* 426 means abnormal term */
    int res = 0;
    int sockfd;

    sockfd = tcp_connect(proxy_server, proxy_port);
    if(sockfd < 0)
        return sockfd;

    res = recv(sockfd, scan_str, 1024, 0);/* clear FTP banner */

    snprintf(scan_str, 1024, "USER %s\r\n", svcuser);
    send(sockfd, scan_str, strlen(scan_str), 0);
    recv(sockfd, scan_str, 1024, 0);

    snprintf(scan_str, 1024, "PASS %s\r\n", svcpass);
    send(sockfd, scan_str, strlen(scan_str), 0);
    recv(sockfd, scan_str, 1024, 0);

    iptoa(ip, buf);
    strrepl(buf, 16, ".",",");
    
    snprintf(scan_str, 1024, "PORT %s,%d,%d\r\n", buf,
             port%256, port/256);
    send(sockfd, scan_str, strlen(scan_str), 0);
    res = timed_recv(sockfd, scan_str, 1024, 0, 10000); /*10s wait*/

    if(res && strstr(scan_str, SUCCESS1))
    {
        snprintf(scan_str, 1024, "LIST\r\n\r\n");
        send(sockfd, scan_str, strlen(scan_str), 0);
        res = timed_recv(sockfd, scan_str, 1024, 0, 10000);
        if(res && (strstr(scan_str, SUCCESS1)||strstr(scan_str, SUCCESS2)))
        {
            printf("[+] %s: %d open\n", iptoa(ip, buf), port);
            close(sockfd);
            return 0;
        }
    }
    if(verbose > 1)
        printf("[+] %s: %d closed.\n", iptoa(ip, buf), port);
    close(sockfd);
    return 0;
}

int portscan4_tcp_connect(unsigned int ip, unsigned short port)
{
    char buf[16] = {0};
    int sockfd = tcp_connect(ip, port);
    if(sockfd < 0)
    {
        if(verbose > 1)
            printf("[+] %s: %d closed.\n", iptoa(ip, buf), port);
        return 0;
    }
    printf("[+] %s: %d open.\n", iptoa(ip, buf), port);
    close(sockfd);
    return 0;
}

int portscan4_tcp_syn(unsigned int ip, unsigned short port)
{
    int sockfd; int on = 1;
    char buf[16];
    char ipbuf[256] = {0};

    struct iphdr *ip_h;
    struct tcphdr *tcp_h;

    struct sockaddr_in destAddr;

    if(getuid() && geteuid())
    {
        fprintf(stderr, "[-] Requested a scan type which requires root. Aborting.\n");
        exit(0);
    }

    ip_h = (struct iphdr *) ipbuf;
    tcp_h = (struct tcphdr *)(ipbuf + sizeof(struct iphdr));

    ip_h->ihl      = 5;
    ip_h->version  = 4;
    ip_h->tot_len  = htons(sizeof(struct iphdr)+sizeof(struct tcphdr));
    ip_h->ttl      = 0xff;
    ip_h->protocol = IPPROTO_TCP;
    ip_h->saddr    = proxy_server;
    ip_h->daddr    = ip;
    ip_h->check    = in_cksum((unsigned short *)ip_h, sizeof(struct iphdr));
    
    tcp_h->doff    = 5;
    tcp_h->source  = htons(proxy_port);
    tcp_h->seq     = glob_id;
    tcp_h->syn     = 1;
    tcp_h->window  = htons(1024);
    tcp_h->dest    = htons(port);
    tcp_h->check   = 0;
    tcp_h->check   = tcp_cksum(ip_h, tcp_h);

    destAddr.sin_addr.s_addr = ip;
    destAddr.sin_family      = AF_INET;
    destAddr.sin_port        = 0; /* we're including the header, so who cares */

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(sockfd < 0)
    {
        fprintf(stderr, "[-] Unable to open socket. Aborting.\n");
        exit(0);
    }

    if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
    {
        fprintf(stderr, "[-] Unable to set iphdr incl. Aborting.!\n");
        exit(0);
    }
    
    if(sendto(sockfd, ipbuf, ntohs(ip_h->tot_len), 0,
              (struct sockaddr *)&destAddr, sizeof(destAddr)) < 0)
    {
        fprintf(stderr, "[-] Unable to send. Aborting.\n");
        close(sockfd);
        exit(0);
    }

    while((on = timed_read(sockfd, ipbuf, sizeof(ipbuf), 10000) > 0))
    {
        ip_h  = (struct iphdr *) ipbuf;
        tcp_h = (struct tcphdr *)(ipbuf + (sizeof (struct iphdr)));
        if(ip_h->saddr == ip)
        {
            if(htons(tcp_h->source) == port)
            {
                close(sockfd);
                if(tcp_h->syn && tcp_h->ack)
                {
                    printf("[+] %s: %d open.\n", iptoa(ip, buf), port);
                    return 0;
                }
                if(verbose > 1)
                    printf("[+] %s: %d closed.\n", iptoa(ip, buf), port);
                return 0;
            }
        }
    }

    if(verbose > 1)
        printf("[+] %s: %d closed.\n", iptoa(ip, buf), port);

    return 0;
}

unsigned char scanner_id(const char *scan_name)
{
    int i;
    for(i = 0; i < sizeof(scanners); ++i)
        if(scanners[i].svc_name && 
           !strncasecmp(scanners[i].svc_name, scan_name,
                        strlen(scanners[i].svc_name)))
        {
            return scanners[i].svc_id;
        }
    
    return 0;
}

const char *scanner_name(unsigned char svc)
{
    int i;
    for(i = 0; i < sizeof(scanners); ++i)
        if(scanners[i].svc_id && scanners[i].svc_id == svc)
            return scanners[i].svc_name;
    return "Unknown!";
}

port_scan scanner_scan(unsigned char svc)
{
    int i;
    for(i = 0; i < sizeof(scanners); ++i)
        if(scanners[i].svc_id && scanners[i].svc_id == svc)
            return scanners[i].svc_scan;
    return null_scan;  
}

unsigned short scanner_def_port(unsigned char svc)
{
    int i;
    for(i = 0; i < sizeof(scanners); ++i)
        if(scanners[i].svc_id && scanners[i].svc_id == svc)
            return scanners[i].svc_default_port;
    return 0;
}

unsigned int first_target(char *tgts)
{
    unsigned int subneted;
    unsigned int mask;
    char buf[1024] = {0};
    char *subnet;
    if(!(subnet = strchr(tgts, '/')))
    {
        return atoip(tgts);
    }

    if(strlen(tgts) > 1024)
        return 0;

    if(strlen(subnet+1) < 1)
    {
        fprintf(stderr, "[-] Error! No subnet specified.\n");
        return 0;
    }
    mask = atoi(subnet+1);
    if(mask > 31)
    {
        fprintf(stderr, "[-] Error! Invalid subnet specified.\n");
        return 0;
    }

    strncpy(buf, tgts, strlen(tgts) - (strlen(strchr(tgts,'/'))));

    subneted = atoip(buf);

    subnet_start = subneted;

    if((htonl(subneted)<<mask)>>mask)
    {
        return subneted;
    }
    else
    {
        return ntohl(htonl(subneted)+1);
    }

    return 0;
}

unsigned int next_target(char *tgts, unsigned int current)
{
    unsigned int subneted;
    char buf[1024] = {0};
    char *subnet;
    unsigned int mask;
    
    if(!(subnet = strchr(tgts, '/')))
        return 0;

    mask = atoi(subnet+1);
    subneted = ntohl(current) << mask;
    subneted = subneted >> mask;
    ++subneted;
  
    if((subneted << mask) == 0)
        return 0;

    if((ntohl(current)<<mask) >> mask)
    {
        return htonl(ntohl(current)+1);
    }

    return htonl(ntohl(current) + 2);
}

pthread_mutex_t g_lock;
int started = 0;
int get_next_target_port_combo(unsigned int *ip, unsigned short *port)
{
    pthread_mutex_lock(&g_lock);
    ++glob_id;
    if(!cur_target && !started)
    {
        ++started;
        cur_target = first_target(target_spec);
        cur_port   = first_port();
        *ip = cur_target; *port = cur_port;
        pthread_mutex_unlock(&g_lock);
        return cur_target ? 0 : -1;
    }

    if(!cur_target && started)
    {
        pthread_mutex_unlock(&g_lock);
        return -1;
    }

    if(cur_port == target_end)
    {
        cur_target = next_target(target_spec, cur_target);
        cur_port   = first_port();
        *ip = cur_target; *port = cur_port;
        pthread_mutex_unlock(&g_lock);
        if(cur_target) return 0;
        else           return -1;
    }

    cur_port = next_port(cur_port);
    *ip = cur_target; *port = cur_port;
    pthread_mutex_unlock(&g_lock);
    return 0;
}

void *run_thread(void *args)
{
    char buf[16];
    port_scan run_scan;
    unsigned int ip; unsigned short port;
    int i;

    run_scan = scanner_scan(proxy_svc);
 
    while(get_next_target_port_combo(&ip, &port) == 0)
    {
        if(verbose > 1)
            printf("[+] scanning %s : %d\n", iptoa(ip, buf), port);
        
        if(run_scan(ip, port) < 0)
        {
            fprintf(stderr, "[-] Aborting.\n");
            return NULL;
        }
	fflush(stdout);
    }
}

void dump_help()
{
    printf("+ Help\n");
    printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    printf("+ --help\t\t-h\tThis menu\n");
    printf("+ --verbose\t\t-v\tSets to verbose mode\n");
    printf("+ --quiet\t\t-q\tSets to quiet mode\n");
    printf("+ --host\t\t-x\tSets the proxy server. Alternately,\n");
    printf("\t\t\t\tin tcp-syn mode, sets the source addr.\n");
    printf("+ --scan\t\t-s\tSets the scan service type. Valid types are:\n");
    printf("\t\t\thttp-connect, ftp-port, tcp-connect, tcp-syn\n");
    printf("+ --port\t\t-p\tSets the proxy service port number. Alternately,\n");
    printf("\t\t\t\tin tcp-syn mode, sets the source port.\n");
    printf("+ --target\t\t-t\tSets the target. Either a single host, or\n\t\t\t\thost/mask\n");
/*
    printf("+ --start-port\t\t-b\tSets the starting port number for scanning.\n");
    printf("+ --end-port\t\t-e\tSets the end port number for scanning.\n");
*/
    printf("+ --port-range\t\t-r\tSets the port range to scan.\n");
    printf("+ --svc-user\t\t-u\tSets the scan service username (default: anonymous).\n");
    printf("+ --svc-pass\t\t-w\tSets the scan service password.\n");
    printf("+ --threads\t\t-T\tSets the number of threads to use for scanning.\n");
    printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    printf("+ Examples:\n");
    printf("+ To scan all ports on a class C network 172.16.1.0/24 through\n");
    printf("+ http proxy server 192.168.0.1 port 8080 using 3 threads:\n");
    printf("+ ./ppscan -x 192.168.0.1 -s http-connect -p 8080 -r 1-65535 -t 172.16.1.0/24 -T 3 -v\n");
    printf("+ \n");
    printf("+ To scan all Class C address 192.168.0.0/24 using tcp-syn and\n");
    printf("+ for ports 20 and 25, from 192.168.1.1 source port 6667:\n");
    printf("+ ./ppscan -s tcp-syn -x 192.168.1.1 -p 6667 -r 20,25 -T 256 -v 192.168.0.0/24\n");
    printf("+ \n");
    printf("+ To scan a Class C network using TCP Connect for all ports:\n");
    printf("+ ./ppscan 192.168.0.0/24\n");
    printf("+ or\n");
    printf("+ ./ppscan -t 192.168.0.0/24\n");
    printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
}

char *timetoa()
{
    static char buffer[40];
    struct timeval tv;
    time_t curtime;

    gettimeofday(&tv, NULL);
    curtime = tv.tv_sec;

/* enable once I figure out how to get relative time working.
    curtime = curtime - birth;
*/

    strftime(buffer, 40, "%H:%M:%S", localtime(&curtime));
    
    return buffer;
}

int main(int argc, char *argv[])
{
    char buf[16];
    int   threads = 0;
    int   help_flag = 0;
    pthread_t *thr = NULL;
    int       thrs;

    static struct option long_options[] =
        {
            {   "help",             no_argument,       0,   'h' },
            {   "verbose",          no_argument,       0,   'v' },
            {   "quiet",            no_argument,       0,   'q' },
            {   "host",       required_argument,       0,   'x' },
            {   "scan",       required_argument,       0,   's' },
            {   "port",       required_argument,       0,   'p' },
            {   "target",     required_argument,       0,   't' },
            {   "port-range", required_argument,       0,   'r' },
            {   "ftp-user",   required_argument,       0,   'u' },
            {   "ftp-pass",   required_argument,       0,   'w' },
            {   "threads",    required_argument,       0,   'T' }
        };

    while(1)
    {
        int option_index = 0;
        int c;
        c = getopt_long(argc, argv, "hvqx:s:p:t:r:T:u:w:",
                        long_options, &option_index);
     
        if(c == -1)
            break;
    rerun:
        switch(c)
	{
	case 0:
            c = long_options[option_index].val;
            goto rerun;
	case 'h':
            help_flag = 1;
            break;
	case 'x':
            proxy_server = atoip(optarg);
            break;
	case 's':
            proxy_svc = scanner_id(optarg);
            break;
	case 'p':
            proxy_port = atoi(optarg);
            break;
        case 'v':
            verbose = 2;
            break;
        case 'q':
            verbose = 0;
            break;
        case 'u':
            svcuser = malloc(strlen(optarg)+1);
            if(svcuser)
                strcpy(svcuser, optarg);
            else
            {
                fprintf(stderr, "- Error: unable to alloc space.\n");
                exit(0);
            }
            break;
        case 'w':
            svcpass = malloc(strlen(optarg)+1);
            if(svcpass)
                strcpy(svcpass, optarg);
            else
            {
                fprintf(stderr, "- Error: unable to alloc space.\n");
                exit(0);
            }
            break;
	case 't':
            target_spec = malloc(strlen(optarg)+1);
            if(target_spec)
                strcpy(target_spec, optarg);
            else
            {
                fprintf(stderr, "- Error: Unable to alloc space.\n");
                exit(0);
            }
            break;
        case 'r':
            port_range(optarg);
            break;
	case 'T':
            threads = atoi(optarg);
            break;
	default:
            printf("+ unknown option.\n");
            printf
                ("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
            exit(0);
	}
    }
    if(verbose || help_flag)
        printf
            (
            "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
            "+                 parallel port scanner v0.3                 +\n"
            "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
            "+               copyright(c) 2009 aaron conole               +\n"
            "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
            );

    if(help_flag)
    {
        dump_help();
        return 0;
    }

    if(argv[optind])
    {
        target_spec = malloc(strlen(argv[optind])+1);
        if(target_spec)
            strcpy(target_spec, argv[optind]);
        else
        {
            fprintf(stderr, "- Error: Unable to alloc space.\n");
            return -1;
        }
	++optind;
    }

    if(target_spec == NULL)
    {
        printf ("+ Error! Please specify at least a target!\n");
        return -1;
    }

    if(!target_ports)
    {
        if(optind <= argc && argv[optind])
        {
            port_range(argv[optind]);
        }
        else{
            add_range(1,65535);
        }
    }

    if(proxy_svc == 0)
    {
        printf("+ Error! Invalid proxy type specified\n");
        return -1;
    }

    if(proxy_port == 0)
    {
        proxy_port = scanner_def_port(proxy_svc);
    }
    
    pthread_mutex_init(&g_lock, NULL);

    if(threads == 0)
    {
        if(strstr(target_spec, "/"))
        {
            threads = 64;
        }
        else
            threads = 1;
    }

    if(verbose)
        printf
            (
            "+ Target(s)   : [%s]\n"
            "+ Target Ports: [%s]\n"
            "+ Service type: [%d - %s]\n"
            "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n",
            target_spec,
            target_ports ? target_ports : "1-65535",
            proxy_svc, scanner_name(proxy_svc)
            );

    if(verbose && proxy_server)
    {
        printf(
            "+ Proxy/Source host: [%s]\n"
            "+ Proxy/Source port: [%d]\n"
            "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n",
            iptoa(proxy_server, buf),
            proxy_port
            );
    }

    if(verbose && threads > 1)
    {
        printf(
            "+ Threads: %d\n"
            "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n",
            threads
            );
    }

    if(verbose)
        if(proxy_svc == FTP_PORT_SVC)
        {
            printf("+ Service Login: %s : %s\n",
                   svcuser, svcpass);
            printf
                ("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
        }
    
    if(verbose)
        printf("\n[+] beginning [%s]\n", timetoa());
    if(threads > 1) /* optimise this */
    {
        for(thrs = 0; thrs < threads; ++thrs)
        {
            if(verbose > 1)
               printf("[+] Spawning thread #%d\n", thrs+1);
            thr = (pthread_t *)realloc(thr, (sizeof(pthread_t) * thrs) + 1);
            pthread_create((pthread_t *)thr+thrs, NULL, run_thread, NULL);
        }
    

        for(thrs = 0; thrs < threads; ++thrs)
        {
            pthread_join(*((pthread_t *)thr+thrs), 
                         NULL);
        }
    }else{
        run_thread(NULL);
    }

    printf("[+] Scanning completed [%s]\n", timetoa());
    return 0;
}

/* EOF */
