/*
 * Monitor hosts using ICMP "echo" and notify when down.
 *
 * © 2019 Aaron Taylor <ataylor at subgeniuskitty dot com>
 * © 1999 Vadim Zaliva <lord@crocodile.org>
 * © 1989 The Regents of the University of California & Mike Muuss
 * See LICENSE file for copyright and license details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <string.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <errno.h>

#include "cfg.h"

#define MAXPACKETSIZE  (65536 - 60 - 8) /* TODO: What are the magic numbers? */
#define DEFAULTDATALEN (64 - 8)         /* TODO: What are the magic numbers? */

struct monitor_host {
    /* From the config file */
    char * name;
    int    ping_interval;
    int    max_delay;
    char * upcmd;
    char * downcmd;

    /* Calculated values */
    int                socket;
    struct timeval     last_ping_received;
    struct timeval     last_ping_sent;
    bool               hostup;
    struct sockaddr_in dest;
    unsigned int       sentpackets;
    unsigned int       recvdpackets;

    /* linked list */
    struct monitor_host * next;
};

/* globals */
static struct monitor_host ** hosts       = NULL;
static bool                   verbose     = false;
static int                    keepBanging = 0;
static int                    send_delay  = 1;

/*
 * Checksum routine for Internet Protocol family headers
 */
static int
in_cksum(unsigned short * addr, int len)
{
    int nleft = len;
    unsigned short * w = addr;
    int sum = 0;
    unsigned short answer = 0;

    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nleft == 1) {
        *(u_char *)(&answer) = *(u_char *)w;
        sum += answer;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16);                 /* add carry */
    answer = ~sum;                      /* truncate to 16 bits */
    return(answer);
}

/*
 * Subtracts two timeval structs.
 * Ensure out >= in.
 * Modifies out = out - in.
 */
static void
tvsub(register struct timeval * out, register struct timeval * in)
{
    if ((out->tv_usec -= in->tv_usec) < 0) {
        --out->tv_sec;
        out->tv_usec += 1000000;
    }
    out->tv_sec -= in->tv_sec;
}

/*
 * Compose and transmit an ICMP ECHO REQUEST packet. The IP packet
 * will be added on by the kernel. The ID field is our UNIX process ID,
 * and the sequence number is an ascending integer. The first 8 bytes
 * of the data portion are used to hold a UNIX "timeval" struct in VAX
 * byte-order, to compute the round-trip time.
 */
static void
pinger(int ignore)
{
    int cc, i;
    struct icmp * icp;
    struct monitor_host * p;
    u_char outpack[MAXPACKETSIZE];

    p = hosts[0];
    while (p) {
        if (p->socket != -1) {
            struct timeval now;

            gettimeofday(&now, (struct timezone *) NULL);
            tvsub(&now, &p->last_ping_received);

            if (now.tv_sec > (p->max_delay + p->ping_interval)) {
                if ((p->hostup) || keepBanging) {
                    if (verbose) printf("INFO: Host %s stopped responding. Executing DOWN command.\n", p->name);
                    p->hostup = false;
                    if (!fork()) {
                        system(p->downcmd);
                        exit(EXIT_SUCCESS);
                    } else {
                        wait(NULL);
                    }
                }
            }

            gettimeofday(&now, (struct timezone *) NULL);
            tvsub(&now, &p->last_ping_sent);

            if (now.tv_sec > p->ping_interval) { /* Time to send ping */
                icp = (struct icmp *) outpack;
                icp->icmp_type  = ICMP_ECHO;
                icp->icmp_code  = 0;
                icp->icmp_cksum = 0;
                icp->icmp_seq   = p->socket;
                icp->icmp_id    = getpid() & 0xFFFF;

                if (verbose) printf("INFO: Sending ICMP packet to %s.\n", p->name);

                gettimeofday((struct timeval *) &outpack[8], (struct timezone *) NULL);

                cc = DEFAULTDATALEN + 8;  /* skips ICMP portion */

                /* compute ICMP checksum */
                icp->icmp_cksum = in_cksum((unsigned short *) icp, cc);

                i = sendto(p->socket, (char *) outpack, cc, 0, (const struct sockaddr *) (&p->dest), sizeof(struct sockaddr));

                gettimeofday(&p->last_ping_sent, (struct timezone *) NULL);

                if (i < 0 || i != cc) {
                    if (i<0) fprintf(stderr, "WARN: Failed sending ICMP packet to %s.\n", p->name);
                }
                p->sentpackets++;
            }
        }
        p = p->next;
    }

    signal(SIGALRM, pinger); /* restore handler */
    alarm(send_delay);
}

static void
read_icmp_data(struct monitor_host * p)
{
    int cc, iphdrlen, delay;
    socklen_t fromlen;
    struct sockaddr_in from;
    struct ip * ip;
    struct icmp * icmp;
    struct timeval tv;
    unsigned char buf[MAXPACKETSIZE];

    gettimeofday(&tv, (struct timezone *) NULL);

    fromlen = sizeof(from);
    if ((cc = recvfrom(p->socket, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen)) < 0) {
        if (errno != EINTR) fprintf(stderr, "WARN: Error reading ICMP data from %s.\n", p->name);
        return;
    }

    /* check IP header actual len */
    ip       = (struct ip *) buf;
    iphdrlen = ip->ip_hl << 2;
    icmp     = (struct icmp *) (buf + iphdrlen);

    if (cc < iphdrlen + ICMP_MINLEN) {
        fprintf(stderr, "WARN: Received short packet from %s.\n", p->name);
        return;
    }

    if (icmp->icmp_type == ICMP_ECHOREPLY && icmp->icmp_id == (getpid() & 0xFFFF) && icmp->icmp_seq == p->socket) {
        p->recvdpackets++;

        memcpy(&p->last_ping_received, &tv, sizeof(tv));

        tvsub(&tv, (struct timeval *) &icmp->icmp_data[0]);
        delay = tv.tv_sec * 1000 + (tv.tv_usec / 1000);

        if (verbose) printf("INFO: Got ICMP reply from %s in %d ms.\n", p->name, delay);
        if (!p->hostup) {
            if (verbose) printf("INFO: Host %s started responding. Executing UP command.\n", p->name);
            p->hostup = true;
            if (!fork()) {
                system(p->upcmd);
                exit(EXIT_SUCCESS);
            } else {
                wait(NULL);
            }
        }
    } else {
        /* TODO: Do anything here? */
    }
}

static void
get_response(void)
{
    fd_set rfds;
    int retval, maxd = -1;
    struct monitor_host * p;

    while (1) {
        p = hosts[0];
        FD_ZERO(&rfds);
        while (p) {
            if (p->socket != -1) {
                if (p->socket > maxd) maxd=p->socket;
                FD_SET(p->socket, &rfds);
            }
            p = p->next;
        }

        retval = select(maxd+1, &rfds, NULL, NULL, NULL);
        if (retval < 0) {
            /* Intentionally empty. We arrive here when interrupted by a signal. No action should be taken. */
        } else {
            if (retval > 0) {
                p = hosts[0];
                while (p) {
                    if (p->socket!=-1 && FD_ISSET(p->socket, &rfds)) read_icmp_data(p);
                    p = p->next;
                }
            } else {
                /* TODO: How to handle this error? */
            }
        }
    }
}

static void
read_hosts(const char * cfg_file_name)
{
    int i, n = 0;
    struct Cfg * cfg;

    if ((cfg = readcfg(cfg_file_name)) == NULL) {
        fprintf(stderr, "ERROR: Failed to read config.\n");
        exit(EXIT_FAILURE);
    }

    if (cfg->nelements) {
        hosts = malloc(sizeof(struct monitor_host *) * cfg->nelements);
        for (i = 0; i < cfg->nelements; i++) {
            if (cfg->dict[i]->nvalues < 4) {
                fprintf(stderr, "ERROR: Not enough fields in record %d of cfg file. Got %d.\n", n, cfg->dict[i]->nvalues+1);
                exit(EXIT_FAILURE);
            } else if (cfg->dict[i]->nvalues>5) {
                fprintf(stderr, "ERROR: Too many fields in record %d of cfg file. Got %d.\n", n, cfg->dict[i]->nvalues+1);
                exit(EXIT_FAILURE);
            }

            hosts[n]                = malloc(sizeof(struct monitor_host));
            hosts[n]->name          = strdup(cfg->dict[i]->name);
            hosts[n]->ping_interval = atoi  (cfg->dict[i]->value[0]);
            hosts[n]->max_delay     = atoi  (cfg->dict[i]->value[1]);
            hosts[n]->upcmd         = strdup(cfg->dict[i]->value[2]);
            hosts[n]->downcmd       = strdup(cfg->dict[i]->value[3]);

        if (cfg->dict[i]->nvalues == 4) {
            hosts[n]->hostup = true;
        } else if (strcmp(cfg->dict[i]->value[4], "up") == 0) {
            hosts[n]->hostup = true;
        } else if (strcmp(cfg->dict[i]->value[4], "down") == 0) {
            hosts[n]->hostup = false;
        } else if (strcmp(cfg->dict[i]->value[4], "auto") == 0) {
            /* TODO: Send a ping and set initial state accordingly. */
        } else {
            fprintf(stderr, "ERROR: Illegal value %s in record %d for startup condition.\n", cfg->dict[i]->value[4], n);
            exit(EXIT_FAILURE);
        }
            hosts[n]->sentpackets   = 0;
            hosts[n]->recvdpackets  = 0;

            hosts[n]->socket           = -1;
            hosts[n]->next             = NULL;
            if (n > 0) hosts[n-1]->next=hosts[n];
            gettimeofday(&(hosts[n]->last_ping_received), (struct timezone *)NULL);

            n++;
        }
    }

    freecfg(cfg);

    if (n <= 0) {
        fprintf(stderr, "ERROR: No hosts defined in cfg file, exiting.\n");
        exit(EXIT_FAILURE);
    }
}

static int
gethostaddr(const char * name)
{
    static int res;
    struct hostent * he;

    if ((res = inet_addr(name)) < 0) {
    he = gethostbyname(name);
        if (!he) return -1;
        memcpy(&res, he->h_addr, he->h_length);
    }
    return(res);
}

static int
gcd(int x, int y)
{
    int remainder = x % y;
    if (remainder == 0) return y;
    return gcd(y, remainder);
}

static void
init_hosts(void)
{
    struct monitor_host * p = hosts[0];
    struct protoent * proto;
    int ok = 0;

    if ((proto = getprotobyname("icmp")) == NULL) {
        fprintf(stderr, "ERROR: Unknown protocol: icmp.\n");
        exit(EXIT_FAILURE);
    }

    while (p) {
        bzero(&p->dest, sizeof(p->dest));
        p->dest.sin_family = AF_INET;
        if ((p->dest.sin_addr.s_addr = gethostaddr(p->name)) <= 0) {
            fprintf(stderr, "WARN: Can't resolve host. Skipping client %s.\n", p->name);
            p->socket=-1;
        } else {
            if ((p->socket = socket(AF_INET,SOCK_RAW,proto->p_proto)) < 0) {
                fprintf(stderr, "WARN: Can't create socket. Skipping client %s.\n", p->name);
                p->socket=-1;
            } else {
                if (ok == 0) send_delay = p->ping_interval;
                else send_delay = gcd(send_delay, p->ping_interval);
                ok++;
            }
        }
        p = p->next;
    }

    if (!ok) {
        fprintf(stderr, "ERROR: No hosts left to process.\n");
        exit(EXIT_FAILURE);
    }
}

int
main(int argc, char ** argv)
{
    extern char * optarg;
    extern int optind;
    char * cfgfile = NULL;
    int param;

    while ((param = getopt(argc, argv, "rvf:")) != -1) {
        switch(param) {
            case 'v':
                verbose = true;
                break;
            case 'r':
                keepBanging = 1;
                break;
            case 'f':
                cfgfile=strdup(optarg);
                break;
            default:
                fprintf(stderr,"Usage: icmpmonitor [-v] [-r] [-f cfgfile]\n");
                exit(EXIT_FAILURE);
        }
    }

    if (!cfgfile) {
        fprintf(stderr, "ERROR: No config file specified.\n");
        exit(EXIT_FAILURE);
    }

    read_hosts(cfgfile);

    init_hosts();

    signal(SIGALRM, pinger);
    alarm(send_delay);

    get_response();

    exit(EXIT_SUCCESS);
}
