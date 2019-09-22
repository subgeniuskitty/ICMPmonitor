/*
 * ICMPmonitor
 *
 * Monitors hosts using ICMP 'echo', executing a user-specified command
 * whenever hosts change state between responsive and unresponsive.
 *
 * © 2019 Aaron Taylor <ataylor at subgeniuskitty dot com>
 * © 1999 Vadim Zaliva <lord@crocodile.org>
 * © 1989 The Regents of the University of California & Mike Muuss
 *
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

#include "iniparser/iniparser.h"

#define VERSION 2

#define MAXPACKETSIZE  (65536 - 60 - 8) /* TODO: What are the magic numbers? */
#define DEFAULTDATALEN (64 - 8)         /* TODO: What are the magic numbers? */

/* Must be larger than the length of the longest configuration key (currently 'start_condition'). */
#define MAXCONFKEYLEN 20

/* One struct per host as listed in the config file. */
struct monitor_host {
    /* From the config file */
    char * name;
    int    ping_interval;
    int    max_delay;
    char * up_cmd;
    char * down_cmd;

    /* Calculated values */
    int                socket;
    struct timeval     last_ping_received;
    struct timeval     last_ping_sent;
    bool               host_up;
    struct sockaddr_in dest;

    /* Linked list */
    struct monitor_host * next;
};

/* Globals */
    /* Since the program is based around signals, a linked list of hosts is maintained here. */
    static struct monitor_host * hosts          = NULL;
    static int                   send_delay     = 1;
    /* Set by command line flags. */
    static bool                  verbose        = false;
    static bool                  retry_down_cmd = false;

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
tv_sub(register struct timeval * out, register struct timeval * in)
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
    int i;
    struct icmp * icp;
    struct monitor_host * p = hosts;
    u_char outpack[MAXPACKETSIZE];

    while (p) {
        if (p->socket != -1) {
            struct timeval now;

            gettimeofday(&now, (struct timezone *) NULL);
            tv_sub(&now, &p->last_ping_received);

            if (now.tv_sec > (p->max_delay + p->ping_interval)) {
                if ((p->host_up) || retry_down_cmd) {
                    if (verbose) printf("INFO: Host %s stopped responding. Executing DOWN command.\n", p->name);
                    p->host_up = false;
                    if (!fork()) {
                        system(p->down_cmd);
                        exit(EXIT_SUCCESS);
                    } else {
                        wait(NULL);
                    }
                }
            }

            gettimeofday(&now, (struct timezone *) NULL);
            tv_sub(&now, &p->last_ping_sent);

            if (now.tv_sec > p->ping_interval) { /* Time to send ping */
                icp = (struct icmp *) outpack;
                icp->icmp_type  = ICMP_ECHO;
                icp->icmp_code  = 0;
                icp->icmp_cksum = 0;
                icp->icmp_seq   = p->socket;
                icp->icmp_id    = getpid() & 0xFFFF;

                if (verbose) printf("INFO: Sending ICMP packet to %s.\n", p->name);

                gettimeofday((struct timeval *) &outpack[8], (struct timezone *) NULL);

                int cc = DEFAULTDATALEN + 8;  /* skips ICMP portion */

                /* compute ICMP checksum */
                icp->icmp_cksum = in_cksum((unsigned short *) icp, cc);

                i = sendto(p->socket, (char *) outpack, cc, 0, (const struct sockaddr *) (&p->dest), sizeof(struct sockaddr));

                gettimeofday(&p->last_ping_sent, (struct timezone *) NULL);

                if (i < 0 || i != cc) {
                    if (i<0) fprintf(stderr, "WARN: Failed sending ICMP packet to %s.\n", p->name);
                }
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

        memcpy(&p->last_ping_received, &tv, sizeof(tv));

        tv_sub(&tv, (struct timeval *) &icmp->icmp_data[0]);
        delay = tv.tv_sec * 1000 + (tv.tv_usec / 1000);

        if (verbose) printf("INFO: Got ICMP reply from %s in %d ms.\n", p->name, delay);
        if (!p->host_up) {
            if (verbose) printf("INFO: Host %s started responding. Executing UP command.\n", p->name);
            p->host_up = true;
            if (!fork()) {
                system(p->up_cmd);
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
        p = hosts;
        FD_ZERO(&rfds);
        while (p) {
            if (p->socket != -1) {
                if (p->socket > maxd) maxd = p->socket;
                FD_SET(p->socket, &rfds);
            }
            p = p->next;
        }

        retval = select(maxd+1, &rfds, NULL, NULL, NULL);
        if (retval < 0) {
            /* Intentionally empty. We arrive here when interrupted by a signal. No action should be taken. */
        } else {
            if (retval > 0) {
                p = hosts;
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
parse_config(const char * conf_file)
{
    dictionary * conf = iniparser_load(conf_file);
    if (conf == NULL) {
        fprintf(stderr, "ERROR: Unable to parse configuration file %s.\n", conf_file);
        exit(EXIT_FAILURE);
    }

    int host_count = iniparser_getnsec(conf);
    if (host_count < 1 ) {
        fprintf(stderr, "ERROR: Unable to determine number of hosts in configuration file.\n");
        exit(EXIT_FAILURE);
    }

    struct monitor_host * host_list_end = NULL;
    for (int i=0; i < host_count; i++) {
        /* Allocate a reusable buffer large enough to hold the full 'section:key' string. */
        int section_len = strlen(iniparser_getsecname(conf, i));
        char * key_buf = malloc(section_len + 1 + MAXCONFKEYLEN + 1);
        strcpy(key_buf, iniparser_getsecname(conf, i));
        key_buf[section_len++] = ':';

        struct monitor_host * cur_host = malloc(sizeof(struct monitor_host));

        key_buf[section_len] = '\0';
        strncat(key_buf, "host", MAXCONFKEYLEN);
        cur_host->name = strdup(iniparser_getstring(conf, key_buf, NULL));

        key_buf[section_len] = '\0';
        strncat(key_buf, "interval", MAXCONFKEYLEN);
        cur_host->ping_interval = iniparser_getint(conf, key_buf, -1);

        key_buf[section_len] = '\0';
        strncat(key_buf, "max_delay", MAXCONFKEYLEN);
        cur_host->max_delay = iniparser_getint(conf, key_buf, -1);

        key_buf[section_len] = '\0';
        strncat(key_buf, "up_cmd", MAXCONFKEYLEN);
        cur_host->up_cmd = strdup(iniparser_getstring(conf, key_buf, NULL));

        key_buf[section_len] = '\0';
        strncat(key_buf, "down_cmd", MAXCONFKEYLEN);
        cur_host->down_cmd = strdup(iniparser_getstring(conf, key_buf, NULL));

        key_buf[section_len] = '\0';
        /* TODO: Parse for up/down/auto in start_condition. */
        /* TODO: Do a host up/down check if necessary. */
        cur_host->host_up = true;

        /* TODO: Do I want to make any checks for start_condition? */
        if (cur_host->name == NULL || cur_host->ping_interval == -1 || cur_host->max_delay == -1) {
            fprintf(stderr, "ERROR: Problems parsing section %s.\n", iniparser_getsecname(conf, i));
            exit(EXIT_FAILURE);
        }

        cur_host->socket = -1;
        cur_host->next = NULL;
        gettimeofday(&(cur_host->last_ping_received), (struct timezone *) NULL);

        if (hosts == NULL) {
            hosts = cur_host;
            host_list_end = cur_host;
        } else {
            host_list_end->next = cur_host;
            host_list_end = cur_host;
        }

        free(key_buf);
    }
    iniparser_freedict(conf);
}

static int
get_host_addr(const char * name)
{
    static int res;
    struct hostent * host_ent;

    if ((res = inet_addr(name)) < 0) {
        host_ent = gethostbyname(name);
        if (!host_ent) return -1;
        memcpy(&res, host_ent->h_addr, host_ent->h_length);
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
    struct monitor_host * p = hosts;
    struct protoent * proto;
    int ok = 0;

    if ((proto = getprotobyname("icmp")) == NULL) {
        fprintf(stderr, "ERROR: Unknown protocol: icmp.\n");
        exit(EXIT_FAILURE);
    }

    while (p) {
        bzero(&p->dest, sizeof(p->dest));
        p->dest.sin_family = AF_INET;
        if ((p->dest.sin_addr.s_addr = get_host_addr(p->name)) <= 0) {
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

void
print_usage(char ** argv)
{
    printf( "ICMPmonitor v%d (www.subgeniuskitty.com)\n"
            "Usage: %s [-h] [-v] [-r] -f <file>\n"
            "  -v         Verbose mode. Prints message for each packet sent and received.\n"
            "  -r         Repeat down_cmd every time a host fails to respond to a packet.\n"
            "             Note: Default behavior executes down_cmd only once, resetting once the host is back up.\n"
            "  -h         Help (prints this message)\n"
            "  -f <file>  Specify a configuration file.\n"
            , VERSION, argv[0]);
}

void
parse_params(int argc, char ** argv)
{
    int param;
    while ((param = getopt(argc, argv, "hrvf:")) != -1) {
        switch(param) {
            case 'v':
                verbose = true;
                break;
            case 'r':
                retry_down_cmd = true;
                break;
            case 'f':
                parse_config(optarg);
                break;
            case 'h':
            default:
                print_usage(argv);
                exit(EXIT_FAILURE);
                break;
        }
    }
    if (hosts == NULL) {
        fprintf(stderr, "ERROR: Unable to parse a config file.\n");
        exit(EXIT_FAILURE);
    }
}

int
main(int argc, char ** argv)
{
    parse_params(argc, argv);

    init_hosts();

    signal(SIGALRM, pinger);
    alarm(send_delay);

    get_response();

    exit(EXIT_SUCCESS);
}
