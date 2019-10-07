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

/* Wishlist */
/* TODO: Add IPv6 support. */
/* TODO: Turn the global '-r' functionality into per-host config file option. */
/* TODO: Add 'auto' keyword to 'start_condition', testing host on startup. */
/* TODO: Double-check the network code when interrupted while receiving a packet. */

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
#include <assert.h>

#include "iniparser/iniparser.h"

#define VERSION 2

#define MAXPACKETSIZE  (65536 - 60 - 8) /* TODO: What are the magic numbers? */
#define DEFAULTDATALEN (64 - 8)         /* TODO: What are the magic numbers? */

/* ICMP header contains: type, code, checksum, identifier and sequence number. */
#define ICMP_ECHO_HEADER_BYTES  8
#define ICMP_ECHO_DATA_BYTES    sizeof(struct timeval)
#define ICMP_ECHO_PACKET_BYTES  ICMP_ECHO_HEADER_BYTES + ICMP_ECHO_DATA_BYTES

/* Minimum time in seconds between pings. If this value is increased above the */
/* `ping_interval` for a given host, some pings to that host may not be sent.  */
#define TIMER_RESOLUTION        1

/* Must be larger than the length of the longest configuration key (currently 'start_condition'). */
#define MAXCONFKEYLEN 20

/* One struct per host as listed in the config file. */
struct host_entry {
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
    struct host_entry * next;
};

/* Globals */
    /* Since the program is based around signals, a linked list of hosts is maintained here. */
    static struct host_entry * first_host_in_list = NULL;
    /* Set by command line flags. */
    static bool                  verbose        = false;
    static bool                  retry_down_cmd = false;

/*
 * Generate an Internet Checksum per RFC 1071.
 *
 * This is not a general purpose implementation of RFC 1071.  Since we only
 * send ICMP echo packets, we assume 'data' will contain a specific number of
 * bytes.
 */
uint16_t
checksum(const uint16_t * data)
{
    uint32_t accumulator = 0;
    for (size_t i = 0; i < ICMP_ECHO_PACKET_BYTES / 2; i++) {
        accumulator += ntohs(data[i]);
        if (accumulator > 0xffff) accumulator -= 0xffff;
    }
    return htons(~accumulator);
}

/*
 * Calculate difference (a-b) between two timeval structs.
 */
void
timeval_diff(struct timeval * a, const struct timeval * b)
{
    if (a->tv_usec < b->tv_usec) {
        a->tv_sec--;
        a->tv_usec += 1000000;
    }
    a->tv_usec -= b->tv_usec;
    a->tv_sec -= b->tv_sec;
}

/*
 * This function iterates over the list of hosts, pinging any which are due.
 */
void
pinger(int ignore) /* Dummy parameter since this function registers as a signal handler. */
{
    assert(first_host_in_list);

    struct icmp * icmp_packet;
    struct host_entry * host = first_host_in_list;
    unsigned char packet[IP_PACKET_MAX_BYTES]; /* Use char so this can be aliased later. */

    while (host) {
        struct timeval elapsed_time;
        gettimeofday(&elapsed_time, NULL);
        timeval_diff(&elapsed_time, &host->last_ping_received);

        if ((elapsed_time.tv_sec > host->max_delay) && (host->host_up || retry_down_cmd)) {
            if (verbose) printf("INFO: Host %s stopped responding. Executing DOWN command.\n", host->name);
            host->host_up = false;
            if (!fork()) {
                system(host->down_cmd);
                exit(EXIT_SUCCESS);
            }
        }

        if (elapsed_time.tv_sec > host->ping_interval) {
            if (verbose) printf("INFO: Sending ICMP packet to %s.\n", host->name);

            icmp_packet = (struct icmp *) packet;
            icmp_packet->icmp_type  = ICMP_ECHO;
            icmp_packet->icmp_code  = 0;
            icmp_packet->icmp_cksum = 0;
            icmp_packet->icmp_seq   = host->socket;
            icmp_packet->icmp_id    = getpid() & 0xFFFF;

            /* Write a timestamp struct in the packet's data segment for use in calculating travel times. */
            gettimeofday((struct timeval *) &packet[ICMP_ECHO_HEADER_BYTES], NULL);

            icmp_packet->icmp_cksum = checksum((uint16_t *) packet);

            size_t bytes_sent = sendto(host->socket, packet, ICMP_ECHO_PACKET_BYTES, 0,
                                       (const struct sockaddr *) &host->dest,
                                       sizeof(struct sockaddr));

            if (bytes_sent == ICMP_ECHO_PACKET_BYTES) {
                gettimeofday(&host->last_ping_sent, NULL);
            } else {
                fprintf(stderr, "WARN: Failed sending ICMP packet to %s.\n", host->name);
            }
        }
        host = host->next;
    }

    signal(SIGALRM, pinger);
    alarm(TIMER_RESOLUTION);
}

void
read_icmp_data(struct host_entry * host)
{
    struct timeval now;
    gettimeofday(&now, NULL);

    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    int bytes;
    unsigned char packet[IP_PACKET_MAX_BYTES]; /* Use char so this can be aliased later. */
    if ((bytes = recvfrom(host->socket, packet, sizeof(packet), 0, (struct sockaddr *) &from, &fromlen)) < 0) {
        if (errno != EINTR) fprintf(stderr, "WARN: Error reading ICMP data from %s.\n", host->name);
        return;
    }

    struct ip * ip     = (struct ip *) packet;
    int iphdrlen       = ip->ip_hl << 2;
    struct icmp * icmp = (struct icmp *) (packet + iphdrlen);

    if (bytes < iphdrlen + ICMP_MINLEN) {
        fprintf(stderr, "WARN: Received short packet from %s.\n", host->name);
        return;
    }

    if (icmp->icmp_type == ICMP_ECHOREPLY && icmp->icmp_id == (getpid() & 0xFFFF) && icmp->icmp_seq == host->socket) {
        memcpy(&host->last_ping_received, &now, sizeof(now));
        if (verbose) printf("INFO: Got ICMP reply from %s.\n", host->name);
        if (!host->host_up) {
            if (verbose) printf("INFO: Host %s started responding. Executing UP command.\n", host->name);
            host->host_up = true;
            if (!fork()) {
                system(host->up_cmd);
                exit(EXIT_SUCCESS);
            }
        }
    } else {
        /* The packet isn't what we expected. Ignore it and move on. */
    }
}

static void
get_response(void)
{
    fd_set rfds;
    int retval, maxd = -1;
    struct host_entry * p;

    while (1) {
        p = first_host_in_list;
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
                p = first_host_in_list;
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

    struct host_entry * host_list_end = NULL;
    for (int i=0; i < host_count; i++) {
        /* Allocate a reusable buffer large enough to hold the full 'section:key' string. */
        int section_len = strlen(iniparser_getsecname(conf, i));
        char * key_buf = malloc(section_len + 1 + MAXCONFKEYLEN + 1);
        strcpy(key_buf, iniparser_getsecname(conf, i));
        key_buf[section_len++] = ':';

        struct host_entry * cur_host = malloc(sizeof(struct host_entry));

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

        if (first_host_in_list == NULL) {
            first_host_in_list = cur_host;
            host_list_end = cur_host;
        } else {
            host_list_end->next = cur_host;
            host_list_end = cur_host;
        }

        free(key_buf);
    }
    iniparser_freedict(conf);
}

/*
 * Parse string (IP or hostname) to Internet address.
 *
 * Returns 0 if host can't be resolved, otherwise returns an Internet address.
 */
uint32_t
get_host_addr(const char * name)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;

    int rv;
    struct addrinfo * address;
    if ((rv = getaddrinfo(name, NULL, &hints, &address)) != 0) return 0;
    uint32_t result = ((struct sockaddr_in *)(address->ai_addr))->sin_addr.s_addr;
    freeaddrinfo(address);
    return result;
}

size_t
gcd(const size_t x, const size_t y)
{
    size_t remainder = x % y;
    if (remainder == 0) return y;
    return gcd(y, remainder);
}

void
remove_host_from_list(struct host_entry * host)
{
    assert(first_host_in_list);
    assert(host);

    if (host == first_host_in_list) {
        first_host_in_list = host->next;
    } else {
        struct host_entry * temp = first_host_in_list;
        while (temp->next != host && temp->next != NULL) temp = temp->next;
        if (temp->next == NULL) return;
        temp->next = temp->next->next;
    }
    free(host);
}

void
init_hosts(void)
{
    struct host_entry * host;
    struct protoent * proto;

    if ((proto = getprotobyname("icmp")) == NULL) {
        fprintf(stderr, "ERROR: Unknown protocol: icmp.\n");
        exit(EXIT_FAILURE);
    }

    assert(first_host_in_list);
    host = first_host_in_list;
    while (host) {
        struct host_entry * next_host = host->next;
        bzero(&host->dest, sizeof(host->dest));
        host->dest.sin_family = AF_INET;
        if (!(host->dest.sin_addr.s_addr = get_host_addr(host->name))) {
            fprintf(stderr, "WARN: Removing unresolvable host %s from list.\n", host->name);
            remove_host_from_list(host);
        }
        host = next_host;
    }

    assert(first_host_in_list);
    host = first_host_in_list;
    while (host) {
        struct host_entry * next_host = host->next;
        if ((host->socket = socket(AF_INET, SOCK_RAW, proto->p_proto)) < 0) {
            fprintf(stderr, "WARN: Failed creating socket. Removing host %s from list.\n", host->name);
            remove_host_from_list(host);
        }
        host = next_host;
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
    if (first_host_in_list == NULL) {
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
    alarm(TIMER_RESOLUTION);

    get_response();

    exit(EXIT_SUCCESS);
}
