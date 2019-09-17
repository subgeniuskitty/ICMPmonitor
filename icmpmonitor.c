/*
 * Copyright (c) 1989 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Muuss.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 *			ICMPMONITOR.C
 *
 * Using the InterNet Control Message Protocol (ICMP) "ECHO" facility,
 * monitor several hosts, and notify admin if some of them are down.
 *
 * Author -
 *      Vadim Zaliva <lord@crocodile.org>
 *
 * Status -
 *	Public Domain.  Distribution Unlimited.
 */

char copyright[] =
"@(#) Copyright (c) 1989 The Regents of the University of California.\n"
"All rights reserved.\n";

char rcsid[] = "$Id: icmpmonitor.c,v 1.8 2004/05/28 01:33:07 lord Exp $";

#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_SYSLOG_H
# include <syslog.h>
#endif
#include <stdarg.h>
#include <signal.h>
#include <string.h>
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#include <sys/socket.h>
#include <sys/types.h>
#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
#ifdef HAVE_SYS_FCNTL_H
# include <sys/fcntl.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

/* Workaround for broken ICMP header on Slackware 4.x */
#ifdef _LINUX_ICMP_H
# warning "Broken Slackware 4.x 'netinet/ip_icmp.h' header detected. Using replacement 'struct icmp' definition."
# define ICMP_MINLEN    8
struct icmp
{
    u_int8_t  icmp_type;
    u_int8_t  icmp_code;
    u_int16_t icmp_cksum;
    union
    {
        struct ih_idseq
        { 
            u_int16_t icd_id;
            u_int16_t icd_seq;
        } ih_idseq;
    } icmp_hun;
    
# define icmp_id         icmp_hun.ih_idseq.icd_id
# define icmp_seq        icmp_hun.ih_idseq.icd_seq
    
    union {
        u_int8_t    id_data[1];
    } icmp_dun;
    
# define icmp_data       icmp_dun.id_data
    
};
#endif /* _LINUX_ICMP_H */

#include <stddef.h>
#include <errno.h>

#include "cfg.h"

/* defines */

/* #define DEBUG */

#ifndef nil
# define nil NULL
#endif

/* return codes */
#define RET_OK         0
#define RET_NO_HOSTS   1
#define RET_INIT_ERROR 2
#define RET_BAD_CFG    3
#define RET_BAD_OPT    4

#define	MAXPACKET	(65536 - 60 - 8) /* max packet size     */
#define	DEFDATALEN	(64 - 8)	 /* default data length */

#define VERSION "ICMPmonitor v1.2 by lord@crocodile.org"
#define MAX_LOG_MSG_SIZE 4096

# define icmphdr			icmp

/* typedefs */
typedef struct monitor_host
{
    /* following are coming from cfg */
    char  *name;
    int    ping_interval;
    int    max_delay;
    char  *upcmd;
    char  *downcmd;

    /* following values are calculated */
    int    socket;
    struct timeval last_ping_received;
    struct timeval last_ping_sent;
    int    up;
    int    down;
    struct sockaddr_in dest;

    unsigned int sentpackets ;
    unsigned int recvdpackets;
    
    /* linked list */
    struct monitor_host *next;
} monitor_host_t;

/* protos */
static void logopen(void);
static void logclose(void);
static void log(int type, char *format, ...);
static int  gethostaddr(const char *name);
static void read_hosts(const char *cfg_file_name);
static void init_hosts(void);
static void get_response(void);
static void pinger(int);
static int  in_cksum(u_short *addr, int len);
static void read_icmp_data(monitor_host_t *p);
static void tvsub(struct timeval *out, struct timeval *in);
static void done(int code);
static void start_daemon(void);
static int gcd(int x, int y);

/* globals */

static monitor_host_t **hosts      = nil;
static int             isDaemon    = 0; 
static int             isVerbose   = 0;
static int             keepBanging = 0;
static unsigned short  ident;
static int             send_delay  = 1;

int main(int ac, char **av)
{
    extern char* optarg;
    extern int   optind;
    char         *cfgfile=nil;
    int          param;
    
    logopen();
    log(LOG_INFO, VERSION " is starting.");

    while((param = getopt(ac, av, "rvdf:")) != -1)
  	switch(param)
        { 
 	case 'v':
            isVerbose = 1;
 	    break; 
 	case 'd':
            isDaemon = 1;
 	    break; 
 	case 'r':
            keepBanging = 1;
 	    break; 
  	case 'f':  
  	    cfgfile=strdup(optarg);  
  	    break;  
 	default: 
 	    fprintf(stderr,"Usage: icmpmonitor [-d] [-v] [-r] [-f cfgfile]\n");
            done(RET_BAD_OPT);
 	} 
    
    if(!cfgfile)
    {
        log(LOG_WARNING,"No cfg file specified. Assuming 'icmpmonitor.cfg'");
	cfgfile="icmpmonitor.cfg";
    }

    read_hosts(cfgfile); /* we do this before becoming daemon,
                            to be able process relative path */

    if(isDaemon)
        start_daemon();
    
    init_hosts();
    
    ident=getpid() & 0xFFFF;
    
    (void)signal(SIGALRM, pinger);
    alarm(send_delay); 

    get_response();
    
    done(RET_OK);
}


/*
 * in_cksum --
 *	Checksum routine for Internet Protocol family headers (C Version)
 */
static int
in_cksum(u_short *addr, int len)
{
    register int nleft = len;
    register u_short *w = addr;
    register int sum = 0;
    u_short answer = 0;
    
    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)  {
        sum += *w++;
        nleft -= 2;
    }
    
    /* mop up an odd byte, if necessary */
    if (nleft == 1) {
        *(u_char *)(&answer) = *(u_char *)w ;
        sum += answer;
    }
    
    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
    sum += (sum >> 16);			/* add carry */
    answer = ~sum;			/* truncate to 16 bits */
    return(answer);
}

/*
 * pinger --
 * 	Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
 * will be added on by the kernel.  The ID field is our UNIX process ID,
 * and the sequence number is an ascending integer.  The first 8 bytes
 * of the data portion are used to hold a UNIX "timeval" struct in VAX
 * byte-order, to compute the round-trip time.
 */
static void pinger(int ignore)
{
    register struct icmphdr *icp;
    register int             cc;
    int                      i;
    monitor_host_t           *p;
    u_char outpack[MAXPACKET];

    p=hosts[0];
    while(p)
    {
        if(p->socket!=-1)
        {
            struct timeval now;
            
            (void)gettimeofday(&now,(struct timezone *)NULL);
            tvsub(&now, &p->last_ping_received);

            if(now.tv_sec > (p->max_delay+p->ping_interval))
            {            
                p->up=0;
                if((!p->down) || keepBanging)
                {
		    p->down = 1;
                    
                    if(isVerbose)
                        log(LOG_INFO,"Host %s in down. Executing DOWN command",p->name);
                    if(!fork())
                    {
                        system(p->downcmd);
                        exit(0);
                    } else
                    {
                        wait(nil);
                    }
                }
            }
            
            (void)gettimeofday(&now,(struct timezone *)NULL);
            tvsub(&now, &p->last_ping_sent);
            
            if(now.tv_sec > p->ping_interval)
            {
                /* Time to send ping */
                
                icp = (struct icmphdr *)outpack;
                icp->icmp_type  = ICMP_ECHO;
                icp->icmp_code  = 0;
                icp->icmp_cksum = 0;
                icp->icmp_seq   = p->socket;
                icp->icmp_id    = ident;			

                if(isVerbose)
                    log(LOG_INFO,"Sending ICMP packet to %s.",p->name);
                
                (void)gettimeofday((struct timeval *)&outpack[8],
                                   (struct timezone *)NULL);
                
                cc = DEFDATALEN + 8;  /* skips ICMP portion */
                
                /* compute ICMP checksum here */
                icp->icmp_cksum = in_cksum((u_short *)icp, cc);
                
                i = sendto(p->socket, (char *)outpack, cc, 0, (const struct sockaddr *)(&p->dest),
                           sizeof(struct sockaddr));
                
                (void)gettimeofday(&p->last_ping_sent,
                                   (struct timezone *)NULL);
                
                if(i<0 || i!=cc)
                {
                    if(i<0)
                        log(LOG_WARNING,"Sending ICMP packet to %s failed.",p->name);
                }
                p->sentpackets++;
            }
        }
        p=p->next;
        
    }
    
    (void)signal(SIGALRM, pinger); /* restore handler */
    alarm(send_delay);
}

static void get_response(void)
{
    fd_set rfds;
    int    retval;
    monitor_host_t *p;
    int    maxd=-1;
    
    while(1)
    {
        p=hosts[0];
        FD_ZERO(&rfds);
        while(p)
        {
            if(p->socket != -1)
            {
                if(p->socket > maxd)
                    maxd=p->socket;
                FD_SET(p->socket, &rfds);
            }
            p=p->next;
        }

        retval = select(maxd+1, &rfds, nil, nil, nil);
        if(retval<0)
        {
            /* we get her in case we are interrupted by signal.
               it's ok. */
        }
        else
        {
            if(retval>0)
            {
                /* log(LOG_DEBUG,"ICMP data is available now."); */
                p=hosts[0];
                while(p)
                {
                    if(p->socket!=-1 && FD_ISSET(p->socket, &rfds))
                    {
                        /* Read data */
                        read_icmp_data(p);
                    }
                    p=p->next;
                }
            } else
            {
                log(LOG_DEBUG,"select returns 0."); /* TODO */
            }
        }
    }
}

static void read_icmp_data(monitor_host_t *p)
{
    socklen_t fromlen       ;
    struct sockaddr_in from ;
    int cc                  ;
    struct ip   *ip         ;
    struct icmp *icmp       ;
    int    iphdrlen         ;
    int    delay            ;
    struct timeval tv       ;
    unsigned char buf[MAXPACKET]; /* read buffer */

    (void)gettimeofday(&tv, (struct timezone *)NULL);
    
    fromlen = sizeof(from);
    if((cc = recvfrom(p->socket, buf, sizeof(buf), 0,
                      (struct sockaddr *)&from, &fromlen)) < 0)
    {
        if(errno != EINTR)
            log(LOG_WARNING,"Error reading ICMP data from %s.",p->name);
        return;
    } 

    /* log(LOG_DEBUG,"Got %d bytes of ICMP data from %s.",cc, p->name); */

    /* check IP header actual len */ 
    ip       = (struct ip *)buf               ; 
    iphdrlen = ip->ip_hl<<2                   ; 
    icmp     = (struct icmp *) (buf+iphdrlen) ;
    
    if(cc < iphdrlen+ICMP_MINLEN)
    {
        log(LOG_WARNING,"Received short packet from %s.",p->name);
        return;
    }
    
    if(icmp->icmp_type == ICMP_ECHOREPLY &&
       icmp->icmp_id   == ident          &&
       icmp->icmp_seq  == p->socket)
    {
        p->recvdpackets++;

        memcpy(&p->last_ping_received, &tv, sizeof(tv));
        
        tvsub(&tv, (struct timeval *) &icmp->icmp_data[0]);
        delay=tv.tv_sec*1000+(tv.tv_usec/1000);
        
        if(isVerbose)
            log(LOG_INFO,"Got ICMP reply from %s in %d ms.",p->name,delay);
	p->down=0;
        if(!p->up)
        {
            p->up=1;
            if(isVerbose)
                log(LOG_INFO,"Host %s in now up. Executing UP command",p->name);
            if(!fork())
            {
                system(p->upcmd);
                exit(0);
            } else
            {
                wait(nil);
            }
        }
    } else
    {
        /*
          log(LOG_DEBUG,"ICMP packet of type %d from %s. Ident=%d",icmp->icmp_type,
          p->name,
          icmp->icmp_id
          );
        */
    }
}

static void read_hosts(const char *cfg_file_name)
{
    int    i,n=0;
    struct Cfg *cfg;
    
    if((cfg=readcfg(cfg_file_name))==NULL)
    {
        log(LOG_ERR,"Error reading cfg. Exiting.");
        done(RET_BAD_CFG);
    }
    
    if(cfg->nelements)
    {
        hosts=malloc(sizeof(monitor_host_t *)*cfg->nelements);
        for(i=0;i<cfg->nelements;i++)
        {
            if(cfg->dict[i]->nvalues<4)
            {
                log(LOG_ERR,"Not enough fields in record %d of cfg file. Got %d.",n, cfg->dict[i]->nvalues+1);
                done(RET_BAD_CFG);
            } else if(cfg->dict[i]->nvalues>5)
            {
                log(LOG_ERR,"Too many fields in record %d of cfg file. Got %d.",n, cfg->dict[i]->nvalues+1);
                done(RET_BAD_CFG);
            }
            
            hosts[n]=malloc(sizeof(monitor_host_t));
            hosts[n]->name          = strdup(cfg->dict[i]->name);
            hosts[n]->ping_interval = atoi  (cfg->dict[i]->value[0]);
            hosts[n]->max_delay     = atoi  (cfg->dict[i]->value[1]);
            hosts[n]->upcmd         = strdup(cfg->dict[i]->value[2]);
            hosts[n]->downcmd       = strdup(cfg->dict[i]->value[3]);
            
	    if(cfg->dict[i]->nvalues==4)
	    {
		hosts[n]->down = 0;
		hosts[n]->up   = 1;
	    } else if(strcmp(cfg->dict[i]->value[4], "up")==0)
	    {
		hosts[n]->down = 0;
		hosts[n]->up   = 1;
	    } else if(strcmp(cfg->dict[i]->value[4], "down")==0)
	    {
		hosts[n]->down = 1;
		hosts[n]->up   = 0;
	    } else if(strcmp(cfg->dict[i]->value[4], "auto")==0)
	    {
		hosts[n]->down = 1;
		hosts[n]->up   = 1;
	    } else if(strcmp(cfg->dict[i]->value[4], "none")==0)
	    {
		hosts[n]->down = 0;
		hosts[n]->up   = 0;
	    } else
	    {
		log(LOG_ERR,"Illegal value %s in record %n for startup condition.", cfg->dict[i]->value[4], n);
		done(RET_BAD_CFG);
	    }
            hosts[n]->sentpackets   = 0;
            hosts[n]->recvdpackets  = 0;

            hosts[n]->socket           = -1;
            hosts[n]->next             = nil;
            if(n>0)
                hosts[n-1]->next=hosts[n];
            (void)gettimeofday(&(hosts[n]->last_ping_received), (struct timezone *)NULL);

            n++;
        } 
    }

    freecfg(cfg);

    if(n<=0)
    {
        log(LOG_ERR,"No hosts defined in cfg file, exiting.");
        done(RET_NO_HOSTS);
    }
    else
        log(LOG_DEBUG,"%d host(s) found in cfg file,", n);
    
}

static int gethostaddr(const char *name)
{
    static  int  res;
    struct hostent *he;
    
    if((res=inet_addr(name))<0)
    {
	he=gethostbyname(name);
        if(!he)
            return -1;
	memcpy( &res , he->h_addr , he->h_length );
    } 
    return(res);
}

static void init_hosts(void)
{
    monitor_host_t *p=hosts[0];
    struct protoent   *proto;
    int ok=0;

    if((proto=getprotobyname("icmp"))==nil)
    {
        log(LOG_ERR,"Unknown protocol: icmp. Exiting.");
        done(RET_INIT_ERROR);
    }
    
    while(p)
    {
        log(LOG_DEBUG,"resolving host %s", p->name);
        
        bzero(&p->dest,sizeof(p->dest));
        p->dest.sin_family=AF_INET;
        if((p->dest.sin_addr.s_addr=gethostaddr(p->name))<=0)
        {
            log(LOG_ERR,"Can't resolve host. Skipping client %s.",p->name);
            p->socket=-1;
        } else
        {
            if((p->socket=socket(AF_INET,SOCK_RAW,proto->p_proto))<0)
            {
                log(LOG_ERR,"Can't create socket. Skipping client %s.",p->name);
                p->socket=-1;
            } else
            {
                if(ok==0)
                    send_delay = p->ping_interval;
                else
                    send_delay = gcd(send_delay, p->ping_interval);
                ok++;
            }
        }
        p=p->next;
    }

    if(!ok)
    {
        log(LOG_ERR,"No hosts left to process, exiting.");
        done(RET_NO_HOSTS);
    }
}

/*
 * tvsub --
 *	Subtract 2 timeval structs:  out = out - in.  Out is assumed to
 * be >= in.
 */
static void
tvsub(register struct timeval *out, register struct timeval *in)
{
	if ((out->tv_usec -= in->tv_usec) < 0) {
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}

void done(int code)
{
    logclose();
    exit(code);
}

void start_daemon(void)
{
    if(fork())
	exit(0);
    
    chdir("/");
    umask(0);
    (void) close(0);
    (void) close(1);
    (void) close(2);
    (void) open("/", O_RDONLY);
    (void) dup2(0, 1);
    (void) dup2(0, 2);
    setsid();
}

static void logopen(void)
{
#if HAVE_OPENLOG
    if(isDaemon)
        openlog("icmpmonitor", LOG_PID| LOG_CONS|LOG_NOWAIT, LOG_USER);
#else
    log(LOG_WARNING,"Compiled without syslog. Syslog can't be used.");
#endif
}

static void logclose(void)
{
#if HAVE_CLOSELOG
    if(isDaemon)
        closelog();
#endif
}

/**
 * This function should be used as central logging facility.
 * 'type' argument should be one of following:
 *
 *  LOG_EMERG	system is unusable 
 *  LOG_ALERT	action must be taken immediately 
 *  LOG_CRIT	critical conditions 
 *  LOG_ERR	error conditions 
 *  LOG_WARNING	warning conditions 
 *  LOG_NOTICE	normal but significant condition 
 *  LOG_INFO	informational 
 *  LOG_DEBUG	debug-level messages 
 */
static void log(int type, char *format, ...)
{
    va_list ap;

#ifndef DEBUG
    if(type==LOG_DEBUG)
        return;
#endif
    
    va_start(ap, format);

    if(isDaemon)
    {
        char buffer[MAX_LOG_MSG_SIZE];
            
#if HAVE_VSNPRINTF    
        (void)vsnprintf(buffer, MAX_LOG_MSG_SIZE, format, ap);
#else
# if HAVE_VSPRINTF
#  warning "Using VSPRINTF. Buffer overflow could happen!"
        (void)vsprintf(buffer, format, ap);
# else
#  error "Your standard libabry have neither vsnprintf nor vsprintf defined. One of them is reqired!"
# endif
#endif
#if HAVE_SYSLOG            
        syslog(type,buffer);
#endif
    } else
    {
        (void)  fprintf(stderr, "icmpmonitor[%d]:", (int)getpid());
        (void) vfprintf(stderr, format, ap);
        (void)  fprintf(stderr, "\n");
    }
    va_end(ap);
}

static int gcd(int x, int y)
{
    while(x!=y)
    {
        if(x<y)
            y-=x;
        else 
            x-=y;
    }
    return x;
}
