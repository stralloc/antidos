#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

// http://www.fefe.de/libowfat needed
#include <fmt.h>
#include <scan.h>
#include <byte.h>
#include <buffer.h>
#include <stralloc.h>
#include <open.h>
#include <str.h>
#include <dns.h>

#define DEFAULT_MAX_SYN 30    // block ips with more than x connections in syn state
#define DEFAULT_MAX_CONNECTIONS 1024    // check only x connections per pass
#define DEFAULT_WAIT 20		// in seconds
#define DEFAULT_STEPS 100
#define EMAIL "post2rene@googlemail.com" // bug report
#define DUMP_PATH "/root/" // must end with /
#define IPTABLES_BIN "/sbin/iptables"

struct node {
	struct in_addr ip;
	unsigned int count;
	struct node *next;
};

static struct node **list;

static int options;
#define OPTION_RECV_SIG 1
#define OPTION_DO_DUMP 2

extern char *optarg;
extern int optind;

static void sigterm(int sig)
{
	options |= OPTION_RECV_SIG;
}

static void usage(void)
{
	buffer_putsflush(buffer_1, "antidos v1\n"
			 "Usage: antidos [options]\n"
			 "-h\tprint help\n"
			 "-d\tdump all ip connections to " DUMP_PATH " on attack\n"
			 "-c number\t block all IPs with more than number simultaneous connections in SYN state (default 30)\n"
			 "-M number\tcheck maximum number connections per pass (default 1024)\n" 
			 "-t number\tWait number seconds between tests of network connections (default 20)\n"
			 "Please send any errors or improvements to <" EMAIL ">\n");
	_exit(1);
}

static void block(struct in_addr ip)
{
	char string_ip[16];
	pid_t pid;

	str_copy(string_ip,inet_ntoa(ip));

	char *args[] = { IPTABLES_BIN, "-I", "INPUT", "-s", string_ip, "-j", "DROP", "-m",
		"comment", "--comment", "TCP-SYN-Block", NULL
	};

	buffer_puts(buffer_1, "INFO: block ");
	buffer_puts(buffer_1, string_ip);
	buffer_putsflush(buffer_1, "\n");

	if ((pid = vfork()) < 0) {
		buffer_putsflush(buffer_2, "ERROR: vfork(" IPTABLES_BIN ") failed!\n");
		options |= OPTION_RECV_SIG;
	} else if (pid > 0) {
		waitpid(pid, NULL, 0);
	} else {
		execve(IPTABLES_BIN, args, 0);
		_exit(0);
	}
}

static unsigned int fmt_2digits(char* dest,int i) {
    dest[0]=(i/10)+'0';
    dest[1]=(i%10)+'0';
    return 2;
}

static void dump(struct in_addr ip)
{
        int infd,outfd;
        char inbuf[1024],outbuf[1024];
        buffer in,out;

        struct in_addr rip,lip;
        unsigned long rport,lport;

        stralloc sbuf;
        struct stat sa;

        time_t t;
        struct tm *x;

        char path[256];
        size_t len;

        char string_ip[16];
        str_copy(string_ip,inet_ntoa(ip));

        rport=lport=0;

        stralloc_init(&sbuf);
        if(!stralloc_ready(&sbuf,1024)) {
			buffer_putsflush(buffer_2, "ERROR: Out of mem!\n");
			return;
        }

        infd = open_read("/proc/net/tcp");
        if(infd<0) {
                buffer_putsflush(buffer_2, "ERROR: Can't read /proc/net/tcp\n");
                return;
        }
        buffer_init(&in, read, infd, inbuf, sizeof(inbuf));

        t=time(NULL);
        x=localtime(&t);
        len = fmt_str(path,DUMP_PATH);
        len += fmt_2digits(path+len,(x->tm_year+1900)/100);
        len += fmt_2digits(path+len,(x->tm_year+1900)%100);
        path[len++]='_';
        len += fmt_2digits(path+len,x->tm_mon+1);
        path[len++]='_';
        len += fmt_2digits(path+len,x->tm_mday);
        len += fmt_str(path+len,".txt");

        outfd = open_append(path);
        if(outfd<0) {
                buffer_puts(buffer_2, "ERROR: Can't write ");
                buffer_puts(buffer_2, path);
                buffer_putsflush(buffer_2,"\n");
                return;
        }
        buffer_init(&out, write, outfd, outbuf, sizeof(outbuf));

	// if exists
        if(stat(path,&sa)==0) {
            buffer_puts(&out,"------------------------------------------------------------------------------\n");
        }
        buffer_puts(&out,"attacker ip: ");
        buffer_puts(&out,string_ip);

        if(dns_name4(&sbuf,(char *)&ip)==0) {
            buffer_puts(&out,"\nattacker dns: ");
            buffer_putsa(&out,&sbuf);
        }

        buffer_puts(&out,"\ntime: ");
        buffer_puts(&out,asctime(x));
        buffer_puts(&out,"\n");

        // copy head line
        buffer_getnewline_sa(&in, &sbuf);
        buffer_putsa(&out,&sbuf);

        while (buffer_getnewline_sa(&in, &sbuf)) {

            if(sbuf.len>113) {

                scan_xlong(sbuf.s + 20,(unsigned long *) &rip);
                scan_xlong(sbuf.s + 6,(unsigned long *) &lip);
                scan_xlong(sbuf.s + 29,&rport);
                scan_xlong(sbuf.s + 15, &lport);

                buffer_put(&out,sbuf.s,6);

                buffer_puts(&out,inet_ntoa(lip));
                buffer_put(&out,":",1);
                buffer_putulong(&out,lport);

                buffer_put(&out,"\t",1);

                buffer_puts(&out,inet_ntoa(rip));
                buffer_put(&out,":",1);
                buffer_putulong(&out,rport);

                buffer_put(&out,"\t",1);
                buffer_putsflush(&out,sbuf.s+34);
            }
        }

        stralloc_free(&sbuf);
        buffer_close(&in);
        close(infd);
        buffer_close(&out);
        close(outfd);
}

static void check(stralloc * sbuf, unsigned int max_connections, unsigned int max_syn)
{
	int fd;
	char fdbuf[1024];
	buffer in;

	struct in_addr i_ip;

	struct node *it;
	struct node *old;
	struct node *tmp;

	register int max_rounds = max_connections;
	unsigned int tmp_ip;
	unsigned char last_byte;

	old = it = tmp = NULL;

	fd = open_read("/proc/net/tcp");
	if (fd < 0) {
		buffer_putsflush(buffer_2, "ERROR: Can't read /proc/net/tcp\n");
		return;
	}

	buffer_init(&in, read, fd, fdbuf, sizeof(fdbuf));

	// ignore head line
	buffer_getnewline_sa(&in, sbuf);

 nextline:
	while (buffer_getnewline_sa(&in, sbuf)) {

		if (--max_rounds < 1)
			break;

		// status SYN_RECV
		if (sbuf->s[34] == '0' && sbuf->s[35] == '3') {

			scan_xlong(sbuf->s + 20, (unsigned long *)&i_ip);

			byte_copy(&tmp_ip, sizeof(unsigned int), &i_ip);
			last_byte = (tmp_ip >> 24) & 255;

			if (list[last_byte] != 0) {

				for (it = list[last_byte]; it != 0; old = it, it = it->next) {

					if (it->ip.s_addr == i_ip.s_addr) {

						// found
						it->count++;	// we need all connections
						if (it->count + 1 == max_syn) {	// block only one time
							if(options & OPTION_DO_DUMP) {
								dump(it->ip);
							}
							block(it->ip);
						}
						goto nextline;
					}
				}
			}
			// not found -> create
			tmp = alloca(sizeof(struct node));
			if (tmp) {
				tmp->ip.s_addr = i_ip.s_addr;
				tmp->count = 0;
				tmp->next = NULL;

				// insert
				if (list[last_byte] == 0) {
					list[last_byte] = tmp;
				} else {
					old->next = tmp;
				}
			}
		}
	}

	close(fd);
}

int main(int argc, char **argv)
{
	int i;
	unsigned int max_syn = DEFAULT_MAX_SYN;
	unsigned int max_connections = DEFAULT_MAX_CONNECTIONS;

	unsigned long wait_msec = (DEFAULT_WAIT * 1024 * 1024) / DEFAULT_STEPS;

	stralloc sbuf;
	stralloc_init(&sbuf);
	stralloc_ready(&sbuf, 1024);

	options = 0;
	while ((i = getopt(argc, argv, "dhc:M:t:")) != -1) {
		switch (i) {
		case 'd':
			options |= OPTION_DO_DUMP;
		case 'c':
			scan_uint(optarg, &max_syn);
			break;
		case 'M':
			scan_uint(optarg, &max_connections);
			break;
		case 't':
			scan_ulong(optarg, &wait_msec);
			wait_msec = (wait_msec * 1024 * 1024) / DEFAULT_STEPS;
			break;
		case 'h':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	list = (struct node **)
	    malloc(sizeof(struct node *) * 256);
	if (list == NULL) {
		buffer_putsflush(buffer_2, "ERROR: Out of mem!\n");
		return -1;
	}

	signal(SIGTERM, sigterm);
	signal(SIGSTOP, sigterm);
	signal(SIGINT, sigterm);
	signal(SIGQUIT, sigterm);
	signal(SIGKILL, sigterm);

	// ignore SIGHUP, we dont have any configs
	signal(SIGHUP, SIG_IGN);

	buffer_putsflush(buffer_1, "INFO: antidos starts\n");

	for (;;) {
		for (i = 0; i < DEFAULT_STEPS; i++) {
			if (options & OPTION_RECV_SIG)
				goto end;

			usleep(wait_msec);
		}

		byte_zero(list, sizeof(struct node *) * 256);
		check(&sbuf, max_connections, max_syn);
	}

 end:

	free(list);
	stralloc_free(&sbuf);

	buffer_putsflush(buffer_1, "INFO: antidos closed\n");

	return 0;
}
