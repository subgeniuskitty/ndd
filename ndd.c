/*
 * © 2019 Aaron Taylor <ataylor at subgeniuskitty dot com>
 * © 2015 jansen@atlas.cz
 * See LICENSE.txt file for copyright and license details.
 */

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <syslog.h>
#include <signal.h>

#include "iniparser/iniparser.h"

/* *****************************************************************************
 * User Configurable Values
 */

#define VERSION             "ndd v1.0"
#define INI_FILE            "ndd.ini"
#define DEFAULT_LOCK_FILE   "/tmp/ndd.lock"
#define MAX_LOG_LEN         100

/* *****************************************************************************
 * Misc Defines
 */

/* np_op operation codes */
#define ND_OP_READ  1       /* read */
#define ND_OP_WRITE 2       /* write */
#define ND_OP_ERROR 3       /* error flag, see error in np_error */
#define ND_OP_CODE  7       /* op code mask */
#define ND_OP_WAIT  010     /* waiting for DONE or next request (flag) */
#define ND_OP_DONE  020     /* operation done (flag) */

/* misc protocol defines */
#define ND_MAXDATA  1024                                    /* max data per packet */
#define ND_MAXIO    63*1024                                 /* max np_bcount */
#define ND_IPPROTO  77                                      /* IP protocol number */
#define ND_HDRSZ    (sizeof (ndpkt_t) - sizeof (void *))    /* header size */
#define ND_MAXPKT   (ND_HDRSZ + ND_MAXDATA)                 /* max packet size */
#define MAX_MINOR   4                                       /* max number of disks */

#define RDONLY_STR  "RO"
#define WR_STR      "WR"

#define RDONLY      1
#define WR          2

/*
 * ND(4P) does not provide support for any ioctl() operation directly, but
 * client can use a reserved value of np_blkno to obtain some information.
 * As far as I know, this is not documented anywhere so the following is based
 * only on my observation.
 */
/*
 * SunOS 3.5 sends ND_OP_READ for the following blkno for np_min 1 during
 * the boot. I suppose it's trying to determine the size of swap/dump device.
 * Server seems to be expected to reply with the device size (in 512 blocks)
 * stored in np_data (in network order).
 * If client dislikes the returned size, it panics with: "panic: vstodb".
 */
#define GET_SIZE_REQ    0x10000000

/* *****************************************************************************
 * Data Types
 */

/*
 * Following definitions are based on ND(4P) man pages found on Internet.
 */
typedef struct ndpkt {
    struct  ip np_ip;   /* IP header */
    u_char  np_op;      /* operation code, see below */
    u_char  np_min;     /* minor device */
    int8_t  np_error;   /* b_error */
    int8_t  np_ver;     /* version number */
    int32_t np_seq;     /* sequence number */
    int32_t np_blkno;   /* b_blkno, disk block number */
    int32_t np_bcount;  /* b_bcount, byte count */
    int32_t np_resid;   /* b_resid, residual byte count */
    int32_t np_caddr;   /* current byte offset of this packet */
    int32_t np_ccount;  /* current byte count of this packet */
    void    *np_data;   /* data */
} ndpkt_t;

typedef struct ndd {
    int     sc_fd;
    int     lf_fd;
    short   log_level;
    short   exiting;
    short   is_daemon;
    short   simple_ack;
    char    *lf;
} ndd_t;

/* pending packet (but we don't use this now) */
typedef struct ndack {
    uint32_t        seq;
    uint32_t        blkno;
    uint32_t        caddr;
    time_t          last_pkt;
    struct ndack    *next;
} ndack_t;

/* softstate */
typedef struct ndmin {
    int     fd;     /* file descriptor */
    int     size;   /* disk size in bytes */
    int     mode;   /* RDONLY or WR */
    ndack_t *ack;   /* XXX list of pending ACKs for this disk */
} ndmin_t;

/* *****************************************************************************
 * Function declarations
 */

int load_config(const char *, ndd_t *);
int init_network();
int serve(ndd_t *);
void close_minors();
void log_msg(int level, const char *fmt, ...);
ndmin_t *get_minor(int mn);
int add_ack(ndmin_t *m, ndpkt_t *p);
uint32_t get_minor_size(int mn);

/* *****************************************************************************
 * Globals
 */

ndd_t nds;
static ndmin_t *nd_minors[MAX_MINOR];

/* *****************************************************************************
 * Source code
 */

/*
 * Return 'sofstate' for given minor.
 */
ndmin_t *
get_minor(int mn)
{
    if (mn < 0 || mn > MAX_MINOR)
        return (NULL);
    return (nd_minors[mn]);
}

/*
 * Return the disk size in blocks (512 bytes).
 * Size of non-existing disk is 0.
 */
uint32_t
get_minor_size(int mn)
{
    ndmin_t *m;

    m = get_minor(mn);
    return (m != NULL ? m->size / 512 : 0);
}

/*
 * Initialize given 'softstate'.
 */
static int
open_minor(int n, const char *name, int m)
{
    struct stat st;
    mode_t mode = O_RDONLY;
    ndmin_t *minor;
    int fd;

    if (m == WR)
        mode = O_RDWR;

    if ((fd = open(name, mode)) < 0) {
        log_msg(0, "Unable to open file %s: %s",
            name, strerror(errno));
        return (1);
    }
    if (fstat(fd, &st) == -1) {
        (void) close(fd);
        log_msg(0, "Unable to get size of %s: %s",
            name, strerror(errno));
        return (1);
    }

    if ((minor = malloc(sizeof (ndmin_t))) == NULL) {
        (void) close(fd);
        log_msg(0, "Unable to allocate memory for minor");
        return (1);
    }
    minor->fd = fd;
    minor->size = st.st_size;
    minor->mode = m;
    minor->ack = NULL;
    nd_minors[n] = minor;
    log_msg(2, "nd%d is %s, %llu blocks %s", n, name,
        (unsigned long long ) st.st_size / 512, (m != WR) ? "(RO)" : "");

    return (0);
}

/*
 * Load configuration.
 * Note that logging is not available yet.
 */
int
load_config(const char *cf, ndd_t *nds)
{
    dictionary *ini;
    int m;

    ini = iniparser_load(cf ? cf : INI_FILE);
    if (ini == NULL)
        return (ENOENT);

    nds->log_level = (short) iniparser_getint(ini, "general:log_level", 0);
    nds->simple_ack = (short) iniparser_getboolean(ini,
        "general:simple_ack", -1);

    for (m = 0; m < MAX_MINOR; m++) {
        char key[100];
        const char *fn, *mods;
        int mode;

        nd_minors[m] = NULL;
        (void) sprintf(key, "nd%d:path", m);
        if ((fn = iniparser_getstring(ini, key, NULL)) == NULL)
            continue;
        (void) sprintf(key, "nd%d:mode", m);
        if ((mods =  iniparser_getstring(ini, key, WR_STR)) == NULL)
            continue;
        if (strcmp(mods, RDONLY_STR) == 0) {
            mode = RDONLY;
        } else if (strcmp(mods, WR_STR) == 0) {
            mode = WR;
        } else {
            log_msg(0, "nd%d has unknown mode: '%s'! Skipping.",
                m, mods);
            continue;
        }
        if (open_minor(m, fn, mode))
            log_msg(0, "Skipping nd%d.", m);
    }
    iniparser_freedict(ini);

    return (0);
}

void
close_minors()
{
    int m;
    for (m = 0; m < MAX_MINOR; m++) {
        ndmin_t *mn = get_minor(m);
        ndack_t *next;

        if (mn == NULL)
            continue;
        (void) close(mn->fd);
        while (mn->ack) {
            next = mn->ack->next;
            free(mn->ack);
            mn->ack = next;
        }
        log_msg(5, "nd%d removed", m);
    }
}

/*
 * Print the usage message.
 */
void
usage()
{
    (void) fprintf(stderr, "ndd [-dvh] [-c config] [-l lock_file]\n");
    exit(1);
}

/*
 * Log message using the syslogd(8). If we are not a daemon, print it also
 * to stderr.
 */
void
log_msg(int level, const char *fmt, ...)
{
    va_list arg;
    char log_str[MAX_LOG_LEN];

    if (level > nds.log_level)
        return;

    va_start(arg, fmt);
    (void) vsnprintf(log_str, MAX_LOG_LEN, fmt, arg);
    va_end(arg);

    syslog(LOG_INFO, "%s", log_str);
    if (!nds.is_daemon) {
        (void) fprintf(stderr, "%s\n", log_str);
        (void) fflush(stderr);
    }
}

/*
 * Handle signals. We currently handle only SIGTERM and SIGINT; we simply
 * exit in both cases.
 */
void
signal_handler(int sig)
{
    assert(sig == SIGTERM || sig == SIGINT);
    log_msg(0, "Shutting down...");
    nds.exiting = 1;
    exit(0);
}

/*
 * Daemonise ndd so it can run at background.
 */
int
daemonise()
{
    pid_t pid, sid;

    pid = fork();
    if (pid < 0) {
        log_msg(0, "Fork failed: %d", errno);
        return (1);
    }
    if (pid > 0) {
        /* We are the parent process. */
        exit(0);
    }

    umask(0);

    if ((sid = setsid()) < 0) {
        log_msg(0, "Unable to create a new SID: %d", errno);
        return (1);
    }
    if ((chdir("/")) < 0) {
        log_msg(0, "Unable to change to /: %d", errno);
        return (1);
    }
    /* Close all standard file descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    /* stderr is no more available */
    nds.is_daemon = 1;

    signal(SIGCHLD, SIG_IGN);
    return (0);
}

/*
 * We use a lock file to make sure we are the only instance of this
 * program running on the system. The lock file contains the pid so
 * the children has to call this again after it daemonize to write
 * down its pid.
 * Note that we use O_EXCL so this may not work properly for lock
 * file on NFS.
 */
int
create_lock(ndd_t *ndd)
{
    char pid_str[10];
    int pid_len;

    if (ndd->lf_fd < 0) {
        /* We don't have the lock file yet -- create it. */
        if ((ndd->lf_fd = open(ndd->lf, O_RDWR | O_CREAT | O_EXCL,
            0640)) < 0) {
            log_msg(0, "Unable to create lock file %s: %d",
                ndd->lf, errno);
            return (1);
        }
        log_msg(0, "Lock file %s created, fd: %d", ndd->lf, ndd->lf_fd);
    } else {
        /* The lock file already exists, just update the pid. */
        (void) lseek(ndd->lf_fd, 0, SEEK_SET);
        log_msg(0, "Updating pid only: %d", ndd->lf_fd);
    }
    (void) snprintf(pid_str, sizeof (pid_str), "%d\n", getpid());
    pid_len = strlen(pid_str);

    if (write(ndd->lf_fd, pid_str, pid_len) != pid_len) {
        log_msg(0, "Unable to write the lock file %s: %d",
            ndd->lf, errno);
        return (1);
    }

    return (0);
}

/*
 * Close and remove the lock file.
 */
void
remove_lock()
{
    if (nds.lf_fd < 0)
        return;
    (void) close(nds.lf_fd);
    (void) unlink(nds.lf);
    log_msg(5, "Lock file %s removed.", nds.lf);
    nds.lf_fd = -1;
}

/*
 * We call this from atexit(). The main purpose of this function is
 * remove the lock file.
 */
void
cleanup()
{
    if (!nds.exiting)
        log_msg(1, "Warning: exiting for uknown reason.");

    /* Close the network socket. */
    if (nds.sc_fd >= 0)
        (void) close(nds.sc_fd);

    /* Close all minors. */
    close_minors();
    remove_lock();
}

int
main(int argc, char **argv)
{
    char *conf_file = NULL;
    int do_daemon = 1;
    int c;

    /* Initialize the context */
    nds.is_daemon = 0;
    nds.exiting = 0;
    nds.lf_fd = -1;
    nds.sc_fd = -1;
    nds.lf = DEFAULT_LOCK_FILE;

    while ((c = getopt(argc, argv, "dc:l:vh")) != -1) {
        switch (c) {
        case 'd':   /* debug */
            do_daemon = 0;
            break;
        case 'c':   /* config file */
            conf_file = optarg;
            break;
        case 'l':   /* lock file */
            nds.lf = optarg;
            break;
        case 'v':
            (void) printf("Version: %s\n", VERSION);
            exit(0);
            break;
        case 'h':
            usage();
            break;
        case '?':
            if (optopt == 'c') {
                (void) fprintf(stderr, "Missing configuration"
                    " file name.\n");
            } else if (optopt == 'l') {
                (void) fprintf(stderr, "Missing lock file "
                    "name.\n");
            }
            usage();
            break;
        default:
            abort();
        }
    }

    openlog(NULL, LOG_PID, LOG_USER);

    /* Load the config file. */
    if (load_config(conf_file, &nds) != 0) {
        (void) fprintf(stderr, "Unable to load configuration.\n");
        exit(1);
    }

    /* Try to create the lock file. */
    if (create_lock(&nds)) {
        log_msg(0, "Unable to get the lock. Exiting.");
        close_minors();
        exit(1);
    }

    /* Initialize the network. */
    if ((nds.sc_fd = init_network()) == -1) {
        log_msg(0, "Unable to initialize network. Exiting.");
        close_minors();
        remove_lock();
        exit(1);
    }

    if (do_daemon) {
        if (daemonise()) {
            log_msg(0, "Unable to deamonize. Exiting.");
            close_minors();
            remove_lock();
            exit(1);
        }
        /* Update the lock file with the new PID the child got. */
        if (create_lock(&nds)) {
            log_msg(0, "Unable to lock. Exiting.");
            close_minors();
            remove_lock();
            exit(1);
        }
    }

    /* We handle SIGTERM and SIGINT only */
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    /* atexit function will remove the lock file. */
    atexit(cleanup);

    serve(&nds);

    exit(0);
}

/*
 * Open RAW IP socket.
 */
int
init_network()
{
    int sc;
    int one = 1;
    int *val = &one;

    sc = socket(AF_INET, SOCK_RAW, ND_IPPROTO);
    if (sc == -1) {
        log_msg(0, "Unable to open socket: %s.", strerror(errno));
        return (sc);
    }
    if (setsockopt(sc, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) == -1) {
        log_msg(0, "Unable to set IP_HDRINCL: %s.", strerror(errno));
        close(sc);
        return (-1);
    }
    return (sc);
}

/*
 * Verify incoming packet.
 */
static int
verify_pkt(ndpkt_t *p)
{
    ndmin_t *m;
    long blkno = ntohl(p->np_blkno);
    long bcount = ntohl(p->np_bcount);

    if (ntohl(p->np_bcount) > ND_MAXIO) {
        log_msg(3, "bcount is too big: %lu.",
            (unsigned long) ntohl(p->np_bcount));
        return (EIO);
    }

    if ((m = get_minor(p->np_min)) == NULL) {
        log_msg(3, "nd%d does not exist.", p->np_min);
        return (EIO);
    }

    if (m->mode == RDONLY && p->np_op & ND_OP_WRITE) {
        log_msg(3, "nd%d is read only.", p->np_min);
        return (EROFS);
    }

    if (blkno != GET_SIZE_REQ && blkno > (m->size / 512)) {
        log_msg(1, "nd%d is too small: has no blkno %lu.",
            p->np_min, (unsigned long) blkno);
        return (EIO);
    }

    if (blkno == GET_SIZE_REQ && bcount != sizeof (uint32_t))
        return (EINVAL);

    return (0);
}

/*
 * Prepare the IP header for outgoing packet.
 */
static void
prepare_ip_header(ndpkt_t *p)
{
    struct sockaddr_in dst;

    /* IP_HDRINCL will fill the rest. */
    memcpy(&dst.sin_addr.s_addr, &p->np_ip.ip_src, sizeof (in_addr_t));
    memset(&p->np_ip, 0, sizeof (struct ip));
    p->np_ip.ip_hl = 5;
    p->np_ip.ip_v = 4;
    p->np_ip.ip_p = ND_IPPROTO;
    memcpy(&p->np_ip.ip_dst, &dst.sin_addr.s_addr, sizeof (in_addr_t));
}

/*
 * Send the reply.
 */
static int
send_packet(ndd_t *nds, ndpkt_t *p, int size, int err)
{
    struct sockaddr_in sin;

    if (err) {
        /*
         * It appears that client ignores read replies if their
         * size differs from what is expected. So we need
         * to send enough data even when we hit error.
         */
        if (p->np_op & ND_OP_READ)
            (void) memset(&p->np_data, 0, ntohl(p->np_ccount));
        p->np_op |= ND_OP_ERROR;
        p->np_error = err;
    }

    memset(&sin, 0, sizeof (struct sockaddr_in));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = p->np_ip.ip_dst.s_addr;
    p->np_ip.ip_len = htons(size);

    if (sendto(nds->sc_fd, p, size, 0, (struct sockaddr *) &sin,
        sizeof (struct sockaddr)) < 0) {
        log_msg(0, "Unable to send packet: %s", strerror(errno));
        return (1);
    }
    return (0);
}

/*
 * Read request processing.
 */
static int
serve_read(ndd_t *nds, ndpkt_t *p, int err)
{
    long caddr = 0;
    long bcount = ntohl(p->np_bcount);
    long blkno = ntohl(p->np_blkno);

    prepare_ip_header(p);

    if (blkno == GET_SIZE_REQ) {
        /* The client wants to know the size of this disk */
        if (err == 0) {
            uint32_t disk_size = htonl(get_minor_size(p->np_min));

            assert(bcount == sizeof (uint32_t));
            memcpy(&p->np_data, &disk_size, bcount);
            p->np_op |= ND_OP_DONE;
            p->np_caddr = 0;
            p->np_ccount = htonl(bcount);
            log_msg(8, "nd%d: get size request - has %d blks",
                p->np_min, get_minor_size(p->np_min));
        } else {
            log_msg(4, "nd%d: get size request failed", p->np_min);
        }
        return (send_packet(nds, p, ND_HDRSZ + bcount, err));
    }

    /* This is normal read request. */
    assert(blkno < GET_SIZE_REQ);
    log_msg(9, "nd%d: read - blkno: %ld, count: %ld",
        p->np_min, blkno, bcount);
    while (bcount > caddr) {
        long size, ccount, resid = bcount - caddr;
        off_t offset = blkno * 512 + caddr;

        ccount = resid > ND_MAXDATA ? ND_MAXDATA : resid;
        size = ND_HDRSZ + ccount;
        p->np_op |= ND_OP_DONE;
        p->np_caddr = htonl(caddr);
        p->np_ccount = htonl(ccount);

        if (err)
            return (send_packet(nds, p, size, err));

        ssize_t rc = pread(get_minor(p->np_min)->fd, &p->np_data,
            (size_t) ccount, offset);
        if (rc != ccount) {
            log_msg(1, "nd%d: unable to read %ld bytes at "
                "%ld. Got %ld, error: %d", p->np_min,
                ccount, offset,
                rc, errno);
            err = errno;
        }
        caddr += ccount;
        /* send reply */
        if (send_packet(nds, p, size, err))
            return (1);
    }
    return (0);
}

/*
 * Write request processing.
 */
static int
serve_write(ndd_t *nds, ndpkt_t *p, int err)
{
    long caddr = ntohl(p->np_caddr);
    long ccount = ntohl(p->np_ccount);
    long blkno = ntohl(p->np_blkno);
    off_t offset = blkno * 512 + caddr;

    log_msg(9, "nd%d: write - blkno: %ld, count: %ld",
        p->np_min, blkno, ccount);
    if (err == 0) {
        ndmin_t *m = get_minor(p->np_min);

        if (pwrite(m->fd, &p->np_data, ccount, offset) != ccount) {
            log_msg(1, "nd%d: unable to write %ld bytes,"
                " offset %lu: %d", p->np_min, ccount, offset,
                errno);
            err = errno;
        }
    }

    /*
     * Send nothing when the client does not wait for the response or
     * the packet was invalid (and hence we pretend that we got none.
     */
    if (!(p->np_op & ND_OP_WAIT) || err == EINVAL)
        return (0);

    /* Prepare and send the reply. */
    prepare_ip_header(p);
    p->np_op = ND_OP_WRITE | ND_OP_DONE | ND_OP_WAIT;
    p->np_caddr = htonl(caddr + ccount);

    return (send_packet(nds, p, sizeof (ndpkt_t) - sizeof (void*), err));
}

/*
 * This the main loop receiving, processing, and sending packets.
 */
int
serve(ndd_t *nds)
{
    ndpkt_t *pkt;
    int rc;

    /*
     * Since we process only packet at time, we need just one
     * preallocated buffer.
     */
    if ((pkt = (ndpkt_t *)malloc(ND_MAXPKT)) == NULL) {
        log_msg(0, "Unable to allocate buffer: %s.",
            strerror(errno));
        return (1);
    }

    do {
        ssize_t pkt_len;
        int op, err;

        /* Get packet from the network */
        pkt_len = recv(nds->sc_fd, (void *)pkt, ND_MAXPKT, 0);
        if (nds->exiting)
            break;

        if (pkt_len == -1) {
            log_msg(0, "Unable to receive packet: %s.",
                strerror(errno));
            break;
        }

        /* Verify just received packet */
        err = verify_pkt(pkt);

        /* ND protocol supports only 2 operations: read and write */
        op = pkt->np_op & ND_OP_CODE;
        if (op == ND_OP_READ) {
            rc = serve_read(nds, pkt, err);
        } else if (op == ND_OP_WRITE) {
            rc = serve_write(nds, pkt, err);
        } else {
            log_msg(1, "Unknown operation %d.", op);
            rc = 1;
        }
    } while (rc == 0 && nds->exiting == 0);

    free(pkt);
    return (rc);
}
