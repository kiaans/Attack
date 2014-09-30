/******************************************************************************
 *  [ dns hijacker v1.3 ]                                                     *
 *                                                                            *
 *  pedram amini (pedram@redhive.com)                                         *
 *  pedram.redhive.com                                                        *
 *                                                                            *
 ******************************************************************************/

/* includes */
#include <libnet.h>
#include <pcap.h>


/* defines */
#define SNAPLEN     128
#define PROMISC       1
#define TO_MS         0
#define T_A           1                 /* host address        */
#define T_PTR        12                 /* domain name pointer */
#define VERSION  "v1.3"


/* our chewycenter ... holds important information */
struct cc  {
    u_long  src_address;                /* source address               */
    u_long  dst_address;                /* destination address          */
    u_short src_port;                   /* source port                  */
    u_short dst_port;                   /* destination port             */
    u_short dns_id;                     /* dns id                       */
    int     is_a;                       /* are we an A                  */
    int     have_answer;                /* do we have an answer?        */
    int     payload_size;               /* size of our payload          */
    u_char  payload[512];               /* payload storage              */
    char    *default_answer;            /* default answer to use        */
    char    current_question[128];      /* current question being asked */
    char    *current_answer;            /* current answer we are using  */
};


/* our fabrication table entry struct, holds the rule table for spoofing */
struct ft_entry {
    char ip[16],                        /* new ip address to map it to */
         name[128];                     /* dns name to look for        */
};


/* globals */
int    offset,                          /* datalink offset                    */
       dflag = 0,                       /* default answer specified flag      */
       fflag = 0,                       /* fabrication table specified flag   */
       oflag = 0,                       /* output statistics                  */
       pflag = 0,                       /* print only flag                    */
       sflag = 0,                       /* suppress printing of "ignored *"   */
       vflag = 0,                       /* verbose flag                       */
       zflag = 0,                       /* daemonize flag                     */
       num_entries = 0,                 /* number of entries read into ftable */
       num_spoofed_answers = 0;         /* number of spoofed answers          */
struct ft_entry *ftable;                /* fabrication table                  */
struct cc chewycenter;                  /* mmmm, chewycenter                  */


/* function prototypes */
/*void catch_signals (int);*/           /* signal catcher and handler      */
char *copy_argv      (char **argv);     /* taken from tcpdump util.c       */
void fill_table      (char *);          /* fill the frabrication table     */
void parse_dns       (char *, int);     /* parse a packet, build an answer */
char *search_table   (char *);          /* search the fabrication table    */
pcap_t *set_cap_dev  (char *, char *);  /* set capdev up to capture dns    */
void spoof_dns       (int);             /* spoof a dns packet              */
void usage           (char **);         /* print usage (arg: program name) */


/* dns packet header
 *
 *  |--- 1 byte ----|
 *  +---------------|---------------|---------------|---------------+
 *  |            DNS ID             | QR,OP,AA,TC,RD|RA,0,AD,CD,CODE|
 *  |---------------|---------------|---------------|---------------|
 *  |         # Questions           |          # Answers            |
 *  |---------------|---------------|---------------|---------------|
 *  |         # Authority           |          # Resource           |
 *  +---------------|---------------|---------------|---------------+
 *
 */
struct dnshdr   {
    unsigned    id:      16;            /* query identification number     */
    unsigned    rd:       1;            /* recursion desired               */
    unsigned    tc:       1;            /* truncated message               */
    unsigned    aa:       1;            /* authoritative answer            */
    unsigned    opcode:   4;            /* purpose of message              */
    unsigned    qr:       1;            /* response flag                   */
    unsigned    rcode:    4;            /* response code                   */
    unsigned    cd:       1;            /* checking disabled by resolver   */
    unsigned    ad:       1;            /* authentic data from named       */
    unsigned    unused:   1;            /* unused bits (MBZ as of 4.9.3a3) */
    unsigned    ra:       1;            /* recursion available             */
    unsigned    qdcount: 16;            /* number of question entries      */
    unsigned    ancount: 16;            /* number of answer entries        */
    unsigned    nscount: 16;            /* number of authority entries     */
    unsigned    arcount: 16;            /* number of resource entries      */
};

