#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include <pcap.h>
#include <libnet.h>

#include "mydiag.h"
#include "reflector.h"

#define DEBUG

/*
 * GLOBALS
 */
char *device = NULL; /* The device to sniff on */
pcap_t *handle; /* Session handle */
u_int8_t victim_eth_addr[ETHER_ADDR_LEN]; /* Ethernet address of the victim */ 
u_int8_t relayer_eth_addr[ETHER_ADDR_LEN]; /* Ethernet address of the relayer */
u_int32_t victim_ip_addr; /* IP address of the victim, in net byte order */
u_int32_t relayer_ip_addr; /* IP address of the relayer, in net byte order */

void usage() 
{
  fprintf(stderr, "reflector --victim-ip <IP address> [--victim-ethernet <Ethernet address>] --relayer-ip <IP address> [--relayer-ethernet <Ethernet address>] [--interface <device>] [--netmask <netmask>]\n");
}

void process_packet(u_char *user_data, 
		    const struct pcap_pkthdr *header, 
		    const u_char *packet)
{
  struct ethernet_header *eth_h = NULL;
  const u_char *eth_p = NULL;
  struct arp_header *arp_h = NULL;
  struct arp_payload *arp_p = NULL;
  struct ip_header *ip_h = NULL, *ip_h2 = NULL;
  const u_char *ip_p = NULL;
  struct icmp_header *icmp_h = NULL;
  u_int8_t *icmp_p = NULL;
  u_int16_t icmp_p_length = 0;
  struct udp_header *udp_h = NULL;
  u_int8_t *udp_p = NULL;
  u_int16_t udp_p_length = 0;
#ifdef CUT
  u_int8_t *tmp = NULL;
  u_int16_t udp_h_length = 0;
#endif

  struct tcp_header *tcp_h = NULL;
  u_int8_t *tcp_options = NULL;
  u_int8_t *tcp_p = NULL;
  u_int16_t tcp_p_length = 0;

  libnet_t *context;
  char errbuf[LIBNET_ERRBUF_SIZE];
  libnet_ptag_t t;
  int res;

  u_int32_t arp_reply_ip_addr;
  u_int8_t *arp_reply_eth_addr;
  u_int32_t ip_reply_ip_addr;
  u_int8_t *ip_reply_eth_addr;

#ifdef DEBUG
  my_debug(__FILE__, __LINE__, "DMP: %lu.%lu len is %d of %d bytes", 
	   header->ts.tv_sec, 
	   header->ts.tv_usec, 
	   header->caplen, 
	   header->len);
#endif

  /* Parses Ethernet header */
  eth_h = (struct ethernet_header *)packet;
  eth_p = packet + sizeof(struct ethernet_header);

#ifdef DEBUG
  my_debug(__FILE__, __LINE__, "ETH: %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x 0x%04x",
	   eth_h->ether_shost[0], 
	   eth_h->ether_shost[1], 
	   eth_h->ether_shost[2], 
	   eth_h->ether_shost[3], 
	   eth_h->ether_shost[4], 
	   eth_h->ether_shost[5], 
	   eth_h->ether_dhost[0], 
	   eth_h->ether_dhost[1], 
	   eth_h->ether_dhost[2], 
	   eth_h->ether_dhost[3], 
	   eth_h->ether_dhost[4], 
	   eth_h->ether_dhost[5], 
	   ntohs(eth_h->ether_type));
#endif  

  switch (ntohs(eth_h->ether_type)) {
  case ETHERTYPE_ARP:
    /* Parses ARP header */
    arp_h = (struct arp_header *)eth_p;

    /* Performs sanity check */
    if ((ntohs(arp_h->hardware) != 0x0001) || /* Checks if Ether to IP */ 
	(ntohs(arp_h->protocol) != 0x0800) ||
	(arp_h->hardware_length != 6) ||
	(arp_h->protocol_length != 4) ||
	(ntohs(arp_h->operation) != 0x0001) || /* Checks if request */
	(eth_h->ether_dhost[0] != 0xFF) || /* Checks if broadcast */
	(eth_h->ether_dhost[1] != 0xFF) ||
	(eth_h->ether_dhost[2] != 0XFF) ||
	(eth_h->ether_dhost[3] != 0xFF) || 
	(eth_h->ether_dhost[4] != 0xFF) || 
	(eth_h->ether_dhost[5] != 0xFF))
      {
	return;
      }
    arp_p = (struct arp_payload *)(eth_p + sizeof(struct arp_header));

#ifdef DEBUG
    my_debug(__FILE__, __LINE__, "ARP: h: %04x p: %04x hl: %02x pl: %02x op: %04x sha: %02x:%02x:%02x:%02x:%02x:%02x spa: %d.%d.%d.%d tha: %02x:%02x:%02x:%02x:%02x:%02x tpa: %d.%d.%d.%d",
	     htons(arp_h->hardware), 
	     htons(arp_h->protocol),
	     arp_h->hardware_length,
	     arp_h->protocol_length,
	     htons(arp_h->operation),
	     arp_p->sha[0],
	     arp_p->sha[1],
	     arp_p->sha[2],
	     arp_p->sha[3],
	     arp_p->sha[4],
	     arp_p->sha[5],
	     arp_p->spa[0],
	     arp_p->spa[1],
	     arp_p->spa[2],
	     arp_p->spa[3],
	     arp_p->tha[0],
	     arp_p->tha[1],
	     arp_p->tha[2],
	     arp_p->tha[3],
	     arp_p->tha[4],
	     arp_p->tha[5],
	     arp_p->tpa[0],
	     arp_p->tpa[1],
	     arp_p->tpa[2],
	     arp_p->tpa[3]);
#endif


    if (*((u_int32_t *)(&(arp_p->tpa))) == victim_ip_addr)
      {
#ifdef DEBUG
	my_debug(__FILE__, __LINE__, "ARP request for victim's address");
#endif
	arp_reply_ip_addr = victim_ip_addr;
	arp_reply_eth_addr = victim_eth_addr;
      }
    else if (*((u_int32_t *)(&(arp_p->tpa))) == relayer_ip_addr)
      {
#ifdef DEBUG
	my_debug(__FILE__, __LINE__, "ARP request for relayer's address");
#endif
	arp_reply_ip_addr = relayer_ip_addr;
	arp_reply_eth_addr = relayer_eth_addr;
      }
    else
      {
	return;
      }

    /* Initializes the libnet context */
    context = libnet_init(LIBNET_LINK, device, errbuf);

    if (context == NULL)
    {
      my_error(__FILE__, __LINE__, "cannot initialize packet generation routines: %s", errbuf);
      exit(ERR_LIBNET);
    }

    t = libnet_build_arp(ARPHDR_ETHER, /* Hardware address */
			 ETHERTYPE_IP, /* Protocol address */
			 6, /* Hardware size */
			 4, /* Protocol size */
			 ARPOP_REPLY, /* Operation */
			 arp_reply_eth_addr, /* Sender hardware addr */
			 (u_int8_t *)&arp_reply_ip_addr,  /* Sender protocol addr */
			 eth_h->ether_shost, /* Target hardware addr */
			 (u_int8_t*)&(arp_p->spa),  /* Target protocol addr */
			 NULL, /* Payload */
			 0, /* Payload size */
			 context, /* Libnet context */
			 0); /* Protocol tag */ 
    if (t == -1)
      {
        my_error(__FILE__, __LINE__, "Can't build ARP header: %s", 
		 libnet_geterror(context));
        exit(ERR_LIBNET);
      }

    t = libnet_build_ethernet(
            eth_h->ether_shost, /* Ethernet destination */
	    arp_reply_eth_addr, /* Ethernet source */
            ETHERTYPE_ARP, /* Protocol type */
	    NULL, /* Payload */
	    0, /* Payload size */
            context, /* Libnet context */
	    0); /* Protocol tag */
    if (t == -1)
    {
      my_error(__FILE__, __LINE__, "Can't build ethernet header: %s",
	       libnet_geterror(context));
      exit(ERR_LIBNET);
    }

    res = libnet_write(context);

    if (res == -1)
    {
      my_error(__FILE__, __LINE__, "Libnet write error: %s", 
	       libnet_geterror(context));
      exit(ERR_LIBNET);
    }

#ifdef DEBUG
    my_debug(__FILE__, __LINE__, "ARP packet sent");
#endif
    libnet_destroy(context);

    break;
  case ETHERTYPE_IP:
    /* Parses IP header */
    ip_h = (struct ip_header *)eth_p;

#ifdef DEBUG
    my_debug(__FILE__, __LINE__, "IP: v: %d hl: %d tos: %0x len: %d id: %d off: %04x ttl: %d proto: %02x sum: %02x src: %d.%d.%d.%d dst: %d.%d.%d.%d",
	     ip_h->v,
	     ip_h->hl,
	     ip_h->tos,
	     ntohs(ip_h->len),
	     ntohs(ip_h->id),
	     ntohs(ip_h->off),
	     ip_h->ttl,
	     ip_h->p,
	     ntohs(ip_h->sum),
	     ip_h->src[0],
	     ip_h->src[1],
	     ip_h->src[2],
	     ip_h->src[3],
	     ip_h->dst[0],
	     ip_h->dst[1],
	     ip_h->dst[2],
	     ip_h->dst[3]);
#endif
    /* Verifies if the datagram is a fragment */

    if (ntohs(ip_h->off) & 0x3FFF)
      {
	my_error(__FILE__, __LINE__, "Fragmentation not supported!");
	return;
      }

    /* Verifies that source and destination are not victim AND relayer's */
    if (((*((u_int32_t *)(&(ip_h->dst))) == victim_ip_addr) ||
	 (*((u_int32_t *)(&(ip_h->dst))) == relayer_ip_addr)) &&
	((*((u_int32_t *)(&(ip_h->src))) == relayer_ip_addr) ||
	 (*((u_int32_t *)(&(ip_h->src))) == victim_ip_addr)))
      {
	my_error(__FILE__, __LINE__, "Detected victim/relayer loop!");
	return;
      }
	
    /* Checks if destination is relayer or victim */
    if (*((u_int32_t *)(&(ip_h->dst))) == victim_ip_addr)
      {
#ifdef DEBUG
	my_debug(__FILE__, __LINE__, "IP datagram for victim's address");
#endif
	ip_reply_ip_addr = relayer_ip_addr;
	ip_reply_eth_addr = relayer_eth_addr;
      }
    else if (*((u_int32_t *)(&(ip_h->dst))) == relayer_ip_addr)
      {
#ifdef DEBUG
	my_debug(__FILE__, __LINE__, "IP datagram for relayer's address");
#endif
	ip_reply_ip_addr = victim_ip_addr;
	ip_reply_eth_addr = victim_eth_addr;
      }
    else
      {
	return;
      }
    ip_p = eth_p + (ip_h->hl * 4);

    switch (ip_h->p) {
    case IPPROTO_ICMP:
      /* Parses ICMP header */
      icmp_h = (struct icmp_header *)ip_p;

#ifdef DEBUG
      my_debug(__FILE__, __LINE__, "ICMP: type: %02x code: %02x sum: %04x",
	       icmp_h->type,
	       icmp_h->code,
	       ntohs(icmp_h->checksum));
#endif
      switch (icmp_h->type) {
      case ICMP_ECHO:
      case ICMP_ECHOREPLY:
	icmp_p_length = ntohs(ip_h->len) - (ip_h->hl * 4) - 
	  sizeof(struct icmp_header);
	if (icmp_p_length <= 0)
	  {
	    icmp_p = NULL;
	  }
	else
	  {
	    icmp_p = ((u_int8_t *)icmp_h) + sizeof(struct icmp_header);
	  }
#ifdef DEBUG
	my_debug(__FILE__, __LINE__, "ICMP ECHO: id: %04x sequence: %04x payload: %d",
		 ntohs(icmp_h->un.echo.id),
		 ntohs(icmp_h->un.echo.sequence),
		 icmp_p_length);
#endif

	/* Initializes the libnet context */
	context = libnet_init(LIBNET_LINK, device, errbuf);

	if (context == NULL)
	  {
	    my_error(__FILE__, __LINE__, "cannot initialize packet generation routines: %s", errbuf);
	    exit(ERR_LIBNET);
	  }
	t = libnet_build_icmpv4_echo(icmp_h->type,
				     0, /* Code */
				     0, /* Sum */
				     htons(icmp_h->un.echo.id),
				     htons(icmp_h->un.echo.sequence),
				     icmp_p,
				     icmp_p_length,
				     context,
				     0);
	if (t == -1)
	  {
	    my_error(__FILE__, __LINE__, "Can't build icmp header: %s",
		     libnet_geterror(context));
	    exit(ERR_LIBNET);
	  }

	t = libnet_build_ipv4(htons(ip_h->len),
			      ip_h->tos,
			      htons(ip_h->id),
			      htons(ip_h->off),
			      ip_h->ttl,
			      ip_h->p,
			      0, /* Checksum */
			      ip_reply_ip_addr,
			      *((u_int32_t*)ip_h->src),
			      NULL, /* Payload */
			      0, /* Payload length */
			      context,
			      0);
	if (t == -1)
	  {
	    my_error(__FILE__, __LINE__, "Can't build ip header: %s",
		     libnet_geterror(context));
	    exit(ERR_LIBNET);
	  }

	t = libnet_build_ethernet(eth_h->ether_shost, /* Ethernet destination */
	    ip_reply_eth_addr, /* Ethernet source */
            ETHERTYPE_IP, /* Protocol type */
	    NULL, /* Payload */
	    0, /* Payload size */
            context, /* Libnet context */
	    0); /* Protocol tag */
	if (t == -1)
	  {
	    my_error(__FILE__, __LINE__, "Can't build ethernet header: %s",
		     libnet_geterror(context));
	    exit(ERR_LIBNET);
	  }

	res = libnet_write(context);

	if (res == -1)
	  {
	    my_error(__FILE__, __LINE__, "Libnet write error: %s", 
		     libnet_geterror(context));
	    exit(ERR_LIBNET);
	  }
	
#ifdef DEBUG
	my_debug(__FILE__, __LINE__, "ICMP packet sent");
#endif
	libnet_destroy(context);

	break;
      case ICMP_DEST_UNREACH:
	icmp_p_length = ntohs(ip_h->len) - (ip_h->hl * 4) - 
	  sizeof(struct icmp_header);

	if (icmp_p_length <=0)
	  {
	    icmp_p_length = 0;
	    icmp_p = NULL;
	  }
	else
	  {
	    icmp_p = ((u_int8_t *)icmp_h) + sizeof(struct icmp_header);
	  }
#ifdef DEBUG
	my_debug(__FILE__, __LINE__, "ICMP UNREACH:  payload: %d",
		 icmp_p_length);
#endif

	/* Initializes the libnet context */
	context = libnet_init(LIBNET_LINK, device, errbuf);

	if (context == NULL)
	  {
	    my_error(__FILE__, __LINE__, "cannot initialize packet generation routines: %s", errbuf);
	    exit(ERR_LIBNET);
	  }

	if (icmp_p != NULL)
	  {
	    ip_h2 = (struct ip_header *)icmp_p;
	    if (memcmp(&ip_h2->src, &relayer_ip_addr, 4) == 0)
	      {
		memcpy(ip_h2->src, ip_h2->dst, 4);
		memcpy(ip_h2->dst, &victim_ip_addr, 4);

		libnet_do_checksum(context, icmp_p, 0, 1); 
	      }
	    else if (memcmp(&ip_h2->src, &victim_ip_addr, 4) == 0)
	      {
		memcpy(ip_h2->src, ip_h2->dst, 4);
		memcpy(ip_h2->dst, &relayer_ip_addr, 4);

		libnet_do_checksum(context, icmp_p, 0, 1); 
	      }

	  }
	t = libnet_build_icmpv4_unreach(icmp_h->type,
					icmp_h->code, /* Code */
					0, /* Sum */
					icmp_p,
					icmp_p_length,
					context,
					0);
	if (t == -1)
	  {
	    my_error(__FILE__, __LINE__, "Can't build icmp header: %s",
		     libnet_geterror(context));
	    exit(ERR_LIBNET);
	  }

	t = libnet_build_ipv4(htons(ip_h->len),
			      ip_h->tos,
			      htons(ip_h->id),
			      htons(ip_h->off),
			      ip_h->ttl,
			      ip_h->p,
			      0, /* Checksum */
			      ip_reply_ip_addr,
			      *((u_int32_t*)ip_h->src),
			      NULL, /* Payload */
			      0, /* Payload length */
			      context,
			      0);
	if (t == -1)
	  {
	    my_error(__FILE__, __LINE__, "Can't build ip header: %s",
		     libnet_geterror(context));
	    exit(ERR_LIBNET);
	  }

	t = libnet_build_ethernet(eth_h->ether_shost, /* Ethernet destination */
	    ip_reply_eth_addr, /* Ethernet source */
            ETHERTYPE_IP, /* Protocol type */
	    NULL, /* Payload */
	    0, /* Payload size */
            context, /* Libnet context */
	    0); /* Protocol tag */
	if (t == -1)
	  {
	    my_error(__FILE__, __LINE__, "Can't build ethernet header: %s",
		     libnet_geterror(context));
	    exit(ERR_LIBNET);
	  }

	res = libnet_write(context);

	if (res == -1)
	  {
	    my_error(__FILE__, __LINE__, "Libnet write error: %s", 
		     libnet_geterror(context));
	    exit(ERR_LIBNET);
	  }
	
#ifdef DEBUG
	my_debug(__FILE__, __LINE__, "ICMP packet sent");
#endif
	libnet_destroy(context);
	break;
      }
      break;
    case IPPROTO_UDP:
      /* Parses UDP header */
      udp_h = (struct udp_header *)ip_p;
      udp_p_length = ntohs(ip_h->len) - (ip_h->hl * 4) - 
	sizeof(struct udp_header);

      if (udp_p_length <= 0)
	{
	  udp_p = NULL;
	}
      else
	{
	  udp_p = ((u_int8_t *)ip_p) + sizeof(struct udp_header);
	}
#ifdef DEBUG
      my_debug(__FILE__, __LINE__, "UDP: src: %d dst: %d len: %d sum: %04x clen: %d",
	       ntohs(udp_h->src),
	       ntohs(udp_h->dst),
	       ntohs(udp_h->length),
	       ntohs(udp_h->checksum),
	       udp_p_length);
#endif
      /* Initializes the libnet context */
      context = libnet_init(LIBNET_LINK, device, errbuf);

      if (context == NULL)
	{
	  my_error(__FILE__, __LINE__, "cannot initialize packet generation routines: %s", errbuf);
	  exit(ERR_LIBNET);
	}

      t = libnet_build_udp(htons(udp_h->src),
			   htons(udp_h->dst),
			   htons(udp_h->length),
			   0, /* Checksum */
			   udp_p,
			   udp_p_length,
			   context,
			   0);

#ifdef CUT
      if (udp_p_length % 2)
	{
	  udp_p_length++;
	  udp_h_length = udp_p_length + sizeof(struct udp_header);
	  tmp = malloc(udp_p_length);
	  assert(tmp);
	  memcpy(tmp, udp_p, udp_p_length - 1);
	  tmp[udp_p_length - 1] = 0x0;
	  udp_p = tmp;
	}
      else
	{
	  udp_h_length = htons(udp_h->length);
	}

      t = libnet_build_udp(htons(udp_h->src),
			   htons(udp_h->dst),
			   udp_h_length,
			   0, /* Checksum */
			   udp_p,
			   udp_p_length,
			   context,
			   0);
#endif

      if (t == -1)
	{
	  my_error(__FILE__, __LINE__, "Can't build udp header: %s",
		   libnet_geterror(context));
	  exit(ERR_LIBNET);
	}

      t = libnet_build_ipv4(htons(ip_h->len),
			    ip_h->tos,
			    htons(ip_h->id),
			    htons(ip_h->off),
			    ip_h->ttl,
			    ip_h->p,
			    0, /* Checksum */
			    ip_reply_ip_addr,
			    *((u_int32_t*)ip_h->src),
			    NULL, /* Payload */
			    0, /* Payload length */
			    context,
			    0);
      if (t == -1)
	{
	  my_error(__FILE__, __LINE__, "Can't build ip header: %s",
		   libnet_geterror(context));
	  exit(ERR_LIBNET);
	}

      t = libnet_build_ethernet(eth_h->ether_shost, /* Ethernet destination */
				ip_reply_eth_addr, /* Ethernet source */
				ETHERTYPE_IP, /* Protocol type */
				NULL, /* Payload */
				0, /* Payload size */
				context, /* Libnet context */
				0); /* Protocol tag */
      if (t == -1)
	{
	  my_error(__FILE__, __LINE__, "Can't build ethernet header: %s",
		   libnet_geterror(context));
	  exit(ERR_LIBNET);
	}
      
      res = libnet_write(context);

      if (res == -1)
	{
	  my_error(__FILE__, __LINE__, "Libnet write error: %s", 
		   libnet_geterror(context));
	  exit(ERR_LIBNET);
	}
      
#ifdef DEBUG
      my_debug(__FILE__, __LINE__, "UDP packet sent");
#endif
      libnet_destroy(context);
      
      break;
    case IPPROTO_TCP:
      /* Parses TCP header */
      tcp_h = (struct tcp_header *)ip_p;

#ifdef DEBUG
      my_debug(__FILE__, __LINE__, "TCP: src: %d dst: %d seq: %08x ack: %08x hl: %d S: %d A: %d F: %d R: %d P: %d U: %d win: %d sum: %04x urg: %04x",
	       ntohs(tcp_h->src),
	       ntohs(tcp_h->dst),
	       ntohl(tcp_h->seqn),
	       ntohl(tcp_h->ackn),
	       tcp_h->len,
	       (tcp_h->flags & TH_SYN) ? 1 : 0,
	       (tcp_h->flags & TH_ACK) ? 1 : 0,
	       (tcp_h->flags & TH_FIN) ? 1 : 0,
	       (tcp_h->flags & TH_RST) ? 1 : 0,
	       (tcp_h->flags & TH_PSH) ? 1 : 0,
	       (tcp_h->flags & TH_URG) ? 1 : 0,
	       ntohs(tcp_h->window),
	       ntohs(tcp_h->checksum),
	       ntohs(tcp_h->urgent_ptr));
#endif
      tcp_p_length = ntohs(ip_h->len) - (ip_h->hl * 4) - (tcp_h->len * 4);
      if (tcp_p_length <= 0)
	{
	  tcp_p = NULL;
	}
      else
	{
	  tcp_p = ((u_int8_t *)ip_p) + (tcp_h->len * 4);
	}
      
      /* Initializes the libnet context */
      context = libnet_init(LIBNET_LINK, device, errbuf);

      if (context == NULL)
	{
	  my_error(__FILE__, __LINE__, "cannot initialize packet generation routines: %s", errbuf);
	  exit(ERR_LIBNET);
	}

      /* Checks if TCP contains options */
      if (tcp_h->len > 5) 
	{
	  tcp_options = ((u_int8_t *)ip_p) + 20;
	  t = libnet_build_tcp_options(tcp_options,
				       (tcp_h->len * 4) - 20,
				       context,
				       0);
	  if (t == -1)
	    {
	      my_error(__FILE__, __LINE__, "Can't build tcp options: %s",
		       libnet_geterror(context));
	      exit(ERR_LIBNET);
	    }
	}

      t = libnet_build_tcp(htons(tcp_h->src),
			   htons(tcp_h->dst),
			   htonl(tcp_h->seqn),
			   htonl(tcp_h->ackn),
			   tcp_h->flags,
			   htons(tcp_h->window),
			   0, /* Checksum */
			   htons(tcp_h->urgent_ptr),
			   (tcp_h->len * 4) + tcp_p_length,
			   tcp_p,
			   tcp_p_length, 
			   context,
			   0);
      if (t == -1)
	{
	  my_error(__FILE__, __LINE__, "Can't build tcp header: %s",
		   libnet_geterror(context));
	  exit(ERR_LIBNET);
	}

      t = libnet_build_ipv4(htons(ip_h->len),
			    ip_h->tos,
			    htons(ip_h->id),
			    htons(ip_h->off),
			    ip_h->ttl,
			    ip_h->p,
			    0, /* Checksum */
			    ip_reply_ip_addr,
			    *((u_int32_t*)ip_h->src),
			    NULL, /* Payload */
			    0, /* Payload length */
			    context,
			    0);
      if (t == -1)
	{
	  my_error(__FILE__, __LINE__, "Can't build ip header: %s",
		   libnet_geterror(context));
	  exit(ERR_LIBNET);
	}

      t = libnet_build_ethernet(eth_h->ether_shost, /* Ethernet destination */
				ip_reply_eth_addr, /* Ethernet source */
				ETHERTYPE_IP, /* Protocol type */
				NULL, /* Payload */
				0, /* Payload size */
				context, /* Libnet context */
				0); /* Protocol tag */
      if (t == -1)
	{
	  my_error(__FILE__, __LINE__, "Can't build ethernet header: %s",
		   libnet_geterror(context));
	  exit(ERR_LIBNET);
	}
      
      res = libnet_write(context);

      if (res == -1)
	{
	  my_error(__FILE__, __LINE__, "Libnet write error: %s", 
		   libnet_geterror(context));
	  exit(ERR_LIBNET);
	}
      
#ifdef DEBUG
      my_debug(__FILE__, __LINE__, "TCP packet sent");
#endif
      libnet_destroy(context);
      

      break;
    }
    break;
  }
  return;
}


char *random_eth() 
{
  char eth_str[32];
  sprintf(eth_str, "00:16:%02x:%02x:%02x:%02x", 
	  abs(random() % 254),
	  abs(random() % 254),
	  abs(random() % 254),
	  abs(random() % 254));
  return strdup(eth_str);
}


int main(int argc, char *argv[])
{
  char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
  struct bpf_program filter; /* The compiled filter */
  char *filter_expr = NULL; /* The filter expression */
  int i; 
  char *victim_ip_str = NULL;
  char *victim_eth_str = NULL;
  char *relayer_ip_str = NULL;
  char *relayer_eth_str = NULL;
  char *netmask_str = NULL;
  u_int32_t netmask_addr;  /* Netmask */
  struct timeval tp;

  if (gettimeofday(&tp, NULL) != 0) {
        my_error(__FILE__, __LINE__, "gettimeofday failed");
  }
	
  srandom(tp.tv_sec);

  /* Parses the command line */
  i = 1;
  while (i < argc)
    {
      if (!strcmp(argv[i], "--victim-ip"))
	{
	  i++;
	  if (argv[i] == NULL) { 
	    my_error(__FILE__, __LINE__, 
		     "missing argument of parameter %s", argv[i - 1]);
	    usage();
	    exit(ERR_WRONG_PARAMS);
	  }
	  
	  victim_ip_str = argv[i];
	}
      else if (!strcmp(argv[i], "--victim-ethernet"))
	{
	  i++;
	  if (argv[i] == NULL) { 
	    my_error(__FILE__, __LINE__, 
		     "missing argument of parameter %s", argv[i - 1]);
	    usage();
	    exit(ERR_WRONG_PARAMS);
	  }
	  
	  victim_eth_str = argv[i];
	}
      else if (!strcmp(argv[i], "--relayer-ip"))
	{
	  i++;
	  if (argv[i] == NULL) { 
	    my_error(__FILE__, __LINE__, 
		     "missing argument of parameter %s", argv[i - 1]);
	    usage();
	    exit(ERR_WRONG_PARAMS);
	  }
	  
	  relayer_ip_str = argv[i];
	}
      else if (!strcmp(argv[i], "--relayer-ethernet"))
	{
	  i++;
	  if (argv[i] == NULL) { 
	    my_error(__FILE__, __LINE__, 
		     "missing argument of parameter %s", argv[i - 1]);
	    usage();
	    exit(ERR_WRONG_PARAMS);
	  }
	  
	  relayer_eth_str = argv[i];
	}
      else if (!strcmp(argv[i], "--interface"))
	{
	  i++;
	  if (argv[i] == NULL) { 
	    my_error(__FILE__, __LINE__, 
		     "missing argument of parameter %s", argv[i - 1]);
	    usage();
	    exit(ERR_WRONG_PARAMS);
	  }
	  
	  device = argv[i];
	}
      else if (!strcmp(argv[i], "--netmask"))
	{
	  i++;
	  if (argv[i] == NULL) { 
	    my_error(__FILE__, __LINE__, 
		     "missing argument of parameter %s", argv[i - 1]);
	    usage();
	    exit(ERR_WRONG_PARAMS);
	  }
	  
	  netmask_str = argv[i];
	}
      else
	{
	  my_error(__FILE__, __LINE__, 
		    "unknown parameter %s", argv[i]);
	  usage();
	  exit(ERR_WRONG_PARAMS);
	}
      i++;
    }

  /* Checks the mandatory parameters */
  if ((victim_ip_str == NULL) || (relayer_ip_str == NULL))
    {
      my_error(__FILE__, __LINE__, "missing IP address(es)");
      usage();
      exit(ERR_SETUP);
    }

  if (victim_eth_str == NULL) {
    victim_eth_str = random_eth(); 
  }
  if (relayer_eth_str == NULL) {
    relayer_eth_str = random_eth();
  }

  victim_ip_addr = (u_int32_t)inet_addr(victim_ip_str);
  relayer_ip_addr = (u_int32_t)inet_addr(relayer_ip_str);
  memcpy((void *)victim_eth_addr,  (void *)ether_aton(victim_eth_str), ETHER_ADDR_LEN);
  memcpy((void *)relayer_eth_addr, (void *)ether_aton(relayer_eth_str), ETHER_ADDR_LEN);
  
  if ((victim_ip_addr == 0) || (relayer_ip_addr == 0) ||
      (victim_eth_addr == NULL) || (relayer_eth_addr == NULL)) 
    {
      my_error(__FILE__, __LINE__, "cannot parse IP and/or Ethernet parameters");
      usage();
      exit(ERR_SETUP);
    }

#ifdef DEBUG 
  my_debug(__FILE__, __LINE__, "using victim %02x:%02x:%02x:%02x:%02x:%02x/%d.%d.%d.%d and relayer %02x:%02x:%02x:%02x:%02x:%02x/%d.%d.%d.%d",
	   victim_eth_addr[0],
	   victim_eth_addr[1],
	   victim_eth_addr[2],
	   victim_eth_addr[3],
	   victim_eth_addr[4],
	   victim_eth_addr[5],
	   ((u_int8_t *)&victim_ip_addr)[0],
	   ((u_int8_t *)&victim_ip_addr)[1],
	   ((u_int8_t *)&victim_ip_addr)[2],
	   ((u_int8_t *)&victim_ip_addr)[3],
	   relayer_eth_addr[0],
	   relayer_eth_addr[1],
	   relayer_eth_addr[2],
	   relayer_eth_addr[3],
	   relayer_eth_addr[4],
	   relayer_eth_addr[5],
	   ((u_int8_t *)&relayer_ip_addr)[0],
	   ((u_int8_t *)&relayer_ip_addr)[1],
	   ((u_int8_t *)&relayer_ip_addr)[2],
	   ((u_int8_t *)&relayer_ip_addr)[3]);
#endif

  /* Checks the optional parameters */
  if (netmask_str == NULL)
    {
      netmask_str = DEFAULT_NETMASK;
    }

  netmask_addr = (u_int32_t)htonl(inet_addr(netmask_str));

#ifdef DEBUG
  my_debug(__FILE__, __LINE__, "using netmask %d.%d.%d.%d", 
	   (netmask_addr >> 24) & 0xFF,
	   (netmask_addr >> 16) & 0xFF,
	   (netmask_addr >> 8) & 0xFF,
	   (netmask_addr >> 0) & 0xFF);
#endif
 
  /* Defines the device */
  if (device == NULL)
    {
      device = pcap_lookupdev(errbuf);
      if (device == NULL)
	{
	  my_error(__FILE__, __LINE__, "no network device found: %s", errbuf);
	  exit(ERR_SETUP);
	}
    }

#ifdef DEBUG
  my_debug(__FILE__, __LINE__, "listening on %s", device);
#endif

  /* Opens the session in promiscuous mode */
  handle = pcap_open_live(device, BUFSIZ, 1, 0, errbuf);
  if (handle == NULL)
    {
      my_error(__FILE__, __LINE__, "network device %s cannot be opened: %s", 
	       device, errbuf);
      exit(ERR_SETUP);
    }


  /* Builds the filter */
#ifdef CUT
  filter_expr = (char *) malloc(strlen("ether dst ") + 
				strlen(victim_eth_str) +
				strlen(" or ether dst ") + 
				strlen(victim_eth_str) + 
				strlen(" or ether broadcast") + 1);
  assert(filter_expr);

  sprintf(filter_expr, "ether dst %s or ether dst %s or ether broadcast", 
	  victim_eth_str, relayer_eth_str);
#endif

  filter_expr = (char *) malloc(strlen("host ") + 
				strlen(victim_ip_str) +
				strlen(" or host ") + 
				strlen(relayer_ip_str) + 1);
  assert(filter_expr);

  sprintf(filter_expr, "host %s or host %s", 
	  victim_ip_str, relayer_ip_str);

#ifdef DEBUG
  my_debug(__FILE__, __LINE__, "using filter %s", filter_expr);
#endif  

  /* Compiles and applies the filter */
  if (pcap_compile(handle, &filter, filter_expr, 0, netmask_addr) == -1)
    {
      my_error(__FILE__, __LINE__, "filter '%s' compilation failed", 
	       filter_expr);
      exit(ERR_SETUP);
    }

  if (pcap_setfilter(handle, &filter) == -1)
    {
      my_error(__FILE__, __LINE__, "could not set filter: %s", 
	       filter_expr);
      exit(ERR_SETUP);
    }

  /* Enters the endless loop */
  pcap_loop(handle, -1, process_packet, NULL);

  /* Closes the session -- never reached, really */
  pcap_close(handle);

  return 0;
}
