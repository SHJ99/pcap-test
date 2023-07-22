#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#define ETHER_ADDR_LEN 6

void usage() {
   printf("syntax: pcap-test <interface>\n");
   printf("sample: pcap-test wlan0\n");
}

typedef struct {
   char* dev_;
} Param;

void print_mac(u_int8_t *m){
   printf("%02x:%02x:%02x:%02x:%02x:%02x",m[0], m[1],m[2], m[3], m[4], m[5], m[6]);
}

void print_tcp(u_int16_t m){
	printf("%5d", m);
}

void print_ip(struct in_addr m){
	//printf("%u", m);
	char* ip = inet_ntoa(m);
	printf(ip);
}

void ptint_patload(u_char* payload, int size){
	for(int i=0; i<size && i<10; i++)
		printf("%02x ", payload[i]);
}

Param param = {
   .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
   if (argc != 2) {
      usage();
      return false;
   }
   param->dev_ = argv[1];
   return true;
}

int main(int argc, char* argv[]) {
   if (!parse(&param, argc, argv))
      return -1;

   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
   if (pcap == NULL) {
      fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
      return -1;
   }

   while (true) {
      struct pcap_pkthdr* header;
      const u_char* packet;
      int res = pcap_next_ex(pcap, &header, &packet);
      if (res == 0) continue;
      if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
         printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
         break;
      }
      printf("%u bytes captured\n", header->caplen);
      struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr *)packet;
      printf("src mac : ");
      print_mac(eth_hdr->ether_shost);
      printf("\n");
      printf("dst mac : ");
      print_mac(eth_hdr->ether_dhost);
      printf("\n"); 

      struct libnet_ipv4_hdr *ip_hdr = (struct libnet_ipv4_hdr *)(packet+14);
      printf("src ip :");
      print_ip(ip_hdr->ip_src);
      printf("\n");
      printf("dst ip : ");
      print_ip(ip_hdr->ip_dst);
      printf("\n");

      struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr *)(packet+14+ip_hdr->ip_hl*4);
      printf("tcp src port : ");
      print_tcp(tcp_hdr->th_sport);
      printf("\n");
      printf("tcp dst port : ");
      print_tcp(tcp_hdr->th_dport);
      printf("\n");

     

     // int offset = 20;
      u_char* payload =  packet + 14 + tcp_hdr->th_off*4 + ip_hdr->ip_hl*4;
      int size=header->caplen;
      size=size-14-tcp_hdr->th_off*4-ip_hdr->ip_hl*4;
      printf("print payload :  ");
     // printf("ip hdr size : %d", ip_hdr->ip_hl*4);
      ptint_patload(payload, size);
      printf("\n");

     // printf("total packet size : %d\n", header->caplen);
     // printf("total payload size : %d\n", size);
     // printf("ip header size : %d\n", ip_hdr->ip_hl*4);
     // printf("tcp header size : %d\n", tcp_hdr->th_off*4);
   }

   pcap_close(pcap);
}
