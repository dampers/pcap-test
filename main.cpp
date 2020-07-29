#include <pcap.h>
#include <stdio.h>

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        printf("syntax: pcap-test <interface>\n");
    	printf("sample: pcap-test wlan0\n");
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr)
    {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true)
    {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        printf("%u bytes captured\n", header->caplen);
	
	//printf("%04x\n", ((u_int16_t)packet[12]<<8)|packet[13]);
	if(packet[12] == 0x08 && packet[13] == 0x00 && packet[23]==0x06)
	{
		//printf("Total len = %d\n", header->len);
		printf("---------------------------------------------------\n");
		/* MAC */
		printf("Destination: %02x:%02x:%02x:%02x:%02x:%02x\n", packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
		printf("Source: %02x:%02x:%02x:%02x:%02x:%02x\n\n", packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);


		/* IP */
		printf("sender: %d.%d.%d.%d\n", packet[26], packet[27], packet[28], packet[29]);
		printf("Destination: %d.%d.%d.%d\n\n", packet[30], packet[31], packet[32], packet[33]);

		u_int8_t iphlen = (packet[14] & 0x0F) << 2;
		/* PORT */
		printf("Source Port: %d\n", (packet[14+iphlen]<<8)|packet[15+iphlen]);
		printf("Destination Port: %d\n\n", (packet[16+iphlen]<<8)|packet[17+iphlen]);

		/* Payload  */
		u_int8_t tcphlen = packet[26+iphlen] >> 2;//14+iphlen+12
		u_int32_t start = 14+iphlen+tcphlen;
		u_int32_t paylen = (header->len)-start>16?start+16:(header->len);

		//printf("iphlen = %d\n", iphlen);
		//printf("tcphlen = %d\n", tcphlen);
		//printf("start = %d\npaylen = %d\n", start, paylen);
		for(u_int32_t i=start;i<paylen;i++)
			printf("%02x ", packet[i]);
		printf("\n\n");
		printf("---------------------------------------------------\n");

	}	
    }

    pcap_close(handle);
    return 0;
}
