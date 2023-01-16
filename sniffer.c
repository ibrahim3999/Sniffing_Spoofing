#include <stdlib.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>



int main(int argc, char *argv[])
{
  char *device ,errbuf[PCAP_ERRBUF_SIZE];  // Name of device and Error message
    
  pcap_t *handle;  // Packet capture handle

  // Check command line arguments
  if (argc != 2)
  {
    fprintf(stderr, "Usage: %s device\n", argv[0]);
    return 1;
  }

  // Get device name from command line arguments
  device = argv[1];

  // Open device for packet capture
  handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL)
  {
    fprintf(stderr, "Could not open device %s: %s\n", device, errbuf);
    return 1;
  }
//if program doesnt support link layer... throws exception
if (pcap_datalink(handle) != DLT_EN10MB) {
	fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", device);
	return(2);
}


  // Set up a packet capture filter
  struct bpf_program filter;
  char filter_exp[] = "tcp";  // Capture only TCP packets
  if (pcap_compile(handle, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1)
  {
    fprintf(stderr, "Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    return 1;
  }
  if (pcap_setfilter(handle, &filter) == -1)
  {
    fprintf(stderr, "Could not install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    return 1;
  }


//////////////////////the actual sniffing///////////////////
//print to file the packets captured
FILE *f = fopen("313357196.txt", "w");
if (f == NULL)
{
    printf("Error opening file!\n");
    exit(1);
}




int count =0;
  // Loop, capturing and processing packets
  while (1)
  {
    struct pcap_pkthdr *header;  // Packet (unsigned long)
    const u_char *packet;  // Packet data

    // Capture a packet
    int result = pcap_next_ex(handle, &header, &packet);
    if (result == 0) continue;  // Timeout expired, continue loop
    if (result == -1 || result == -2) break;  // Error, break loop

        
        if (packet[12]==8&&packet[13]==0){ //Checking if its IPv4 packet
            fprintf(f, "{source_ip: %d %d %d %d,dest_ip: %d %d %d %d,source_port: %d ,dest_port: %d,timestamp: %ld,total_length: %d} \n",
             packet[26], packet[27], packet[28], packet[29],packet[30], packet[31], packet[32], packet[33],
             (packet[34] << 8) | packet[35],(packet[36] << 8) | packet[37],(unsigned long)header->ts.tv_sec,header->len);
             
             printf("{source_ip: %d %d %d %d,dest_ip: %d %d %d %d,source_port: %d,dest_port: %d,timestamp: %ld,total_length: %d} \n",
             packet[26], packet[27], packet[28], packet[29],packet[30], packet[31], packet[32], packet[33],
             (packet[34] << 8) | packet[35],(packet[36] << 8) | packet[37],(unsigned long)header->ts.tv_sec,header->len);
             if((packet[47]&0x04)==0x04){
            printf("cache flag is set\n");
            }
            else{
                printf("cache flag is not set\n");
            }

           /////////////////////////
           
            if ((packet[39] & 0x20) == 0x20) {
            printf("Type flag is set1111111111111111111111111111111111\n");
            } else {
                printf("Type flag is not set\n");
            }
           
           if (packet[12]==8&&packet[13]==0) { //Checking if it's an IPv4 packet
            int ip_header_length = (packet[14] & 0x0F) * 4; // Extract the IP (unsigned long) length
            int tcp_offset = ip_header_length + 12; // Extract the offset of the TCP (unsigned long)
            int status_code = packet[tcp_offset + 13]; // Extract the status code
            printf("status code: %d\n", status_code);
            
           }

          
          /*
          if (packet[12]==8&&packet[13]==0) { //Checking if it's an IPv4 packet
          int ip_header_length = (packet[14] & 0x0F) * 4; // Extract the IP (unsigned long) length
          int tcp_offset = ip_header_length + 12; // Extract the offset of the TCP (unsigned long)
          int status_code = packet[tcp_offset + 13]; // Extract the status code
          printf("status code: %d\n", status_code);
          
          */

        //printf("source_ip: %02X %02X %02X %02X\n", packet[26], packet[27], packet[28], packet[29]);
        //printf("dest_ip: %02X %02X %02X %02X\n", packet[30], packet[31], packet[32], packet[33]);
        /*if(packet[23]==6) {  //Checking if its TCP
          //printf("source_port: %02X %02X\n", packet[34], packet[35]);
          //printf("dest_port: %02X %02X\n", packet[36], packet[37]);
          //printf("timestamp: %02X\n", (unsigned int)(unsigned long)->ts.tv_sec);
          //printf("total_length: %02X\n",(unsigned long)->len);


        }
        */
        printf("###########################\n");
        
    }
        count++;
        if(count==10){
            break;
        }
  }
    fclose(f);
  // Close the packet capture handle
  pcap_close(handle);

  return 0;
}
