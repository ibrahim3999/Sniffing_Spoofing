#include <stdlib.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>





int main(int argc, char *argv[])
{
  char device;  / Name of device (e.g. "eth0") */
  char error_buffer[PCAP_ERRBUF_SIZE];  
  pcap_t handle;  / Packet capture handle */

  // Check command line arguments
  if (argc != 2)
  {
    fprintf(stderr, "Usage: %s device\n", argv[0]);
    return 1;
  }

  // Get device name from command line arguments
  device = argv[1];

  // Open device for packet capture
  handle = pcap_open_live(device, BUFSIZ, 1, 1000, error_buffer);
  if (handle == NULL)
  {
    fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
    return 1;
  }

  // Set up a packet capture filter
  struct bpf_program filter;
  char filter_exp[] = "tcp";  /* Capture only TCP packets */
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

  // Loop, capturing and processing packets
  while (1)
  {
    struct pcap_pkthdr header;  /* Packet header */
    const u_char packet;  / Packet data */

    // Capture a packet
    int result = pcap_next_ex(handle, &header, &packet);
    if (result == 0) continue;  /* Timeout expired, continue loop */
    if (result == -1 || result == -2) break;  /* Error, break loop */

    // Processing the packet here
    
  }

  // Close the packet capture handle
  pcap_close(handle);

  return 0;
}