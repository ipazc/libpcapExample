/*
 * Course on NGN @ University of León
 * Dept. IESA (Systems and Electrical Eng)
 * (C) 2015, José María Foces Morán
 * 
 * LABS on the pcap capture library
 * ngn-libcap-test2.c
 * v 1.0 9/March/2015
 * 
 * Captures n Ethernet frames (n is provided as first command-line argument) and
 * for each, it prints the header fields
 * 
 * 
 * Modified by Iván de Paz Centeno
 * @email ipazce00@estudiantes.unileon.es 
 * date: 04/04/2016
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pcap.h>

#define MAC_BYTES_SIZE 6
#define BCAST_MASK 0xFF
#define MAX_CHARACTERS_PER_LINE_PRESENTATION 70


enum ETHERTYPES
{
    IPv4 = 0x800,
};


unsigned int frameCount = 0;

/*
 * CRC: Last 4 bytes of frame
 */
void printCRC(u_char *frame) {

    printf("\nCRC: \n");
    fflush(stdout);

}

/*
 * frame bytes ( 12 and 13 )
 * DESTINATION MAC ADDRESS
 */
void printEthertype(u_char *frame) {
    uint16_t *originalEtherType = (uint16_t*)&frame[12];
    uint16_t etherType = ntohs(*originalEtherType);
    
    printf("\nEthertype: 0x%04x", etherType);
    fflush(stdout);

}

/**
 * Returns whether a received frame is an IPv4 packet or not.
 */
int isIPv4(u_char *frame)
{
    uint16_t *originalEtherType = (uint16_t*)&frame[12];
    uint16_t etherType = ntohs(*originalEtherType);
    return etherType == IPv4;
}

/**
 * Determines if a given mac address is a broadcast one or not.
 * 
 * @param macAddress pointer to a mac address 48 bit integer.
 *
 * @returns logical true if is a broadcast address. Logical false otherwise.
 */
int isBroadcast(u_char *macAddress)
{
    int i;
    int result = 1;
    
    for (i=0; i<MAC_BYTES_SIZE; i++)
        result = result && (macAddress[i] & BCAST_MASK == BCAST_MASK);
    
    return result;
}

/**
 * Prints the especified mac address as a string.
 * 
 * @param macAddress pointer to a mac address 48 bit integer.
 */
void printMac(u_char *macAddress)
{
    int i;
    
    for (i = 0; i < MAC_BYTES_SIZE; i++) {
        if (i)
            printf(":"); 
        
        printf("%02x", macAddress[i]);
    }  
}

/**
 * Prints the payload of the given packet in hexadecimal format.
 * 
 * @param payload   pointer to the payload.
 * @param payloadSize   size in bytes of the payload.
 * 
 */
void printPayload(u_char *payload, size_t payloadSize)
{
   int i;   
   int lineFeedNeeded;
   
   for (i=0; i<payloadSize; i++)
   {
       lineFeedNeeded = (i*2) % MAX_CHARACTERS_PER_LINE_PRESENTATION == 0;
       
        if (lineFeedNeeded)
            printf("\n\t");
        
        printf("%02x ", payload[i]);       
   }
   
   printf("\n");
}

/*
 * Print the MAC addresses
 */
void printMacsFromFrame(u_char *frame) {
    
    /*
     * First six bytes of frame ( 0 - 5 )
     * DESTINATION MAC ADDRESS
     */
    printf("Destination MAC: ");
    printMac(&frame[0]);
    
    if (isBroadcast(&frame[0]))
        printf(" (** IS BROADCAST)");
    

    printf("\nSource MAC: ");

    /*
     * Ensuing six bytes of frame ( 6 - 11 )
     * SOURCE MAC ADDRESS
     */
    printMac(&frame[6]);
    
    if (isBroadcast(&frame[6]))
        printf(" (** IS BROADCAST)");
}

/**
 * Prints the payload from the specified frame
 */
void printPayloadFromFrame(u_char *frame, size_t frameSize)
{
    // We know that the payload starts at position 14 of the frame and finishes
    // at the end of the frame (no CRC is present).
    printf("Payload: ");
    printPayload(&frame[14], frameSize-14);
}

/**
 * Prints the packet IPv4 information (ip addresses)
 * 
 * @param packet     IPv4 packet (payload of the frame).
 * @param packetLength size in bytes of the packet.
 */
void printIPv4Info(u_char *packet, size_t packetLength)
{
    // We know from the schema (https://en.wikipedia.org/wiki/IPv4#Header)
    // that the source IP address is at byte 12 
    // and the dest IP address is at byte 16
    
    struct in_addr *ipSrcPointer;
    struct in_addr *ipDstPointer;
    const char *srcIP;
    const char *dstIP;
    
    printf("\nIt's an IPv4 packet.");
    
    ipSrcPointer = (struct in_addr*)&packet[12];
    srcIP = inet_ntoa(*ipSrcPointer);

    printf("\nSource IP Address: %s", srcIP);

    ipDstPointer = (struct in_addr*)&packet[16];
    dstIP = inet_ntoa(*ipDstPointer);
    printf("\nDestination IP Address: %s\n", dstIP);
}

/*
 * pcap_pkthdr Generic per-packet information, as supplied by libpcap:
 *      packet lengths and the packet timestamp
 * 
 * u_char* frame: Bytes of data from the frame itself with all
 *                the wire bits stripped
 */
void printFrame(const struct pcap_pkthdr *frameHeader, u_char* frame) {

    printf("Header length: %u\n", frameHeader->len);
    printMacsFromFrame(frame);
    printEthertype(frame);
    printCRC(frame);
    printPayloadFromFrame(frame, frameHeader->len);
    
    
    
    if (isIPv4(frame))
    {
        printIPv4Info(&frame[14], frameHeader->len-14);
    }
}

/*
 * Callback function specified into  pcap_loop(...)
 * This callback will capture 1 frame whose header is available in frameHeader
 * The frame itself is stored into frame
 */
void getNewFrame(u_char *dummy, const struct pcap_pkthdr *frameHeader, u_char *frame) {
    printf("Packet captured no. %u  ", frameCount++);

    /*
     * Print the frame just captured
     */
    printFrame(frameHeader, frame);

    fflush(stdout);

}

/*
 * printIPandMask(char *defaultDev)
 * 
 * Prints the IP address and the Network mask configured into the network
 * device whose p_cap name is into defatultDevice
 * 
 */
void printIPandMask(char *defaultDev) {
    bpf_u_int32 netAddress;
    bpf_u_int32 netMask;
    struct in_addr inAddress;
    char errbuf[PCAP_ERRBUF_SIZE];

    printf("Network device name = %s\n", defaultDev);

    /*
     * pcap_lookupnet() returns the IP and the netmask of the passed device
     * Actual parameters netAddress and netMask are passed by reference since
     * we want them to hold the IP and the netmask, they are therefore output
     * parameters
     */
    if (pcap_lookupnet(defaultDev, &netAddress, &netMask, errbuf) == -1) {
        printf("%s\n", errbuf);
        exit(3);
    }

    /*
     * inet_ntoa() turns a "binary network address into an ascii string"
     */
    inAddress.s_addr = netAddress;
    char *ip;

    if ((ip = inet_ntoa(inAddress)) == NULL) {
        perror("inet_ntoa");
        exit(4);
    }

    printf("IP address = %s\n", ip);

    inAddress.s_addr = netMask;
    char *mask = inet_ntoa(inAddress);

    if (mask == NULL) {
        perror("inet_ntoa");
        exit(5);
    }

    printf("Network mask = %s\n", mask);
    fflush(stdout);
}

unsigned int performCapture(unsigned int nFramesToCapture) {

    char *defaultNetDevice;
    char errbuf[PCAP_ERRBUF_SIZE]; //The pcap error string buffer

    /*
     * Lookup the default network device on which to capture by invoking
     * pcap_lookupdev()
     */
    //defaultNetDevice = pcap_lookupdev(errbuf);
    defaultNetDevice = "wlan0";
    if (defaultNetDevice == (char *) NULL) {
        printf("%s\n", errbuf);
        exit(2);
    }

    /*
     * Printout of IP address + Net mask
     */
    printIPandMask(defaultNetDevice);

    /*
     * Open network device for capturing frames not-in-promiscuous mode:
     * 
     * pcap_t *pcap_open_live(
     * const char *device, 
     * int snaplen, 
     * int promisc, 
     * int timeout_ms,
     * char *errbuf);
     * 
     */
    pcap_t* status;
    status = pcap_open_live(defaultNetDevice, BUFSIZ, 0, -1, errbuf);


    if (status == (pcap_t *) NULL) {
        printf("Call to pcap_open_live() returned error: %s\n", errbuf);
        exit(4);
    }

    printf("\n\nCapturing %u frames:\n", nFramesToCapture);
    fflush(stdout);

    /*
     * int pcap_loop(
     * pcap_t *status,
     * int number_of_frames_to_capture,
     * pcap_handler callback_function,
     * u_char *user
     * )
     * 
     */
    pcap_loop(status, nFramesToCapture, getNewFrame, (const char *) NULL);

    return nFramesToCapture;
}

int main(int argc, char *args[]) {
    /*
     * Process command line arguments:
     * get the number of frames to capture
     */
    if (argc != 2) {
        printf("%s <n_frames_to_capture>\n", args[0]);
        exit(-1);
    }

    int frameCount = performCapture(atoi(args[1]));

    printf("\n\nFinished. %u frames captured.\n", frameCount);

}
