/*
    $ Compile with:
        gcc PacketSniff.c MyTimer.c -o PacketSniff -l lpcap -l pthread

    $ Run with sudo:
        sudo ./PacketSniff <Network_Interface>

    $ log file:
        PacketSniff_log

    $ Install libpcap using:
        sudo apt install libpcap-dev

    $ Description:
        This app takes a Network Interface and monitors and logs TCP/UDP/ICMP
        traffic on the basis of their count, size, difference between the first
        and last packet of each protocol. Also it checks if a source ip sends
        more packets than a threshold and detects it as DoS attack.

    $ Developed By: 
        S. Saeed Hosseini
*/

#include <stdio.h>  // For printf
#include <stdlib.h> // For exit 
#include <string.h> // For strcmp
#include <netinet/ip.h> // For IP struct
#include <net/ethernet.h> // For Ethernet struct
#include "MyTimer.h" // For Timers
#include <time.h> // To get timestamps
#include <arpa/inet.h> // For inet_ntoa
#include <pcap.h>   // For many things :)

#define run_time 30 // App running time in seconds
#define max_att_log 500 // Max number of IPs for DETECTING potential attackers
#define max_real_att_log max_att_log / 5 // Max number of IPs for DETECTING real attackers
#define pot_att_time 10 // Time in which we check for DETECTING potential attacks - in Seconds
#define pot_att_trs 100 // Threshold of requests in pot_att_time for DETECTING potential_attacks

// To keep the number of TCP/UDP/ICMP and total packets & Bytes;
int tcp_pkt, tcp_pkt_bytes, udp_pkt, udp_pkt_bytes, icmp_pkt, icmp_pkt_bytes, total_pkt, total_pkt_bytes; 

// To get the first and last TCP/UDP/ICMP packet
struct tm app_first, app_last, tcp_first, tcp_last, udp_first, udp_last, icmp_first, icmp_last; 

// To check if we received the first TCP/UDP/ICMP packet
char got_tcp, got_udp, got_icmp, *device;

struct sockaddr_in source;

struct pot_att_log
{
    char addr[100];
    int prot;
    int cnt;
} potential_attacker[max_att_log], real_attacker[max_real_att_log];

// To keep track of potential and real attacks
int pot_att_index;
int real_att_index;

pcap_t *handle;

void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer);
void timer_handler1(size_t timer_id, void * user_data);
void log_file(int, int, int, int);

int main(int argc, char const *argv[])
{
    system("clear");

    if(argc != 2)
    {
        printf("- Invalid parameters!!!\n");
        printf("- Usage: %s <interface>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */

    /* Find a device */
    device = pcap_lookupdev(error_buffer);
    if (device == NULL || strcmp(device, argv[1]) != 0) 
    {
        printf("Error finding/using device %s\n", error_buffer);
        exit(EXIT_FAILURE);
    }

    int timeout_limit = 300000; /* 5 minutes in milliseconds */

    /* Open device for live capture */
    handle = pcap_open_live(
            device,
            BUFSIZ,
            0,
            timeout_limit,
            error_buffer
        );

    if (handle == NULL) 
    {
        fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
        exit(EXIT_FAILURE);
    }

    time_t t = time(NULL);
    app_first = *localtime(&t);

    printf("Using %s to monitor TCP/UDP/ICMP @ %4d/%02d/%02d, %02d:%02d:%02d\n\n",
            device, 1900 + app_first.tm_year, app_first.tm_mon, app_first.tm_mday,
                           app_first.tm_hour, app_first.tm_min, app_first.tm_sec);

    bpf_u_int32 ip;
    struct bpf_program filter;
    char filter_exp[] = "tcp or udp or icmp"; // Only traffic for TCP/UDP/ICMP Protocol

    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1)
    {
        printf("Bad filter - %s\n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(handle, &filter) == -1)
    {
        printf("Error setting filter - %s\n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    size_t timer1;
    initialize();
    timer1 = start_timer(1, timer_handler1, TIMER_PERIODIC, NULL);

    pcap_loop(handle, 0, my_packet_handler, NULL);

    return 0;
}

void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    time_t t = time(NULL);
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    total_pkt++;
    total_pkt_bytes += header->len;

    // Keeping count of simillar requests 
    char found = 0;
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    for(int i = 0; i < pot_att_index; i++)
        if(!strcmp(potential_attacker[i].addr, inet_ntoa(source.sin_addr)) &&
                   potential_attacker[i].prot == iph->protocol)
        {
            potential_attacker[i].cnt++;
            found = 1;
        }
            
    if(!found)
    {
        strcpy(potential_attacker[pot_att_index].addr, inet_ntoa(source.sin_addr));
        potential_attacker[pot_att_index].prot = iph->protocol;
        potential_attacker[pot_att_index].cnt = 1;
        pot_att_index++;
    }
    
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 1:  //ICMP Protocol
            icmp_pkt++;
            icmp_pkt_bytes += header->len;
            icmp_last = *localtime(&t);
            if(!got_icmp)
            {
                icmp_first = *localtime(&t);
                got_icmp = 1;
            }
                
            break;

        case 6:  //TCP Protocol
            tcp_pkt++;
            tcp_pkt_bytes += header->len;
            tcp_last = *localtime(&t);
            if(!got_tcp)
            {
                tcp_first = *localtime(&t);
                got_tcp = 1;
            }
                
            break;
         
        case 17: //UDP Protocol
            udp_pkt++;
            udp_pkt_bytes += header->len;
            udp_last = *localtime(&t);
            if(!got_udp)
            {
                udp_first = *localtime(&t);
                got_udp = 1;
            }
                
            break;         
    }
}

void timer_handler1(size_t timer_id, void * user_data)
{
    static int current_run_time = 0;

    system("clear");
    printf("Using %s to monitor TCP/UDP/ICMP @ %4d/%02d/%02d, %02d:%02d:%02d\n\n",
            device, 1900 + app_first.tm_year, app_first.tm_mon, app_first.tm_mday,
                           app_first.tm_hour, app_first.tm_min, app_first.tm_sec);

    // Calculate difference between the first & last TCP packet in seconds
    int tcp_time =  (tcp_last.tm_year - tcp_first.tm_year) * 31556952 + 
                    (tcp_last.tm_mon - tcp_first.tm_mon) * 2628000 + 
                    (tcp_last.tm_mday - tcp_first.tm_mday) * 86400 + 
                    (tcp_last.tm_hour - tcp_first.tm_hour) * 3600 + 
                    (tcp_last.tm_min - tcp_first.tm_min) * 60 + 
                    (tcp_last.tm_sec - tcp_first.tm_sec);

    // Calculate difference between the first & last UDP packet in seconds
    int udp_time =  (udp_last.tm_year - udp_first.tm_year) * 31556952 + 
                    (udp_last.tm_mon - udp_first.tm_mon) * 2628000 + 
                    (udp_last.tm_mday - udp_first.tm_mday) * 86400 + 
                    (udp_last.tm_hour - udp_first.tm_hour) * 3600 + 
                    (udp_last.tm_min - udp_first.tm_min) * 60 + 
                    (udp_last.tm_sec - udp_first.tm_sec);

    // Calculate difference between the first & last ICMP packet in seconds
    int icmp_time = (icmp_last.tm_year - icmp_first.tm_year) * 31556952 + 
                    (icmp_last.tm_mon - icmp_first.tm_mon) * 2628000 + 
                    (icmp_last.tm_mday - icmp_first.tm_mday) * 86400 + 
                    (icmp_last.tm_hour - icmp_first.tm_hour) * 3600 + 
                    (icmp_last.tm_min - icmp_first.tm_min) * 60 + 
                    (icmp_last.tm_sec - icmp_first.tm_sec);

    printf(" - TCP: %10d packets, %12d Bytes, For %5d Secs\n", tcp_pkt, tcp_pkt_bytes, tcp_time);
    printf(" - UDP: %10d packets, %12d Bytes, For %5d Secs\n", udp_pkt, udp_pkt_bytes, udp_time);
    printf(" - ICMP:%10d packets, %12d Bytes, For %5d Secs\n", icmp_pkt, icmp_pkt_bytes, icmp_time);
    printf(" $ Total:%9d packets, %12d Bytes, For %5d Secs\n", total_pkt, total_pkt_bytes, current_run_time);

    char found;
    if(current_run_time % pot_att_time == 0)
    {
        for(int i = 0; i < pot_att_index; i++)
        { 
            found = 0;
            if(potential_attacker[i].cnt > pot_att_trs)
            {
                for(int j = 0; j < real_att_index; j++)
                {
                    if(!strcmp(real_attacker[j].addr, potential_attacker[i].addr) && 
                               real_attacker[j].prot == potential_attacker[i].prot)
                    {
                        if(potential_attacker[i].cnt > real_attacker[j].cnt)
                            real_attacker[j].cnt = potential_attacker[i].cnt;
                        found = 1;
                    }
                }
                if(!found)
                {
                    strcpy(real_attacker[real_att_index].addr, potential_attacker[i].addr);
                    real_attacker[real_att_index].prot = potential_attacker[i].prot;
                    real_attacker[real_att_index].cnt = potential_attacker[i].cnt;
                    real_att_index++;
                } 
            }    
        }              
        pot_att_index = 0;
    }

    for(int i = 0; i < real_att_index; i++)
    {
        if(i == 0)
            printf("\nDoS Attacks - More than %d requests per %d seconds:\n\n", pot_att_trs, pot_att_time);
        
        printf(" - %s", real_attacker[i].addr);
        for(int k = 0; k < 15 - strlen(real_attacker[i].addr); k++)
            printf(" ");
            
        switch(real_attacker[i].prot)
        {
            case 1:
                printf(", ICMP    with %6d requests\n", real_attacker[i].cnt);
            break;
            
            case 6:
                printf(", TCP     with %6d requests\n", real_attacker[i].cnt);
            break;

            case 17:
                printf(", UDP     with %6d requests\n", real_attacker[i].cnt);
            break;
        }
    }

    if(current_run_time != run_time)
        current_run_time++;
    else
    {
        time_t t = time(NULL);
        app_last = *localtime(&t);

        printf("\nFinished monitoring %s @ %4d/%02d/%02d, %02d:%02d:%02d\n\n",
                device, 1900 + app_last.tm_year, app_last.tm_mon, app_last.tm_mday,
                               app_last.tm_hour, app_last.tm_min, app_last.tm_sec);

        log_file(tcp_time, udp_time, icmp_time, current_run_time);
        pcap_close(handle);
        exit(EXIT_SUCCESS);
    }      
}

void log_file(int tcp_time, int udp_time, int icmp_time, int current_run_time)
{
    FILE *fp = fopen("PacketSniff_log.txt", "a");
    if(fp == NULL)
        printf("Could not create/open the log file!");
    else
    {
        fprintf(fp,"* Using %s to monitor TCP/UDP/ICMP @ %4d/%02d/%02d, %02d:%02d:%02d\n\n",
                    device, 1900 + app_first.tm_year, app_first.tm_mon, app_first.tm_mday,
                                    app_first.tm_hour, app_first.tm_min, app_first.tm_sec);
        fprintf(fp, " - TCP: %10d packets, %12d Bytes, For %5d Secs\n", tcp_pkt, tcp_pkt_bytes, tcp_time);
        fprintf(fp, " - UDP: %10d packets, %12d Bytes, For %5d Secs\n", udp_pkt, udp_pkt_bytes, udp_time);
        fprintf(fp, " - ICMP:%10d packets, %12d Bytes, For %5d Secs\n", icmp_pkt, icmp_pkt_bytes, icmp_time);
        fprintf(fp, " $ Total:%9d packets, %12d Bytes, For %5d Secs\n", total_pkt, total_pkt_bytes, current_run_time);

        for(int i = 0; i < real_att_index; i++)
        {
            if(i == 0)
                fprintf(fp, "\nDoS Attacks - More than %d requests per %d seconds:\n\n", pot_att_trs, pot_att_time);
            
            fprintf(fp, " - %s", real_attacker[i].addr);
            for(int k = 0; k < 15 - strlen(real_attacker[i].addr); k++)
                fprintf(fp, " ");
                
            switch(real_attacker[i].prot)
            {
                case 1:
                    fprintf(fp, ", ICMP    with %6d requests\n", real_attacker[i].cnt);
                break;
                
                case 6:
                    fprintf(fp, ", TCP     with %6d requests\n", real_attacker[i].cnt);
                break;

                case 17:
                    fprintf(fp, ", UDP     with %6d requests\n", real_attacker[i].cnt);
                break;
            }
        }

        fprintf(fp, "\n* Finished monitoring %s @ %4d/%02d/%02d, %02d:%02d:%02d\n\n",
                    device, 1900 + app_last.tm_year, app_last.tm_mon, app_last.tm_mday,
                                    app_last.tm_hour, app_last.tm_min, app_last.tm_sec);
        fprintf(fp, "################################################################\n\n");
        fclose(fp);
    }
}
