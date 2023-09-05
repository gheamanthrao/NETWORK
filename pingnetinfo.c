#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include <netinet/ip.h>
#include <poll.h>
#include <netinet/ip_icmp.h>
#include <time.h>

#define ERROR(msg, ...) printf("\033[1;31m" msg " \033[0m\n", ##__VA_ARGS__);
#define SUCCESS(msg, ...) printf("\033[1;36m" msg " \033[0m\n", ##__VA_ARGS__);
#define INFO(msg, ...) printf("\033[1;34m" msg " \033[0m\n", ##__VA_ARGS__);
#define DEBUG(msg, ...) printf("\033[1;32m[DEBUG] " msg "\033[0m", ##__VA_ARGS__);

#define PACKET_SIZE 1024
#define MAX_HOPS 30
#define POLL_TIMEOUT 2000

FILE *fptr;

unsigned short checksum(unsigned short *buf, int len)
{
    unsigned int sum = 0;
    while (len > 1)
    {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1)
    {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

char *dns_lookup(char *addr_host, struct sockaddr_in *addr_con)
{
    struct hostent *host_entity;
    char *ip = (char *)malloc(NI_MAXHOST * sizeof(char));
    int sockfd;

    if ((host_entity = gethostbyname(addr_host)) == NULL)
    {
        return NULL;
    }

    strcpy(ip, inet_ntoa(*(struct in_addr *)host_entity->h_addr));

    addr_con->sin_family = AF_INET;
    addr_con->sin_port = htons(0);
    addr_con->sin_addr.s_addr = inet_addr(ip);

    return ip;
}

void ping_net_info(char *hostname, int probes, int time_between_probes)
{
    int sockfd, ttl = 1, timeout = 1, flag = 1, i, recv_len;
    clock_t start, end;
    char packet[PACKET_SIZE];
    struct sockaddr_in addr_con;
    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    struct iphdr *ip = (struct iphdr *)packet;
    struct icmphdr *icmp = (struct icmphdr *)(packet + sizeof(struct iphdr));
    struct sockaddr_in r_addr;
    socklen_t len = sizeof(r_addr);
    int random_seqno1 = 10000;
    int random_seqno2 = 20000;
    int random_seqno3 = 40000;

    memset(&addr_con, 0, sizeof(addr_con));
    addr_con.sin_family = AF_INET;

    char *ip_addr = dns_lookup(hostname, &addr_con);
    char *data = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s,Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s,Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s,Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s,Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s";

    printf("Tracerouting to %s (%s), %d hops max\n", hostname, ip_addr, MAX_HOPS);
    INFO("S.NO.\tIP Address\t\tLatency\t\tBandwidth");

    int completion_flag_no_data = 0, count_no_data = 0, completion_flag_with_data = 0, count_with_data = 0;
    double total_time_no_data = 0, prev_time_no_data = 0;
    double total_time_with_data = 0, prev_time_with_data = 0;
    for (i = 1; i <= MAX_HOPS; ++i)
    {
        // part 1 - finding the intermediate node
        int flag_found = 0;
        struct sockaddr_in *temp;
        for (int j = 1; j <= 5; ++j)
        {

            setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
            setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
            memset(packet, 0, sizeof(packet));
            icmp->type = ICMP_ECHO;
            icmp->code = 0;
            icmp->un.echo.id = 0;
            icmp->un.echo.sequence = random_seqno1 + i + j;
            ip->saddr = 0;
            ip->daddr = addr_con.sin_addr.s_addr;
            ip->version = 4;
            ip->ihl = 5;
            ip->ttl = i;
            ip->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr);
            ip->protocol = IPPROTO_ICMP;
            icmp->checksum = 0;
            icmp->checksum = checksum((unsigned short *)icmp, sizeof(struct icmphdr));

            if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
            {
                perror("socket");
                exit(EXIT_FAILURE);
            }

            if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &flag, sizeof(flag)) < 0)
            {
                perror("setsockopt");
                exit(EXIT_FAILURE);
            }

            struct pollfd count_down;
            count_down.fd = sockfd;
            count_down.events = POLLIN;

            // printing the sending packet headers
            fprintf(fptr, "\n\nSending packet\n");
            fprintf(fptr, "TTL: %d\n", ip->ttl);
            fprintf(fptr, "SEQUENCE: %d\n", icmp->un.echo.sequence);
            fprintf(fptr, "TOTAL LENGTH: %d\n", ip->tot_len);
            fprintf(fptr, "PROTOCOL: %d\n", ip->protocol);
            fprintf(fptr, "DEST ADDR: %s\n", inet_ntoa(addr_con.sin_addr));



            if (sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&addr_con, sizeof(addr_con)) <= 0)
            {
                perror("sendto");
                continue;
            }

            int retval = poll(&count_down, 1, POLL_TIMEOUT); // wait for 5 seconds

            if (retval > 0)
            {
                if ((recv_len = recvfrom(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&r_addr, &len)) < 0)
                {
                    perror("recvfrom");
                    continue;
                }

                fprintf(fptr, "\n\nReceived packet\n");
                struct iphdr *ip = (struct iphdr *)packet;
                struct icmphdr *icmp = (struct icmphdr *)(packet + sizeof(struct iphdr));
                fprintf(fptr, "TTL: %d\n", ip->ttl);
                fprintf(fptr, "SEQUENCE: %d\n", icmp->un.echo.sequence);
                fprintf(fptr, "TOTAL LENGTH: %d\n", ip->tot_len);
                fprintf(fptr, "PROTOCOL: %d\n", ip->protocol);
                fprintf(fptr, "SOURCE ADDR: %s\n", inet_ntoa(r_addr.sin_addr));

                // if (ip->protocol != IPPROTO_TCP || ip->protocol != IPPROTO_UDP)
                //     fprintf(fptr, "The received packet protocol is neither TCP nor UDP\n");
                fprintf(fptr, "%s\n", inet_ntoa(r_addr.sin_addr));

                end = clock();
            }
            else if (retval < 0)
            {
                perror("poll");
                close(sockfd);
                continue;
            }
            else
            {
                // printf("%d\t* * *\n", i);
                close(sockfd);
                continue;
            }

            if (recv_len > 0)
            {
                flag_found = 1;
                temp = (struct sockaddr_in *)&r_addr;
                // if (temp->sin_addr.s_addr == addr_con.sin_addr.s_addr)
                // {
                //     // printf("\nTrace Completed\n");
                // }
            }

            close(sockfd);
            sleep(1);
        }
        if (!flag_found)
        {
            ERROR("%d\t* * *", i);
            continue;
        }

        for (int j = 1; j <= probes; ++j)
        {
            {
                // starting the clock here because, we are considering the time taken to process the headers as mentioned in question

                setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
                setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
                memset(packet, 0, sizeof(packet));
                icmp->type = ICMP_ECHO;
                icmp->code = 0;
                icmp->un.echo.id = 0;
                icmp->un.echo.sequence = random_seqno2 + i + j;
                ip->saddr = 0;
                ip->daddr = addr_con.sin_addr.s_addr;
                ip->version = 4;
                ip->ihl = 5;
                ip->ttl = i;
                ip->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr);
                ip->protocol = IPPROTO_ICMP;
                icmp->checksum = 0;
                icmp->checksum = checksum((unsigned short *)icmp, sizeof(struct icmphdr));

                if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
                {
                    perror("socket");
                    exit(EXIT_FAILURE);
                }

                if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &flag, sizeof(flag)) < 0)
                {
                    perror("setsockopt");
                    exit(EXIT_FAILURE);
                }

                struct pollfd count_down;
                count_down.fd = sockfd;
                count_down.events = POLLIN;

                fprintf(fptr, "\n\nSending packet\n");
                fprintf(fptr, "TTL: %d\n", ip->ttl);
                fprintf(fptr, "SEQUENCE: %d\n", icmp->un.echo.sequence);
                fprintf(fptr, "TOTAL LENGTH: %d\n", ip->tot_len);
                fprintf(fptr, "PROTOCOL: %d\n", ip->protocol);
                fprintf(fptr, "DEST ADDR: %s\n", inet_ntoa(addr_con.sin_addr));

                start = clock(); // start clock
                if (sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&addr_con, sizeof(addr_con)) <= 0)
                {
                    perror("sendto");
                    continue;
                }

                int retval = poll(&count_down, 1, POLL_TIMEOUT); // wait for 5 seconds

                if (retval > 0)
                {
                    if ((recv_len = recvfrom(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&r_addr, &len)) < 0)
                    {
                        perror("recvfrom");
                        continue;
                    }
                    fprintf(fptr, "\n\nReceived packet\n");
                    struct iphdr *ip = (struct iphdr *)packet;
                    struct icmphdr *icmp = (struct icmphdr *)(packet + sizeof(struct iphdr));
                    fprintf(fptr, "TTL: %d\n", ip->ttl);
                    fprintf(fptr, "SEQUENCE: %d\n", icmp->un.echo.sequence);
                    fprintf(fptr, "TOTAL LENGTH: %d\n", ip->tot_len);
                    fprintf(fptr, "PROTOCOL: %d\n", ip->protocol);
                    fprintf(fptr, "SOURCE ADDR: %s\n", inet_ntoa(r_addr.sin_addr));
                    end = clock();
                }
                else if (retval < 0)
                {
                    perror("poll");
                    close(sockfd);
                    continue;
                }
                else
                {
                    // printf("%d\t* * *\n", i);
                    close(sockfd);
                    continue;
                }

                if (recv_len > 0)
                {
                    count_no_data++;
                    double time_taken = ((double)(end - start)) / CLOCKS_PER_SEC;
                    struct sockaddr_in *s = (struct sockaddr_in *)&r_addr;
                    total_time_no_data += time_taken * 1000.0;
                    if (s->sin_addr.s_addr == addr_con.sin_addr.s_addr)
                    {
                        // printf("\nTrace Completed\n");
                        // break;
                        completion_flag_no_data = 1;
                    }
                }

                close(sockfd);
                sleep(time_between_probes);
            }
            // sending to the ip address found before
            {

                setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
                setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
                memset(packet, 0, sizeof(packet));
                icmp->type = ICMP_ECHO;
                icmp->code = 0;
                icmp->un.echo.id = 0;
                icmp->un.echo.sequence = random_seqno3+  i+ j;
                ip->saddr = 0;
                // ip->daddr = addr_con.sin_addr.s_addr;
                ip->daddr = temp->sin_addr.s_addr; // setting it to the address found before
                ip->version = 4;
                ip->ihl = 5;
                ip->ttl = 30; // changing the ttl
                ip->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr) + strlen(data);
                for (int i = 0; i < strlen(data) + 1; ++i)
                {
                    packet[sizeof(struct iphdr) + sizeof(struct icmphdr) + i] = data[i];
                }
                ip->protocol = IPPROTO_ICMP;
                icmp->checksum = 0;
                icmp->checksum = checksum((unsigned short *)icmp, sizeof(struct icmphdr) + strlen(data));

                if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
                {
                    perror("socket");
                    exit(EXIT_FAILURE);
                }

                if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &flag, sizeof(flag)) < 0)
                {
                    perror("setsockopt");
                    exit(EXIT_FAILURE);
                }

                struct pollfd count_down;
                count_down.fd = sockfd;
                count_down.events = POLLIN;

                start = clock();
                fprintf(fptr, "\n\nSending packet\n");
                fprintf(fptr, "TTL: %d\n", ip->ttl);
                fprintf(fptr, "SEQUENCE: %d\n", icmp->un.echo.sequence);
                fprintf(fptr, "TOTAL LENGTH: %d\n", ip->tot_len);
                fprintf(fptr, "PROTOCOL: %d\n", ip->protocol);
                fprintf(fptr, "DEST ADDR: %s\n", inet_ntoa(addr_con.sin_addr));
                if (sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&addr_con, sizeof(addr_con)) <= 0)
                {
                    perror("sendto");
                    continue;
                }

                int retval = poll(&count_down, 1, POLL_TIMEOUT); // wait for 5 seconds
                bzero(packet, PACKET_SIZE);
                if (retval > 0)
                {
                    if ((recv_len = recvfrom(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&r_addr, &len)) < 0)
                    {
                        perror("recvfrom");
                        continue;
                    }
                    fprintf(fptr, "\n\nReceived packet\n");
                    struct iphdr *ip = (struct iphdr *)packet;
                    struct icmphdr *icmp = (struct icmphdr *)(packet + sizeof(struct iphdr));
                    fprintf(fptr, "TTL: %d\n", ip->ttl);
                    fprintf(fptr, "SEQUENCE: %d\n", icmp->un.echo.sequence);
                    fprintf(fptr, "TOTAL LENGTH: %d\n", ip->tot_len);
                    fprintf(fptr, "PROTOCOL: %d\n", ip->protocol);
                    fprintf(fptr, "SOURCE ADDR: %s\n", inet_ntoa(r_addr.sin_addr));
                    end = clock();
                }
                else if (retval < 0)
                {
                    perror("poll");
                    close(sockfd);
                    continue;
                }
                else
                {
                    // printf("%d\t* * *\n", i);
                    close(sockfd);
                    continue;
                }

                if (recv_len > 0)
                {
                    count_with_data++;
                    double time_taken = ((double)(end - start)) / CLOCKS_PER_SEC;
                    struct sockaddr_in *s = (struct sockaddr_in *)&r_addr;
                    total_time_with_data += time_taken * 1000.0;
                    if (s->sin_addr.s_addr == addr_con.sin_addr.s_addr)
                    {
                        // printf("\nTrace Completed\n");
                        // break;
                        completion_flag_with_data = 1;
                    }
                }

                close(sockfd);
                sleep(time_between_probes);
            }
        }
        if (count_no_data == 0)
        {
            ERROR("%d\t* * *", i);
        }
        else
        {
            double l1 = (total_time_no_data - prev_time_no_data) / (2 * count_no_data);
            double l2 = (total_time_with_data - prev_time_with_data)/(2*count_with_data);
            printf("%d\t", i);
            printf("%s", inet_ntoa(r_addr.sin_addr));
            printf("\t\t%.3f ms", l1);
            printf("\t%.3f Mbps\n", strlen(data)*0.008  / (0.1+l2-l1));
            // printf("\t%.3fMbps\t%f\t%f\n", strlen(data)*0.008  / (l2-l1),l1,l2);
        }
        if (completion_flag_no_data)
        {
            SUCCESS("PINGNETINFO Completed");
            break;
        }
        count_no_data = count_with_data = 0;
        prev_time_no_data = total_time_no_data;
        prev_time_with_data = total_time_with_data;
        // total_time_no_data = total_time_with_data = 0;

        ttl++;
    }

    free(ip_addr);
}

void band_width_computation(char *hostname, int probes, int time_between_probes)
{
    int sockfd, ttl = 30, timeout = 1, flag = 1, i, recv_len;
    char packet[PACKET_SIZE];
    clock_t start, end;
    struct sockaddr_in addr_con;
    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    struct iphdr *ip = (struct iphdr *)packet;
    struct icmphdr *icmp = (struct icmphdr *)(packet + sizeof(struct iphdr));
    struct sockaddr_in r_addr;
    socklen_t len = sizeof(r_addr);

    memset(&addr_con, 0, sizeof(addr_con));
    addr_con.sin_family = AF_INET;

    char *ip_addr = dns_lookup(hostname, &addr_con);
    char *data = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s";
    printf("PING to %s (%s), %d hops max\n", hostname, ip_addr, MAX_HOPS);

    for (i = 1; i <= MAX_HOPS; ++i)
    {
        for (int j = 1; j <= probes; ++j)
        {
            // starting the clock here because, we are considering the time taken to process the headers as mentioned in question
            start = clock();

            setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
            setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
            memset(packet, 0, sizeof(packet));
            icmp->type = ICMP_ECHO;
            icmp->code = 0;
            icmp->un.echo.id = 0;
            icmp->un.echo.sequence = i;
            ip->saddr = 0;
            ip->daddr = addr_con.sin_addr.s_addr;
            ip->version = 4;
            ip->ihl = 5;
            ip->ttl = ttl;
            ip->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr) + strlen(data);
            for (int i = 0; i < strlen(data) + 1; ++i)
            {
                packet[sizeof(struct iphdr) + sizeof(struct icmphdr) + i] = data[i];
            }

            ip->protocol = IPPROTO_ICMP;
            icmp->checksum = 0;
            icmp->checksum = checksum((unsigned short *)icmp, sizeof(struct icmphdr) + strlen(data));

            if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
            {
                perror("socket");
                exit(EXIT_FAILURE);
            }

            if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &flag, sizeof(flag)) < 0)
            {
                perror("setsockopt");
                exit(EXIT_FAILURE);
            }

            struct pollfd count_down;
            count_down.fd = sockfd;
            count_down.events = POLLIN;

            fprintf(fptr, "\n\nSending packet\n");
            fprintf(fptr, "TTL: %d\n", ip->ttl);
            fprintf(fptr, "SEQUENCE: %d\n", icmp->un.echo.sequence);
            fprintf(fptr, "TOTAL LENGTH: %d\n", ip->tot_len);
            fprintf(fptr, "PROTOCOL: %d\n", ip->protocol);
            fprintf(fptr, "DEST ADDR: %s\n", inet_ntoa(addr_con.sin_addr));

            if (sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&addr_con, sizeof(addr_con)) <= 0)
            {
                perror("sendto");
            }

            int retval = poll(&count_down, 1, 5000); // wait for 5 seconds
            bzero(packet, PACKET_SIZE);
            // printf("length of packet now: %ld\n", strlen(packet));

            if (retval > 0)
            {
                if ((recv_len = recvfrom(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&r_addr, &len)) < 0)
                {
                    perror("recvfrom");
                    continue;
                }

                fprintf(fptr, "\n\nReceived packet\n");
                struct iphdr *ip = (struct iphdr *)packet;
                struct icmphdr *icmp = (struct icmphdr *)(packet + sizeof(struct iphdr));
                fprintf(fptr, "TTL: %d\n", ip->ttl);
                fprintf(fptr, "SEQUENCE: %d\n", icmp->un.echo.sequence);
                fprintf(fptr, "TOTAL LENGTH: %d\n", ip->tot_len);
                fprintf(fptr, "PROTOCOL: %d\n", ip->protocol);
                fprintf(fptr, "SOURCE ADDR: %s\n", inet_ntoa(r_addr.sin_addr));
                end = clock();
            }
            else if (retval < 0)
            {
                perror("poll");
                close(sockfd);
                continue;
            }
            else
            {
                printf("%d\t* * *\n", i);
                close(sockfd);
                continue;
            }

            if (recv_len > 0)
            {
                // printf("Reply: %s\n", packet+sizeof(struct iphdr)+sizeof(struct icmphdr));
                double time_taken = ((double)(end - start)) / CLOCKS_PER_SEC;
                struct sockaddr_in *s = (struct sockaddr_in *)&r_addr;
                printf("%d\t", i);
                printf("%s\n", inet_ntoa(r_addr.sin_addr));
                printf("\t%.3f ms\n", time_taken * 1000.0);
                if (s->sin_addr.s_addr == addr_con.sin_addr.s_addr)
                {
                    printf("\tTrace Completed\n");
                    break;
                }

                struct iphdr *ip_packet;
                ip_packet = (struct iphdr *)packet;
                printf("total length: %d\n", ip_packet->tot_len);
                struct icmphdr *icmp_reply;
                icmp_reply = (struct icmphdr *)(packet + (ip_packet->ihl << 2));
                if (icmp_reply->type == ICMP_ECHOREPLY)
                {
                    printf("this is the type: %d\n", icmp_reply->type);
                    printf("64 bytes from %s: icmp_seq=%d ttl=%d time=%d ms\n", inet_ntoa(r_addr.sin_addr), icmp_reply->un.echo.sequence, ip_packet->ttl, 0);
                }
            }

            close(sockfd);
            sleep(time_between_probes);
        }
    }
    free(ip_addr);
}

int main(int argc, char *argv[])
{
    if (argc < 4)
    {
        printf("Usage: %s <host> <probe> <time-difference>\n", argv[0]);
        return EXIT_FAILURE;
    }
    fptr = fopen("log.txt", "w");
    printf("CHECK LOG FILE FOR MORE DETAILS\n");
    int probe = atoi(argv[2]);
    int time_between_probes = atoi(argv[3]);
    ping_net_info(argv[1], probe, time_between_probes);
    fclose(fptr);
    return 0;
}