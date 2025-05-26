#include "ft_nmap.h" // Assuming this will be provided or created later
#include <pcap.h>
#include <time.h>
#include <netinet/if_ether.h> // For ETH_P_IP, ETH_ALEN, struct ethhdr
#include <netinet/ip.h>       // For struct ip
#include <netinet/tcp.h>      // For struct tcphdr, TH_SYN, TH_ACK, TH_RST
#include <getopt.h>
#include <errno.h>
#include <limits.h>
#include <string.h>      // For memset, memcpy, strncpy
#include <arpa/inet.h>   // For inet_addr, htons, ntohs, inet_ntoa, inet_ntop
#include <stdlib.h>      // For rand, srand, malloc, free, atoi, exit
#include <stdio.h>       // For printf, fprintf, stderr, FILE, fopen, fclose, fgets
#include <netdb.h>       // For getaddrinfo, gai_strerror, struct addrinfo

// Define constants if not in ft_nmap.h
#ifndef MAXSCANS
#define MAXSCANS 6 // Number of scan types in scan_modes array
#endif
#ifndef SCAN_SYN
#define SCAN_SYN 0x01
#endif
#ifndef SCAN_NULL
#define SCAN_NULL 0x02
#endif
#ifndef SCAN_FIN
#define SCAN_FIN 0x04
#endif
#ifndef SCAN_XMAS
#define SCAN_XMAS 0x08
#endif
#ifndef SCAN_ACK
#define SCAN_ACK 0x10
#endif
#ifndef SCAN_UDP
#define SCAN_UDP 0x20
#endif
#ifndef SCAN_ALL
#define SCAN_ALL (SCAN_SYN | SCAN_NULL | SCAN_FIN | SCAN_XMAS | SCAN_ACK | SCAN_UDP)
#endif


#define MAXIPHDRLEN	60 // Max IP header length (including options)
#define PROMISC_TRUE	1
#define PROMISC_FALSE 	0
#define TIMESTRLEN 	100
#define MAXPORTS 	1024 // Max number of ports to scan from range
#define MINPORTS 	1    // Min port number
#define MAXTHREADS 	250  // Max number of threads (placeholder for future use)
#define DEFAULT_PORT_RANGE "1-1024"
#define PACKET_BUF_SIZE	1024 // Buffer for crafting packets
#define DEFAULT_SRC_IP "127.0.0.1" // Placeholder: should be dynamically determined
#define DEFAULT_SRC_PORT 12345     // Source port for sending packets
#define RECV_TIMEOUT_SECONDS 5     // Timeout for the packet reception phase

#define NMAP_IP_OPTARG 	0x01
#define NMAP_FILE_OPTARG 	0x02
#define NMAP_PORTS_OPTARG 0x04

#define ETH0 	1 // Default network interface for pcap (placeholder)

// Global variables (consider encapsulating these in a struct if complexity grows)
unsigned int number_of_ports = 0;
unsigned short number_of_threads = 0; // Currently unused but parsed
short scan_type = 0;
int debugging = 1; // Controls debug output verbosity
extern char *optarg;
extern int optind;
// extern int errno; // errno is defined in errno.h
char *program_name = NULL;
unsigned short *ports = NULL; // Array of port numbers to scan
char *source = NULL;          // Target hostname or IP string from --ip
char *filename = NULL;        // Filename for --file option

// Data structures for results
typedef enum {
	PORT_OPEN,
	PORT_CLOSED,
	PORT_FILTERED,
	PORT_UNSCANNED
} port_state_t;

struct nmap_port_result {
	int port_number;
	port_state_t state;
	char service_name[64];
};

// Structure for scan mode lookup
struct scan_mode {
	const char *name;
	short flag;
};

static const struct scan_mode scan_modes[] = {
	{"SYN", SCAN_SYN},
	{"NULL", SCAN_NULL},
	{"FIN", SCAN_FIN},
	{"XMAS", SCAN_XMAS},
	{"ACK", SCAN_ACK},
	{"UDP", SCAN_UDP}
};
/*
// Forward declarations
static size_t craft_syn_packet(struct nmap_data *nmap, uint16_t dest_port, u_char *packet_buffer, size_t buffer_size);
static void analyze_response_packet(const struct pcap_pkthdr *header, const u_char *bytes, struct nmap_data *nmap, struct nmap_port_result *results, unsigned int num_total_ports);
static const char* state_to_string(port_state_t state);
void nmap_print_error_and_exit(char *error); // Make it static if only used in this file
*/
// Main nmap data structure
struct nmap_data {
	struct sockaddr_in target_addr; // Target's address information
	// Potentially add source_addr here if dynamically determined
};


void nmap_print_error_and_exit(char *error) {
	fprintf(stderr, "%s: Error: %s\n", program_name ? program_name : "ft_nmap", error);
	if (errno) {
		perror("System error");
	}
	exit(EXIT_FAILURE);
}

unsigned short *nmap_get_ports(char *expr, unsigned int *num_ports_parsed) {
	unsigned short *parsed_ports_array;
	int count = 0, start, end;
	char *next_token, *dash_pos;
	char port_status_flags[MAXPORTS + 1]; // To check for duplicates

	parsed_ports_array = malloc(MAXPORTS * sizeof(unsigned short));
	if (parsed_ports_array == NULL)
		nmap_print_error_and_exit("get_ports: malloc failed.");

	memset(port_status_flags, 0, sizeof(port_status_flags));
	
	char *current_expr_ptr = expr;
	while ((next_token = strsep(&current_expr_ptr, ",")) != NULL) {
		if (*next_token == '\0') continue; // Skip empty tokens if any

		dash_pos = strchr(next_token, '-');
		if (dash_pos) { // Range like "X-Y", "X-", "-Y"
			*dash_pos = '\0'; // Split token
			if (*next_token == '\0') { // Format "-Y"
				start = MINPORTS;
			} else {
				start = atoi(next_token);
			}
			if (*(dash_pos + 1) == '\0') { // Format "X-"
				end = MAXPORTS;
			} else {
				end = atoi(dash_pos + 1);
			}
		} else { // Single port "X"
			start = atoi(next_token);
			end = start;
		}

		if (start < MINPORTS || start > MAXPORTS || end < MINPORTS || end > MAXPORTS || start > end) {
			fprintf(stderr, "Invalid port or range: %s%c%s. Ports must be between %d and %d.\n",
				(*next_token == '\0' && dash_pos) ? "" : next_token,
				dash_pos ? '-' : ' ',
				(dash_pos && *(dash_pos+1)=='\0') ? "" : (dash_pos ? dash_pos+1 : ""),
				MINPORTS, MAXPORTS);
			free(parsed_ports_array);
			nmap_print_error_and_exit("Invalid port specification.");
		}

		for (int i = start; i <= end; ++i) {
			if (count < MAXPORTS && port_status_flags[i] == 0) {
				parsed_ports_array[count++] = i;
				port_status_flags[i] = 1;
			} else if (count >= MAXPORTS) {
                 fprintf(stderr, "Warning: Exceeded maximum number of unique ports (%d). Some ports may not be scanned.\n", MAXPORTS);
                 goto end_parsing; // Break outer loop
            }
		}
	}

end_parsing:
	*num_ports_parsed = count;
	if (count == 0) {
		free(parsed_ports_array);
		nmap_print_error_and_exit("No valid ports specified.");
	}
	return parsed_ports_array;
}


static const char* state_to_string(port_state_t state) {
	switch (state) {
		case PORT_OPEN: return "Open";
		case PORT_CLOSED: return "Closed";
		case PORT_FILTERED: return "Filtered";
		case PORT_UNSCANNED: return "Unscanned";
		default: return "Unknown";
	}
}

static uint16_t tcp_checksum(const void *buff, size_t len, struct in_addr src_addr, struct in_addr dest_addr) {
    const uint16_t *buf = buff;
    uint32_t sum = 0;

    // Pseudo header
    sum += (src_addr.s_addr >> 16) & 0xFFFF;
    sum += (src_addr.s_addr) & 0xFFFF;
    sum += (dest_addr.s_addr >> 16) & 0xFFFF;
    sum += (dest_addr.s_addr) & 0xFFFF;
    sum += htons(IPPROTO_TCP);
    sum += htons(len);

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len > 0) { // If there's an odd byte left
        sum += *(uint8_t *)buf;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

static size_t craft_syn_packet(struct nmap_data *nmap, uint16_t dest_port, u_char *packet_buffer, size_t buffer_size) {
	struct ethhdr *eth = (struct ethhdr *)packet_buffer;
	struct ip *iph = (struct ip *)(packet_buffer + sizeof(struct ethhdr)); // Use struct ip
	struct tcphdr *tcph = (struct tcphdr *)(packet_buffer + sizeof(struct ethhdr) + sizeof(struct ip));
	struct sockaddr_in src_sock_addr;
	size_t packet_total_size = sizeof(struct ethhdr) + sizeof(struct ip) + sizeof(struct tcphdr);

	if (buffer_size < packet_total_size) {
		fprintf(stderr, "craft_syn_packet: Buffer too small (%zu B) for packet size (%zu B)\n", buffer_size, packet_total_size);
		return 0;
	}
	memset(packet_buffer, 0, packet_total_size); // Zero out headers

	// Ethernet Header (dummy MACs, replace with actual interface MACs if possible)
	memset(eth->h_source, 0xAA, ETH_ALEN); // Source MAC
	memset(eth->h_dest, 0xBB, ETH_ALEN);   // Dest MAC (TODO: ARP lookup for target MAC on local nets)
	eth->h_proto = htons(ETH_P_IP);

	// IP Header
	src_sock_addr.sin_addr.s_addr = inet_addr(DEFAULT_SRC_IP); // TODO: Get this from the actual interface

	iph->ip_hl = 5; // Header Length (5 words * 4 bytes = 20 bytes)
	iph->ip_v = 4;  // Version IPv4
	iph->ip_tos = 0; // Type of Service
	iph->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr)); // Total Length of IP packet
	iph->ip_id = htons(rand() % 65535); // Identification (random)
	iph->ip_off = 0; // Fragment Offset
	iph->ip_ttl = 64; // Time To Live
	iph->ip_p = IPPROTO_TCP; // Protocol (TCP)
	iph->ip_sum = 0; // Checksum (kernel will fill it if 0, or calculate manually)
	iph->ip_src = src_sock_addr.sin_addr;
	iph->ip_dst = nmap->target_addr.sin_addr;
	// TODO: Optionally calculate IP checksum here if not relying on kernel/offloading

	// TCP Header
	tcph->th_sport = htons(DEFAULT_SRC_PORT); // Source Port
	tcph->th_dport = htons(dest_port);        // Destination Port
	tcph->th_seq = htonl(rand());             // Sequence Number (random)
	tcph->th_ack = 0;                         // Acknowledgement Number (0 for SYN)
	tcph->th_off = 5;                         // Data Offset (5 words * 4 bytes = 20 bytes)
	tcph->th_flags = TH_SYN;                  // Flags (SYN)
	tcph->th_win = htons(5840);               // Window Size
	tcph->th_sum = 0;                         // Checksum (calculated below)
	tcph->th_urp = 0;                         // Urgent Pointer

	tcph->th_sum = tcp_checksum(tcph, sizeof(struct tcphdr), iph->ip_src, iph->ip_dst);

	return packet_total_size;
}

static void analyze_response_packet(const struct pcap_pkthdr *header, const u_char *bytes, struct nmap_data *nmap, struct nmap_port_result *results, unsigned int num_total_ports) {
	const struct ethhdr *ethernet_header;
	const struct ip *ip_header;
	const struct tcphdr *tcp_header;
	unsigned int ip_header_len_bytes;

	if (header->caplen < sizeof(struct ethhdr)) {
		if (debugging > 1) fprintf(stderr, "Debug: Packet too short for Ethernet header (caplen: %u B, required: %zu B)\n", header->caplen, sizeof(struct ethhdr));
		return;
	}
	ethernet_header = (struct ethhdr *)bytes;

	if (ntohs(ethernet_header->h_proto) != ETH_P_IP) return;

	if (header->caplen < (sizeof(struct ethhdr) + sizeof(struct ip))) {
		if (debugging > 1) fprintf(stderr, "Debug: Packet too short for minimal IP header (caplen: %u B, required: %zu B)\n", header->caplen, sizeof(struct ethhdr) + sizeof(struct ip));
		return;
	}
	ip_header = (struct ip *)(bytes + sizeof(struct ethhdr));
	
	ip_header_len_bytes = ip_header->ip_hl * 4;
	if (ip_header_len_bytes < sizeof(struct ip)) {
		if (debugging) fprintf(stderr, "Debug: Invalid IP header length: %u bytes (ip_hl: %u words). Min expected: %zu bytes. (caplen: %u B)\n", ip_header_len_bytes, ip_header->ip_hl, sizeof(struct ip), header->caplen);
		return;
	}
	if (header->caplen < (sizeof(struct ethhdr) + ip_header_len_bytes)) {
		if (debugging) fprintf(stderr, "Debug: Packet too short for declared IP header length (caplen: %u B, required eth+ip_hl: %zu B)\n", header->caplen, sizeof(struct ethhdr) + ip_header_len_bytes);
		return;
	}

	if (ip_header->ip_src.s_addr != nmap->target_addr.sin_addr.s_addr ||
		ip_header->ip_dst.s_addr != inet_addr(DEFAULT_SRC_IP)) {
		return;
	}

	if (ip_header->ip_p != IPPROTO_TCP) return;

	if (header->caplen < (sizeof(struct ethhdr) + ip_header_len_bytes + sizeof(struct tcphdr))) {
		if (debugging) fprintf(stderr, "Debug: Packet too short for minimal TCP header (caplen: %u B, required eth+ip+tcp_min: %zu B)\n", header->caplen, sizeof(struct ethhdr) + ip_header_len_bytes + sizeof(struct tcphdr));
		return;
	}
	tcp_header = (struct tcphdr *)(bytes + sizeof(struct ethhdr) + ip_header_len_bytes);
	
	uint16_t responsive_port = ntohs(tcp_header->th_sport);
	uint16_t our_source_port = ntohs(tcp_header->th_dport);

	if (our_source_port != DEFAULT_SRC_PORT) {
		if (debugging > 1) printf("Debug: Packet received for unexpected destination port: %u (expected %d)\n", our_source_port, DEFAULT_SRC_PORT);
		return;
	}

	for (unsigned int i = 0; i < num_total_ports; ++i) {
		if (results[i].port_number == responsive_port) {
			if ((tcp_header->th_flags & TH_SYN) && (tcp_header->th_flags & TH_ACK)) {
				results[i].state = PORT_OPEN;
			} else if (tcp_header->th_flags & TH_RST) {
				if (results[i].state != PORT_OPEN) { // Avoid overriding OPEN if a late RST arrives
					results[i].state = PORT_CLOSED;
				}
			}
			if (debugging) {
				char current_ip_str[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, &(ip_header->ip_src), current_ip_str, INET_ADDRSTRLEN);
				printf("Debug: Response for port %s:%u -> State: %s (Flags: S%d A%d R%d F%d P%d U%d)\n", 
					current_ip_str, responsive_port, state_to_string(results[i].state),
					(tcp_header->th_flags & TH_SYN)?1:0, (tcp_header->th_flags & TH_ACK)?1:0,
					(tcp_header->th_flags & TH_RST)?1:0, (tcp_header->th_flags & TH_FIN)?1:0,
					(tcp_header->th_flags & TH_PUSH)?1:0, (tcp_header->th_flags & TH_URG)?1:0);
			}
			return; 
		}
	}
	if (debugging > 1) {
		char current_ip_str[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &(ip_header->ip_src), current_ip_str, INET_ADDRSTRLEN);
		printf("Debug: Response from %s for port %u, but not in our scanned list or wrong dest port %u.\n", current_ip_str, responsive_port, our_source_port);
	}
}

void
nmap_print_scan_config(struct nmap_data *nmap, int ports, short scan_mode, int threads)
{
	printf("Scan configurations\n");
	printf("Target IP-Address : %s\n",
		inet_ntoa(nmap->target_addr.sin_addr));
	printf("No of ports to scan : %d\n", ports);
	printf("Scans to be performed :");
	for (int i = 0; i < MAXSCANS; ++i)
	{
		if (scan_modes[i].flag & scan_mode)
			printf(" %s", scan_modes[i].name);
	}
	printf("\n");
	printf("No of threads : %d\n", threads);
}

int
nmap_set_target(struct nmap_data *nmap, const char *hostname)
{
	int s;
	struct addrinfo hints, *res;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;

	s = getaddrinfo(hostname, NULL, &hints, &res);
	if (s != 0)
	{
		fprintf(stderr, "ft_nmap: failed to resolve \"%s\": %s\n", hostname, gai_strerror(s));
		return 1;
	}
	memcpy(&nmap->target_addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	return 0;
}

void nmap_run(struct nmap_data *nmap, const char *hostname, pcap_t *pcap_handle) {
	time_t scan_overall_start_time, scan_overall_end_time;
	struct nmap_port_result *results = NULL;

	scan_overall_start_time = time(NULL);
	srand(time(NULL)); // Seed for rand() used in packet crafting

	if (nmap_set_target(nmap, hostname)) // nmap_set_target already calls exit on failure
        return; // Should not be reached if nmap_set_target fails
	
    nmap_print_scan_config(nmap, number_of_ports, scan_type, number_of_threads);

	results = malloc(number_of_ports * sizeof(struct nmap_port_result));
	if (results == NULL) {
		nmap_print_error_and_exit("nmap_run: malloc for results failed.");
	}
	for (unsigned int i = 0; i < number_of_ports; ++i) {
		results[i].port_number = ports[i];
		results[i].state = PORT_UNSCANNED;
		strncpy(results[i].service_name, "", sizeof(results[i].service_name) -1);
        results[i].service_name[sizeof(results[i].service_name)-1] = '\0';
	}

	if (debugging) printf("Starting XMIT phase...\n");
	for (unsigned int i = 0; i < number_of_ports; ++i) {
		uint16_t current_port = results[i].port_number; // Use port from results struct
		if (scan_type & SCAN_SYN) { // Assuming only SYN scan for now
			u_char packet_buffer[PACKET_BUF_SIZE];
			size_t packet_size = craft_syn_packet(nmap, current_port, packet_buffer, sizeof(packet_buffer));
			if (packet_size > 0) {
				if (pcap_inject(pcap_handle, packet_buffer, packet_size) == -1) {
					fprintf(stderr, "ERROR: pcap_inject failed for port %u on %s: %s. Continuing scan.\n", 
						current_port, inet_ntoa(nmap->target_addr.sin_addr), pcap_geterr(pcap_handle));
				} else if (debugging > 1) {
					printf("SYN packet sent to %s:%u\n", inet_ntoa(nmap->target_addr.sin_addr), current_port);
				}
			}
		}
		// TODO: Implement other scan types here
	}

	if (debugging) printf("Waiting for responses (RECV phase for %d seconds)...\n", RECV_TIMEOUT_SECONDS);
	time_t recv_phase_start_time = time(NULL);
	struct pcap_pkthdr *pkt_header;
	const u_char *pkt_data;
	int pcap_ret;

	while (1) {
		if (time(NULL) - recv_phase_start_time > RECV_TIMEOUT_SECONDS) {
			if (debugging) printf("Reception timeout reached.\n");
			break;
		}
		pcap_ret = pcap_next_ex(pcap_handle, &pkt_header, &pkt_data);
		if (pcap_ret == 1) {
			analyze_response_packet(pkt_header, pkt_data, nmap, results, number_of_ports);
		} else if (pcap_ret == 0) { // Timeout from pcap_next_ex (normal if pcap_open_live timeout is short)
			if (debugging > 2) printf("Debug: pcap_next_ex timed out (no packet during internal pcap timeout)\n");
			continue; 
		} else if (pcap_ret == PCAP_ERROR_BREAK) { // pcap_breakloop called
			if (debugging) printf("pcap_next_ex: PCAP_ERROR_BREAK received.\n");
			break;
		} else if (pcap_ret == PCAP_ERROR) {
			fprintf(stderr, "pcap_next_ex error: %s. Ending reception phase.\n", pcap_geterr(pcap_handle));
			break;
		}
	}
	scan_overall_end_time = time(NULL);

	printf("\nScan Results for %s (%s):\n", hostname ? hostname : inet_ntoa(nmap->target_addr.sin_addr), inet_ntoa(nmap->target_addr.sin_addr));
	printf("--------------------------------------------------\n");
	printf("%-10s %-10s %s\n", "Port", "State", "Service");
	printf("--------------------------------------------------\n");

	int open_count = 0, closed_count = 0, filtered_count = 0;
	for (unsigned int i = 0; i < number_of_ports; ++i) {
		if (results[i].state == PORT_UNSCANNED) {
			results[i].state = PORT_FILTERED; // Unanswered SYN implies filtered
		}
		if (results[i].state == PORT_OPEN) {
			if (results[i].port_number == 80) strncpy(results[i].service_name, "http", sizeof(results[i].service_name)-1);
			else if (results[i].port_number == 443) strncpy(results[i].service_name, "https", sizeof(results[i].service_name)-1);
			else if (results[i].port_number == 22) strncpy(results[i].service_name, "ssh", sizeof(results[i].service_name)-1);
            else if (results[i].port_number == 21) strncpy(results[i].service_name, "ftp", sizeof(results[i].service_name)-1);
			else if (results[i].port_number == 23) strncpy(results[i].service_name, "telnet", sizeof(results[i].service_name)-1);
			else if (results[i].port_number == 25) strncpy(results[i].service_name, "smtp", sizeof(results[i].service_name)-1);
			else if (results[i].port_number == 53) strncpy(results[i].service_name, "dns", sizeof(results[i].service_name)-1);
            results[i].service_name[sizeof(results[i].service_name)-1] = '\0'; // Ensure null term
		}
		printf("%-10d %-10s %s\n", results[i].port_number, state_to_string(results[i].state), results[i].service_name);
		if (results[i].state == PORT_OPEN) open_count++;
		else if (results[i].state == PORT_CLOSED) closed_count++;
		else if (results[i].state == PORT_FILTERED) filtered_count++;
	}
	printf("--------------------------------------------------\n");
	double scan_duration = difftime(scan_overall_end_time, scan_overall_start_time);
	printf("\nScan Summary:\n");
	printf("Target: %s (%s)\n", hostname ? hostname : inet_ntoa(nmap->target_addr.sin_addr), inet_ntoa(nmap->target_addr.sin_addr));
	printf("Total ports scanned: %u\n", number_of_ports);
	printf("Open ports: %d\n", open_count);
	printf("Closed ports: %d\n", closed_count);
	printf("Filtered ports: %d\n", filtered_count);
	printf("Scan completed in %.2f seconds.\n", scan_duration);

	free(results);
	results = NULL;
}

struct nmap_data *nmap_init() {
	struct nmap_data *nmap = malloc(sizeof(struct nmap_data));
	if (nmap == NULL) {
        nmap_print_error_and_exit("nmap_init: malloc failed.");
    }
	memset(nmap, 0, sizeof(*nmap));
	return nmap;
}

void print_usage_and_exit(char *name) {
	printf("Usage: %s [OPTIONS] --ip <target_ip_or_hostname>\n"
		"OPTIONS:\n"
		"  --help        Print this help screen\n"
		"  --ports <p>   Ports to scan (e.g., '1-1024', '80,443', '22,25,50-100')\n"
		"  --ip <host>   Target IP address or hostname (required)\n"
		"  --file <file> File name containing IP addresses/hostnames to scan (not yet implemented)\n"
		"  --speedup <n> Number of parallel threads [1-250] (not yet implemented)\n"
		"  --scan <type> Scan type(s) (e.g., 'SYN', 'NULL,FIN') (SYN is default)\n"
        "  --debuglevel <lvl> Set debug output verbosity (0=none, 1=basic, 2=detailed, 3=pcap internal)\n",
		name);
	exit(EXIT_FAILURE);
}

void nmap_ip_file_parse(const char *fname) {
  // TODO: Implement parsing IPs from a file
  fprintf(stderr, "Warning: --file option is not yet implemented. Scanning %s instead if provided via --ip.\n", source ? source : "no target");
  if (!source) { // If --file was the only source of targets
      nmap_print_error_and_exit("--file processing not implemented and no --ip target given.");
  }
  (void)fname;
}

char *get_program_name(char *arg) {
	char *pos = strrchr(arg, '/'); // Use strrchr to get last component
	return pos ? pos + 1 : arg;
}

short nmap_get_scan_type_by_name(char *expr) {
    short type_flags = 0;
    char *token;
    char *rest = expr;

    while ((token = strsep(&rest, ",")) != NULL) {
        if (*token == '\0') continue;
        int found = 0;
        for (int i = 0; i < MAXSCANS; ++i) {
            if (strcasecmp(scan_modes[i].name, token) == 0) { // case-insensitive compare
                type_flags |= scan_modes[i].flag;
                found = 1;
                break;
            }
        }
        if (!found) {
            fprintf(stderr, "Warning: Unknown scan type '%s'. Ignoring.\n", token);
        }
    }
    return type_flags;
}


int nmap_arg_parse(int argc, char **argv) { // Removed arg_index, not used
	int opt;
	const struct option long_options[] = {
		{"help", no_argument, 0, 'h'},
		{"ports", required_argument, 0, 'p'},
		{"ip", required_argument, 0, 'i'},
		{"file", required_argument, 0, 'f'},
		{"speedup", required_argument, 0, 's'},
		{"scan", required_argument, 0, 'S'},
        {"debuglevel", required_argument, 0, 'd'},
		{0, 0, 0, 0}
	};
    int option_index = 0; // Required by getopt_long

	program_name = get_program_name(argv[0]);

	if (argc < 2) print_usage_and_exit(program_name);

	while ((opt = getopt_long(argc, argv, "hp:i:f:s:S:d:", long_options, &option_index)) != -1) {
		switch (opt) {
			case 'p':
				if (ports) { // Prevent multiple --ports options
                    free(ports); // Free previously allocated ports if any
                    fprintf(stderr, "Warning: --ports option specified multiple times. Using last definition.\n");
                }
				ports = nmap_get_ports(optarg, &number_of_ports);
				break;
			case 'i':
				if (source) { // Prevent multiple --ip options
                    // free(source); // optarg should not be freed by us here
                    fprintf(stderr, "Warning: --ip option specified multiple times. Using last definition: %s.\n", optarg);
                }
				source = optarg; // This is a pointer to argv, do not free.
				break;
			case 'f':
				if (filename) {
                     fprintf(stderr, "Warning: --file option specified multiple times. Using last definition: %s.\n", optarg);
                }
                filename = optarg;
				break;
			case 's':
				number_of_threads = atoi(optarg);
				if (number_of_threads == 0 || number_of_threads > MAXTHREADS) {
                    fprintf(stderr, "Invalid number for speedup: %s. Must be 1-%d.\n", optarg, MAXTHREADS);
                    nmap_print_error_and_exit("Invalid speedup value.");
                }
				break;
			case 'S':
                if (scan_type != 0) {
                     fprintf(stderr, "Warning: --scan option specified multiple times or combined. Resulting scan_type: %d\n", scan_type);
                }
				scan_type |= nmap_get_scan_type_by_name(optarg);
				break;
            case 'd':
                debugging = atoi(optarg);
                if (debugging < 0 || debugging > 3) {
                    fprintf(stderr, "Invalid debug level: %s. Must be 0-3.\n", optarg);
                    debugging = 1; // Default to 1
                }
                break;
			case 'h':
			default: /* '?' */
				print_usage_and_exit(program_name);
		}
	}

    // After loop, optind is the index in argv of the first argv-element that is not an option.
    // We don't expect non-option arguments other than for --ip, --ports etc.
    if (optind < argc) {
        printf("Warning: Non-option ARGV-elements: ");
        while (optind < argc)
            printf("%s ", argv[optind++]);
        printf("\nIgnoring non-option arguments.\n");
    }

	if (!source && !filename) {
        nmap_print_error_and_exit("Target host must be specified with --ip or --file.");
    }
    if (filename && source) {
		fprintf(stderr, "Warning: Both --ip and --file options used. --ip '%s' will be scanned. --file '%s' will be ignored.\n", source, filename);
        // Or choose to scan both, or error out. Current behavior: --ip takes precedence if both.
        // For now, let --ip take precedence. If --file is to be used, --ip should not be.
        // To make it strict:
        // nmap_print_error_and_exit("--ip and --file options cannot be used at the same time.");
	}
    if (filename && !source) { // Only --file is specified
        nmap_ip_file_parse(filename); // This function needs to set 'source' or handle multiple targets
    }


	if (!number_of_ports) { // If --ports not given
		ports = nmap_get_ports(DEFAULT_PORT_RANGE, &number_of_ports);
	}
	if (!scan_type) { // If --scan not given
		scan_type = SCAN_SYN; // Default to SYN scan
	}
	return 0;
}

pcap_t *nmap_get_pcap_handle() {
	pcap_if_t *alldevs, *dev_iter;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap_handle_local; // Renamed to avoid conflict if any global named pcap_handle
    char *default_dev_name = NULL;

	if (pcap_findalldevs(&alldevs, errbuf) == PCAP_ERROR) {
		fprintf(stderr, "Couldn't find any device: %s\n", errbuf);
		exit(EXIT_FAILURE); // Cannot proceed without devices
	}

    // Attempt to find a suitable default device (e.g., "eth0", "en0")
    // This part is very OS-dependent. For now, using the first non-loopback device.
    for (dev_iter = alldevs; dev_iter != NULL; dev_iter = dev_iter->next) {
        if (dev_iter->name && !(dev_iter->flags & PCAP_IF_LOOPBACK)) {
            default_dev_name = dev_iter->name;
            break;
        }
    }

    if (!default_dev_name && alldevs) { // Fallback to the first device if no non-loopback found
        default_dev_name = alldevs->name;
    }

	if (!default_dev_name) {
        fprintf(stderr, "No suitable network interface found.\n");
        pcap_freealldevs(alldevs);
        exit(EXIT_FAILURE);
    }

	if (debugging) printf("Using interface: %s\n", default_dev_name);

    // pcap_open_live: (device, snaplen, promisc, to_ms, errbuf)
    // BUFSIZ is from <stdio.h>, typically 8192. snaplen should be large enough for expected packets.
    // to_ms = 1000ms (1s timeout for pcap_next_ex). If 0, pcap_next_ex blocks.
	pcap_handle_local = pcap_open_live(default_dev_name, BUFSIZ, PROMISC_TRUE, 1000, errbuf);
	if (pcap_handle_local == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", default_dev_name, errbuf);
		pcap_freealldevs(alldevs);
		exit(EXIT_FAILURE);
	}

	if (pcap_datalink(pcap_handle_local) != DLT_EN10MB) { // Check if Ethernet headers are available
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported by this version of ft_nmap.\n", default_dev_name);
		pcap_close(pcap_handle_local);
		pcap_freealldevs(alldevs);
		exit(EXIT_FAILURE);
	}

	pcap_freealldevs(alldevs); // Free the device list
	return pcap_handle_local;
}

int main(int argc, char **argv) {
	pcap_t *pcap_handle_main; // Renamed to make it clear it's main's copy
	struct nmap_data *nmap_main; // Renamed

	nmap_arg_parse(argc, argv); // Parses args and populates globals like 'ports', 'source', 'scan_type'

	pcap_handle_main = nmap_get_pcap_handle(); // Exits on failure

	nmap_main = nmap_init(); // Exits on failure

    // 'source' global variable (target hostname/IP) is used by nmap_run
	nmap_run(nmap_main, source, pcap_handle_main);

    if (debugging) printf("Cleaning up resources...\n");
	free(nmap_main);
	free(ports); // Ports array allocated in nmap_get_ports
	pcap_close(pcap_handle_main);
	
    if (debugging) printf("ft_nmap finished.\n");
	return 0;
}
