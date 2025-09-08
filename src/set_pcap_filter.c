#include "ft_nmap.h"

int
set_pcap_filter(pcap_t *pcap_handle, char *filter_exp)
{
	struct bpf_program fp;

	if (pcap_compile(pcap_handle, &fp, filter_exp, 0, 0) == -1)
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
			filter_exp,
			pcap_geterr(pcap_handle));
		return 1;
	}
	if (pcap_setfilter(pcap_handle, &fp) == -1)
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n",
			filter_exp,
			pcap_geterr(pcap_handle));
		return 1;
	}
	pcap_freecode(&fp);
	return 0;
}
