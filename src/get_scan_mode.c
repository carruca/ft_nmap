#include "ft_nmap.h"

const struct scan_mode *get_scan_mode(int index)
{
  static struct scan_mode scan_modes[] = 
  {
    {"NULL", SCAN_NULL, NULL},
    {"FIN", SCAN_FIN, NULL},
    {"XMAS", SCAN_XMAS, NULL},
    {"ACK", SCAN_ACK, NULL},
    {"UDP", SCAN_UDP, NULL},
    {"SYN", SCAN_SYN, NULL}, // syn_encode_and_send}
  }; 

  return (scan_modes + index);
}
