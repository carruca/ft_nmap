#include "ft_nmap.h"

const struct scan_mode *get_scan_mode(int index)
{
  static struct scan_mode scan_modes[] =
  {
    {"SYN", SCAN_SYN, NULL}, // syn_encode_and_send}
    {"ACK", SCAN_ACK, NULL},
    {"FIN", SCAN_FIN, NULL},
    {"XMAS", SCAN_XMAS, NULL},
    {"NULL", SCAN_NULL, NULL},
    {"UDP", SCAN_UDP, NULL},
  }; 

  return (scan_modes + index);
}
