#include "ft_nmap.h"

/*
** fqdn_is_valid_ipv4
**
** Valida que el string sea una IPv4 válida: 4 octetos entre 0-255
** separados por puntos. Solo usa strtok_r y strtol — sin resolución.
*/
static int
fqdn_is_valid_ipv4(const char *str)
{
	char	buf[16];
	char	*token;
	char	*rest;
	char	*endptr;
	long	octet;
	int		count;

	if (!str || strlen(str) > 15)
		return 0;

	strncpy(buf, str, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';

	count = 0;
	rest = buf;
	while ((token = strtok_r(rest, ".", &rest)))
	{
		if (*token == '\0')
			return 0;
		octet = strtol(token, &endptr, 10);
		if (*endptr != '\0' || octet < 0 || octet > 255)
			return 0;
		count++;
	}
	return count == 4;
}

/*
** fqdn_is_valid_hostname
**
** Valida que el string sea un hostname/FQDN válido:
**   - longitud total <= 253 caracteres
**   - labels separados por puntos, cada uno de 1-63 chars
**   - caracteres válidos: a-z A-Z 0-9 guión
**   - el guión no puede estar al inicio ni al final de un label
*/
static int
fqdn_is_valid_hostname(const char *str)
{
	char		buf[254];
	char		*token;
	char		*rest;
	size_t		label_len;
	size_t		total_len;
	const char	*c;

	total_len = strlen(str);
	if (total_len == 0 || total_len > 253)
		return 0;

	strncpy(buf, str, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';

	rest = buf;
	while ((token = strtok_r(rest, ".", &rest)))
	{
		label_len = strlen(token);
		if (label_len == 0 || label_len > 63)
			return 0;
		if (token[0] == '-' || token[label_len - 1] == '-')
			return 0;
		for (c = token; *c; c++)
			if (!isalnum((unsigned char)*c) && *c != '-')
				return 0;
	}
	return 1;
}

/*
** fqdn_is_valid
**
** Acepta IPv4 (192.168.1.1) o hostname/FQDN (google.com).
** Retorna 1 si válido, 0 si no.
*/
int
fqdn_is_valid(const char *str)
{
	return fqdn_is_valid_ipv4(str) || fqdn_is_valid_hostname(str);
}
