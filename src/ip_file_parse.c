#include "ft_nmap.h"
#include "logging/log.h"

void
ip_file_parse(t_opts *opts, const char *filename)
{
	FILE	*stream;
	char	line[HOST_NAME_MAX];
	char	**targets;
	char	*newline;
	int		count;
	int		capacity;

	stream = fopen(filename, "r");
	if (stream == NULL)
	{
		log_message(LOG_LEVEL_FATAL, "fopen: not able to open the file.");
		exit(EXIT_FAILURE);
	}

	capacity = 16;
	count = 0;
	targets = malloc(capacity * sizeof(char *));
	if (targets == NULL)
	{
		fclose(stream);
		log_message(LOG_LEVEL_FATAL, "malloc failed");
		exit(EXIT_FAILURE);
	}

	while (fgets(line, sizeof(line), stream))
	{
		newline = strchr(line, '\n');
		if (newline)
			*newline = '\0';

		if (*line == '\0' || *line == '#')
			continue;

		if (!fqdn_is_valid(line))
		{
			log_message(LOG_LEVEL_WARN, "skipping invalid target: %s", line);
			continue;
		}

		if (count == capacity)
		{
			capacity *= 2;
			targets = realloc(targets, capacity * sizeof(char *));
			if (targets == NULL)
			{
				fclose(stream);
				log_message(LOG_LEVEL_FATAL, "realloc failed");
				exit(EXIT_FAILURE);
			}
		}
		log_message(LOG_LEVEL_DEBUG, "target added: %s", line);
		targets[count++] = strdup(line);
	}
	fclose(stream);

	if (count == 0)
	{
		free(targets);
		log_message(LOG_LEVEL_FATAL, "no valid targets found in file.");
		exit(EXIT_FAILURE);
	}

	log_message(LOG_LEVEL_INFO, "loaded %d target(s) from %s", count, filename);
	opts->file_targets = targets;
	opts->num_file_targets = count;
}
