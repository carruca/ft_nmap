NAME    	= ft_nmap

INCSPATH  = inc/
SRCSPATH	= src/
OBJSPATH	= obj/

SRCSFILES	= \
						checksum.c \
						error.c \
						fqdn.c \
						ft_nmap.c \
						get_pcap_handle.c \
						get_ports.c \
						get_raw_socket_by_protocol.c \
						get_scan_mode.c \
						get_scan_type_by_name.c \
						ip_file_parse.c \
						packet_response.c \
						print_usage.c \
						scan_probe_list_create.c \
						scan_probe_list_destroy.c \
						probe_send_syn.c \
						scan_config_print.c \
						scan_create.c \
						scan_destroy.c \
						scan_init.c \
						scan_options_parse.c \
						scan_options_program_name_set.c \
						scan_options_destroy.c \
						scan_run.c \
						scan_source_sockaddr_set.c \
						scan_target_sockaddr_set.c \
						set_pcap_filter.c \
						tcp_checksum.c \
						logging/config.c \
						logging/core.c \
						logging/level_string.c \
						logging/level.c \
						logging/message.c \
						logging/name.c \
						logging/stream.c \


SRCS			= $(addprefix $(SRCSPATH), $(SRCSFILES))
OBJS			= $(patsubst $(SRCSPATH)%, $(OBJSPATH)%, $(SRCS:.c=.o))
DEPS			= $(OBJS:.o=.d)

LIBFTPATH	= libft/
LIBFT			= $(LIBFTPATH)/libft.a

RM 				= rm -rf
CC      	= gcc
CFLAGS  	= -Wall -Werror -Wextra -MMD -Wunused -D_DEFAULT_SOURCE
INC 			= -I$(INCSPATH) -I$(LIBFTPATH)
LDFLAGS 	= -lm -lpcap -lpthread -L $(LIBFTPATH) -lft
FSANITIZE = -g3 -fsanitize=address -fsanitize=leak -fsanitize=undefined -fsanitize=bounds -fsanitize=null

all: $(NAME)

$(OBJSPATH)%.o: $(SRCSPATH)%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(INC) -c $< -o $@

$(NAME): $(OBJS) $(LIBFT)
	$(CC) $(OBJS) -o $(NAME) $(LDFLAGS)

$(LIBFT): 
	$(MAKE) -s -C $(LIBFTPATH)

SILENT += print
print:
	echo $(SRCS)
	echo $(OBJS)

own: $(NAME)
	sudo chown root:root $(NAME)
	sudo chmod u+s $(NAME)

sanitize: LDFLAGS += $(FSANITIZE)
sanitize: CFLAGS += $(FSANITIZE)
sanitize: $(NAME)

tags:
	ctags $(SRCS)

clean:
	$(MAKE) -s -C $(LIBFTPATH) clean
	$(RM) $(OBJSPATH)

fclean: clean
	$(MAKE) -s -C $(LIBFTPATH) fclean
	$(RM) $(NAME)

re: fclean all

-include $(DEPS)

docker:
	docker compose -f docker/docker-compose.yml up -d --build

sh:
	docker compose -f docker/docker-compose.yml exec nmap_develop sh

run:
	./$(NAME) --help

.SILENT: $(SILENT)
.PHONY: docker sh tags run all clean fclean re sanitize own print
