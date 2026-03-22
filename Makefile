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
					get_scan_type_by_name.c \
					ip_file_parse.c \
					probe_match.c \
					print_usage.c \
					probe_mark_sent.c \
					probe_send.c \
					probe_send_tcp.c \
					probe_send_udp.c \
					scan_defs.c \
					probe_dequeue.c \
					probe_list_create.c \
					probe_list_destroy.c \
					scan_config_print.c \
					scan_results_print.c \
					scan_create.c \
					scan_destroy.c \
					scan_opts_parse.c \
					scan_opts_destroy.c \
					scan_run.c \
					scan_thread_init.c \
					scan_thread_run.c \
					scan_thread_entry.c \
					scan_thread_dispatch.c \
					scan_thread_destroy.c \
					scan_detect_source.c \
					scan_resolve_target.c \
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
