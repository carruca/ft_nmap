NAME    	= ft_nmap

INCSPATH  = inc/
SRCSPATH	= src/
OBJSPATH	= obj/

SRCSFILES	= \
						checksum.c \
						ft_nmap.c	\
						get_pcap_handler.c \
						get_ports.c \
						get_probe_batch.c \
						get_program_name.c \
						get_raw_socket_by_protocol.c \
						get_scan_mode.c \
						nmap_get_scan_technique_by_name.c \
						nmap_ip_file_parse.c \
						nmap_print_error_and_exit.c \
						packet_capture_thread.c \
						packet_create.c \
						packet_dequeue.c \
						packet_destroy.c \
						packet_enqueue.c \
						packet_queue_create.c \
						packet_queue_destroy.c \
						packet_queue_handler.c \
						packet_response.c \
						packet_worker_thread.c \
						parse_args.c \
						print_usage_and_exit.c \
						probe_list_create.c \
						scan_probe_list_destroy.c \
						probe_list_timeout.c \
						probe_print.c \
						probe_syn_send.c \
						probe_update.c \
						scan_engine_config_print.c \
						scan_engine_destroy.c \
						scan_engine_init.c \
						scan_engine_results_print.c \
						scan_options_free.c \
						scan_ports.c \
						scan_ports_parallel.c \
						send_probe_batch.c \
						send_probe_list.c \
						send_worker_create.c \
						send_worker_thread.c \
						set_local_sockaddr.c \
						set_pcap_filter.c \
						set_socketaddr_by_hostname.c \
						tcp_checksum.c \
						tvsub.c \


SRCS			= $(addprefix $(SRCSPATH), $(SRCSFILES))
OBJS			= $(patsubst $(SRCSPATH)%, $(OBJSPATH)%, $(SRCS:.c=.o))
DEPS			= $(OBJS:.o=.d)

LIBFTPATH	= libft/
LIBFT			= $(LIBFTPATH)/libft.a

CC      	= gcc
CFLAGS  	= -Wall -Werror -Wextra -MMD
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
sanitize: $(NAME)

tag:
	$(RM) tags
	ctags $(SRCS)

clean:
	$(MAKE) -s -C $(LIBFTPATH) clean
	$(RM) $(OBJS)

fclean: clean
	$(MAKE) -s -C $(LIBFTPATH) fclean
	$(RM) $(NAME)

re: fclean all

-include $(DEPS)


.SILENT: $(SILENT)
