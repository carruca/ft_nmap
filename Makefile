NAME    	= ft_nmap

SRCSPATH	= src/
OBJSPATH	= obj/
SRCSFILES	= \
						ft_nmap.c
SRCS			= $(addprefix $(SRCSPATH), $(SRCSFILES))
OBJS			= $(patsubst $(SRCSPATH)%, $(OBJSPATH)%, $(SRCS:.c=.o))

CC      	= gcc
CFLAGS  	= -Wall -Werror -Wextra
INC 			= -I.
LDFLAGS 	= -lm -lpcap
FSANITIZE = -g3 -fsanitize=address -fsanitize=leak -fsanitize=undefined -fsanitize=bounds -fsanitize=null

all: $(NAME)

$(OBJSPATH)%.o: $(SRCSPATH)%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(INC) -c $< -o $@

$(NAME): $(OBJS)
	$(CC) $(OBJS) -o $(NAME) $(LDFLAGS)

SILENT += print
print:
	echo $(SRCS)
	echo $(OBJS)

config: $(NAME)
	sudo chown root:root $(NAME)
	sudo chmod u+s $(NAME)

sanitize: LDFLAGS += $(FSANITIZE)
sanitize: $(NAME)

tag:
	$(RM) tags
	ctags $(SRCS)

clean:
	$(RM) $(OBJS)

fclean: clean
	$(RM) $(NAME)

re: fclean all

.SILENT: $(SILENT)
