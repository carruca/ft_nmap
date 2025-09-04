NAME    	= ft_nmap

SRCSPATH	= src/
OBJSPATH	= obj/
SRCSFILES	= \
						ft_nmap.c
SRCS			= $(addprefix $(SRCSPATH), $(SRCSFILES))
OBJS			= $(patsubst $(SRCSPATH)%, $(OBJSPATH)%, $(SRCS:.c=.o))

LIBFTPATH	= libft/
LIBFT			= $(LIBFTPATH)/libft.a

CC      	= gcc
CFLAGS  	= -Wall -Werror -Wextra
INC 			= -I. -I$(LIBFTPATH)
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

.SILENT: $(SILENT)
