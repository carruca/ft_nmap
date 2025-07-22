# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: tsierra- <marvin@42.fr>                    +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2019/11/07 17:05:33 by tsierra-          #+#    #+#              #
#    Updated: 2021/05/24 16:53:33 by tsierra-         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME = libft

LNAME = libft.a

CFLAGS = -Wall -Werror -Wextra

LFLAGS = -c

LSOURCE = \
		  ft_lstnew.c \
		  ft_lstadd_front.c \
		  ft_lstadd_back.c \
		  ft_lstclear.c \
		  ft_lstdelone.c \
		  ft_lstiter.c \
		  ft_lstlast.c \
		  ft_lstmap.c \
		  ft_lstsize.c \
		  ft_lstsize_if.c \
		  ft_lstfind.c \
		  ft_lsttoa_if.c \
		  ft_lstclone.c \
		  ft_lstsort.c \
		  ft_lstremove_if.c \

OBJS = $(LSOURCE:.c=.o)

all: $(NAME)

$(NAME):
	gcc $(CFLAGS) $(LFLAGS) $(LSOURCE)
	ar rcs $(LNAME) $(OBJS) 

clean:
	rm -f $(OBJS)
fclean:	clean
	rm -f $(LNAME)

re: fclean all

.PHONY: clean fclean all re
