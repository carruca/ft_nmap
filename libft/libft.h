/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   libft.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: tsierra- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/11/11 12:15:52 by tsierra-          #+#    #+#             */
/*   Updated: 2021/06/02 20:19:28 by tsierra-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_H
# define LIBFT_H

# include <string.h>
# include <strings.h>
# include <ctype.h>
# include <stdlib.h>
# include <stddef.h>
# include <unistd.h>
# include <fcntl.h>

typedef struct s_list
{
	void			*content;
	struct s_list	*next;
}					t_list;

t_list	*ft_lstnew(void *content);
void	ft_lstadd_front(t_list **lst, t_list *new);
int		ft_lstsize(t_list *lst);
int		ft_lstsize_if(t_list *lst, int (*cmp)());
t_list	*ft_lstlast(t_list *lst);
void	ft_lstadd_back(t_list **lst, t_list *new);
void	ft_lstdelone(t_list *lst, void (*del)(void *));
void	ft_lstclear(t_list **lst, void (*del)(void *));
void	ft_lstiter(t_list *lst, void (*f)(void *));
void	ft_lstiter_if(t_list *lst, void *cond, int (*cmp)(), void (*f)(void *));
t_list	*ft_lstmap(t_list *lst, void *(*f)(void *), void (*del)(void *));
t_list	*ft_lstfind(t_list *lst, void *content, int (*cmp)(void *, void *));
char	**ft_lsttoa_if(t_list *lst, char *(*cpy)(), int (*cmp)());
t_list	*ft_lstclone(t_list *lst, void (*del)(void *));
void	ft_lstsort(t_list *lst, int (*cmp)());
void	ft_lstremove_if(t_list **alst, void *content,
			int (*cmp)(), void (*del)(void *));
void	ft_free_tab(char **ptr);

#endif
