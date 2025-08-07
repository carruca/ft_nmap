/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstiter_if.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: tsierra- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/03/01 11:51:29 by tsierra-          #+#    #+#             */
/*   Updated: 2021/03/01 11:52:58 by tsierra-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	ft_lstiter_if(t_list *lst, void *cond,
		int (*cmp)(), void (*f)(void *))
{
	while (lst)
	{
		if (cmp(cond, lst->content) == 0)
			f(lst->content);
		lst = lst->next;
	}
}
