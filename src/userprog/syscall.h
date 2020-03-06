#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <list.h>

typedef int pid_t;

struct process_exit_record
{
  pid_t pid;
  int exit_status;
  struct list_elem elem;
};

struct process_parent_child
{
  struct thread *parent;
  pid_t child_pid;
  bool is_blocking_parent;
  bool is_parent_alive;
  struct list_elem elem;
};

void syscall_init (void);
bool try_get_process_parent_child (pid_t, struct process_parent_child **)

#endif /* userprog/syscall.h */
