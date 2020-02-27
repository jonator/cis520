#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/pte.h"
#include "userprog/pagedir.h"
//#include "lib/user"

static void syscall_handler (struct intr_frame *);

bool
is_valid_user_pointer (void *vaddr)
{
  return vaddr != NULL 
        && is_user_vaddr (vaddr)
        && pagedir_get_page (thread_current ()->pagedir, vaddr);
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  // TODO - Needs to get system call number, then any arguments
  // then carry out appropriate actions
  printf ("system call!\n");
  // if (!is_valid_user_pointer (/* ? */))
  // try debugging to get where vaddr is
  thread_exit ();
}

void
halt (void)
{
  // TODO - Terminate Pintos by calling power_off()
}

void
exit (int status)
{
  // TODO
}

// pid_t
// exec (const char *cmd_line)
// {
//   // TODO
//   return 0;
// }

// int
// wait (pid_t p)
// {
//   // TODO
//   return 0;
// }

bool
create (const char *file, unsigned initial_size)
{
  // TODO
  return false;
}

bool
remove (const char *file)
{
  // TODO
  return false;
}

int 
open (const char *file)
{
  // TODO
  return 0;
}

int
filesize (int fd)
{
  // TODO
  return 0;
}

int
read (int fd, void *buffer, unsigned size)
{
  // TODO
  return 0;
}

int
write (int fd, const void *buffer, unsigned size)
{
  // TODO
  return 0;
}

void
seek (int fd, unsigned position)
{
  // TODO
}

unsigned
tell (int fd)
{
  // TODO
  return 0;
}

void
close (int fd)
{
  // TODO
}
