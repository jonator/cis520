#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/pte.h"
#include "userprog/pagedir.h"

static void syscall_handler (struct intr_frame *);
void halt (void);
void exit (int);
pid_t exec (const char *);
int wait (pid_t);
bool create (const char*, unsigned);
bool remove (const char*);
int open (const char*);
int filesize (int);
int read (int, void*, unsigned);
int write (int, const void *, unsigned);
void seek (int, unsigned);
unsigned tell (int);
void close (int);

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
syscall_handler (struct intr_frame *f) 
{
  int fd;
  int status;
  pid_t pid;
  char *file;
  unsigned int initial_size;
  int size;
  void *buffer;
  unsigned int position;

  switch (*((int*)f->esp))
  {
    case SYS_HALT:
      halt ();
      break;
    case SYS_EXIT:
      status = *((int*) (f->esp + sizeof(int)));
      exit (status);
      break;
    case SYS_WAIT:
      pid = (int) (f->esp + sizeof(int));
      wait (pid);
      break;
    case SYS_CREATE:
      file = (char*) *((int*) (f->esp + sizeof(int)));
      initial_size = *((int*) (f->esp + sizeof(int) * 2));
      create (file, initial_size);
      break;
    case SYS_REMOVE:
      file = (char*) *((int*) (f->esp + sizeof(int)));
      if (is_valid_user_pointer (file))
        remove (file);
      break;
    case SYS_OPEN:
      file = 0;
      open (file);
      break;
    case SYS_FILESIZE:
      fd = *((int*) (f->esp + sizeof(int)));
      filesize (fd);
      break;
    case SYS_READ:
      fd = *((int*) (f->esp + sizeof(int)));
      buffer = (void*) *((int*) (f->esp + sizeof(int) * 2));
      size = 0;
      if (is_valid_user_pointer (buffer))
        read (fd, buffer, size);
      break;
    case SYS_WRITE:
      fd = *((int*) (f->esp + sizeof(int)));
      buffer = (void*) *((int*) (f->esp + sizeof(int) * 2));
      size = *((int*) (f->esp + sizeof(int) * 3));
      if (is_valid_user_pointer (buffer))
        write (fd, buffer, size);
      break;
    case SYS_SEEK:
      fd = *((int*) (f->esp + sizeof(int)));
      position = *((int*) (f->esp + sizeof(int) * 2));
      seek (fd, position);
      break;
    case SYS_TELL:
      fd = *((int*) (f->esp + sizeof(int)));
      tell (fd);
      break;
    case SYS_CLOSE:
      fd = *((int*) (f->esp + sizeof(int)));
      close (fd);
      break;
  }
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

pid_t
exec (const char *cmd_line)
{
  // TODO
  return 0;
}

int
wait (pid_t p)
{
  // TODO
  return 0;
}

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
  switch (fd)
  {
    case 1:
    case 2:
      putbuf (buffer, size);
      break;

    default:
      break;
  }
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
