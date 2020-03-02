#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/malloc.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/pte.h"
#include "userprog/pagedir.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include <list.h>

struct open_file {
    int fd;
    struct file *file;
    struct list_elem elem;
};
struct file *get_file (int);

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

struct file
*get_file(int fd)
{
  struct list *open_files = &thread_current ()->open_files;
  struct list_elem *open_file;
  
  struct list_elem *e;
  for (e = list_begin (&open_files); e != list_end (&open_files);
      e = list_next (e))
  {
    struct open_file *cur = list_entry (e, struct open_file, elem);
    if (cur->fd == fd)
      return cur;
  }
  return NULL;
}

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
      file = (char*) *((int*) (f->esp + sizeof(int)));
      if (is_valid_user_pointer (file))
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
  // TODO - Terminate Pintos by shutdown_calling power_off()
  shutdown_power_off ();
  thread_exit ();
}

void
exit (int status)
{
  // TODO return status to kernel
  thread_exit ();
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
  struct file *opened_file = filesys_open (file);
  if (opened_file == NULL)
    return -1;

  struct thread *t = thread_current ();
  struct open_file *new_open_file = malloc (sizeof(struct open_file));
  new_open_file->fd = t->next_fd++;
  new_open_file->file = opened_file;
  list_push_back (&t->open_files, &new_open_file->elem);
  
  return new_open_file->fd;
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
    case 0:
    case 1:
      putbuf (buffer, size);
      return size;
    default:
      if (fd > 1)
      {
        struct file *file = get_file (fd);
        if (file != NULL)
        {
          return file_write (file, buffer, size);
        }
      }
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
