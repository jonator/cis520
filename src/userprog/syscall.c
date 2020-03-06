#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/malloc.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/pte.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "lib/string.h"
#include <list.h>
#include "devices/input.h"

struct open_file {
    int fd;
    struct file *file;
    char *file_name;
    struct list_elem elem;
};
struct open_file *open_file_create (struct file*, const char*);
struct open_file *get_open_file (int);
struct open_file *get_open_file_by_name (const char*);

// struct process_exit_record
// {
//   pid_t pid;
//   int exit_status;
//   struct list_elem elem;
// };
void process_exit_record_init (struct process_exit_record*, pid_t, int);

// struct process_parent_child
// {
//   struct thread *parent;
//   pid_t child_pid;
//   bool is_blocking_parent;
//   bool is_parent_alive;
//   struct list_elem elem;
// };
void process_parent_child_init (struct process_parent_child*, struct thread*);

static struct list process_exit_records;
static struct list process_children;

bool is_valid_user_pointer (void *);
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

void
process_exit_record_init (struct process_exit_record *r, pid_t pid, int status)
{
  r->pid = pid;
  r->exit_status = status;
}

void
process_parent_child_init (struct process_parent_child *pc, struct thread *parent)
{
  pc->parent = parent;
  pc->is_blocking_parent = false;
  pc->is_parent_alive = true;
  pc->child_pid = NULL;
}

struct open_file
*open_file_create (struct file *file, const char *file_name)
{
  struct thread *t = thread_current ();
  struct open_file *new_open_file = malloc (sizeof(struct open_file));
  new_open_file->fd = t->next_fd++;
  new_open_file->file = file;

  int len = strlen (file_name);
  new_open_file->file_name = malloc (sizeof (char) * len + 1);
  memcpy (new_open_file->file_name, file_name, len);

  list_push_back (&t->open_files, &new_open_file->elem);
  
  return new_open_file;
}

struct open_file
*get_open_file(int fd)
{
  struct list *open_files = &thread_current ()->open_files;
  
  if (!list_empty (open_files))
  {
    struct list_elem *e;
    for (e = list_begin (open_files); e != list_end (open_files);
        e = list_next (e))
    {
      struct open_file *cur = list_entry (e, struct open_file, elem);
      if (cur->fd == fd)
        return cur;
    }
  }
  return NULL;
}

struct open_file
*get_open_file_by_name (const char *file_name)
{
  struct list *open_files = &thread_current ()->open_files;
  
  if (!list_empty (open_files))
  {
    struct list_elem *e;
    for (e = list_begin (open_files); e != list_end (open_files);
        e = list_next (e))
    {
      struct open_file *cur = list_entry (e, struct open_file, elem);
      if (strcmp (file_name, cur->file_name) == 0)
        return cur;
    }
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
  list_init (&process_exit_records);
  list_init (&process_children);
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
  int return_value = NULL;

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
      pid = *((int*) (f->esp + sizeof(int)));
      return_value = wait (pid);
      break;
    case SYS_CREATE:
      file = (char*) *((int*) (f->esp + sizeof(int)));
      initial_size = *((int*) (f->esp + sizeof(int) * 2));
      return_value = (int) create (file, initial_size);
      break;
    case SYS_REMOVE:
      file = (char*) *((int*) (f->esp + sizeof(int)));
      if (is_valid_user_pointer (file))
        return_value = (int) remove (file);
      break;
    case SYS_OPEN:
      file = (char*) *((int*) (f->esp + sizeof(int)));
      if (is_valid_user_pointer (file))
        return_value = open (file);
      break;
    case SYS_FILESIZE:
      fd = *((int*) (f->esp + sizeof(int)));
      return_value = filesize (fd);
      break;
    case SYS_READ:
      fd = *((int*) (f->esp + sizeof(int)));
      buffer = (void*) *((int*) (f->esp + sizeof(int) * 2));
      size = *((int*) (f->esp + sizeof(int) * 3));
      if (is_valid_user_pointer (buffer))
        return_value = read (fd, buffer, size);
      break;
    case SYS_WRITE:
      fd = *((int*) (f->esp + sizeof(int)));
      buffer = (void*) *((int*) (f->esp + sizeof(int) * 2));
      size = *((int*) (f->esp + sizeof(int) * 3));
      if (is_valid_user_pointer (buffer))
        return_value = write (fd, buffer, size);
      break;
    case SYS_SEEK:
      fd = *((int*) (f->esp + sizeof(int)));
      position = *((int*) (f->esp + sizeof(int) * 2));
      seek (fd, position);
      break;
    case SYS_TELL:
      fd = *((int*) (f->esp + sizeof(int)));
      return_value = (int) tell (fd);
      break;
    case SYS_CLOSE:
      fd = *((int*) (f->esp + sizeof(int)));
      close (fd);
      break;
  }

  // set callers's return registers
  f->eax = return_value;
}

void
halt (void)
{
  //TODO - not done yet
  shutdown_power_off (); // not right
  thread_exit ();
}

bool
try_get_process_parent_child (pid_t child_pid
                            , struct process_parent_child **ppc)
{
  if (!list_empty (&process_children))
  {
    struct list_elem *e;
    for (e = list_begin (&process_children); e != list_end (&process_children);
        e = list_next (e))
    {
      struct process_parent_child *cur = list_entry (e, struct process_parent_child, elem);
      if (cur->child_pid == child_pid)
      {
        *ppc = cur;
        return true;
      }
    }
  }
  return false;
}

bool
try_get_process_exit_record (pid_t child_pid
                            , struct process_exit_record **per)
{
  if (!list_empty (&process_exit_records))
  {
    struct list_elem *e;
    for (e = list_begin (&process_exit_records); e != list_end (&process_exit_records);
        e = list_next (e))
    {
      struct process_exit_record *cur = list_entry (e, struct process_exit_record, elem);
      if (cur->pid == child_pid)
      {
        *per = cur;
        return true;
      }
    }
  }
  return false;
}

void
push_exit_records (pid_t pid, int status)
{
  struct process_exit_record *p_exit = malloc (sizeof (struct process_exit_record));
  process_exit_record_init (p_exit, pid, status);
  list_push_back (&process_exit_records, p_exit);
}

bool
try_remove_exit_records (pid_t pid)
{
  if (!list_empty (&process_exit_records))
  {
    struct list_elem *e;
    for (e = list_begin (&process_exit_records);
        e != list_end (&process_exit_records);
        e = list_next (e))
    {
      struct process_exit_record *cur = list_entry (e
                                            , struct process_exit_record
                                            , elem);
      if (cur->pid == pid)
      {
        list_remove (&cur->elem);
        free (cur);
        return true;
      }      
    }
  }
  return false;
}

void
exit_as_parent (tid_t parent)
{
  if (!list_empty (&process_children))
  {
    struct list_elem *e;
    for (e = list_begin (&process_children); e != list_end (&process_children);
        e = list_next (e))
    {
      struct process_parent_child *cur = list_entry (e, struct process_parent_child, elem);
      if (cur->parent->tid == parent)
      {
        if (try_remove_exit_records (cur->child_pid))
        {
          list_remove (&cur->elem);
          free (cur);
        }
        else
        {
          cur->is_parent_alive = false;
        }
      }
    }
  }
}

void
exit_as_child (pid_t child, int status)
{
  struct process_parent_child *ppc;
  if (try_get_process_parent_child (child, &ppc))
  {
    if (ppc->is_parent_alive)
    {
      push_exit_records ((pid_t) child, status);
      if (ppc->is_blocking_parent)
      {
        thread_unblock (ppc->parent);
      }
    }
    else
    {
      list_remove (&ppc->elem);
      free (ppc);
    }
  }
  else
  {
    // parent hasn't returned from thread_create
    // child exited
    push_exit_records (child, status);
  }
}


void
exit (int status)
{
  struct thread *cur = thread_current ();
  printf("%s: exit(%d)\n", cur->name, status);

  exit_as_parent (cur->tid);
  exit_as_child (cur->tid, status);

  thread_exit ();
}

pid_t
exec (const char *cmd_line)
{
  // TODO - This likely needs to move most functionality into process_execute
  struct thread *cur = thread_current ();
  struct process_parent_child *p_child = malloc (sizeof (struct process_parent_child));
  process_parent_child_init (p_child, cur);
  list_push_back (&process_children, &p_child->elem);
  p_child->child_pid = process_execute (cmd_line);

  return p_child->child_pid;
}


int
wait (pid_t p)
{
  // all wait functionality needs to be in process_wait ()
  // may mean we expose a lot from this file
  return process_wait (p);
}

bool
create (const char *file, unsigned initial_size)
{
  return filesys_create (file, initial_size);
}

bool
remove (const char *file)
{
  struct file *opened_file = filesys_open (file);
  if (opened_file == NULL)
    return false;
  inode_remove (file_get_inode (opened_file));
  return true;
}

int 
open (const char *file)
{
  struct open_file *opened_file = get_open_file_by_name (file);
  struct file *file_ptr;
  if (opened_file != NULL)
  {
    file_ptr = file_reopen (opened_file->file);
  }
  else
  {
    file_ptr = filesys_open (file);
    if (file_ptr == NULL)
      return -1;
  }

  return open_file_create (file_ptr, file)->fd;
}

int
filesize (int fd)
{
  return file_length (get_open_file (fd)->file);
}

int
read (int fd, void *buffer, unsigned size)
{
  unsigned read_bytes;
  switch (fd)
  {
    case 0:
      read_bytes = 0;
      while (read_bytes < size)
      {
        uint8_t key = input_getc ();
        memcpy (buffer, &key, sizeof (uint8_t));
        buffer += sizeof (uint8_t);
        read_bytes++;
      }
      return read_bytes;
    case 1:
      break;
    default:
      if (fd > 1)
      {
        struct file *file = get_open_file (fd)->file;
        if (file != NULL)
        {
          return file_read (file, buffer, size);
        }
      }
      break;
  }
  return 0;
}

int
write (int fd, const void *buffer, unsigned size)
{
  switch (fd)
  {
    case 0:
      break;
    case 1:
      putbuf (buffer, size);
      return size;
    default:
      if (fd > 1)
      {
        struct file *file = get_open_file (fd)->file;
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
  file_seek (get_open_file (fd)->file, position);
}

unsigned
tell (int fd)
{
  return file_tell ( get_open_file (fd)->file );
}

void
close (int fd)
{
  struct open_file *open_file = get_open_file (fd);
  file_close (open_file->file);
  list_remove (&open_file->elem);
  free (open_file->file_name);
  free (open_file);
}
