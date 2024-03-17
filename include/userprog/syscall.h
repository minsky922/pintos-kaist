#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <debug.h>
#include <stddef.h>

bool check_addr(char *addr);
//int create_fd(struct file *f);
struct file *fd_to_file(int fd);
void process_close_file(int fd);
typedef int pid_t;
void syscall_init (void);
/* Projects 2 and later. */
void halt (void); //NO_RETURN
void exit (int status);// NO_RETURN
pid_t fork (const char *thread_name);
int exec (const char *file);
int wait (pid_t);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

int dup2(int oldfd, int newfd);
#endif /* userprog/syscall.h */
