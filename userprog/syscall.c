#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "devices/input.h"
#include "lib/kernel/stdio.h"
#include "vm/vm.h"

// struct lock filesys_lock;
void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	//lock_init(&filesys_lock);
}

// void check_addr(char *addr){
// 	if (addr == NULL || !is_user_vaddr(addr) || !pml4_get_page(thread_current()->pml4,addr)){
// 		exit(-1);
// 	}
// }
bool check_addr(char* addr){
	if(!addr || !is_user_vaddr(addr)|| !pml4_get_page(thread_current()->pml4,addr))
		return false;
	return true;
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	switch(f->R.rax){
		case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	case SYS_FORK:
		f->R.rax = fork(f->R.rdi);
		break;
	case SYS_EXEC:  
		f->R.rax = exec(f->R.rdi);
		break;
	case SYS_WAIT:
		wait(f->R.rdi);
		break;
	case SYS_CREATE:
		if(!check_addr(f->R.rdi)){
			exit(-1);
		}
		if(f->R.rdi ==NULL || strcmp(f->R.rdi,"")== 0)
			exit(-1);
		if (!create(f->R.rdi,f->R.rsi))
			f->R.rax = false;
		else 
			f->R.rax = true;
		break;
	case SYS_REMOVE:
		remove(f->R.rdi);
		break;
	case SYS_OPEN:
		if(!check_addr(f->R.rdi))
			exit(-1);
		f->R.rax = open(f->R.rdi);

		break;
	case SYS_FILESIZE:
		f->R.rax = filesize(f->R.rdi);
		break;
	case SYS_READ:
		// if(!check_addr(f->R.rsi))
		// 	exit(-1);
		f->R.rax = read(f->R.rdi,f->R.rsi,f->R.rdx);
		break;
	case SYS_WRITE:
		f->R.rax = write(f->R.rdi,f->R.rsi,f->R.rdx);
		break;
	case SYS_SEEK:
		break;
	case SYS_TELL:
		break;
	case SYS_CLOSE:
		close(f->R.rdi);
		break;
	default:
		break;
	}
}

void halt (void)
{
	power_off();
}

void exit (int status)
{
	 struct thread *cur = thread_current (); 
    /* Save exit status at process descriptor */
	
    printf("%s: exit(%d)\n" , cur -> name , status);
    thread_exit();
}

pid_t fork (const char *thread_name){
	// struct thread *curr = thread_current ();
	// return process_fork(thread_name, curr->tf);
}

/* process_create_initd 과 유사, thread_create은 fork에서 */
int exec (const char *cmd_line){
	// struct file *open_file = filesys_open(cmd_line);
	// if(open_file == NULL){
	// 	return -1;
	// }
	if(!check_addr(cmd_line))
		exit(-1);
	int size = strlen(cmd_line) + 1;
	char *cmd_line_copy;
	cmd_line_copy = palloc_get_page(0);
	if (cmd_line_copy == NULL)
		exit(-1);
	strlcpy (cmd_line_copy, cmd_line, size);
	if (process_exec(cmd_line_copy) == -1)
		exit(-1);
}

int wait (pid_t child_tid){
	return process_wait(child_tid);
}
int create_fd(struct file *file){
	struct thread *curr = thread_current();
	if(curr->fd_idx <64){
		int idx = curr->fd_idx;
		curr->fdt[idx] = file;
		curr->fd_idx ++;
		return idx+2;
	}
	return -1;
}

struct file* find_file_by_fd(int fd){
	fd -=2;
	if(fd >64 || fd <0)
		exit(-1);
	struct thread *curr = thread_current();
	return curr->fdt[fd];
}

void del_fd(int fd){
	fd -= 2;
	struct thread *curr = thread_current();

	if(fd == curr->fd_idx-1)
	{
		curr->fdt[fd] = NULL;
		curr->fd_idx --;
	}else{
		for(int i = fd; i < curr->fd_idx ; i++){
			curr->fdt[i] = curr->fdt[i+1];
		}
		curr->fd_idx --;
	}	 
}
bool create (const char *file, unsigned initial_size){
	if(strlen(file) >= 511)
		return 0;
	return filesys_create(file,initial_size);
}
// bool create (const char *file, unsigned initial_size){
// 	// check_addr(file);
// 	// printf("%d\n",strlen(file));
// 	// if (file==NULL || strlen(file) == 0){
// 	// 	exit(-1);
// 	// }
// 	// if (strlen(file) >= 511){
// 	// 	return 0;
// 	// lock_acquire(&filesys_lock);
// 	check_addr(file);
// 	bool success = filesys_create(file, initial_size);
// 	// lock_release(&filesys_lock);
// 	return success;
// 	}
bool remove (const char *file){
	return filesys_remove(file);
}

int open (const char *file){
	if(file == NULL){
		exit(-1);
	}
	if(strcmp(file,"")== 0){
		return -1;
	}
	struct file *open_file = filesys_open(file);
	if(open_file == NULL){
		return -1;
	}else {
		int fd = create_fd(open_file);
		return fd;
	}
}
// /* returns fd*/
// int open (const char *file){
// 	check_addr(file);
// 	//lock_acquire(&filesys_lock);
// 	struct file *f= filesys_open(file);
	
// 	if (f == NULL){
// 	   	return -1;
// 	}
	
// 	int fd = create_fd(file);
// 	if (fd == -1)
// 		file_close(f);
// 	//lock_release(&filesys_lock);
// 	return fd;
// }
int filesize (int fd){
	struct file *file = find_file_by_fd(fd);
	if(file == NULL)
		return -1;
	return file_length(file);
}

int read (int fd, void *buffer, unsigned length){
	struct file *file = find_file_by_fd(fd);
	if(!check_addr(buffer))
			exit(-1);
	if (file == NULL){
		return -1;
	}
	return file_read(file,buffer,length);
}

// /* STDIN:0 STDOUT:1*/
int write (int fd, const void *buffer, unsigned length){
	if (fd == 1) 
		putbuf(buffer,length);
	else
	{
		if(check_addr(buffer) == 0)
			exit(-1);
		struct file *file = find_file_by_fd(fd);
		return file_write(file,buffer,length);
	}
}


/*파일 편집 위치 변경*/
void seek (int fd, unsigned position){
	struct file *file = find_file_by_fd(fd);
	if(!check_addr(file))
		exit(-1);
	if (file == NULL) {
	 	return;
	}
	file_seek(file, position);
}

/*파일 위치 반환*/
unsigned tell (int fd){
	struct file *file = find_file_by_fd(fd);
	if(!check_addr(file))
		exit(-1);
	if (file == NULL) {
	 	return;
	}
	return file_tell(file);
}


/* set 0 at file descriptor entry at index fd */
void close (int fd){
	struct file *file = find_file_by_fd(fd);
	if(file == NULL)
		return;
	file_close(file);
	del_fd(fd);
}


