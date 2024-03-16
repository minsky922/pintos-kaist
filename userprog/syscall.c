#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "threads/flags.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "intrinsic.h"
#include "threads/synch.h"
#include "devices/input.h"
#include "lib/kernel/stdio.h"
#include "threads/palloc.h"
#include "vm/vm.h"

struct lock filesys_lock;
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
	lock_init(&filesys_lock);
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

void check_addr(char *addr){
	if (addr == NULL || !is_user_vaddr(addr) || !pml4_get_page(thread_current()->pml4,addr)){
		exit(-1);
	}
}

int create_fd(struct file *f){
	struct thread *curr = thread_current();
          struct file **fdt = curr->fdt;

          // limit을 넘지 않는 범위 안에서 빈 자리 탐색
          while (curr->next_fd < FDT_COUNT_LIMIT && fdt[curr->next_fd])
              curr->next_fd++;
          if (curr->next_fd >= FDT_COUNT_LIMIT)
              return -1;
          fdt[curr->next_fd] = f;

          return curr->next_fd;
    // for (int fd = curr->next_fd; fd < 64; fd++) {
    //     if (curr->fdt[fd] == NULL) {
    //         curr->fdt[fd] = f; 
    //         curr->next_fd = fd + 1;        
    //         return fd;                    
    //     }
	// 	if (fd <0 || fd>=64){
	// 		return -1;
	// 	}
    // }

    // 사용 가능한 파일 디스크립터가 없는 경우
    // return -1;
}

struct file *fd_to_file(int fd) {
	struct thread *curr = thread_current();
    struct file **fdt = curr->fdt;
    /* 파일 디스크립터에 해당하는 파일 객체를 리턴 */
    /* 없을 시 NULL 리턴 */
    if (fd < 2 || fd >= FDT_COUNT_LIMIT)
        return NULL;
    return fdt[fd];
}

// 파일 디스크립터 테이블에서 파일 객체를 제거하는 함수
void process_close_file(int fd)
{
    struct thread *curr = thread_current();
    struct file **fdt = curr->fdt;
    if (fd < 2 || fd >= FDT_COUNT_LIMIT)
        return NULL;
    fdt[fd] = NULL;
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
			f->R.rax = wait(f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = remove(f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = open(f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:
			f->R.rax = tell(f->R.rdi);
			break;
		case SYS_CLOSE:
			close(f->R.rdi);
			break;
		// default:
		// 	thread_exit();
		// 	break;
	}
	//printf ("system call!\n");
	//thread_exit ();
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
	// if(thread_current()->name != thread_name)
	// 	return thread_create(thread_name,PRI_DEFAULT,pml4_for_each,thread_current());
	// else
	// 	return 0;
}
// int exec (const char *file){

// }
int exec(const char *cmd_line)
{
    check_addr(cmd_line);

   
    char *cmd_line_copy;
    cmd_line_copy = palloc_get_page(0);
    if (cmd_line_copy == NULL)
        exit(-1);                              
    strlcpy(cmd_line_copy, cmd_line, PGSIZE); 
   
    if (process_exec(cmd_line_copy) == -1)
        exit(-1); 
}
int wait (pid_t child_tid){
	return process_wait(child_tid);
}

bool create (const char *file, unsigned initial_size){
	// check_addr(file);
	// printf("%d\n",strlen(file));
	// if (file==NULL || strlen(file) == 0){
	// 	exit(-1);
	// }
	// if (strlen(file) >= 511){
	// 	return 0;
	// lock_acquire(&filesys_lock);
	check_addr(file);
	bool success = filesys_create(file, initial_size);
	// lock_release(&filesys_lock);
	return success;
	}

bool remove (const char *file){
	check_addr(file);
	return filesys_remove(file);
}

/* returns fd*/
int open (const char *file){
	check_addr(file);
	lock_acquire(&filesys_lock);
	struct file *f= filesys_open(file);
	
	if (f == NULL){
	   	return -1;
	}
	
	int fd = create_fd(file);
	if (fd == -1)
		file_close(f);
	lock_release(&filesys_lock);
	return fd;
}

int filesize(int fd) {
	struct file *f = fd_to_file(fd);
	if (f == NULL) {
		return -1;
	}
	return file_length(f);
}

// int read (int fd, void *buffer, unsigned length){
// 	check_addr(fd);
// }

int read(int fd, void *buffer, unsigned size) {
   // 유효한 주소인지부터 체크
	check_addr(buffer); // 버퍼 시작 주소 체크
	check_addr(buffer + size -1); // 버퍼 끝 주소도 유저 영역 내에 있는지 체크
	unsigned char *buf = buffer;
	int read_count;
	
	struct file *f = fd_to_file(fd);

	if (f == NULL) {
		return -1;
	}

	/* STDIN일 때: */
	if (fd == 0) {
		char key;
		for (int read_count = 0; read_count < size; read_count++) {
			key  = input_getc();
			*buf++ = key;
			if (key == '\0') { // 엔터값
				break;
			}
		}
	}
	/* STDOUT일 때: -1 반환 */
	else if (fd == 1){
		return -1;
	}

	else {
		lock_acquire(&filesys_lock);
		read_count = file_read(f, buffer, size); // 파일 읽어들일 동안만 lock 걸어준다.
		lock_release(&filesys_lock);

	}
	return read_count;
	}

/* STDIN:0 STDOUT:1*/
int write (int fd, const void *buffer, unsigned size){
	printf("##########%d\n",fd);
	check_addr(buffer);
	int bytes_write = 0;
	if (fd == 1)
	{
		putbuf(buffer, size);
		bytes_write = size;
	}
	else
	{
		if (fd < 2)
			return -1;
		struct file *f = fd_to_file(fd);
		if (f == NULL)
			return -1;
		lock_acquire(&filesys_lock);
		bytes_write = file_write(f, buffer, size);
		lock_release(&filesys_lock);
	}
	return bytes_write;
}

/*파일 편집 위치 변경*/
void seek (int fd, unsigned position){
	struct file *f = fd_to_file(fd);
	check_addr(f);
	if (fd < 2) {
		return;
	}
	if (f == NULL) {
		return;
	}
	file_seek(f, position);

}

/*파일 위치 반환*/
unsigned tell (int fd){
	struct file *f = fd_to_file(fd);
	check_addr(f);
	if (fd <2) {
		return;
	}
	if (f == NULL) {
		return;
	}
	return file_tell(fd);
}


/* set 0 at file descriptor entry at index fd */
void close (int fd){
	struct file *f = fd_to_file(fd);
	if (f == NULL)
		return;
	file_close(f);
	process_close_file(fd);
}


