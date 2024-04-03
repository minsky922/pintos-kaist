#include "userprog/process.h"
#include "userprog/syscall.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#include "threads/synch.h"
#ifdef VM
#include "vm/vm.h"
#include "userprog/syscall.h"
#endif

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);
struct thread *find_child(tid_t child_tid);

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);
	char *token, *save_ptr;
	token = strtok_r(file_name," ",&save_ptr);

	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create (token, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
	// printf("initd start!!!");
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init ();

	if (process_exec (f_name) < 0){
		PANIC("Fail to launch initd\n");
	}
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */

tid_t
process_fork (const char *name, struct intr_frame *if_ UNUSED) {
	/* Clone current thread to new thread.*/
	struct thread *curr = thread_current();

	memcpy(&curr->parent_if, if_, sizeof (struct intr_frame)); // &curr->tf를 parent_if에 copy

	tid_t tid = thread_create (name, PRI_DEFAULT, __do_fork, thread_current ());

	if (tid == TID_ERROR){
		return TID_ERROR;
	}

	struct thread *t = find_child(tid);

	lock_acquire(&filesys_lock);
	sema_down(&t->child_load_sema);
	lock_release(&filesys_lock);

	if (t->exit_status == -1){
		// sema_up(&t->exit_sema);
		return TID_ERROR;
	}
	return tid;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
	if (is_kernel_vaddr(va))
		return true;

	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page (parent->pml4, va);
	if (parent_page == NULL)
		return false;

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
	newpage = palloc_get_page(PAL_USER | PAL_ZERO);
	if (newpage == NULL)
		return false;

	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	memcpy(newpage, parent_page, PGSIZE);
	writable = is_writable(pte);

	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		
		/* 6. TODO: if fail to insert page, do error handling. */
		palloc_free_page(newpage);
		return false;
	}
	return true;
}

#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork (void *aux) {
	struct intr_frame if_;
	struct thread *parent = (struct thread *) aux;
	struct thread *current = thread_current ();
	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	struct intr_frame *parent_if = &parent->parent_if;
	bool succ = true;
	/* 1. Read the cpu context to local stack. */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));
	if_.R.rax = 0;

	/* 2. Duplicate PT */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	process_activate (current);
#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
		goto error;
#endif

	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/

	if (parent->fd_idx == FDT_COUNT_LIMIT){
		goto error;
	}
	
	for(int i = 0; i < FDT_COUNT_LIMIT; i++)
	{
		struct file *file = parent->fdt[i];
		if(file==NULL)
			continue;
		file = file_duplicate(file);
		current->fdt[i] = file;
	}
	current->fd_idx = parent->fd_idx;
	// lock_acquire(&filesys_lock);
	sema_up(&current->child_load_sema);
	// lock_release(&filesys_lock);
	process_init ();

	/* Finally, switch to the newly created process. */
	if (succ)
		do_iret (&if_);
error:
	sema_up(&current->child_load_sema);
	exit(-1);
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int
process_exec (void *f_name) {
	char *file_name = f_name;
	bool success;

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* We first kill the current context */
	process_cleanup ();
	supplemental_page_table_init(&thread_current()->spt); //초기화해주지 않으면 exec 실패함

	char *fn_copy;
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);
	char *token, *save_ptrr;
	token = strtok_r(fn_copy," ",&save_ptrr);

	/* And then load the binary */
	lock_acquire(&filesys_lock);
	success = load (token, &_if);
	palloc_free_page(fn_copy);
	lock_release(&filesys_lock);

	/* If load failed, quit. */
	if (!success)
	{
		palloc_free_page(file_name);
		return -1;
	}

	/* argument_passing(f_name); */
	int arg_cnt=1;
	char *save_ptr;

	for(int i=0;i<strlen(file_name);i++)
	{
		if(file_name[i] == ' ')
			arg_cnt++;
	}
	char *arg_list[arg_cnt];
	int64_t arg_addr_list[arg_cnt];

	int total_cnt=0;


	for(int i=0;i<arg_cnt;i++)
	{
		arg_list[i] = strtok_r((i==0) ? file_name : NULL," ",&save_ptr);
		if (arg_list[i] == NULL){
			arg_cnt--;
		}
		// printf("arg_list[%d] : %s\n",i,arg_list[i]);
	}

	for(int i=arg_cnt-1;i>=0;i--)
	{
		_if.rsp -= strlen(arg_list[i])+1;
		total_cnt+=strlen(arg_list[i])+1;
		strlcpy(_if.rsp,arg_list[i],strlen(arg_list[i])+1);
		arg_addr_list[i] = _if.rsp;
		//printf("arg_addr_list[%d] : %x\n",i,arg_addr_list[i]);
	
	}
	//printf("total : %d\n",total_cnt);
	if(total_cnt%8!=0){
		_if.rsp -= 8-(total_cnt%8);
		memset(_if.rsp,0,8-(total_cnt%8));
	}

	_if.rsp -= 8;
	memset(_if.rsp,0,8);

	for(int i=arg_cnt-1;i>=0;i--)
	{
		_if.rsp -= 8;
		memcpy(_if.rsp,&arg_addr_list[i],8);
	}
	_if.rsp -= 8;
	memset(_if.rsp,0,8);

	_if.R.rdi = arg_cnt;
	_if.R.rsi = _if.rsp+8;

	/* If load failed, quit. */
	palloc_free_page (file_name);
	// if (!success)
	// 	return -1;

	// hex_dump(_if.rsp, _if.rsp, USER_STACK - _if.rsp, true);
	/* Start switched process. */
	do_iret (&_if);
	NOT_REACHED ();
}


/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
struct thread *find_child(tid_t child_tid){
	struct thread *curr = thread_current();
	struct list_elem *e;
	for (e=list_begin(&curr->child_list);e != list_end(&curr->child_list);e=list_next(e)){
		struct thread *t = list_entry(e,struct thread,child_elem);
		if (t->tid == child_tid){
			return t;
		}
	}
	return NULL;
}
int
process_wait (tid_t child_tid UNUSED) {
	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	 * XXX:       to add infinite loop here before
	 * XXX:       implementing the process_wait. */
	struct thread *t = find_child(child_tid);
	if (t == NULL){
		return -1;
	}
	sema_down(&t->wait_sema); //부모가 자식이 종료될때까지 대기 (process_exit에서 자식이 종료될때 sema_up)
	int result = t->exit_status;
	sema_up(&t->exit_sema); // 부모 프로세스가 자식 프로세스의 종료 상태를 읽고, 자식 프로세스가 이제 완전히 종료될 수 있음을 알림.
	list_remove(&t->child_elem); //자식이 종료됨을 알리는 'wait_signal'을 받으면 현재스레드(부모)의 자식리스트에서 제거
	//timer_sleep(10);
	
	return result;
	// return t->exit_status;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */
	// printf("%s: exit(%d)\n" , curr -> name , curr->status);
	//printf("process_exit\n");

	// printf("PEXIT(): 1\n"); ///

	// printf("fdt at %p\n", curr->fdt);
	// printf("fdt[0] %p\n", curr->fdt[0]); 

	while(!list_empty(&curr->child_list)){
		struct thread *child = list_entry(list_begin(&curr->child_list),struct thread, child_elem);
		wait(child->tid);
	}	

	int i;
 	for(i=2;i<FDT_COUNT_LIMIT;i++){
		// printf("close iter: %d, curr->fdt[%d] = %p\n", i, i, curr->fdt[i]);
    if (curr->fdt[i] != NULL)
			close(i);
  }
//   printf("PEXIT(): 2\n"); ///
	palloc_free_page(curr->fdt);
	// printf("PEXIT(): 3\n"); ///
	file_close(curr->exec_file);
	// printf("PEXIT(): 4\n"); ///
	process_cleanup ();
	// printf("PEXIT(): 5\n"); ///
	sema_up(&curr->wait_sema); //자식이 종료 될때까지 대기하고 있는 부모에게 signal을 보낸다.
	// printf("PEXIT(): 6\n"); ///
	sema_down(&curr->exit_sema); //자식 프로세스가 부모 프로세스로부터 완전히 종료되기 위한 "허가"를 받을 때까지 자식 프로세스를 대기 상태로 만듬.
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	// printf("process_cleanup_pml4 :%d",pml4);
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;


	/* Allocate and activate page directory. */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ());

	// printf("1.%s\n",file_name);
	// char *fn_copy;
	// fn_copy = palloc_get_page (0);
	// if (fn_copy == NULL)
	// 	return TID_ERROR;
	// strlcpy (fn_copy, file_name, PGSIZE);
	// char *token, *save_ptr;
	// token = strtok_r(fn_copy," ",&save_ptr);
	// printf("2.%s\n",token);

	/* Open executable file. */
	
	file = filesys_open (file_name);
	
	// printf("###########%p\n",file);
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}
	// palloc_free_page(fn_copy);
	

	/* Read and verify executable header. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}
	/* file_deny_write*/
	t->exec_file=file;
    file_deny_write(file);

	/* Set up stack. */
	if (!setup_stack (if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry;

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */

	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	//file_close (file);
	return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

/* 당신은 load_segment 함수 내부의 vm_alloc_page_with_initialize의 네 번째 인자가 lazy_load_segment 라는 것을 알아차렸을 것입니다.
 이 함수는 실행 가능한 파일의 페이지들을 초기화하는 함수이고 
page fault가 발생할 때 호출됩니다. 이 함수는 페이지 구조체와 aux를 인자로 받습니다.
 aux는 load_segment에서 당신이 설정하는 정보입니다. 
 이 정보를 사용하여 당신은 세그먼트를 읽을 파일을 찾고 최종적으로는 세그먼트를 메모리에서 읽어야 합니다.*/
bool
lazy_load_segment (struct page *page, void *aux) {
    /* TODO: Load the segment from the file */
    /* TODO: This called when the first page fault occurs on address VA. */
    /* TODO: VA is available when calling this function. */

   struct lazy_load_info *lazy_load_info = (struct lazy_load_info *)aux;
	file_seek(lazy_load_info->file, lazy_load_info->offset);
	if (file_read(lazy_load_info->file, page->frame->kva, lazy_load_info->read_bytes) != (int)(lazy_load_info->read_bytes))
	{	
		palloc_free_page(page->frame->kva);
		return false;
	}
	// printf("lazy_load_segment : file_read success\n");
	memset(page->frame->kva + lazy_load_info->read_bytes, 0, lazy_load_info->zero_bytes);
	// free(lazy_load_info);

	return true;
}
// bool
// lazy_load_segment(struct page *page, void *aux)
// {
//     /* TODO: Load the segment from the file */
//     /* TODO: This called when the first page fault occurs on address VA. */
//     /* TODO: VA is available when calling this function. */
//     // bool success = true;
//     struct lazy_load_info *info = (struct lazy_load_info *)aux;
// 	file_seek(info->file, info->offset);
//     if (file_read_at(info->file, page->frame->kva, info->read_bytes, info->offset) != (off_t)info->read_bytes)
//     {
//         // vm_dealloc_page(page);
// 		palloc_free_page(page->frame->kva);
//         return false;
//     }
//     // else
//     // {
// 		// printf("mmap-clean : lazy_load_segment\n");
//         memset(page->frame->kva + info->read_bytes, 0, info->zero_bytes);
//     // }
// 	// file_close(info->file);
//     free(info);
//     // return success;
// 	return true;
// }

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */

/* 루프를 돌 때마다 load_segment는 대기 중인 페이지 오브젝트를 생성하는vm_alloc_page_with_initializer를 호출합니다. Page Fault가 발생하는 순간은 Segment가 실제로 파일에서 로드될 때 입니다*/

/* 현재 코드는 메인 루프 안에서 파일로부터 읽을 바이트의 수와 0으로 채워야 할 바이트의 수를 측정합니다. 그리고 그것은 대기 중인 오브젝트를 생성하는 vm_alloc_page_with_initializer함수를 호출합니다.
 당신은 vm_alloc_page_with_initializer에 제공할 aux 인자로써 보조 값들을 설정할 필요가 있습니다.
  당신은 바이너리 파일을 로드할 때 필수적인 정보를 포함하는 구조체를 생성하는 것이 좋습니다.*/

// struct file *file:  데이터를 읽어올 파일을 가리키는 포인터
// off_t ofs: 파일 내에서 데이터를 읽기 시작할 위치(offset)
// uint8_t *upage: 가상 메모리 내에서 데이터를 로드할 시작 주소
// uint32_t read_bytes: 파일에서 읽어야 할 바이트 수
// uint32_t zero_bytes: 0으로 채워야 할 바이트 수
// bool writable: 페이지가 쓰기 가능해야 하는지를 나타내는 플래그
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		/* PAGE_READ_BYTES 만큼 읽고 나머지 PAGE_ZERO_BYTES 만큼 0으로 채움*/
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		struct lazy_load_info* lazy_load_info = (struct lazy_load_info *)malloc(sizeof(struct lazy_load_info));
        
        lazy_load_info->file = file;
        lazy_load_info->offset = ofs;
        lazy_load_info->read_bytes = page_read_bytes;
		lazy_load_info->zero_bytes = page_zero_bytes;
        lazy_load_info->writable = writable;


		//void *aux = NULL;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, lazy_load_info))
			// free(&lazy_load_info);
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
		ofs += page_read_bytes;
	}
	return true;
}
/* 당신은 스택 할당 부분이  새로운 메모리 관리 시스템에 적합할 수 있도록 userprog/process.c에 있는 setup_stack 을 수정해야 합니다.
 첫 스택 페이지는 지연적으로 할당될 필요가 없습니다. 
 당신은 페이지 폴트가 발생하는 것을 기다릴 필요 없이 그것(스택 페이지)을 load time 때 커맨드 라인의 인자들과 함께 할당하고 초기화 할 수 있습니다.
  당신은 스택을 확인하는 방법을 제공해야 합니다. 당신은 vm/vm.h의 vm_type에 있는 보조 marker(예 - VM_MARKER_0)들을 페이지를 마킹하는데 사용할 수 있습니다.*/

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */
	if (vm_alloc_page(VM_ANON | VM_MARKER_0, stack_bottom, 1))
	// writable: argument_stack()에서 값을 넣어야 하니 True
	{
		// 2) 할당 받은 페이지에 바로 물리 프레임을 매핑한다.
		success = vm_claim_page(stack_bottom);
		if (success)
			// 3) rsp를 변경한다. (argument_stack에서 이 위치부터 인자를 push한다.)
			if_->rsp = USER_STACK;
	}
	return success;
}
#endif /* VM */
