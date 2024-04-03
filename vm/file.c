/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "threads/mmu.h"
#include "userprog/syscall.h"

// static struct lock file_backed_lock;
static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
/* 파일 지원 페이지 하위 시스템을 초기화합니다. 이 기능에서는 파일 백업 페이지와 관련된 모든 것을 설정할 수 있습니다. */
void
vm_file_init (void) {
	// lock_init(&file_backed_lock);
}

// struct file *file;
//     off_t offset;
//     uint32_t read_bytes;
//     uint32_t zero_bytes;
//     bool writable;

/* 파일 지원 페이지를 초기화합니다.
 이 함수는 먼저 page->operations에서 파일 지원 페이지에 대한 핸들러를 설정합니다.
  메모리를 지원하는 파일과 같은 페이지 구조에 대한 일부 정보를 업데이트할 수 있습니다.*/
/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;

	struct lazy_load_info *lazy_load_info = page->uninit.aux;

	file_page->file = lazy_load_info->file;
	file_page->offset = lazy_load_info->offset;
	file_page->read_bytes = lazy_load_info->read_bytes;
	file_page->zero_bytes = lazy_load_info->zero_bytes;
	file_page->writable = lazy_load_info->writable;

	return true;
}

/* 파일에서 콘텐츠를 읽어 kva 페이지에서 swap in합니다.
  파일 시스템과 동기화해야 합니다.*/
/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in(struct page *page, void *kva)
{
    // printf("file_backed_swap_in\n");
    struct file_page *file_page = &page->file;

    lock_acquire(&filesys_lock);
    off_t size = file_read_at(file_page->file, kva, (off_t)file_page->read_bytes, file_page->offset);
    lock_release(&filesys_lock);

	// printf("file_bakce_swap_in_ing\n");

    if (size != file_page->read_bytes)
        return false;

    memset(kva + file_page->read_bytes, 0, file_page->zero_bytes);

    return true;
}

/* 내용을 다시 파일에 기록하여 swap out합니다.
  먼저 페이지가 dirty  인지 확인하는 것이 좋습니다.
  더럽지 않으면 파일의 내용을 수정할 필요가 없습니다.
  페이지를 교체한 후에는 페이지의 더티 비트를 꺼야 합니다. */
/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out(struct page *page)
{
	struct file_page *file_page UNUSED = &page->file;
	if (pml4_is_dirty(thread_current()->pml4, page->va))
	{	
		lock_acquire(&filesys_lock);
		file_write_at(file_page->file, page->va, file_page->read_bytes, file_page->offset);
		lock_release(&filesys_lock);
		pml4_set_dirty(thread_current()->pml4, page->va, false);
	}

	// 페이지와 프레임의 연결 끊기
	page->frame->page = NULL;
	page->frame = NULL;
	pml4_clear_page(thread_current()->pml4, page->va);
	return true;
}

/* 관련 파일을 닫아 파일 지원 페이지를 파괴합니다.
 내용이 dirty인 경우 변경 사항을 파일에 다시 기록해야 합니다. 
 이 함수에서 페이지 구조를 free할 필요는 없습니다.(file_backed_destroy의 호출자가 해야함)
  file_backed_destroy의 호출자는 이를 처리해야 합니다.*/
/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy(struct page *page)
{
   struct file_page *file_page = &page->file;
		// printf("file_backed_destroy\n");
    // if (page->frame != NULL)
    // {
    //     lock_acquire(&frame_table_lock);
    //     list_remove(&(page->frame->frame_elem));
    //     lock_release(&frame_table_lock);
    //     free(page->frame);
    // }
	if (pml4_is_dirty(thread_current()->pml4, page->va))
	{	
		lock_acquire(&filesys_lock);
		file_write_at(file_page->file, page->va, file_page->read_bytes, file_page->offset);
		lock_release(&filesys_lock);
		pml4_set_dirty(thread_current()->pml4, page->va, 0);
	}
	pml4_clear_page(thread_current()->pml4, page->va);

    // // list_remove(&(file_page->file_elem));
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {

	bool succ = false;

	void *advance_addr = addr; 
	struct file *f = file_reopen(file);
	// printf("do mmap \n");
	// printf("do mmap addr : %p\n", addr);
	// printf("do mmap length : %d\n", length);
	// printf("do mmap writable : %d\n", writable);
	// printf("do mmap file : %p\n",file);
	// printf("do mmap offset : %d\n", offset);
	int total_page_count = length <= PGSIZE ? 1 : (length % PGSIZE ? length / PGSIZE + 1 : length / PGSIZE); // 이 매핑을 위해 사용한 총 페이지 수

	size_t read_bytes = file_length(f) < length ? file_length(f) : length;
	size_t zero_bytes = PGSIZE - read_bytes % PGSIZE;

	// printf("size of read_bytes : %d\n", read_bytes);
	// ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
	// ASSERT(pg_ofs(addr) == 0);	  // upage가 페이지 정렬되어 있는지 확인
	// ASSERT(offset % PGSIZE == 0); // ofs가 페이지 정렬되어 있는지 확인

	while (read_bytes > 0)
	{
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;
		// printf("size of page_read_bytes : %d\n", page_read_bytes);

		struct lazy_load_info *lazy_load_info = (struct lazy_load_info *)malloc(sizeof(struct lazy_load_info));
		// printf("lazy_load_info \n");
		lazy_load_info->file = f;
		lazy_load_info->offset = offset;
		lazy_load_info->read_bytes = page_read_bytes;
		lazy_load_info->zero_bytes = page_zero_bytes;
		lazy_load_info->writable = writable;
		// if (read_bytes == 0){ // 왜 while 문 타는거지? -> while 조건 ||zero_bytes 없애니까 해결
		// 	break;
		// }
		// printf("lazy_load_info->offset : %d\n", lazy_load_info->offset);
		// printf("lazy_load_info->read_bytes : %d\n", lazy_load_info->read_bytes);
		if (!vm_alloc_page_with_initializer(VM_FILE, advance_addr,
											writable, lazy_load_segment, lazy_load_info)){
			file_close(f);
			free(lazy_load_info);
			// printf("vm_alloc_page_error \n");
			return NULL;
											}
		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		advance_addr += PGSIZE;
		offset += page_read_bytes;
		// printf("advance offset : %d\n",offset);
		// printf("advance readbytes : %d\n",read_bytes);
	}
		struct page *p = spt_find_page(&thread_current()->spt, addr);
		p->mmap_cnt += total_page_count;
		// printf("mmap_cnt: %d\n",p->mmap_cnt);

	// return original_addr;
	if(read_bytes== 0){
		// printf("do mmap length : %d\n", length);
		succ = true;
	}
	if(succ){
		// printf("do mmap success!\n");
		// printf("do mmap final addr : %p\n", addr);
		// printf("do mmap original addr: %p\n", original_addr);
		return addr; // 원래 addr일때 pass
	}
	else{
		return NULL;
	}
	
}

/* Do the munmap */
void
do_munmap (void *addr) {
	struct supplemental_page_table *spt = &thread_current()->spt;
	struct page *p = spt_find_page(spt, addr);
	int count = p->mmap_cnt;
	for (int i = 0; i < count; i++)
	{
		if (p)
			destroy(p);
			// spt_remove_page(spt, p);

		addr += PGSIZE;
		p = spt_find_page(spt, addr);
	}
}

