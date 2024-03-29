/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "threads/mmu.h"

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

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* 관련 파일을 닫아 파일 지원 페이지를 파괴합니다.
 내용이 dirty인 경우 변경 사항을 파일에 다시 기록해야 합니다. 
 이 함수에서 페이지 구조를 free할 필요는 없습니다.(file_backed_destroy의 호출자가 해야함)
  file_backed_destroy의 호출자는 이를 처리해야 합니다.*/
/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
	
	if (pml4_is_dirty(thread_current()->pml4, page->va))
	{
		file_write_at(file_page->file, page->va, file_page->read_bytes, file_page->offset);
		pml4_set_dirty(thread_current()->pml4, page->va, 0);
	}
	pml4_clear_page(thread_current()->pml4, page->va);
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {

	void *original_addr = addr; // 매핑 성공 시 파일이 매핑된 가상 주소 반환하는 데 사용
	struct file *f = file_reopen(file);
	int total_page_count = length <= PGSIZE ? 1 : length % PGSIZE ? length / PGSIZE + 1
																  : length / PGSIZE; // 이 매핑을 위해 사용한 총 페이지 수

	size_t read_bytes = file_length(f) < length ? file_length(f) : length;
	size_t zero_bytes = PGSIZE - read_bytes % PGSIZE;

	ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT(pg_ofs(addr) == 0);	  // upage가 페이지 정렬되어 있는지 확인
	ASSERT(offset % PGSIZE == 0); // ofs가 페이지 정렬되어 있는지 확인

	while (read_bytes > 0 || zero_bytes > 0)
	{
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		struct lazy_load_info *lazy_load_info = (struct lazy_load_info *)malloc(sizeof(struct lazy_load_info));
		lazy_load_info->file = f;
		lazy_load_info->offset = offset;
		lazy_load_info->read_bytes = page_read_bytes;
		lazy_load_info->zero_bytes = page_zero_bytes;

		if (!vm_alloc_page_with_initializer(VM_FILE, addr,
											writable, lazy_load_segment, lazy_load_info))
			return NULL;

		struct page *p = spt_find_page(&thread_current()->spt, original_addr);
		p->mmap_cnt = total_page_count;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		addr += PGSIZE;
		offset += page_read_bytes;
	}

	return original_addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
	struct supplemental_page_table *spt = &thread_current()->spt;
	struct page *page = spt_find_page(spt,addr);
	int count = page->mmap_cnt;
	for (int i = 0; i < count; i++)
	{
		if (page)
			destroy(page);
		addr += PGSIZE;
		page = spt_find_page(spt, addr);
	}
}
