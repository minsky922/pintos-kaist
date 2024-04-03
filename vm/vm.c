/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/mmu.h"
#include "threads/thread.h"
#include "userprog/process.h"

// struct list frame_table;

/* Returns a hash value for page p. */
unsigned
page_hash (const struct hash_elem *p_, void *aux UNUSED) {
  const struct page *p = hash_entry (p_, struct page, hash_elem);
  return hash_bytes (&p->va, sizeof p->va);
}

/* Returns true if page a precedes page b. */
bool
page_less (const struct hash_elem *a_,
           const struct hash_elem *b_, void *aux UNUSED) {
  const struct page *a = hash_entry (a_, struct page, hash_elem);
  const struct page *b = hash_entry (b_, struct page, hash_elem);

  return a->va < b->va;
}

/* Returns the page containing the given virtual address, or a null pointer if no such page exists. */
// struct page *
// page_lookup (const void *address) {
// 	struct page p;
// 	struct hash_elem *e;
// 	struct hash pages;

// 	p.addr = address;
// 	e = hash_find (&pages, &p.hash_elem);
// 	return e != NULL ? hash_entry (e, struct page, hash_elem) : NULL;
// }

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	list_init(&frame_table);
	lock_init(&frame_table_lock);
	lock_init(&kill_lock);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

			// printf("vm_alloc_page_with_initializer type: %d\n", type);
			// printf("vm_alloc_page_with_initializer upage: %p\n", upage);
			// printf("vm_alloc_page_with_initializer writable: %d\n", writable);
	ASSERT (VM_TYPE(type) != VM_UNINIT)

	// printf("before_spt_find_page\n");
	struct supplemental_page_table *spt = &thread_current ()->spt;
	/* Check wheter the upage is already occupied or not. */
	// printf("vm_alloc_page_with_initializer_start\n");
	// printf("spt_find_page: %p\n",spt_find_page(spt,upage));
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		// printf("after_spt_find_page\n");
		struct page *page = (struct page *)malloc(sizeof(struct page));
		/* TODO: Insert the page into the spt. */
		/* Initiate the struct page and maps the pa to the va */
		// bool (*initializer) (struct page *, enum vm_type, void *);
		if (page == NULL)
      		goto err;

		switch (VM_TYPE(type))
        {
        case VM_ANON:
			uninit_new(page, upage, init, type, aux, anon_initializer);
            // initializer = anon_initializer;
			// printf("vm alloc with initializer page type : VM_ANON : uninit_new \n");
            break;
        case VM_FILE:
			uninit_new(page, upage, init, type, aux, file_backed_initializer);
            // initializer = file_backed_initializer;
			// printf("vm alloc with initializer page type : VM_FILE\n");
            break;
        }
		// uninit_new(page, upage, init, type, aux, initializer);
		// printf("vm alloc with initializer uninit 성공\n");

		page->writable = writable;

		if (!spt_insert_page(spt, page)) {
			// printf("vm alloc with initializer insert 실패\n");
			return false;
		}
		// printf("vm alloc with initializer insert 성공\n");
		return true;
	}
	return false;
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page page;
	/* TODO: Fill this function. */
	// malloc은 힙영역에 할당 지금 방식은 지역변수 (스택)-> 함수 끝나면 할당 자동해제
	//page = (struct page *)malloc(sizeof(struct page)); 
	struct hash_elem *e;
	
	page.va = pg_round_down(va); 
	e = hash_find(&spt->spt_hash, &page.hash_elem); // hash_elem 리턴 -> page 찾기 위해
	//free(page);

	// page = page_lookup (spt, va);
	return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	// int succ = false;
	/* TODO: Fill this function. */
	if (hash_insert (&spt->spt_hash, &page->hash_elem) == NULL){
		return true;
	}
	return false;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	hash_delete(&spt->spt_hash, &page->hash_elem);
	vm_dealloc_page (page);
	return true;
}

struct list_elem* start;
/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL; /* victim = 교체 페이지 대상 */

	/* lru_algorithm */
	// lock_acquire(&frame_table_lock);
	// Least Recently Used
	size_t lru_len = list_size(&frame_table); // 현재 프레임 테이블의 크기를 측정한다
	struct list_elem *e = list_begin(&frame_table); // 리스트의 시작점을 가져온다
	struct frame *tmp_frame;
	struct list_elem *next_tmp;
	for (size_t i = 0; i < lru_len; i++)
	{
		tmp_frame = list_entry(e, struct frame, frame_elem); // 현재 리스트 요소에서 프레임 구조체를 추출한다
		// 현재 페이지가 최근에 접근되었는지 확인
		if (pml4_is_accessed(thread_current()->pml4, tmp_frame->page->va))
		{
			// 페이지가 최근에 접근된 경우, 접근 플래그를 false로 설정하고, 해당 프레임을 리스트의 끝으로 이동시킨다
			pml4_set_accessed(thread_current()->pml4, tmp_frame->page->va, false);
			next_tmp = list_next(e);
			list_remove(e); // 현재 요소를 리스트에서 제거
			list_push_back(&frame_table, e); // 제거된 요소를 리스트의 끝에 다시 추가
			e = next_tmp; // 다음 요소로 이동
			continue;
		}
		// 교체 대상(victim)을 찾지 못했으면 현재 프레임을 교체 대상으로 설정
		if (victim == NULL)
		{
			victim = tmp_frame;
			next_tmp = list_next(e);
			list_remove(e); // 교체 대상이 되는 프레임을 리스트에서 제거
			e = next_tmp; // 다음 요소로 이동합
			continue;
		}
		e = list_next(e); // 다음 요소로 이동
	}
	// 모든 프레임이 최근에 사용되었다면, 리스트의 첫 번째 프레임을 교체 대상으로 선택
	if (victim == NULL)
		victim = list_entry(list_pop_front(&frame_table), struct frame, frame_elem);

	// 이 부분은 멀티 스레딩 환경에서 프레임 테이블에 대한 동시 접근을 관리하기 위해 사용될 수 있다.
	// lock_acquire(&frame_table_lock);

	return victim; // 교체 대상 프레임을 반환

	/* clock algorithm */
	 /* TODO: The policy for eviction is up to you. */
	// struct thread *curr = thread_current();
	// struct list_elem *e = start;

	// // printf("vm_get_vicitm start\n");

	// for (start = e; start != list_end(&frame_table); start = list_next(start)) {
	// 	victim = list_entry(start, struct frame, frame_elem);
	// 	if (pml4_is_accessed(curr->pml4, victim->page->va)) // 해당 프레임에 매핑된 페이지가 최근에 접근되었는지 확인 // Accessed 플래그 PTE_A
	// 		pml4_set_accessed(curr->pml4, victim->page->va, 0); // 접근된 경우 접근 비트를 0으로 재설정
	// 	else
	// 		return victim; // 접근 되지 않은 프레임은 교체 페이지 대상
	// }

	// for (start = list_begin(&frame_table); start != e; start = list_next(start)) { // 두번째 순회
	// 	victim = list_entry(start, struct frame, frame_elem);
	// 	if (pml4_is_accessed(curr->pml4, victim->page->va))
	// 		pml4_set_accessed(curr->pml4, victim->page->va, 0);
	// 	else
	// 		return victim;
	// }
	// return victim;

	}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {

	// printf("passed from vm_get_frame\n");
	struct frame *victim = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */
	// if (victim->page)
	swap_out(victim->page);
	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	// struct frame *frame = NULL;
	struct frame *frame = malloc(sizeof(struct frame)); // vm_do_claim_page에 넘어갈때 사라지면 안되니까 지역 변수 x, malloc으로 // malloc을 못하면 kernal 공간부족 그냥 끝
	/* TODO: Fill this function. */
	void *kva = palloc_get_page(PAL_USER);
	/* todo : swap_out 처리 */
	if (kva == NULL){   // palloc_get 실패하면 ram에 공간이 부족하다는 거니까 disk에서 swap_out 처리
    	// PANIC("todo");
		// printf("vm_get_frame: %p\n",kva);
		struct frame *victim = vm_evict_frame();
		frame->page = NULL;
		return victim;
	}
	// struct frame *frame; 
    frame->kva = kva;
	frame->page = NULL; // null로 초기화 함으로써 어떤 페이지와도 연결되지 않았음을 명확히 함

	// list_push_back(&frame_table, &frame->frame_elem); // frame_elem으로 frame 구조체에 접근할수잇음
	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	// todo: 스택 크기를 증가시키기 위해 anon page를 하나 이상 할당하여 주어진 주소(addr)가 더 이상 예외 주소(faulted address)가 되지 않도록 합니다.
    // todo: 페이지를 할당할 때는 주소를 PGSIZE 기준으로 내림
	vm_alloc_page(VM_ANON | VM_MARKER_0, pg_round_down(addr), 1);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
/* f = page fault 예외시 context 정보 담김. addr = 이 va에 접근해서 page fault 뜸
	not_present = ture: 해당 메모리 페이지가 물리적 메모리에 '존재하지 않을 경우 / false : read only page에 writing을 시도 하려는 경우
	user = pagfault가 user모드에서 발생했는지 kernal모드에서 발생했는지
	pagefault가 쓰기 작업중에 발생했는지
	 */
	
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	if (is_kernel_vaddr(addr) && addr == NULL) {
		return false;
	}
	if (not_present) // physical page 존재 x
	{
		void *rsp = f->rsp; // user access 인 경우 rsp는 user stack을 가리킨다.
		if (!user) // kernel access인 경우 thread에서 rsp를 가져와야 한다.
		rsp = thread_current()->rsp;
		/* todo : stack growth */
		// 스택 확장으로 처리할 수 있는 폴트인 경우, vm_stack_growth를 호출한다.
		// 1<<20 = 1MB
		if (USER_STACK - (1 << 20) <= rsp - 8 && rsp - 8 <= addr && addr <= USER_STACK)
			vm_stack_growth(addr);

		page = spt_find_page(spt, addr);
		if (page == NULL)
			return false;
	

		if (write == 1 && page->writable == 0) // write 불가능한 페이지에 write 요청한 경우
            return false;
        return vm_do_claim_page(page);
	}
    return false;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */
	page = spt_find_page(&thread_current()->spt, va);
	if (page == NULL)
		return false;
	
	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	lock_acquire(&frame_table_lock);
	list_push_back(&frame_table, &frame->frame_elem);
	lock_release(&frame_table_lock);

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable);
	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {

	hash_init (&spt->spt_hash, page_hash, page_less, NULL);

}

/* Copy supplemental page table from src to dst */
// &current->spt, &parent->spt
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
			struct hash_iterator i;
			hash_first(&i, &src->spt_hash);
			while (hash_next(&i)){
				struct hash_elem *e = hash_cur(&i);
				struct page *src_page = hash_entry(e, struct page, hash_elem);
				void *upage = src_page->va;
				bool writable = src_page->writable;
				enum vm_type type = src_page->operations->type;
				// void *aux = src_page->uninit.aux;
				// vm_initializer *init = src_page->uninit.init;
				
				/* type이 uninit 이면*/
				if (type == VM_UNINIT)
       		 	{ // uninit src_page 생성 & 초기화
            	vm_initializer *init = src_page->uninit.init;
            	void *aux = src_page->uninit.aux;
            	vm_alloc_page_with_initializer(VM_ANON, upage, writable, init, aux);
            	continue;
        		}

				/* type이 file이면 */
        		if (type == VM_FILE)
    			{
				struct lazy_load_info *file_aux = malloc(sizeof(struct lazy_load_info));

				file_aux->file = src_page->file.file;
				file_aux->offset = src_page->file.offset;
				file_aux->read_bytes = src_page->file.read_bytes;
				file_aux->zero_bytes = src_page->file.zero_bytes;
				file_aux->writable = src_page->file.writable;
				// printf("[DEBUG fork-read] file_aux->writable: %d, src_page->writable: %d\n",file_aux->writable, writable);

				if (!vm_alloc_page_with_initializer(type, upage, writable, NULL, file_aux))
					return false;

				struct page *file_page = spt_find_page(dst, upage);

				file_backed_initializer(file_page, type, NULL);
				file_page->frame = src_page->frame;
				pml4_set_page(thread_current()->pml4, file_page->va, src_page->frame->kva, src_page->writable);
				continue;
        		}

				/* type이 uninit이 아니면*/
				if (!vm_alloc_page(type, upage, writable)){
				// printf("[supplemental_page_table_copy] type : anon\n");
					return false;}
				if (!vm_claim_page(upage)){
				// printf("[supplemental_page_table_copy] type : anon\n");	
					return false;}
				// hash_insert(&dst->spt_hash, &src_page->hash_elem);
				struct page *dst_page = spt_find_page(dst,upage);
				// printf("[supplemental_page_table_copy] page : %p\n",dst_page->frame->kva);
				memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
				// printf("[supplemental_page_table_copy] dst_page : %p\n",memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE));
			}
			return true;
}

void clear_table(struct hash_elem *e, void *aux){
	struct page *page = hash_entry(e, struct page, hash_elem);
	// destroy(page);
	// free(page);
	vm_dealloc_page(page);
}
/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	// 해시 테이블을 재사용하려면 hash_clear를, 해시 테이블을 완전히 제거하려면 hash_destroy를
	// hash_clear(&spt->spt_hash, clear_table);
	lock_acquire(&kill_lock);
	hash_clear(&spt->spt_hash, clear_table);
	lock_release(&kill_lock);
}
