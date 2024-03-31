/* vm.c: Generic interface for virtual memory objects. */

#include "vm/vm.h"

#include "threads/malloc.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "vm/inspect.h"

extern struct lock filesys_lock;

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void)
{
  vm_anon_init();
  vm_file_init();
#ifdef EFILESYS /* For project 4 */
  pagecache_init();
#endif
  register_inspect_intr();
  /* DO NOT MODIFY UPPER LINES. */
  /* TODO: Your code goes here. */
  list_init(&lru);
  lock_init(&lru_lock);
  lock_init(&kill_lock);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type(struct page *page)
{
  int ty = VM_TYPE(page->operations->type);
  switch (ty)
  {
  case VM_UNINIT:
    return VM_TYPE(page->uninit.type);
  default:
    return ty;
  }
}

/* Helpers */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable,
                                    vm_initializer *init, void *aux)
{
  ASSERT(VM_TYPE(type) != VM_UNINIT)

  struct supplemental_page_table *spt = &thread_current()->spt;

  // upage = upage + 0x8000000000;
  /* Check wheter the upage is already occupied or not. */
  if (spt_find_page(spt, upage) == NULL)
  {
    /* TODO: Create the page, fetch the initialier according to the VM type,
     * TODO: and then create "uninit" page struct by calling uninit_new. You
     * TODO: should modify the field after calling the uninit_new. */
    struct page *pg = (struct page *)malloc(sizeof(struct page));
    if (pg == NULL)
      goto err;

    void *va_rounded = pg_round_down(upage);
    switch (VM_TYPE(type))
    {
    case VM_ANON:
      uninit_new(pg, va_rounded, init, type, aux, anon_initializer);
      break;
    case VM_FILE:
      uninit_new(pg, va_rounded, init, type, aux, file_backed_initializer);
      break;
    default:
      NOT_REACHED();
      break;
    }

    pg->writable = writable;
    /* TODO: Insert the page into the spt. */
    spt_insert_page(spt, pg);
    return true;
  }
err:
  return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page(struct supplemental_page_table *spt, void *va)
{
  struct page *page = NULL;
  /* TODO: Fill this function. */
  void *page_addr = pg_round_down(va);

  struct page pg;
  pg.va = page_addr;
  struct hash_elem *found = hash_find(&(spt->spt), &(pg.page_elem));
  if (found == NULL)
    return NULL;
  page = hash_entry(found, struct page, page_elem);

  return page;
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt,
                     struct page *page)
{
  int succ = false;
  /* TODO: Fill this function. */
  if (hash_insert(&(spt->spt), &(page->page_elem)) == NULL)
    succ = true;

  return succ;
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page)
{
  if (hash_delete(&(spt->spt), &(page->page_elem)) == NULL)
    return;

  vm_dealloc_page(page);
  return;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim(void)
{
  struct frame *victim = NULL;
  /* TODO: The policy for eviction is up to you. */
  lock_acquire(&lru_lock);
  size_t lru_len = list_size(&lru);
  struct list_elem *tmp = list_begin(&lru);
  struct frame *tmp_frame;
  struct list_elem *next_tmp;
  for (size_t i = 0; i < lru_len; i++)
  {
    tmp_frame = list_entry(tmp, struct frame, lru_elem);
    if (pml4_is_accessed(thread_current()->pml4, tmp_frame->page->va))
    {
      pml4_set_accessed(thread_current()->pml4, tmp_frame->page->va, false);
      next_tmp = list_next(tmp);
      list_remove(tmp);
      list_push_back(&lru, tmp);
      tmp = next_tmp;
      continue;
    }
    if (victim == NULL)
    {
      victim = tmp_frame;
      next_tmp = list_next(tmp);
      list_remove(tmp);
      tmp = next_tmp;
      continue;
    }
    tmp = list_next(tmp);
  }
  if (victim == NULL)
    victim = list_entry(list_pop_front(&lru), struct frame, lru_elem);
  lock_release(&lru_lock);

  return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame(void)
{
  struct frame *victim = vm_get_victim();
  /* TODO: swap out the victim and return the evicted frame. */
  if (!swap_out(victim->page))
    return NULL;

  victim->page = NULL;
  memset(victim->kva, 0, PGSIZE);

  return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame(void)
{
  struct frame *frame = NULL;
  /* TODO: Fill this function. */
  void *pg_ptr = palloc_get_page(PAL_USER);
  if (pg_ptr == NULL)
  {
    return vm_evict_frame();
  }

  frame = (struct frame *)malloc(sizeof(struct frame));
  frame->kva = pg_ptr;
  frame->page = NULL;

  ASSERT(frame != NULL);
  ASSERT(frame->page == NULL);
  return frame;
}

/* Growing the stack. */
static void
vm_stack_growth(void *addr)
{
  void *pg_addr = pg_round_down(addr);
  ASSERT((uintptr_t)USER_STACK - (uintptr_t)pg_addr <= (1 << 20));

  while (vm_alloc_page(VM_ANON, pg_addr, true))
  {
    struct page *pg = spt_find_page(&thread_current()->spt, pg_addr);
    vm_claim_page(pg_addr);
    pg_addr += PGSIZE;
  }
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp(struct page *page)
{
  void *parent_kva = page->frame->kva;
  page->frame->kva = palloc_get_page(PAL_USER);

  memcpy(page->frame->kva, parent_kva, PGSIZE);
  pml4_set_page(thread_current()->pml4, page->va, page->frame->kva, page->copy_writable);

  return true;
}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f, void *addr,
                         bool user, bool write, bool not_present)
{
  struct supplemental_page_table *spt = &thread_current()->spt;
  struct page *page = NULL;
  /* TODO: Validate the fault */
  /* TODO: Your code goes here */
  if (is_kernel_vaddr(addr) && user)
    return false;
  // printf("TID: %d, addr: %p\n", thread_current()->tid, addr);
  page = spt_find_page(spt, addr);
  if (write && !not_present && page->copy_writable && page)
  {
    // printf("not present is false\n");
    return vm_handle_wp(page);
  }

  if (page == NULL)
  {
    struct thread *current_thread = thread_current();
    void *stack_bottom = pg_round_down(thread_current()->user_rsp);
    if (write && (addr >= pg_round_down(thread_current()->user_rsp - PGSIZE)) && (addr < USER_STACK))
    {
      vm_stack_growth(addr);
      return true;
    }
    return false;
  }
  if (write && !page->writable)
    return false;
  // printf("page->writable : %d\n", page->writable);
  // printf("write : %d\n", write);
  // printf("EQUALS ? : %d\n", page->writable == write);
  // if (is_writable(thread_current()->pml4) && write)
  // {
  //     printf("wp\n");
  //     return vm_handle_wp(page);
  // };

  if (vm_do_claim_page(page))
    return true;
  return false;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page)
{
  destroy(page);
  free(page);
}

/* Claim the page that allocate on VA. */
bool vm_claim_page(void *va)
{
  struct page *page = NULL;
  /* TODO: Fill this function */
  page = spt_find_page(&thread_current()->spt, va);
  if (page == NULL)
  {
    // there is no such page to accomodate va
    return false;
  }

  return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page(struct page *page)
{
  struct frame *frame = vm_get_frame();

  if (frame == NULL)
    return false;

  /* Set links */
  frame->page = page;
  page->frame = frame;

  /* TODO: Insert page table entry to map page's VA to frame's PA. */
  struct thread *t = thread_current();
  lock_acquire(&lru_lock);
  list_push_back(&lru, &(frame->lru_elem));
  lock_release(&lru_lock);

  if (pml4_set_page(t->pml4, page->va, frame->kva, page->writable) == false)
    return false;

  return swap_in(page, frame->kva);
}

static uint64_t spt_hash_func(const struct hash_elem *e, void *aux)
{
  const struct page *pg = hash_entry(e, struct page, page_elem);
  return hash_int(pg->va);
}

static bool spt_less_func(const struct hash_elem *a, const struct hash_elem *b)
{
  const struct page *pg_a = hash_entry(a, struct page, page_elem);
  const struct page *pg_b = hash_entry(b, struct page, page_elem);
  return pg_a->va < pg_b->va;
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt)
{
  hash_init(&(spt->spt), spt_hash_func, spt_less_func, NULL);
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst,
                                  struct supplemental_page_table *src)
{
  struct hash_iterator iter;
  hash_first(&iter, &(src->spt));
  while (hash_next(&iter))
  {
    struct page *tmp = hash_entry(hash_cur(&iter), struct page, page_elem);
    struct page *cpy = NULL;
    // printf("curr_type: %d, parent_va: %p, aux: %p\n", VM_TYPE(tmp->operations->type), tmp->va, tmp->uninit.aux);

    switch (VM_TYPE(tmp->operations->type))
    {
    case VM_UNINIT:
      // printf("tmp->uninit.type: %d, va: %p, aux: %p\n", tmp->uninit.type, tmp->va, tmp->uninit.aux);
      if (VM_TYPE(tmp->uninit.type) == VM_ANON)
      {
        struct load_segment_aux *info = (struct load_segment_aux *)malloc(sizeof(struct load_segment_aux));
        memcpy(info, tmp->uninit.aux, sizeof(struct load_segment_aux));

        info->file = file_duplicate(info->file);

        vm_alloc_page_with_initializer(tmp->uninit.type, tmp->va, tmp->writable, tmp->uninit.init, (void *)info);
      }
      break;
    case VM_ANON:
      // printf("VMANON\n");
      vm_alloc_page(tmp->operations->type, tmp->va, tmp->writable);
      cpy = spt_find_page(dst, tmp->va);

      // printf("child va : %p, type: %d\n", cpy->va, cpy->operations->type);

      if (cpy == NULL)
      {
        return false;
      }

      cpy->copy_writable = tmp->writable;
      struct frame *cpy_frame = malloc(sizeof(struct frame));
      cpy->frame = cpy_frame;
      cpy_frame->page = cpy;
      // memcpy ?
      cpy_frame->kva = tmp->frame->kva;

      struct thread *t = thread_current();
      lock_acquire(&lru_lock);
      list_push_back(&lru, &cpy_frame->lru_elem);
      lock_release(&lru_lock);

      if (pml4_set_page(t->pml4, cpy->va, cpy_frame->kva, 0) == false)
      {
        // printf("child set page flase \n");
        return false;
      }
      swap_in(cpy, cpy_frame->kva);
      // pml4_clear_page(t->pml4, tmp->va);
      // pml4_destroy(t->pml4);
      // if (pml4_set_page(t->pml4, tmp->va, tmp->frame->kva, 0) == false)
      // {
      //   // printf("parent set page flase \n");
      //   return false;
      // }

      // printf("all pass \n");

      // cow - vm_do_claim_page가 페이지를 할당받으니 주석
      // if (vm_do_claim_page(cpy) == false)
      // {
      //     return false;
      // }
      // cow
      // memcpy(cpy->frame->kva, tmp->frame->kva, PGSIZE);
      break;
    case VM_FILE:
      break;
    default:
      break;
    }
  }
  return true;
}

static void spt_destroy_func(struct hash_elem *e, void *aux)
{
  const struct page *pg = hash_entry(e, struct page, page_elem);
  vm_dealloc_page(pg);
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt)
{
  /* TODO: Destroy all the supplemental_page_table hold by thread */
  lock_acquire(&kill_lock);
  hash_destroy(&(spt->spt), spt_destroy_func);
  lock_release(&kill_lock);

  /* TODO: writeback all the modified contents to the storage. */
}
