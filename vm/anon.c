/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include <bitmap.h>
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "vm/vm.h"
#include "devices/disk.h"

// : 1 sector = 512bytes, 1 page = 4096bytes -> 1 slot = 8 sector
#define SECTORS_IN_PAGE PGSIZE / DISK_SECTOR_SIZE // 4096 / 512 = 8
/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
struct bitmap *swap_table;

static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	// uint32_t sip = SECTORS_IN_PAGE;
	swap_disk = disk_get(1, 1);
	int swap_size = disk_size(swap_disk) /SECTORS_IN_PAGE;
	swap_table = bitmap_create(swap_size);
}

/* Initialize the file mapping */

// 이 함수는 익명 페이지의 핸들러를 page->operations에 설정합니다.
// 현재는 빈 구조체인 anon_page에서 일부 정보를 업데이트해야 할 수도 있습니다.
// 이 함수는 익명 페이지(즉, VM_ANON)의 초기화 함수로 사용됩니다.

bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */

	page->operations = &anon_ops;
	
	struct anon_page *anon_page = &page->anon;

	return true;
}


/* Swap in the page by read contents from the swap disk. */

//스왑 디스크 데이터 내용을 읽어서 익명 페이지를(디스크에서 메모리로)  swap in합니다.
// 스왑 아웃 될 때 페이지 구조체는 스왑 디스크에 저장되어 있어야 합니다.
// 스왑 테이블을 업데이트해야 합니다(스왑 테이블 관리 참조).

static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
	
}

/* Swap out the page by writing contents to the swap disk. */

//메모리에서 디스크로 내용을 복사하여 익명 페이지를 스왑 디스크로 교체합니다.
//먼저 스왑 테이블을 사용하여 디스크에서 사용 가능한 스왑 슬롯을 찾은 다음 데이터 페이지를 슬롯에 복사합니다.
// 데이터의 위치는 페이지 구조체에 저장되어야 합니다. 디스크에 사용 가능한 슬롯이 더 이상 없으면 커널 패닉이 발생할 수 있습니다.

static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;

	int page_no = bitmap_scan(swap_table, 0, 1, false); 
	if (page_no == BITMAP_ERROR){
		return false;
	}
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
}
