/* See COPYRIGHT for copyright information. */

#include <inc/x86.h>
#include <inc/mmu.h>
#include <inc/error.h>
#include <inc/string.h>
#include <inc/assert.h>

#include <kern/pmap.h>
#include <kern/kclock.h>
#include <kern/env.h>
#include <kern/cpu.h>

// These variables are set by i386_detect_memory()  这些变量由i386_detect_memory（）设置 
size_t npages;			// Amount of physical memory (in pages)  物理内存量（以页为单位） 
static size_t npages_basemem;	// Amount of base memory (in pages)  基本内存量（以页为单位） 

// These variables are set in mem_init()  这些变量在mem_init（）中设置 
pde_t *kern_pgdir;		// Kernel's initial page directory  内核的初始页面目录 
struct PageInfo *pages;		// Physical page state array 物理页面状态阵列
static struct PageInfo *page_free_list;	// Free list of physical pages 物理页面的自由列表


// --------------------------------------------------------------
// Detect machine's physical memory setup.  检测机器的物理内存设置。 
// --------------------------------------------------------------

static int
nvram_read(int r)
{
	return mc146818_read(r) | (mc146818_read(r + 1) << 8);
}

static void
i386_detect_memory(void)
{
	size_t basemem, extmem, ext16mem, totalmem;

	// Use CMOS calls to measure available base & extended memory.
	// (CMOS calls return results in kilobytes.) 使用CMOS调用来测量可用的基本内存和扩展内存。（CMOS调用返回的结果以KB为单位。）
	basemem = nvram_read(NVRAM_BASELO);
	extmem = nvram_read(NVRAM_EXTLO);
	ext16mem = nvram_read(NVRAM_EXT16LO) * 64;

	// Calculate the number of physical pages available in both base
	// and extended memory.  计算基本页和扩展页中可用的物理页数
	if (ext16mem)
		totalmem = 16 * 1024 + ext16mem;
	else if (extmem)
		totalmem = 1 * 1024 + extmem;
	else
		totalmem = basemem;

	npages = totalmem / (PGSIZE / 1024);
	npages_basemem = basemem / (PGSIZE / 1024);

	cprintf("Physical memory: %uK available, base = %uK, extended = %uK\n",
		totalmem, basemem, totalmem - basemem);
}


// --------------------------------------------------------------
// Set up memory mappings above UTOP.  在UTOP之上设置内存映射。 
// --------------------------------------------------------------

static void mem_init_mp(void);
static void boot_map_region(pde_t *pgdir, uintptr_t va, size_t size, physaddr_t pa, int perm);
static void check_page_free_list(bool only_low_memory);
static void check_page_alloc(void);
static void check_kern_pgdir(void);
static physaddr_t check_va2pa(pde_t *pgdir, uintptr_t va);
static void check_page(void);
static void check_page_installed_pgdir(void);

// This simple physical memory allocator is used only while JOS is setting
// up its virtual memory system.  page_alloc() is the real allocator.

// If n>0, allocates enough pages of contiguous physical memory to hold 'n'
// bytes.  Doesn't initialize the memory.  Returns a kernel virtual address.

// If n==0, returns the address of the next free page without allocating
// anything.

// If we're out of memory, boot_alloc should panic.
// This function may ONLY be used during initialization,
// before the page_free_list list has been set up.
// Note that when this function is called, we are still using entry_pgdir,
// which only maps the first 4MB of physical memory.

// 这个简单的物理内存分配器仅在JOS设置其虚拟内存系统时使用。
// page_alloc（）是真正的分配器。
// 如果n>0，则分配足够的连续物理内存页以容纳“n”个字节。无法初始化内存。返回内核虚拟地址。
// 如果n==0，则返回下一个空闲页的地址，而不分配任何内容。
// 如果内存不足，boot_alloc将死机。此函数只能在初始化期间使用，在设置page_free_list列表之前使用。 
static void *
boot_alloc(uint32_t n)
{
	static char *nextfree;	// virtual address of next byte of free memory  下一字节空闲内存的虚拟地址 
	char *result; 

	// Initialize nextfree if this is the first time.
	// 'end' is a magic symbol automatically generated by the linker,
	// which points to the end of the kernel's bss segment:
	// the first virtual address that the linker did *not* assign
	// to any kernel code or global variables.
	// 如果这是第一次，请初始化nextfree。
	// 'end'是链接器自动生成的一个神奇符号，它指向内核bss段的结尾：
	// 链接器没有分配给任何内核代码或全局变量的第一个虚拟地址。
	if (!nextfree) {
		extern char end[];
		nextfree = ROUNDUP((char *) end, PGSIZE);
	}

	// Allocate a chunk large enough to hold 'n' bytes, then update
	// nextfree.  Make sure nextfree is kept aligned
	// to a multiple of PGSIZE.
	//
	// 分配一个足够大的块以容纳“n”个字节，然后更新nextfree。确保nextfree保持与PGSIZE的倍数对齐。 
	// LAB 2: Your code here.
	result = nextfree;
	nextfree = ROUNDUP(nextfree+n,PGSIZE);

	return result;
}

// Set up a two-level page table:
//    kern_pgdir is its linear (virtual) address of the root

// This function only sets up the kernel part of the address space
// (ie. addresses >= UTOP).  The user part of the address space
// will be set up later.

// From UTOP to ULIM, the user is allowed to read but not write.
// Above ULIM the user cannot read or write.
//设置两级页表：kern_pgdir是其根的线性（虚拟）地址。此函数仅设置地址空间的内核部分（即地址>=UTOP）。
//稍后将设置地址空间的用户部分。从UTOP到ULIM，用户可以读取但不能写入。在ULIM以上，用户无法读取或写入。
void
mem_init(void)
{
	uint32_t cr0;
	size_t n;

	// Find out how much memory the machine has (npages & npages_basemem).  找出机器有多少内存（npages和npages_baselem）。 
	i386_detect_memory();

	// Remove this line when you're ready to test this function.   准备测试此函数时，请删除此行。 
	// panic("mem_init: This function is not finished\n");

	//////////////////////////////////////////////////////////////////////
	// create initial page directory.  创建初始页面目录。 
	kern_pgdir = (pde_t *) boot_alloc(PGSIZE);
	memset(kern_pgdir, 0, PGSIZE);

	//////////////////////////////////////////////////////////////////////
	// Recursively insert PD in itself as a page table, to form
	// a virtual page table at virtual address UVPT.
	// (For now, you don't have understand the greater purpose of the
	// following line.) 递归地将PD作为页表插入其自身，以在虚拟地址UVPT处形成虚拟页表。（现在，你还不明白下面这句话的更大目的。）

	// Permissions: kernel R, user R  权限：内核R，用户R 
	kern_pgdir[PDX(UVPT)] = PADDR(kern_pgdir) | PTE_U | PTE_P;

	//////////////////////////////////////////////////////////////////////
	// Allocate an array of npages 'struct PageInfo's and store it in 'pages'.
	// The kernel uses this array to keep track of physical pages: for
	// each physical page, there is a corresponding struct PageInfo in this
	// array.  'npages' is the number of physical pages in memory.  Use memset
	// to initialize all fields of each struct PageInfo to 0.
	// 分配一个npages“struct PageInfo”数组，并将其存储在“pages”中。
	// 内核使用此数组跟踪物理页面：对于每个物理页面，
	// 此数组中都有一个相应的结构PageInfonpages是内存中物理页面的数量。
	// 使用memset将每个结构PageInfo的所有字段初始化为0。
	// Your code goes here:
	pages  = (struct PageInfo*)(boot_alloc(npages*sizeof(struct PageInfo)));
	memset(pages,0,npages*sizeof(struct PageInfo));
	//////////////////////////////////////////////////////////////////////
	// Make 'envs' point to an array of size 'NENV' of 'struct Env'.
	// LAB 3: Your code here.
	envs   = (struct Env*)(boot_alloc(NENV*sizeof(struct Env)));
	memset(envs,0,NENV*sizeof(struct Env));
	//////////////////////////////////////////////////////////////////////
	// Now that we've allocated the initial kernel data structures, we set
	// up the list of free physical pages. Once we've done so, all further
	// memory management will go through the page_* functions. In
	// particular, we can now map memory using boot_map_region
	// or page_insert
	// 现在我们已经分配了初始的内核数据结构，我们设置了空闲物理页面的列表。
	// 完成后，所有进一步的内存管理都将通过page_*函数完成。
	// 特别是，我们现在可以使用boot_map_region或page_insert映射内存
	page_init();

	check_page_free_list(1);
	check_page_alloc();
	check_page();

	//////////////////////////////////////////////////////////////////////
	// Now we set up virtual memory  现在我们设置虚拟内存 

	//////////////////////////////////////////////////////////////////////
	// Map 'pages' read-only by the user at linear address UPAGES
	// Permissions:
	//    - the new image at UPAGES -- kernel R, user R
	//      (ie. perm = PTE_U | PTE_P)
	//    - pages itself -- kernel RW, user NONE
	// 用户在线性地址UPAGES处只读映射“页面”
	// 权限：
	// -UPAGES上的新图像——内核R，用户R
	// （即perm=PTE_U|PTE_P）
	// -页面本身——内核RW，
	// Your code goes here:
	boot_map_region(kern_pgdir,UPAGES,PTSIZE,PADDR(pages),PTE_U);
	//////////////////////////////////////////////////////////////////////
	// Map the 'envs' array read-only by the user at linear address UENVS
	// (ie. perm = PTE_U | PTE_P).
	// Permissions:
	//    - the new image at UENVS  -- kernel R, user R
	//    - envs itself -- kernel RW, user NONE
	// LAB 3: Your code here.
	boot_map_region(kern_pgdir,UENVS,PTSIZE,PADDR(envs),PTE_U);
	//////////////////////////////////////////////////////////////////////
	// Use the physical memory that 'bootstack' refers to as the kernel
	// stack.  The kernel stack grows down from virtual address KSTACKTOP.
	// We consider the entire range from [KSTACKTOP-PTSIZE, KSTACKTOP)
	// to be the kernel stack, but break this into two pieces:
	//使用“bootstack”所指的物理内存作为内核堆栈。内核堆栈从虚拟地址KSTACKTOP向下扩展。我们将[KSTACKTOP-PTSIZE，KSTACKTOP）的整个范围视为内核堆栈，但将其分为两部分：
	//     * [KSTACKTOP-KSTKSIZE, KSTACKTOP) -- backed by physical memory  由物理内存支持 
	//     * [KSTACKTOP-PTSIZE, KSTACKTOP-KSTKSIZE) -- not backed; so if
	//       the kernel overflows its stack, it will fault rather than
	//       overwrite memory.  Known as a "guard page".不支持；因此，如果内核溢出其堆栈，它将出错，而不是覆盖内存。被称为“保护页”。
	//     Permissions: kernel RW, user NONE
	// Your code goes here:
	boot_map_region(kern_pgdir,KSTACKTOP-KSTKSIZE,KSTKSIZE,PADDR(bootstack),PTE_W);
	//////////////////////////////////////////////////////////////////////
	// Map all of physical memory at KERNBASE.
	// Ie.  the VA range [KERNBASE, 2^32) should map to
	//      the PA range [0, 2^32 - KERNBASE)
	// We might not have 2^32 - KERNBASE bytes of physical memory, but
	// we just set up the mapping anyway.
	// Permissions: kernel RW, user NONE
	// Your code goes here:

	// Initialize the SMP-related parts of the memory map
	mem_init_mp();

	boot_map_region(kern_pgdir,KERNBASE,0xffffffff-KERNBASE,0,PTE_W);
	// Check that the initial page directory has been set up correctly.
	check_kern_pgdir();

	// Switch from the minimal entry page directory to the full kern_pgdir
	// page table we just created.	Our instruction pointer should be
	// somewhere between KERNBASE and KERNBASE+4MB right now, which is
	// mapped the same way by both page tables.
	//
	// If the machine reboots at this point, you've probably set up your
	// kern_pgdir wrong.
	lcr3(PADDR(kern_pgdir));

	check_page_free_list(0);

	// entry.S set the really important flags in cr0 (including enabling
	// paging).  Here we configure the rest of the flags that we care about.
	cr0 = rcr0();
	cr0 |= CR0_PE|CR0_PG|CR0_AM|CR0_WP|CR0_NE|CR0_MP;
	cr0 &= ~(CR0_TS|CR0_EM);
	lcr0(cr0);

	// Some more checks, only possible after kern_pgdir is installed.
	check_page_installed_pgdir();
}

// Modify mappings in kern_pgdir to support SMP
//   - Map the per-CPU stacks in the region [KSTACKTOP-PTSIZE, KSTACKTOP)
//
static void
mem_init_mp(void)
{
	// Map per-CPU stacks starting at KSTACKTOP, for up to 'NCPU' CPUs.
	//
	// For CPU i, use the physical memory that 'percpu_kstacks[i]' refers
	// to as its kernel stack. CPU i's kernel stack grows down from virtual
	// address kstacktop_i = KSTACKTOP - i * (KSTKSIZE + KSTKGAP), and is
	// divided into two pieces, just like the single stack you set up in
	// 对于CPU i，使用“percpu_kstacks[i]”所指的物理内存作为其内核堆栈。
	// CPU i的内核堆栈从虚拟地址kstacktop_i=kstacktop-i*（KSTKSIZE+KSTKGAP）向下扩展，
	// 并分成两部分，就像您在
	// mem_init:
	//     * [kstacktop_i - KSTKSIZE, kstacktop_i)
	//          -- backed by physical memory
	//     * [kstacktop_i - (KSTKSIZE + KSTKGAP), kstacktop_i - KSTKSIZE)
	//          -- not backed; so if the kernel overflows its stack,
	//             it will fault rather than overwrite another CPU's stack.
	//             Known as a "guard page".
	//     Permissions: kernel RW, user NONE
	//
	// LAB 4: Your code here:
	uintptr_t kstacktop_i;
	for(int i = 0; i < NCPU; i++)
	{
		kstacktop_i = KSTACKTOP - i * (KSTKSIZE + KSTKGAP);
		boot_map_region(kern_pgdir, kstacktop_i - KSTKSIZE, KSTKSIZE, 
		PADDR(percpu_kstacks[i]), PTE_W);
	}

}

// --------------------------------------------------------------
// Tracking of physical pages.
// The 'pages' array has one 'struct PageInfo' entry per physical page.
// Pages are reference counted, and free pages are kept on a linked list.
// --------------------------------------------------------------

//
// Initialize page structure and memory free list.
// After this is done, NEVER use boot_alloc again.  ONLY use the page
// allocator functions below to allocate and deallocate physical
// memory via the page_free_list.
// 初始化页面结构和内存空闲列表。完成后，不要再使用boot_alloc。只能使用下面的页面分配器函数通过page_free_list分配和释放物理内存。
//
void
page_init(void)
{
	// LAB 4:
	// Change your code to mark the physical page at MPENTRY_PADDR
	// as in use

	// The example code here marks all physical pages as free.
	// However this is not truly the case.  What memory is free?
	//  1) Mark physical page 0 as in use.
	//     This way we preserve the real-mode IDT and BIOS structures
	//     in case we ever need them.  (Currently we don't, but...)
	//  2) The rest of base memory, [PGSIZE, npages_basemem * PGSIZE)
	//     is free.
	//  3) Then comes the IO hole [IOPHYSMEM, EXTPHYSMEM), which must
	//     never be allocated.
	//  4) Then extended memory [EXTPHYSMEM, ...).
	//     Some of it is in use, some is free. Where is the kernel
	//     in physical memory?  Which pages are already in use for
	//     page tables and other data structures?
	
	// Change the code to reflect this.
	// NB: DO NOT actually touch the physical memory corresponding to
	// free pages!


	// 这里的示例代码将所有物理页面标记为免费。
	// 然而，事实并非如此。什么内存可用？
	// 1） 将物理页面0标记为正在使用中。这样，我们可以保留真实模式IDT和BIOS结构，以备需要。（目前我们没有，但……）
	// 2） 其余的基本内存[PGSIZE，npages_basemem*PGSIZE）是空闲的。
	// 3） 然后是IO孔（IOPHYSEM，EXTPHYSEM），这是绝对不能分配的。
	// 4） 然后是扩展内存[EXTPHYSEM，…）。其中一些在使用，一些是免费的。物理内存中的内核在哪里？哪些页面已经用于页面表和其他数据结构？
	// 更改代码以反映这一点。
	// 注意：不要实际触摸空闲页面对应的物理内存！ 
	struct PageInfo* mp_entry_page = pa2page(MPENTRY_PADDR);
	size_t i;
	for (i = 1; i < npages_basemem; i++) {
		if(pages + i == mp_entry_page)
			continue;
		pages[i].pp_ref = 0;
		pages[i].pp_link = page_free_list;
		page_free_list = &pages[i];
	}
	i = PADDR(boot_alloc(0)) / PGSIZE;
	for(; i < npages; i++)
	{
		pages[i].pp_ref = 0;
		pages[i].pp_link = page_free_list;
		page_free_list = &pages[i];
	}
}

//
// Allocates a physical page.  If (alloc_flags & ALLOC_ZERO), fills the entire
// returned physical page with '\0' bytes.  Does NOT increment the reference
// count of the page - the caller must do these if necessary (either explicitly
// or via page_insert).
// 分配物理页面。如果（alloc_flags&alloc_ZERO），则用“\0”字节填充整个返回的物理页。
// 不增加页面的引用计数-如果需要，调用者必须执行这些操作（显式或通过page_insert）。

// Be sure to set the pp_link field of the allocated page to NULL so
// page_free can check for double-free bugs.
// 确保将已分配页面的pp_link字段设置为NULL，以便page_free可以检查是否存在双自由错误。

// Returns NULL if out of free memory.  如果可用内存不足，则返回NULL。 

// Hint: use page2kva and memset
struct PageInfo *
page_alloc(int alloc_flags)
{
	// Fill this function in
	struct PageInfo * result = NULL;
	if (page_free_list == NULL) return NULL;
	else if (alloc_flags && ALLOC_ZERO)
	{
		memset(page2kva(page_free_list),0,PGSIZE);
	}
	result = page_free_list;
	page_free_list = page_free_list ->pp_link;
	result->pp_link = NULL;
	return result;
}

//
// Return a page to the free list.
// (This function should only be called when pp->pp_ref reaches 0.)
//
void
page_free(struct PageInfo *pp)
{
	// Fill this function in
	// Hint: You may want to panic if pp->pp_ref is nonzero or
	// pp->pp_link is not NULL.
	if (pp->pp_ref == 0 && pp->pp_link == NULL)
	{
		pp->pp_link = page_free_list;
		page_free_list = pp;
	}
	else 
	{
		panic("pp->pp_ref is nonzero or pp->pp_link is not NULL.");
	}
}

//
// Decrement the reference count on a page,
// freeing it if there are no more refs.
//  减少页面上的引用计数，如果没有更多引用，则释放页面。 
//
void
page_decref(struct PageInfo* pp)
{
	if (--pp->pp_ref == 0)
		page_free(pp);
}

// Given 'pgdir', a pointer to a page directory, pgdir_walk returns
// a pointer to the page table entry (PTE) for linear address 'va'.
// This requires walking the two-level page table structure.
//给定“pgdir”（指向页目录的指针），pgdir_walk返回指向线性地址“va”的页表条目（PTE）的指针。这需要遍历两级页表结构。
// The relevant page table page might not exist yet.
// If this is true, and create == false, then pgdir_walk returns NULL.
// Otherwise, pgdir_walk allocates a new page table page with page_alloc. 
// 相关的页表页可能还不存在。如果这是真的，并且create==false，
// 那么pgdir_walk返回NULL。否则，pgdir_wwalk将使用page_alloc分配一个新的页表页面。
//    - If the allocation fails, pgdir_walk returns NULL.  如果分配失败，pgdir_walk将返回NULL。 
//    - Otherwise, the new page's reference count is incremented,
//	the page is cleared,
//	and pgdir_walk returns a pointer into the new page table page.
//否则，新页面的引用计数将递增，页面将被清除，pgdir_walk将返回指向新页面表页面的指针。
// Hint 1: you can turn a PageInfo * into the physical address of the
// page it refers to with page2pa() from kern/pmap.h.
//提示1：您可以将PageInfo*转换为它从kern/pmap.h使用page2pa（）引用的页面的物理地址。 
// Hint 2: the x86 MMU checks permission bits in both the page directory
// and the page table, so it's safe to leave permissions in the page
// directory more permissive than strictly necessary.
//提示2：x86 MMU检查页面目录和页面表中的权限位，因此，将页面目录中的权限保留得比严格需要的更宽松是安全的。
// Hint 3: look at inc/mmu.h for useful macros that manipulate page
// table and page directory entries.
// 提示3：查看inc/mmu.h，以获取操作页表和页目录条目的有用宏。 
pte_t *
pgdir_walk(pde_t *pgdir, const void *va, int create)
{
	// Fill this function in
	pte_t * result = NULL;
	pde_t pde;
	pte_t pte;
	pde = pgdir[PDX(va)]; 
	if (pde & PTE_P)
	{
		pte_t *pt = KADDR(PTE_ADDR(pde));
		result = &pt[PTX(va)];
	}
	else if (create)
	{
		struct PageInfo * newpg = page_alloc(ALLOC_ZERO);
		if (newpg)
		{
			pte_t *pt = (pte_t*)page2kva(newpg);
			result = &pt[PTX(va)];
			newpg->pp_ref++;
			pgdir[PDX(va)] = PADDR(pt)|(PTE_P|PTE_W|PTE_U);
		}
	}
	return result;
}

//
// Map [va, va+size) of virtual address space to physical [pa, pa+size)
// in the page table rooted at pgdir.  Size is a multiple of PGSIZE, and
// va and pa are both page-aligned.
// 将虚拟地址空间的[va，va+大小）映射到以pgdir为根的页表中的物理[pa，pa+大小）。大小是PGSIZE的倍数，并且va和pa都是页面对齐的。
// Use permission bits perm|PTE_P for the entries.
//
// This function is only intended to set up the ``static'' mappings
// above UTOP. As such, it should *not* change the pp_ref field on the
// mapped pages.
// 此函数仅用于在UTOP之上设置“静态”映射。因此，它不应该*更改映射页面上的pp_ref字段。
// Hint: the TA solution uses pgdir_walk
// boot_map_region(kern_pgdir,UPAGES,PTSIZE,PADDR(pages),PTE_U);
static void
boot_map_region(pde_t *pgdir, uintptr_t va, size_t size, physaddr_t pa, int perm)
{
	// Fill this function in
	uint32_t pgcount = size/PGSIZE;
	if (size%PGSIZE) pgcount++;
	for (int i=0;i<pgcount;i++)
	{
		pte_t * pte = pgdir_walk(pgdir,(void*)(va+i*PGSIZE),1);
		if (!pte) panic("boot_map_region:out of memory");
		*pte = (pa+i*PGSIZE)|perm|PTE_P;
	}
}

//
// Map the physical page 'pp' at virtual address 'va'.
// The permissions (the low 12 bits) of the page table entry
// should be set to 'perm|PTE_P'. 
//将物理页“pp”映射到虚拟地址“va”。页表项的权限（低12位）应设置为“perm|PTE_P”。
// Requirements
//   - If there is already a page mapped at 'va', it should be page_remove()d.  如果在“va”处已经映射了一个页面，那么它应该是page_remove（）d。 
//   - If necessary, on demand, a page table should be allocated and inserted
//     into 'pgdir'.  如有必要，应根据需要分配一个页表并将其插入到“pgdir”中。 
//   - pp->pp_ref should be incremented if the insertion succeeds.  如果插入成功，pp->pp_ref应该递增。 
//   - The TLB must be invalidated if a page was formerly present at 'va'.  如果页面以前位于“va”，则TLB必须无效。 
//
// Corner-case hint: Make sure to consider what happens when the same
// pp is re-inserted at the same virtual address in the same pgdir.
// However, try not to distinguish this case in your code, as this
// frequently leads to subtle bugs; there's an elegant way to handle
// everything in one code path.
//角落大小写提示：确保考虑在同一pgdir中的同一虚拟地址重新插入同一pp时会发生什么。
// 但是，尽量不要在代码中区分这种情况，因为这经常会导致细微的错误；有一种优雅的方法可以在一个代码路径中处理所有事情。
// RETURNS:
//   0 on success
//   -E_NO_MEM, if page table couldn't be allocated
//
// Hint: The TA solution is implemented using pgdir_walk, page_remove,
// and page2pa.  提示：TA解决方案是使用pgdir_walk、page_remove和page2pa实现的。 
//
int
page_insert(pde_t *pgdir, struct PageInfo *pp, void *va, int perm)
{
	// Fill this function in
	pte_t *pte = pgdir_walk(pgdir,va,1);
	if (!pte) return -E_NO_MEM;
	else if ((*pte) & PTE_P)
	{
		if (PTE_ADDR(*pte) == page2pa(pp)) pp->pp_ref--;
		else page_remove(pgdir,va);
	}
	*pte = page2pa(pp) |perm | PTE_P;
	pp->pp_ref++;
	return 0;
}

//
// Return the page mapped at virtual address 'va'.
// If pte_store is not zero, then we store in it the address
// of the pte for this page.  This is used by page_remove and
// can be used to verify page permissions for syscall arguments,
// but should not be used by most callers.
//返回映射到虚拟地址“va”的页面。
// 如果pte_store不为零，那么我们将在其中存储此页面的pte地址。
// 这由page_remove使用，可用于验证syscall参数的页面权限，但大多数调用者不应使用。
// Return NULL if there is no page mapped at va.  如果va.处没有映射页面，则返回NULL。 
//
// Hint: the TA solution uses pgdir_walk and pa2page.  提示：TA解决方案使用pgdir_walk和pa2page。 
//
struct PageInfo *
page_lookup(pde_t *pgdir, void *va, pte_t **pte_store)
{
	// Fill this function in
	pte_t * pte = pgdir_walk(pgdir,va,0);
	if (!pte) return NULL;
	if (pte_store) *pte_store = pte;
	if (*pte & PTE_P) return pa2page(PTE_ADDR(*pte));
	return NULL;
}

//
// Unmaps the physical page at virtual address 'va'.
// If there is no physical page at that address, silently does nothing.
//取消映射虚拟地址“va”处的物理页面。如果该地址处没有物理页面，则不执行任何操作。
// Details:
//   - The ref count on the physical page should decrement.  物理页上的引用计数应递减。 
//   - The physical page should be freed if the refcount reaches 0.  如果refcount达到0，则应释放物理页。 
//   - The pg table entry corresponding to 'va' should be set to 0.  与“va”对应的pg表条目应设置为0。 
//     (if such a PTE exists)
//   - The TLB must be invalidated if you remove an entry from
//     the page table.
//
// Hint: The TA solution is implemented using page_lookup,
// 	tlb_invalidate, and page_decref.
//
void
page_remove(pde_t *pgdir, void *va)
{
	// Fill this function in
	struct PageInfo * pginfo = page_lookup(pgdir,va,NULL);
	if (!pginfo) return;
	page_decref(pginfo);
	pde_t *pde = &pgdir[PDX(va)];
	pte_t *pt =KADDR(PTE_ADDR(*pde));
	pte_t *pte = &pt[PTX(va)];
	*pte = 0;
	tlb_invalidate(pgdir,va);
}

//
// Invalidate a TLB entry, but only if the page tables being
// edited are the ones currently in use by the processor.
//
void
tlb_invalidate(pde_t *pgdir, void *va)
{
	// Flush the entry only if we're modifying the current address space.
	if (!curenv || curenv->env_pgdir == pgdir)
		invlpg(va);
}

//
// Reserve size bytes in the MMIO region and map [pa,pa+size) at this
// location.  Return the base of the reserved region.  size does *not*
// have to be multiple of PGSIZE.
//在MMIO区域中保留大小字节，并在此位置映射[pa，pa+size）。
//返回保留区域的基数。大小不必是PGSIZE的倍数。

void *
mmio_map_region(physaddr_t pa, size_t size)
{
	// Where to start the next region.  Initially, this is the
	// beginning of the MMIO region.  Because this is static, its
	// value will be preserved between calls to mmio_map_region
	// (just like nextfree in boot_alloc).
	// 从哪里开始下一个区域。最初，这是MMIO区域的开始。
	// 因为这是静态的，所以它的值将在调用mmio_map_region之间保留（
	// 就像boot_alloc中的nextfree一样）。
	static uintptr_t base = MMIOBASE;

	// Reserve size bytes of virtual memory starting at base and
	// map physical pages [pa,pa+size) to virtual addresses
	// [base,base+size).  Since this is device memory and not
	// regular DRAM, you'll have to tell the CPU that it isn't
	// safe to cache access to this memory.  Luckily, the page
	// tables provide bits for this purpose; simply create the
	// mapping with PTE_PCD|PTE_PWT (cache-disable and
	// write-through) in addition to PTE_W.  (If you're interested
	// in more details on this, see section 10.5 of IA32 volume
	// 3A.)
	//
	// Be sure to round size up to a multiple of PGSIZE and to
	// handle if this reservation would overflow MMIOLIM (it's
	// okay to simply panic if this happens).
	//
	// Hint: The staff solution uses boot_map_region.
	//
	// Your code here:
	size = ROUNDUP(size, PGSIZE);
	// watch out for overflow
	if((base + size > MMIOLIM) || (base + size < base))
		panic("Overflow in mmio region");
	boot_map_region(kern_pgdir, base, size, pa, PTE_PCD | PTE_PWT | PTE_W);
	base += size;
	return (void*)(base - size);
	// panic("mmio_map_region not implemented");
}

static uintptr_t user_mem_check_addr;

//
// Check that an environment is allowed to access the range of memory
// [va, va+len) with permissions 'perm | PTE_P'.
// Normally 'perm' will contain PTE_U at least, but this is not required.
// 'va' and 'len' need not be page-aligned; you must test every page that
// contains any of that range.  You will test either 'len/PGSIZE',
// 'len/PGSIZE + 1', or 'len/PGSIZE + 2' pages.
//
// A user program can access a virtual address if (1) the address is below
// ULIM, and (2) the page table gives it permission.  These are exactly
// the tests you should implement here.
//
// If there is an error, set the 'user_mem_check_addr' variable to the first
// erroneous virtual address.
//
// Returns 0 if the user program can access this range of addresses,
// and -E_FAULT otherwise.
//
int
user_mem_check(struct Env *env, const void *va, size_t len, int perm)
{
	// LAB 3: Your code here.
	uintptr_t start = ROUNDDOWN((uintptr_t)va,PGSIZE);
	uintptr_t end = ROUNDUP((uintptr_t)(va+len),PGSIZE);
	pte_t *cur_pte;
	for(uintptr_t cur_va =start; cur_va < end;cur_va+=PGSIZE){
		cur_pte = pgdir_walk(env->env_pgdir,(void *)cur_va,0);
		if(cur_va>ULIM || cur_pte==NULL || (*cur_pte&(perm|PTE_P))!=(perm|PTE_P)){
		if(cur_va==start)
				user_mem_check_addr = (uintptr_t)va;
		else
				user_mem_check_addr = (uintptr_t)cur_va;

		return -E_FAULT;
		}
	}
	return 0;
}

//
// Checks that environment 'env' is allowed to access the range
// of memory [va, va+len) with permissions 'perm | PTE_U | PTE_P'.
// If it can, then the function simply returns.
// If it cannot, 'env' is destroyed and, if env is the current
// environment, this function will not return.
//
void
user_mem_assert(struct Env *env, const void *va, size_t len, int perm)
{
	if (user_mem_check(env, va, len, perm | PTE_U) < 0) {
		cprintf("[%08x] user_mem_check assertion failure for "
			"va %08x\n", env->env_id, user_mem_check_addr);
		env_destroy(env);	// may not return
	}
}


// --------------------------------------------------------------
// Checking functions.
// --------------------------------------------------------------

//
// Check that the pages on the page_free_list are reasonable.  检查page_free_list上的页面是否合理。 
//
static void
check_page_free_list(bool only_low_memory)
{
	struct PageInfo *pp;
	unsigned pdx_limit = only_low_memory ? 1 : NPDENTRIES;
	int nfree_basemem = 0, nfree_extmem = 0;
	char *first_free_page;

	if (!page_free_list)
		panic("'page_free_list' is a null pointer!");

	if (only_low_memory) {
		// Move pages with lower addresses first in the free
		// list, since entry_pgdir does not map all pages.
		struct PageInfo *pp1, *pp2;
		struct PageInfo **tp[2] = { &pp1, &pp2 };
		for (pp = page_free_list; pp; pp = pp->pp_link) {
			int pagetype = PDX(page2pa(pp)) >= pdx_limit;
			*tp[pagetype] = pp;
			tp[pagetype] = &pp->pp_link;
		}
		*tp[1] = 0;
		*tp[0] = pp2;
		page_free_list = pp1;
	}

	// if there's a page that shouldn't be on the free list,
	// try to make sure it eventually causes trouble.
	for (pp = page_free_list; pp; pp = pp->pp_link)
		if (PDX(page2pa(pp)) < pdx_limit)
			memset(page2kva(pp), 0x97, 128);

	first_free_page = (char *) boot_alloc(0);
	for (pp = page_free_list; pp; pp = pp->pp_link) {
		// check that we didn't corrupt the free list itself
		assert(pp >= pages);
		assert(pp < pages + npages);
		assert(((char *) pp - (char *) pages) % sizeof(*pp) == 0);

		// check a few pages that shouldn't be on the free list
		assert(page2pa(pp) != 0);
		assert(page2pa(pp) != IOPHYSMEM);
		assert(page2pa(pp) != EXTPHYSMEM - PGSIZE);
		assert(page2pa(pp) != EXTPHYSMEM);
		assert(page2pa(pp) < EXTPHYSMEM || (char *) page2kva(pp) >= first_free_page);
		// (new test for lab 4)
		assert(page2pa(pp) != MPENTRY_PADDR);

		if (page2pa(pp) < EXTPHYSMEM)
			++nfree_basemem;
		else
			++nfree_extmem;
	}

	assert(nfree_basemem > 0);
	assert(nfree_extmem > 0);

	cprintf("check_page_free_list() succeeded!\n");
}

//
// Check the physical page allocator (page_alloc(), page_free(),
// and page_init()).  检查物理页面分配器（page_alloc（）、page_free（）和page_init（））。 
//
static void
check_page_alloc(void)
{
	struct PageInfo *pp, *pp0, *pp1, *pp2;
	int nfree;
	struct PageInfo *fl;
	char *c;
	int i;

	if (!pages)
		panic("'pages' is a null pointer!");

	// check number of free pages
	for (pp = page_free_list, nfree = 0; pp; pp = pp->pp_link)
		++nfree;

	// should be able to allocate three pages  应该能够分配三页 
	pp0 = pp1 = pp2 = 0;
	assert((pp0 = page_alloc(0)));
	assert((pp1 = page_alloc(0)));
	assert((pp2 = page_alloc(0)));

	assert(pp0);
	assert(pp1 && pp1 != pp0);
	assert(pp2 && pp2 != pp1 && pp2 != pp0);
	assert(page2pa(pp0) < npages*PGSIZE);
	assert(page2pa(pp1) < npages*PGSIZE);
	assert(page2pa(pp2) < npages*PGSIZE);

	// temporarily steal the rest of the free pages
	fl = page_free_list;
	page_free_list = 0;

	// should be no free memory
	assert(!page_alloc(0));

	// free and re-allocate?
	page_free(pp0);
	page_free(pp1);
	page_free(pp2);
	pp0 = pp1 = pp2 = 0;
	assert((pp0 = page_alloc(0)));
	assert((pp1 = page_alloc(0)));
	assert((pp2 = page_alloc(0)));
	assert(pp0);
	assert(pp1 && pp1 != pp0);
	assert(pp2 && pp2 != pp1 && pp2 != pp0);
	assert(!page_alloc(0));

	// test flags
	memset(page2kva(pp0), 1, PGSIZE);
	page_free(pp0);
	assert((pp = page_alloc(ALLOC_ZERO)));
	assert(pp && pp0 == pp);
	c = page2kva(pp);
	for (i = 0; i < PGSIZE; i++)
		assert(c[i] == 0);

	// give free list back
	page_free_list = fl;

	// free the pages we took
	page_free(pp0);
	page_free(pp1);
	page_free(pp2);

	// number of free pages should be the same
	for (pp = page_free_list; pp; pp = pp->pp_link)
		--nfree;
	assert(nfree == 0);

	cprintf("check_page_alloc() succeeded!\n");
}

//
// Checks that the kernel part of virtual address space
// has been set up roughly correctly (by mem_init()).
//
// This function doesn't test every corner case,
// but it is a pretty good sanity check.
//

static void
check_kern_pgdir(void)
{
	uint32_t i, n;
	pde_t *pgdir;

	pgdir = kern_pgdir;

	// check pages array
	n = ROUNDUP(npages*sizeof(struct PageInfo), PGSIZE);
	for (i = 0; i < n; i += PGSIZE)
		assert(check_va2pa(pgdir, UPAGES + i) == PADDR(pages) + i);

	// check envs array (new test for lab 3)
	n = ROUNDUP(NENV*sizeof(struct Env), PGSIZE);
	// cprintf("%d\n",n);
	for (i = 0; i < n; i += PGSIZE) 
	assert(check_va2pa(pgdir, UENVS + i) == PADDR(envs) + i);
	
		

	// check phys mem
	for (i = 0; i < npages * PGSIZE; i += PGSIZE)
		assert(check_va2pa(pgdir, KERNBASE + i) == i);

	// check kernel stack
	// (updated in lab 4 to check per-CPU kernel stacks)
	for (n = 0; n < NCPU; n++) {
		uint32_t base = KSTACKTOP - (KSTKSIZE + KSTKGAP) * (n + 1);
		for (i = 0; i < KSTKSIZE; i += PGSIZE)
			assert(check_va2pa(pgdir, base + KSTKGAP + i)
				== PADDR(percpu_kstacks[n]) + i);
		for (i = 0; i < KSTKGAP; i += PGSIZE)
			assert(check_va2pa(pgdir, base + i) == ~0);
	}

	// check PDE permissions
	for (i = 0; i < NPDENTRIES; i++) {
		switch (i) {
		case PDX(UVPT):
		case PDX(KSTACKTOP-1):
		case PDX(UPAGES):
		case PDX(UENVS):
		case PDX(MMIOBASE):
			assert(pgdir[i] & PTE_P);
			break;
		default:
			if (i >= PDX(KERNBASE)) {
				assert(pgdir[i] & PTE_P);
				assert(pgdir[i] & PTE_W);
			} else
				assert(pgdir[i] == 0);
			break;
		}
	}
	cprintf("check_kern_pgdir() succeeded!\n");
}

// This function returns the physical address of the page containing 'va',
// defined by the page directory 'pgdir'.  The hardware normally performs
// this functionality for us!  We define our own version to help check
// the check_kern_pgdir() function; it shouldn't be used elsewhere.

static physaddr_t
check_va2pa(pde_t *pgdir, uintptr_t va)
{
	pte_t *p;

	pgdir = &pgdir[PDX(va)];
	
	
	if (!(*pgdir & PTE_P))
		return ~0;
	p = (pte_t*) KADDR(PTE_ADDR(*pgdir));
	// cprintf("%x\n",p[PTX(va)]);
	if (!(p[PTX(va)] & PTE_P))
		return ~0;
	return PTE_ADDR(p[PTX(va)]);
}


// check page_insert, page_remove, &c
static void
check_page(void)
{
	struct PageInfo *pp, *pp0, *pp1, *pp2;
	struct PageInfo *fl;
	pte_t *ptep, *ptep1;
	void *va;
	uintptr_t mm1, mm2;
	int i;
	extern pde_t entry_pgdir[];

	// should be able to allocate three pages
	pp0 = pp1 = pp2 = 0;
	assert((pp0 = page_alloc(0)));
	assert((pp1 = page_alloc(0)));
	assert((pp2 = page_alloc(0)));

	assert(pp0);
	assert(pp1 && pp1 != pp0);
	assert(pp2 && pp2 != pp1 && pp2 != pp0);

	// temporarily steal the rest of the free pages
	fl = page_free_list;
	page_free_list = 0;

	// should be no free memory
	assert(!page_alloc(0));

	// there is no page allocated at address 0
	assert(page_lookup(kern_pgdir, (void *) 0x0, &ptep) == NULL);

	// there is no free memory, so we can't allocate a page table
	assert(page_insert(kern_pgdir, pp1, 0x0, PTE_W) < 0);

	// free pp0 and try again: pp0 should be used for page table
	page_free(pp0);
	assert(page_insert(kern_pgdir, pp1, 0x0, PTE_W) == 0);
	assert(PTE_ADDR(kern_pgdir[0]) == page2pa(pp0));
	assert(check_va2pa(kern_pgdir, 0x0) == page2pa(pp1));
	assert(pp1->pp_ref == 1);
	assert(pp0->pp_ref == 1);

	// should be able to map pp2 at PGSIZE because pp0 is already allocated for page table
	assert(page_insert(kern_pgdir, pp2, (void*) PGSIZE, PTE_W) == 0);
	assert(check_va2pa(kern_pgdir, PGSIZE) == page2pa(pp2));
	assert(pp2->pp_ref == 1);

	// should be no free memory
	assert(!page_alloc(0));

	// should be able to map pp2 at PGSIZE because it's already there
	assert(page_insert(kern_pgdir, pp2, (void*) PGSIZE, PTE_W) == 0);
	assert(check_va2pa(kern_pgdir, PGSIZE) == page2pa(pp2));
	assert(pp2->pp_ref == 1);

	// pp2 should NOT be on the free list
	// could happen in ref counts are handled sloppily in page_insert
	assert(!page_alloc(0));

	// check that pgdir_walk returns a pointer to the pte
	ptep = (pte_t *) KADDR(PTE_ADDR(kern_pgdir[PDX(PGSIZE)]));
	assert(pgdir_walk(kern_pgdir, (void*)PGSIZE, 0) == ptep+PTX(PGSIZE));

	// should be able to change permissions too.
	assert(page_insert(kern_pgdir, pp2, (void*) PGSIZE, PTE_W|PTE_U) == 0);
	assert(check_va2pa(kern_pgdir, PGSIZE) == page2pa(pp2));
	assert(pp2->pp_ref == 1);
	assert(*pgdir_walk(kern_pgdir, (void*) PGSIZE, 0) & PTE_U);
	assert(kern_pgdir[0] & PTE_U);

	// should be able to remap with fewer permissions
	assert(page_insert(kern_pgdir, pp2, (void*) PGSIZE, PTE_W) == 0);
	assert(*pgdir_walk(kern_pgdir, (void*) PGSIZE, 0) & PTE_W);
	assert(!(*pgdir_walk(kern_pgdir, (void*) PGSIZE, 0) & PTE_U));

	// should not be able to map at PTSIZE because need free page for page table
	assert(page_insert(kern_pgdir, pp0, (void*) PTSIZE, PTE_W) < 0);

	// insert pp1 at PGSIZE (replacing pp2)
	assert(page_insert(kern_pgdir, pp1, (void*) PGSIZE, PTE_W) == 0);
	assert(!(*pgdir_walk(kern_pgdir, (void*) PGSIZE, 0) & PTE_U));

	// should have pp1 at both 0 and PGSIZE, pp2 nowhere, ...
	assert(check_va2pa(kern_pgdir, 0) == page2pa(pp1));
	assert(check_va2pa(kern_pgdir, PGSIZE) == page2pa(pp1));
	// ... and ref counts should reflect this
	assert(pp1->pp_ref == 2);
	assert(pp2->pp_ref == 0);

	// pp2 should be returned by page_alloc
	assert((pp = page_alloc(0)) && pp == pp2);

	// unmapping pp1 at 0 should keep pp1 at PGSIZE
	page_remove(kern_pgdir, 0x0);
	assert(check_va2pa(kern_pgdir, 0x0) == ~0);
	assert(check_va2pa(kern_pgdir, PGSIZE) == page2pa(pp1));
	assert(pp1->pp_ref == 1);
	assert(pp2->pp_ref == 0);

	// test re-inserting pp1 at PGSIZE
	assert(page_insert(kern_pgdir, pp1, (void*) PGSIZE, 0) == 0);
	assert(pp1->pp_ref);
	assert(pp1->pp_link == NULL);

	// unmapping pp1 at PGSIZE should free it
	page_remove(kern_pgdir, (void*) PGSIZE);
	assert(check_va2pa(kern_pgdir, 0x0) == ~0);
	assert(check_va2pa(kern_pgdir, PGSIZE) == ~0);
	assert(pp1->pp_ref == 0);
	assert(pp2->pp_ref == 0);

	// so it should be returned by page_alloc
	assert((pp = page_alloc(0)) && pp == pp1);

	// should be no free memory
	assert(!page_alloc(0));

	// forcibly take pp0 back
	assert(PTE_ADDR(kern_pgdir[0]) == page2pa(pp0));
	kern_pgdir[0] = 0;
	assert(pp0->pp_ref == 1);
	pp0->pp_ref = 0;

	// check pointer arithmetic in pgdir_walk
	page_free(pp0);
	va = (void*)(PGSIZE * NPDENTRIES + PGSIZE);
	ptep = pgdir_walk(kern_pgdir, va, 1);
	ptep1 = (pte_t *) KADDR(PTE_ADDR(kern_pgdir[PDX(va)]));
	assert(ptep == ptep1 + PTX(va));
	kern_pgdir[PDX(va)] = 0;
	pp0->pp_ref = 0;

	// check that new page tables get cleared
	memset(page2kva(pp0), 0xFF, PGSIZE);
	page_free(pp0);
	pgdir_walk(kern_pgdir, 0x0, 1);
	ptep = (pte_t *) page2kva(pp0);
	for(i=0; i<NPTENTRIES; i++)
		assert((ptep[i] & PTE_P) == 0);
	kern_pgdir[0] = 0;
	pp0->pp_ref = 0;

	// give free list back
	page_free_list = fl;

	// free the pages we took
	page_free(pp0);
	page_free(pp1);
	page_free(pp2);

	// test mmio_map_region
	mm1 = (uintptr_t) mmio_map_region(0, 4097);
	mm2 = (uintptr_t) mmio_map_region(0, 4096);
	// check that they're in the right region
	assert(mm1 >= MMIOBASE && mm1 + 8192 < MMIOLIM);
	assert(mm2 >= MMIOBASE && mm2 + 8192 < MMIOLIM);
	// check that they're page-aligned
	assert(mm1 % PGSIZE == 0 && mm2 % PGSIZE == 0);
	// check that they don't overlap
	assert(mm1 + 8192 <= mm2);
	// check page mappings
	assert(check_va2pa(kern_pgdir, mm1) == 0);
	assert(check_va2pa(kern_pgdir, mm1+PGSIZE) == PGSIZE);
	assert(check_va2pa(kern_pgdir, mm2) == 0);
	assert(check_va2pa(kern_pgdir, mm2+PGSIZE) == ~0);
	// check permissions
	assert(*pgdir_walk(kern_pgdir, (void*) mm1, 0) & (PTE_W|PTE_PWT|PTE_PCD));
	assert(!(*pgdir_walk(kern_pgdir, (void*) mm1, 0) & PTE_U));
	// clear the mappings
	*pgdir_walk(kern_pgdir, (void*) mm1, 0) = 0;
	*pgdir_walk(kern_pgdir, (void*) mm1 + PGSIZE, 0) = 0;
	*pgdir_walk(kern_pgdir, (void*) mm2, 0) = 0;

	cprintf("check_page() succeeded!\n");
}

// check page_insert, page_remove, &c, with an installed kern_pgdir
static void
check_page_installed_pgdir(void)
{
	struct PageInfo *pp, *pp0, *pp1, *pp2;
	struct PageInfo *fl;
	pte_t *ptep, *ptep1;
	uintptr_t va;
	int i;

	// check that we can read and write installed pages
	pp1 = pp2 = 0;
	assert((pp0 = page_alloc(0)));
	assert((pp1 = page_alloc(0)));
	assert((pp2 = page_alloc(0)));
	page_free(pp0);
	memset(page2kva(pp1), 1, PGSIZE);
	memset(page2kva(pp2), 2, PGSIZE);
	page_insert(kern_pgdir, pp1, (void*) PGSIZE, PTE_W);
	assert(pp1->pp_ref == 1);
	assert(*(uint32_t *)PGSIZE == 0x01010101U);
	page_insert(kern_pgdir, pp2, (void*) PGSIZE, PTE_W);
	assert(*(uint32_t *)PGSIZE == 0x02020202U);
	assert(pp2->pp_ref == 1);
	assert(pp1->pp_ref == 0);
	*(uint32_t *)PGSIZE = 0x03030303U;
	assert(*(uint32_t *)page2kva(pp2) == 0x03030303U);
	page_remove(kern_pgdir, (void*) PGSIZE);
	assert(pp2->pp_ref == 0);

	// forcibly take pp0 back
	assert(PTE_ADDR(kern_pgdir[0]) == page2pa(pp0));
	kern_pgdir[0] = 0;
	assert(pp0->pp_ref == 1);
	pp0->pp_ref = 0;

	// free the pages we took
	page_free(pp0);

	cprintf("check_page_installed_pgdir() succeeded!\n");
}
