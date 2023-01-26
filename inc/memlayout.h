#ifndef JOS_INC_MEMLAYOUT_H
#define JOS_INC_MEMLAYOUT_H

#ifndef __ASSEMBLER__
#include <inc/types.h>
#include <inc/mmu.h>
#endif /* not __ASSEMBLER__ */

/*
 * This file contains definitions for memory management in our OS,
 * which are relevant to both the kernel and user-mode software.
 * 该文件包含操作系统中内存管理的定义，这些定义与内核和用户模式软件都相关。 
 */

// Global descriptor numbers
#define GD_KT     0x08     // kernel text
#define GD_KD     0x10     // kernel data
#define GD_UT     0x18     // user text
#define GD_UD     0x20     // user data
#define GD_TSS0   0x28     // Task segment selector for CPU 0

/*
 * Virtual memory map:                                Permissions
 *                                                    kernel/user
 *
 *    4 Gig -------->  +------------------------------+
 *                     |                              | RW/--
 *                     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *                     :              .               :
 *                     :              .               :
 *                     :              .               :
 *                     |~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~| RW/--
 *                     |                              | RW/--
 *                     |   Remapped Physical Memory   | RW/--   重新映射的物理内存  
 *                     |                              | RW/--
 *    KERNBASE, ---->  +------------------------------+ 0xf0000000      --+
 *    KSTACKTOP        |     CPU0's Kernel Stack ****     | RW/--  KSTKSIZE   |
 *                     | - - - - - - - - - - - - - - -|                   |
 *                     |      Invalid Memory (*) ****     | --/--  KSTKGAP    |
 *                     +------------------------------+                   |
 *                     |     CPU1's Kernel Stack ****     | RW/--  KSTKSIZE   |
 *                     | - - - - - - - - - - - - - - -|                 PTSIZE
 *                     |      Invalid Memory (*) ****     | --/--  KSTKGAP    |
 *                     +------------------------------+                   |
 *                     :              .          ****     :                   |
 *                     :              .          ****     :                   |
 *    MMIOLIM ------>  +------------------------------+ 0xefc00000      --+
 *                     |       Memory-mapped I/O      | RW/--  PTSIZE
 * ULIM, MMIOBASE -->  +------------------------------+ 0xef800000
 *                     |  Cur. Page Table (User R-)****   | R-/R-  PTSIZE
 *    UVPT      ---->  +------------------------------+ 0xef400000
 *                     |          RO PAGES       ****     | R-/R-  PTSIZE
 *    UPAGES    ---->  +------------------------------+ 0xef000000
 *                     |           RO ENVS   ????         | R-/R-  PTSIZE
 * UTOP,UENVS ------>  +------------------------------+ 0xeec00000
 * UXSTACKTOP -/       |     User Exception Stack     | RW/RW  PGSIZE  用户异常堆栈 
 *                     +------------------------------+ 0xeebff000
 *                     |       Empty Memory (*)       | --/--  PGSIZE
 *    USTACKTOP  --->  +------------------------------+ 0xeebfe000
 *                     |      Normal User Stack       | RW/RW  PGSIZE
 *                     +------------------------------+ 0xeebfd000
 *                     |                              |
 *                     |                              |
 *                     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *                     .                              .
 *                     .                              .
 *                     .                              .
 *                     |~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
 *                     |     Program Data & Heap      |
 *    UTEXT -------->  +------------------------------+ 0x00800000
 *    PFTEMP ------->  |       Empty Memory (*)       |        PTSIZE
 *                     |                              |
 *    UTEMP -------->  +------------------------------+ 0x00400000      --+
 *                     |       Empty Memory (*)       |                   |
 *                     | - - - - - - - - - - - - - - -|                   |
 *                     |  User STAB Data (optional)   |                 PTSIZE
 *    USTABDATA ---->  +------------------------------+ 0x00200000        |
 *                     |       Empty Memory (*)       |                   |
 *    0 ------------>  +------------------------------+                 --+
 *
 * (*) Note: The kernel ensures that "Invalid Memory" is *never* mapped.
 *     "Empty Memory" is normally unmapped, but user programs may map pages
 *     there if desired.  JOS user programs map pages temporarily at UTEMP.
 */


// All physical memory mapped at this address 映射到此地址的所有物理内存
#define	KERNBASE	0xF0000000

// At  (640K) there is a 384K hole for I/O.  From the kernel,
// IOPHYSMEM can be addressed IOPHYSMEMat KERNBASE + IOPHYSMEM.  The hole ends
// at physical address EXTPHYSMEM. 在（640K）时，有一个384K的I/O孔。从内核中，IOPHYSEM可以被称为IOPHYSEMAT KERNBASE+IOPHYSME。该洞在物理地址EXTPHYSEM处结束。
#define IOPHYSMEM	0x0A0000
#define EXTPHYSMEM	0x100000

// Kernel stack.
#define KSTACKTOP	KERNBASE
#define KSTKSIZE	(8*PGSIZE)   		// size of a kernel stack
#define KSTKGAP		(8*PGSIZE)   		// size of a kernel stack guard

// Memory-mapped IO.
#define MMIOLIM		(KSTACKTOP - PTSIZE)
#define MMIOBASE	(MMIOLIM - PTSIZE)

#define ULIM		(MMIOBASE)

/*
 * User read-only mappings! Anything below here til UTOP are readonly to user.
 * They are global pages mapped in at env allocation time.
 * 用户只读映射！下面的任何内容直到UTOP都是用户只读的。它们是在env分配时映射到的全局页面。
 */

// User read-only virtual page table (see 'uvpt' below)
#define UVPT		(ULIM - PTSIZE)
// Read-only copies of the Page structures  Page结构的只读副本 
#define UPAGES		(UVPT - PTSIZE)
// Read-only copies of the global env structures  全局env结构的只读副本 
#define UENVS		(UPAGES - PTSIZE)

/*
 * Top of user VM. User can manipulate VA from UTOP-1 and down!
  用户VM顶部。用户可以从UTOP-1向下操纵VA！ 
 */

// Top of user-accessible VM  用户可访问VM的顶部 
#define UTOP		UENVS
// Top of one-page user exception stack  单页用户异常堆栈顶部 
#define UXSTACKTOP	UTOP
// Next page left invalid to guard against exception stack overflow; then:
// Top of normal user stack 下一页保持无效以防止异常堆栈溢出；然后：正常用户堆栈的顶部
#define USTACKTOP	(UTOP - 2*PGSIZE)

// Where user programs generally begin  用户程序通常从哪里开始 
#define UTEXT		(2*PTSIZE)

// Used for temporary page mappings.  Typed 'void*' for convenience  用于临时页面映射。为方便起见，键入“void*” 
#define UTEMP		((void*) PTSIZE)
// Used for temporary page mappings for the user page-fault handler  用于用户页面错误处理程序的临时页面映射 
// (should not conflict with other temporary page mappings)  （不应与其他临时页面映射冲突） 
#define PFTEMP		(UTEMP + PTSIZE - PGSIZE)
// The location of the user-level STABS data structure  用户级STABS数据结构的位置 
#define USTABDATA	(PTSIZE / 2)

// Physical address of startup code for non-boot CPUs (APs)
#define MPENTRY_PADDR	0x7000

#ifndef __ASSEMBLER__

typedef uint32_t pte_t;
typedef uint32_t pde_t;

#if JOS_USER
/*
 * The page directory entry corresponding to the virtual address range
 * [UVPT, UVPT + PTSIZE) points to the page directory itself.  Thus, the page
 * directory is treated as a page table as well as a page directory.
 *
 * One result of treating the page directory as a page table is that all PTEs
 * can be accessed through a "virtual page table" at virtual address UVPT (to
 * which uvpt is set in lib/entry.S).  The PTE for page number N is stored in
 * uvpt[N].  (It's worth drawing a diagram of this!)
 *
 * A second consequence is that the contents of the current page directory
 * will always be available at virtual address (UVPT + (UVPT >> PGSHIFT)), to
 * which uvpd is set in lib/entry.S.
 */
extern volatile pte_t uvpt[];     // VA of "virtual page table"
extern volatile pde_t uvpd[];     // VA of current page directory
#endif

/*
 * Page descriptor structures, mapped at UPAGES.
 * Read/write to the kernel, read-only to user programs.
 *
 * Each struct PageInfo stores metadata for one physical page.
 * Is it NOT the physical page itself, but there is a one-to-one
 * correspondence between physical pages and struct PageInfo's.
 * You can map a struct PageInfo * to the corresponding physical address
 * with page2pa() in kern/pmap.h. 
 * 页面描述符结构，映射到UPAGES。读/写内核，对用户程序只读。每个结构PageInfo存储一个物理页面的元数据。
 * 它不是物理页面本身，而是物理页面和结构PageInfo之间存在一对一的对应关系。
 * 您可以使用kern/pmap.h中的page2pa）将结构PageInfo*映射到对应的物理地址。
 */
struct PageInfo {
	// Next page on the free list.  免费列表的下一页。 
	struct PageInfo *pp_link;

	// pp_ref is the count of pointers (usually in page table entries)
	// to this page, for pages allocated using page_alloc.
	// Pages allocated at boot time using pmap.c's
	// boot_alloc do not have valid reference count fields.
	//pp_ref是指向此页面的指针计数（通常在页面表条目中），
	//用于使用page_alloc分配的页面。使用pmap.c的boot_alloc在启动时分配的页面没有有效的引用计数字段。

	uint16_t pp_ref;
};

#endif /* !__ASSEMBLER__ */
#endif /* !JOS_INC_MEMLAYOUT_H */
