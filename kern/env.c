/* See COPYRIGHT for copyright information. */

#include <inc/x86.h>
#include <inc/mmu.h>
#include <inc/error.h>
#include <inc/string.h>
#include <inc/assert.h>
#include <inc/elf.h>

#include <kern/env.h>
#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/monitor.h>

struct Env *envs = NULL;		// All environments
struct Env *curenv = NULL;		// The current env
static struct Env *env_free_list;	// Free environment list
					// (linked by Env->env_link)

#define ENVGENSHIFT	12		// >= LOGNENV

// Global descriptor table.
//
// Set up global descriptor table (GDT) with separate segments for
// kernel mode and user mode.  Segments serve many purposes on the x86.
// We don't use any of their memory-mapping capabilities, but we need
// them to switch privilege levels. 
//
// The kernel and user segments are identical except for the DPL.
// To load the SS register, the CPL must equal the DPL.  Thus,
// we must duplicate the segments for the user and the kernel.
//
// In particular, the last argument to the SEG macro used in the
// definition of gdt specifies the Descriptor Privilege Level (DPL)
// of that descriptor: 0 for kernel and 3 for user.
//
struct Segdesc gdt[] =
{
	// 0x0 - unused (always faults -- for trapping NULL far pointers)
	SEG_NULL,

	// 0x8 - kernel code segment
	[GD_KT >> 3] = SEG(STA_X | STA_R, 0x0, 0xffffffff, 0),

	// 0x10 - kernel data segment
	[GD_KD >> 3] = SEG(STA_W, 0x0, 0xffffffff, 0),

	// 0x18 - user code segment
	[GD_UT >> 3] = SEG(STA_X | STA_R, 0x0, 0xffffffff, 3),

	// 0x20 - user data segment
	[GD_UD >> 3] = SEG(STA_W, 0x0, 0xffffffff, 3),

	// 0x28 - tss, initialized in trap_init_percpu()
	[GD_TSS0 >> 3] = SEG_NULL
};

struct Pseudodesc gdt_pd = {
	sizeof(gdt) - 1, (unsigned long) gdt
};

//
// Converts an envid to an env pointer.
// If checkperm is set, the specified environment must be either the
// current environment or an immediate child of the current environment.
//
// RETURNS
//   0 on success, -E_BAD_ENV on error.
//   On success, sets *env_store to the environment.
//   On error, sets *env_store to NULL.
//
int
envid2env(envid_t envid, struct Env **env_store, bool checkperm)
{
	struct Env *e;

	// If envid is zero, return the current environment.
	if (envid == 0) {
		*env_store = curenv;
		return 0;
	}

	// Look up the Env structure via the index part of the envid,
	// then check the env_id field in that struct Env
	// to ensure that the envid is not stale
	// (i.e., does not refer to a _previous_ environment
	// that used the same slot in the envs[] array).
	e = &envs[ENVX(envid)];
	if (e->env_status == ENV_FREE || e->env_id != envid) {
		*env_store = 0;
		return -E_BAD_ENV;
	}

	// Check that the calling environment has legitimate permission
	// to manipulate the specified environment.
	// If checkperm is set, the specified environment
	// must be either the current environment
	// or an immediate child of the current environment.
	if (checkperm && e != curenv && e->env_parent_id != curenv->env_id) {
		*env_store = 0;
		return -E_BAD_ENV;
	}

	*env_store = e;
	return 0;
}

// Mark all environments in 'envs' as free, set their env_ids to 0,
// and insert them into the env_free_list.
// Make sure the environments are in the free list in the same order
// they are in the envs array (i.e., so that the first call to
// env_alloc() returns envs[0]).
// 将“envs”中的所有环境标记为空闲，将其env_id设置为0，并将其插入env_free_list中。
// 确保环境在空闲列表中的顺序与在envs数组中的顺序相同（即，第一次调用env_alloc（）
// 返回envs[0]）。
void
env_init(void)
{
	// Set up envs array
	// LAB 3: Your code here.
	struct Env* rear = envs;
	env_free_list = rear;
	for (int i=0;i<NENV;i++)
	{
		envs[i].env_id = 0;
		envs[i].env_status = ENV_FREE;
		if (i)
		{
			rear ->env_link = &envs[i];
			rear = &envs[i];
		}
	}
	rear ->env_link = NULL;
	// Per-CPU part of the initialization
	env_init_percpu();
}

// Load GDT and segment descriptors.
//  加载GDT和段描述符。 
void
env_init_percpu(void)
{
	lgdt(&gdt_pd);
	// The kernel never uses GS or FS, so we leave those set to
	// the user data segment.
	asm volatile("movw %%ax,%%gs" : : "a" (GD_UD|3));
	asm volatile("movw %%ax,%%fs" : : "a" (GD_UD|3));
	// The kernel does use ES, DS, and SS.  We'll change between
	// the kernel and user data segments as needed.
	asm volatile("movw %%ax,%%es" : : "a" (GD_KD));
	asm volatile("movw %%ax,%%ds" : : "a" (GD_KD));
	asm volatile("movw %%ax,%%ss" : : "a" (GD_KD));
	// Load the kernel text segment into CS.
	asm volatile("ljmp %0,$1f\n 1:\n" : : "i" (GD_KT));
	// For good measure, clear the local descriptor table (LDT),
	// since we don't use it.
	lldt(0);
}

//
// Initialize the kernel virtual memory layout for environment e.
// Allocate a page directory, set e->env_pgdir accordingly,
// and initialize the kernel portion of the new environment's address space.
// Do NOT (yet) map anything into the user portion
// of the environment's virtual address space.
//
// Returns 0 on success, < 0 on error.  Errors include:
//	-E_NO_MEM if page directory or table could not be allocated.
//
static int
env_setup_vm(struct Env *e)
{
	int i;
	struct PageInfo *p = NULL;

	// Allocate a page for the page directory 
	//  为页面目录分配页面 
	if (!(p = page_alloc(ALLOC_ZERO)))
		return -E_NO_MEM;

	// Now, set e->env_pgdir and initialize the page directory.
	
	// Hint:
	//    - The VA space of all envs is identical above UTOP
	// 	(except at UVPT, which we've set below).
	// 	See inc/memlayout.h for permissions and layout.
	// 	Can you use kern_pgdir as a template?  Hint: Yes.
	// 	(Make sure you got the permissions right in Lab 2.)
	//    - The initial VA below UTOP is empty.
	//    - You do not need to make any more calls to page_alloc.
	//    - Note: In general, pp_ref is not maintained for
	// 	physical pages mapped only above UTOP, but env_pgdir
	// 	is an exception -- you need to increment env_pgdir's
	// 	pp_ref for env_free to work correctly.
	//    - The functions in kern/pmap.h are handy.


	//现在，设置e->env_pgdir并初始化页面目录。
	//提示：
	//-所有env的VA空间在UTOP之上相同
	//（除了UVPT，我们在下面设置了）。
	//有关权限和布局，请参阅inc/memlayout.h。
	//您可以使用kern_pgdir作为模板吗？提示：是的。
	//（确保您在实验室2中获得了正确的权限。）
	//-UTOP以下的初始VA为空。
	//-您不需要再调用page_alloc。
	//-注意：通常，pp_ref不用于
	//物理页面仅映射在UTOP之上，但env_pgdir
	//是一个例外--您需要增加env_pgdir的
	//pp_ref使env_free正常工作。
	//-kern/pmap.h中的函数很方便。 
	// LAB 3: Your code here.
	e->env_pgdir = (pde_t*)page2kva(p);
	memcpy(e->env_pgdir,kern_pgdir,PGSIZE);
	// UVPT maps the env's own page table read-only.
	// Permissions: kernel R, user R
	e->env_pgdir[PDX(UVPT)] = PADDR(e->env_pgdir) | PTE_P | PTE_U;
	p->pp_ref++;
	return 0;
}

//
// Allocates and initializes a new environment.
// On success, the new environment is stored in *newenv_store.
//
// Returns 0 on success, < 0 on failure.  Errors include:
//	-E_NO_FREE_ENV if all NENV environments are allocated
//	-E_NO_MEM on memory exhaustion
//
int
env_alloc(struct Env **newenv_store, envid_t parent_id)
{
	int32_t generation;
	int r;
	struct Env *e;

	if (!(e = env_free_list))
		return -E_NO_FREE_ENV;

	// Allocate and set up the page directory for this environment.
	if ((r = env_setup_vm(e)) < 0)
		return r;

	// Generate an env_id for this environment.
	generation = (e->env_id + (1 << ENVGENSHIFT)) & ~(NENV - 1);
	if (generation <= 0)	// Don't create a negative env_id.
		generation = 1 << ENVGENSHIFT;
	e->env_id = generation | (e - envs);

	// Set the basic status variables.
	e->env_parent_id = parent_id;
	e->env_type = ENV_TYPE_USER;
	e->env_status = ENV_RUNNABLE;
	e->env_runs = 0;

	// Clear out all the saved register state,
	// to prevent the register values
	// of a prior environment inhabiting this Env structure
	// from "leaking" into our new environment.
	// 清除所有保存的寄存器状态，
	// 以防止驻留在此Env结构中的先前环境的寄存器值“泄漏”到我们的新环境中。 


	memset(&e->env_tf, 0, sizeof(e->env_tf));

	// Set up appropriate initial values for the segment registers.
	// GD_UD is the user data segment selector in the GDT, and
	// GD_UT is the user text segment selector (see inc/memlayout.h).
	// The low 2 bits of each segment register contains the
	// Requestor Privilege Level (RPL); 3 means user mode.  When
	// we switch privilege levels, the hardware does various
	// checks involving the RPL and the Descriptor Privilege Level
	// (DPL) stored in the descriptors themselves.
	// 

	// 为段寄存器设置适当的初始值。GD_UD是GDT中的用户数据段选择器，GD_UT是用户文本段选择器
	// （参见inc/memlayout.h）。每个段寄存器的低2位包含请求者权限级别（RPL）；
	// 3表示用户模式。当我们切换特权级别时，硬件会进行各种检查，
	// 包括存储在描述符自身中的RPL和描述符特权级别（DPL）。 
	e->env_tf.tf_ds = GD_UD | 3;
	e->env_tf.tf_es = GD_UD | 3;
	e->env_tf.tf_ss = GD_UD | 3;
	e->env_tf.tf_esp = USTACKTOP;
	e->env_tf.tf_cs = GD_UT | 3;
	// You will set e->env_tf.tf_eip later.

	// commit the allocation
	env_free_list = e->env_link;
	*newenv_store = e;

	cprintf("[%08x] new env %08x\n", curenv ? curenv->env_id : 0, e->env_id);
	return 0;
}

//
// Allocate len bytes of physical memory for environment env,
// and map it at virtual address va in the environment's address space.
// Does not zero or otherwise initialize the mapped pages in any way.
// Pages should be writable by user and kernel.
// Panic if any allocation attempt fails.
//
//  为env环境分配len字节的物理内存，
//  并将其映射到环境地址空间中的虚拟地址va。
//  不会以任何方式对映射的页面进行清零或初始化。
//  页面应可由用户和内核写入。如果任何分配尝试失败，请恐慌。 
static void
region_alloc(struct Env *e, void *va, size_t len)
{
	// LAB 3: Your code here.
	// (But only if you need it for load_icode.)
	//
	// Hint: It is easier to use region_alloc if the caller can pass
	//   'va' and 'len' values that are not page-aligned.
	//   You should round va down, and round (va + len) up.
	//   (Watch out for corner-cases!)
	// 提示：如果调用者可以传递不对齐的“va”和“len”值，则使用region_alloc更容易。
	// 您应该向下舍入va，向上舍入（va+len）（小心角落的箱子！）
	uint32_t osz  = ROUNDDOWN((uint32_t)va,PGSIZE);
	uint32_t nsz  = ROUNDUP((uint32_t)(va+len),PGSIZE);
	for (int i=osz ;i<nsz;i+=PGSIZE)
	{
		struct PageInfo * p = page_alloc(ALLOC_ZERO);
		if (!p)
		{
			panic("region_alloc : out of memory");
		}
		if (page_insert(e->env_pgdir,p,(char*)i,PTE_W|PTE_U)==-E_NO_MEM)
		{
			panic("region_alloc,page_insert: out of memory");
		}
	}
}

//
// Set up the initial program binary, stack, and processor flags
// for a user process.
// This function is ONLY called during kernel initialization,
// before running the first user-mode environment.

// This function loads all loadable segments from the ELF binary image
// into the environment's user memory, starting at the appropriate
// virtual addresses indicated in the ELF program header.
// At the same time it clears to zero any portions of these segments
// that are marked in the program header as being mapped
// but not actually present in the ELF file - i.e., the program's bss section.

// All this is very similar to what our boot loader does, except the boot
// loader also needs to read the code from disk.  Take a look at
// boot/main.c to get ideas.

// Finally, this function maps one page for the program's initial stack.

// load_icode panics if it encounters problems.
//  - How might load_icode fail?  What might be wrong with the given input?
//


// 为用户进程设置初始程序二进制、堆栈和处理器标志。
// 此函数仅在内核初始化期间调用，然后运行第一个用户模式环境。 

// 此函数将ELF二进制映像中的所有可加载段加载到环境的用户内存中，
// 从ELF程序头中指示的适当虚拟地址开始。
// 同时，它将这些段中在程序头中标记为已映射但实际不存在于ELF文件中的任何部分清零，
// 即程序的bss部分。

// 所有这些都与我们的引导加载程序非常相似，
// 只是引导加载程序还需要从磁盘读取代码。请查看boot/main.c以获得想法。

//  最后，这个函数为程序的初始堆栈映射一个页面。如果遇到问题，load_icode会死机。
static void
load_icode(struct Env *e, uint8_t *binary)
{
	// Hints:
	//  Load each program segment into virtual memory
	//  at the address specified in the ELF segment header.
	//  You should only load segments with ph->p_type == ELF_PROG_LOAD.
	//  Each segment's virtual address can be found in ph->p_va
	//  and its size in memory can be found in ph->p_memsz.
	//  The ph->p_filesz bytes from the ELF binary, starting at
	//  'binary + ph->p_offset', should be copied to virtual address
	//  ph->p_va.  Any remaining memory bytes should be cleared to zero.
	//  (The ELF header should have ph->p_filesz <= ph->p_memsz.)
	//  Use functions from the previous lab to allocate and map pages.
	//
	// 将每个程序段加载到ELF段标头中指定的地址处的虚拟内存中。
	// 只能加载ph->p_type==ELF_PROG_Load的段。
	// 每个段的虚拟地址可以在ph->p_va中找到，其在内存中的大小可以在ph->p_memsz中找到。
	// 应从“binary+ph->p_offset”开始的ELF二进制文件中的ph->p_filesz字节应复制到虚拟地址ph->p_va。
	// 任何剩余的内存字节都应清除为零
	// ELF标头应具有ph->p_filesz<=ph->p_memsz。）使用上一个实验室的函数来分配和映射页面。

	
	//  All page protection bits should be user read/write for now.
	//  ELF segments are not necessarily page-aligned, but you can
	//  assume for this function that no two segments will touch
	//  the same virtual page.
	// 现在，所有页面保护位都应该是用户读/写的。
	// LF段不一定是页面对齐的，但您可以假设没有两个段会接触同一虚拟页面。
	//
	//  You may find a function like region_alloc useful.
	// 您可能会发现region_alloc这样的函数很有用。 
	//  Loading the segments is much simpler if you can move data
	//  directly into the virtual addresses stored in the ELF binary.
	//  So which page directory should be in force during
	//  this function?
	// 如果您可以将数据直接移动到存储在ELF二进制文件中的虚拟地址中，
	// 那么加载段就要简单得多。那么在执行此功能期间，哪个页面目录应该有效？
	//  You must also do something with the program's entry point,
	//  to make sure that the environment starts executing there.
	//  What?  (See env_run() and env_pop_tf() below.)
	//  您还必须对程序的入口点执行一些操作，以确保环境开始在那里执行。 
	// LAB 3: Your code here.
	struct Elf* elfHdr = (struct Elf*) binary;

	if (elfHdr->e_magic !=ELF_MAGIC || !elfHdr->e_entry)
	{
		panic("invalid elf file or invalid entry\n");
	}
	e->env_tf.tf_eip = elfHdr->e_entry;
	struct  Proghdr * ph;
	struct  Proghdr * eph;
	ph = (struct Proghdr*)((uint8_t*)elfHdr+elfHdr->e_phoff);
	eph = ph + elfHdr->e_phnum;

	lcr3(PADDR(e->env_pgdir));
	for (;ph!=eph;ph++)
	{
		if (ph->p_type == ELF_PROG_LOAD)
		{
			if (ph->p_memsz < ph->p_filesz) panic("load_icode:p_memsz< p_filesz");
			region_alloc(e,(char*)ph->p_va,ph->p_memsz);
			memset((char*)ph->p_va,0,ph->p_memsz);
			memcpy((char*)ph->p_va,binary+ph->p_offset,ph->p_filesz);
		}

	}
	lcr3(PADDR(kern_pgdir));
	// Now map one page for the program's initial stack
	// at virtual address USTACKTOP - PGSIZE.
	// LAB 3: Your code here.
	region_alloc(e,(char*)(USTACKTOP-PGSIZE),PGSIZE);
}

//
// Allocates a new env with env_alloc, loads the named elf
// binary into it with load_icode, and sets its env_type.
// This function is ONLY called during kernel initialization,
// before running the first user-mode environment.
// The new env's parent ID is set to 0.
//
void
env_create(uint8_t *binary, enum EnvType type)
{
	// LAB 3: Your code here.
	struct Env* env;
	if (env_alloc(&env,0)<0)
	{
		panic("env_create:fail");
	}
	load_icode(env,binary);
	env->env_type = type;
}

//
// Frees env e and all memory it uses.
//
void
env_free(struct Env *e)
{
	pte_t *pt;
	uint32_t pdeno, pteno;
	physaddr_t pa;

	// If freeing the current environment, switch to kern_pgdir
	// before freeing the page directory, just in case the page
	// gets reused.
	//  如果释放当前环境，请在释放页面目录之前切换到kern_pgdir，以防页面被重用。 
	if (e == curenv)
		lcr3(PADDR(kern_pgdir));

	// Note the environment's demise.
	cprintf("[%08x] free env %08x\n", curenv ? curenv->env_id : 0, e->env_id);

	// Flush all mapped pages in the user portion of the address space
	//  刷新地址空间的用户部分中的所有映射页面 
	static_assert(UTOP % PTSIZE == 0);
	for (pdeno = 0; pdeno < PDX(UTOP); pdeno++) {

		// only look at mapped page tables
		if (!(e->env_pgdir[pdeno] & PTE_P))
			continue;

		// find the pa and va of the page table
		//  查找页表的pa和va 
		pa = PTE_ADDR(e->env_pgdir[pdeno]);
		pt = (pte_t*) KADDR(pa);

		// unmap all PTEs in this page table
		for (pteno = 0; pteno <= PTX(~0); pteno++) {
			if (pt[pteno] & PTE_P)
				page_remove(e->env_pgdir, PGADDR(pdeno, pteno, 0));
		}

		// free the page table itself
		e->env_pgdir[pdeno] = 0;
		page_decref(pa2page(pa));
	}

	// free the page directory
	pa = PADDR(e->env_pgdir);
	e->env_pgdir = 0;
	page_decref(pa2page(pa));

	// return the environment to the free list
	e->env_status = ENV_FREE;
	e->env_link = env_free_list;
	env_free_list = e;
}

//
// Frees environment e.
//
void
env_destroy(struct Env *e)
{
	env_free(e);

	cprintf("Destroyed the only environment - nothing more to do!\n");
	while (1)
		monitor(NULL);
}


//
// Restores the register values in the Trapframe with the 'iret' instruction.
// This exits the kernel and starts executing some environment's code.
//
// This function does not return.
//

// 使用“iret”指令恢复陷阱帧中的寄存器值。
// 这将退出内核并开始执行某些环境代码。 
void
env_pop_tf(struct Trapframe *tf)
{
	asm volatile(
		"\tmovl %0,%%esp\n"
		"\tpopal\n"
		"\tpopl %%es\n"
		"\tpopl %%ds\n"
		"\taddl $0x8,%%esp\n" /* skip tf_trapno and tf_errcode */
		"\tiret\n"
		: : "g" (tf) : "memory");
	panic("iret failed");  /* mostly to placate the compiler */
}

//
// Context switch from curenv to env e.
// Note: if this is the first call to env_run, curenv is NULL.
//
// This function does not return.
//
void
env_run(struct Env *e)
{
	// Step 1: If this is a context switch (a new environment is running):
	//	   1. Set the current environment (if any) back to
	//	      ENV_RUNNABLE if it is ENV_RUNNING (think about
	//	      what other states it can be in),
	//	   2. Set 'curenv' to the new environment,
	//	   3. Set its status to ENV_RUNNING,
	//	   4. Update its 'env_runs' counter,
	//	   5. Use lcr3() to switch to its address space.
	// Step 2: Use env_pop_tf() to restore the environment's
	//	   registers and drop into user mode in the
	//	   environment.

	// Hint: This function loads the new environment's state from
	//	e->env_tf.  Go back through the code you wrote above
	//	and make sure you have set the relevant parts of
	//	e->env_tf to sensible values.

	// LAB 3: Your code here.

	// panic("env_run not yet implemented");

	if (curenv != NULL && curenv->env_status == ENV_RUNNING)
	{
		curenv->env_status = ENV_RUNNABLE;
	}
	curenv = e;
	curenv -> env_status = ENV_RUNNING;
	curenv->env_runs++;
	lcr3(PADDR(curenv->env_pgdir));
	env_pop_tf(&curenv->env_tf);
}

