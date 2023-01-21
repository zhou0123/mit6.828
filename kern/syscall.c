/* See COPYRIGHT for copyright information. */

#include <inc/x86.h>
#include <inc/error.h>
#include <inc/string.h>
#include <inc/assert.h>

#include <kern/env.h>
#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/syscall.h>
#include <kern/console.h>
#include <kern/sched.h>

// Print a string to the system console.
// The string is exactly 'len' characters long.
// Destroys the environment on memory errors.
static void
sys_cputs(const char *s, size_t len)
{
	// Check that the user has permission to read memory [s, s+len).
	// Destroy the environment if not.

	// LAB 3: Your code here.
	user_mem_assert(curenv,s,len,PTE_U|PTE_P);
	// Print the string supplied by the user.
	cprintf("%.*s", len, s);
}

// Read a character from the system console without blocking.
// Returns the character, or 0 if there is no input waiting.
static int
sys_cgetc(void)
{
	return cons_getc();
}

// Returns the current environment's envid.
static envid_t
sys_getenvid(void)
{
	return curenv->env_id;
}

// Destroy a given environment (possibly the currently running environment).
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
static int
sys_env_destroy(envid_t envid)
{
	int r;
	struct Env *e;

	if ((r = envid2env(envid, &e, 1)) < 0)
		return r;
	if (e == curenv)
		cprintf("[%08x] exiting gracefully\n", curenv->env_id);
	else
		cprintf("[%08x] destroying %08x\n", curenv->env_id, e->env_id);
	env_destroy(e);
	return 0;
}

// Deschedule current environment and pick a different one to run.
static void
sys_yield(void)
{
	sched_yield();
}

// Allocate a new environment.
// Returns envid of new environment, or < 0 on error.  Errors are:
//	-E_NO_FREE_ENV if no free environment is available.
//	-E_NO_MEM on memory exhaustion.
static envid_t
sys_exofork(void)
{
	// Create the new environment with env_alloc(), from kern/env.c.
	// It should be left as env_alloc created it, except that
	// status is set to ENV_NOT_RUNNABLE, and the register set is copied
	// from the current environment -- but tweaked so sys_exofork
	// will appear to return 0.
	// 使用env_alloc（）从kern/env.c.创建新环境。
	// 它应该保留为env_allo创建的环境，但状态设置为env_NOT_RUNNABLE，
	// 寄存器集从当前环境复制，但经过调整，sys_exofork将显示为返回0。

	// LAB 4: Your code here.
	// panic("sys_exofork not implemented");
	struct Env* sonEnv = NULL;
	int err = env_alloc(&sonEnv,curenv->env_id);
	if (err<0) return err;
	sonEnv->env_status = ENV_NOT_RUNNABLE;
	memcpy(&sonEnv->env_tf,&curenv->env_tf,sizeof(struct Trapframe));
	sonEnv->env_tf.tf_regs.reg_eax=0;
	return sonEnv->env_id;
	
}

// Set envid's env_status to status, which must be ENV_RUNNABLE
// or ENV_NOT_RUNNABLE.
// 将envid的env_status设置为状态，该状态必须为env_RUNNABLE或env_NOT_RUNNABLE。
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if status is not a valid status for an environment.
static int
sys_env_set_status(envid_t envid, int status)
{
	// Hint: Use the 'envid2env' function from kern/env.c to translate an
	// envid to a struct Env.
	// You should set envid2env's third argument to 1, which will
	// check whether the current environment has permission to set
	// envid's status.
	// 提示：使用kern/env.c中的“envd2env”函数将envid转换为结构env。
	// 您应该将envidenv的第三个参数设置为1，这将检查当前环境是否具有设置envid状态的权限。

	// LAB 4: Your code here.
	int ret = 0;
	struct Env *env;
	if (status != ENV_RUNNABLE && status != ENV_NOT_RUNNABLE) 
		return -E_INVAL;
	
	if ((ret = envid2env(envid, &env, 1)) < 0) 
		return -E_BAD_ENV;

	env->env_status = status;
	return 0;

}

// Set the page fault upcall for 'envid' by modifying the corresponding struct
// Env's 'env_pgfault_upcall' field.  When 'envid' causes a page fault, the
// kernel will push a fault record onto the exception stack, then branch to
// 'func'.
// 通过修改相应结构Env的“Env_pgfault_upcall”字段，为“envid”设置页面错误上调。
// 当“envid”导致页面错误时，内核会将错误记录推送到异常堆栈，然后分支到“func”。

//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
static int
sys_env_set_pgfault_upcall(envid_t envid, void *func)
{
	// LAB 4: Your code here.
	// panic("sys_env_set_pgfault_upcall not implemented");
	struct Env* store = NULL;
	if(envid2env(envid, &store, 1) < 0)return -E_BAD_ENV;
	store->env_pgfault_upcall = func;
	return 0;
}

// Allocate a page of memory and map it at 'va' with permission
// 'perm' in the address space of 'envid'.
// The page's contents are set to 0.
// If a page is already mapped at 'va', that page is unmapped as a
// side effect.
// 分配一页内存，并将其映射到“va”，权限为“perm”，地址空间为“envid”。
// 页面的内容设置为0。如果页面已映射到“va”，则该页面将作为副作用取消映射。
// perm -- PTE_U | PTE_P must be set, PTE_AVAIL | PTE_W may or may not be set,
//         but no other bits may be set.  See PTE_SYSCALL in inc/mmu.h.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if va >= UTOP, or va is not page-aligned.
//	-E_INVAL if perm is inappropriate (see above).
//	-E_NO_MEM if there's no memory to allocate the new page,
//		or to allocate any necessary page tables.
static int
sys_page_alloc(envid_t envid, void *va, int perm)
{
	// Hint: This function is a wrapper around page_alloc() and
	//   page_insert() from kern/pmap.c.
	//   Most of the new code you write should be to check the
	//   parameters for correctness.
	//   If page_insert() fails, remember to free the page you
	//   allocated!
	// 提示：此函数是kern/pmap中page_alloc（）和page_insert（）的包装器。
	// 您编写的大部分新代码应该是检查参数的正确性。如果page_inserd（）失败，请记住释放您分配的页面！

	// LAB 4: Your code here.
	// panic("sys_page_alloc not implemented");
	struct Env* store = NULL;
	struct PageInfo* page =NULL;
	if(envid2env(envid, &store, 1) < 0)return -E_BAD_ENV;
	if(((uintptr_t)va >= (uintptr_t)UTOP) || (ROUNDDOWN((uintptr_t)va, PGSIZE) != (uintptr_t)va))
		return -E_INVAL;
	if(((perm & PTE_U) == 0) || ((perm & PTE_P) == 0))return -E_INVAL;
	if((perm & ~PTE_SYSCALL) != 0)return -E_INVAL;
	if((page = page_alloc(ALLOC_ZERO)) == NULL)return -E_NO_MEM;
	page_insert(store->env_pgdir, page, va, perm);
	return 0;

}

// Map the page of memory at 'srcva' in srcenvid's address space
// at 'dstva' in dstenvid's address space with permission 'perm'.
// Perm has the same restrictions as in sys_page_alloc, except
// that it also must not grant write access to a read-only
// page.
// 将srcenvid地址空间中“srcva”处的内存页映射到dstenvid地址空间中的“dstva”处，权限为“perm”。
// perm具有与sys_page_alloc中相同的限制，但它也不能授予对只读页的写入权限。
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if srcenvid and/or dstenvid doesn't currently exist,
//		or the caller doesn't have permission to change one of them.
//	-E_INVAL if srcva >= UTOP or srcva is not page-aligned,
//		or dstva >= UTOP or dstva is not page-aligned.
//	-E_INVAL is srcva is not mapped in srcenvid's address space.
//	-E_INVAL if perm is inappropriate (see sys_page_alloc).
//	-E_INVAL if (perm & PTE_W), but srcva is read-only in srcenvid's
//		address space.
//	-E_NO_MEM if there's no memory to allocate any necessary page tables.
static int
sys_page_map(envid_t srcenvid, void *srcva,
	     envid_t dstenvid, void *dstva, int perm)
{
	// Hint: This function is a wrapper around page_lookup() and
	//   page_insert() from kern/pmap.c.
	//   Again, most of the new code you write should be to check the
	//   parameters for correctness.
	//   Use the third argument to page_lookup() to
	//   check the current permissions on the page.
	// 提示：此函数是kern/pmap中page_lookup（）和page_insert（）的包装器。
	// 此外，您编写的大部分新代码应该是检查参数的正确性
	// 检查页面上的当前权限。
	// LAB 4: Your code here.
	// panic("sys_page_map not implemented");
	struct Env* src = NULL;
	struct Env* dst = NULL;
	if(envid2env(srcenvid, &src, 1) < 0 || envid2env(dstenvid, &dst, 1) < 0)
		return -E_BAD_ENV;
	if((uintptr_t)srcva >= UTOP || ROUNDDOWN((uintptr_t)srcva, PGSIZE) != (uintptr_t)srcva)
		return -E_INVAL;
	if((uintptr_t)dstva >= UTOP || ROUNDDOWN((uintptr_t)dstva, PGSIZE) != (uintptr_t)dstva)
		return -E_INVAL;
	pte_t* pte_addr = NULL;
	struct PageInfo* page = NULL;
	if((page = page_lookup(src->env_pgdir, srcva, &pte_addr)) == NULL)
		return -E_INVAL;
	if(((perm & PTE_U) == 0) || ((perm & PTE_P) == 0) || ((perm & ~PTE_SYSCALL) != 0))
		return -E_INVAL;
	if(!(*pte_addr & PTE_W) && (perm & PTE_W))
		return -E_INVAL;
	if(page_insert(dst->env_pgdir, page, dstva, perm) < 0)
		return -E_NO_MEM;
	return 0;
}

// Unmap the page of memory at 'va' in the address space of 'envid'.
// If no page is mapped, the function silently succeeds.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if va >= UTOP, or va is not page-aligned.
static int
sys_page_unmap(envid_t envid, void *va)
{
	// Hint: This function is a wrapper around page_remove().

	// LAB 4: Your code here.
	// panic("sys_page_unmap not implemented");
	struct Env* store = NULL;
	if(envid2env(envid, &store, 1) < 0)
		return -E_BAD_ENV;
	if((uintptr_t)va >= UTOP || ROUNDDOWN((uintptr_t)va, PGSIZE) != (uintptr_t)va)
		return -E_INVAL;
	page_remove(store->env_pgdir, va);
	return 0;
}

// Try to send 'value' to the target env 'envid'.
// If srcva < UTOP, then also send page currently mapped at 'srcva',
// so that receiver gets a duplicate mapping of the same page.
//尝试将“value”发送到目标env“envid”。如果srcva＜UTOP，
// 则还发送当前映射到“srcva”的页面，以便接收方获得相同页面的重复映射。
// The send fails with a return value of -E_IPC_NOT_RECV if the
// target is not blocked, waiting for an IPC.
// 如果目标未被阻止，则发送失败，返回值为-E_IPC_NOT_RECV，等待IPC。 
// The send also can fail for the other reasons listed below.
// 由于以下列出的其他原因，发送也可能失败。 
// Otherwise, the send succeeds, and the target's ipc fields are
// updated as follows:
//  否则，发送成功，目标的ipc字段更新如下： 
//    env_ipc_recving is set to 0 to block future sends;
//    env_ipc_from is set to the sending envid;
//    env_ipc_value is set to the 'value' parameter;
//    env_ipc_perm is set to 'perm' if a page was transferred, 0 otherwise.
// The target environment is marked runnable again, returning 0
// from the paused sys_ipc_recv system call.  (Hint: does the
// sys_ipc_recv function ever actually return?)
//
// If the sender wants to send a page but the receiver isn't asking for one,
// then no page mapping is transferred, but no error occurs.
// The ipc only happens when no errors occur.
//
// Returns 0 on success, < 0 on error.
// Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist.
//		(No need to check permissions.)
//	-E_IPC_NOT_RECV if envid is not currently blocked in sys_ipc_recv,
//		or another environment managed to send first.
//	-E_INVAL if srcva < UTOP but srcva is not page-aligned.
//	-E_INVAL if srcva < UTOP and perm is inappropriate
//		(see sys_page_alloc).
//	-E_INVAL if srcva < UTOP but srcva is not mapped in the caller's
//		address space.
//	-E_INVAL if (perm & PTE_W), but srcva is read-only in the
//		current environment's address space.
//	-E_NO_MEM if there's not enough memory to map srcva in envid's
//		address space.
static int
sys_ipc_try_send(envid_t envid, uint32_t value, void *srcva, unsigned perm)
{
	// LAB 4: Your code here.
	struct Env* recv = NULL;
	int error_code = 0;
	if((error_code = envid2env(envid, &recv, 0)) < 0)
		return error_code;
	if(!recv->env_ipc_recving)
		return -E_IPC_NOT_RECV;
	recv->env_ipc_perm = 0;
	recv->env_ipc_from = curenv->env_id;
	recv->env_ipc_value = value;
	// when to do the following check
	if((uintptr_t)srcva < UTOP && (uintptr_t)(recv->env_ipc_dstva) < UTOP)
	{
		if((uintptr_t)srcva != ROUNDDOWN((uintptr_t)srcva, PGSIZE))
			return -E_INVAL;
		// check perm, is PTE_U and PTE_P already set?
		if(((perm & PTE_U) == 0) || ((perm & PTE_P) == 0) )
			return -E_INVAL;
		// is perm set with other perms that should never be set?
		// bit-and ~PTE_SYSCALL clear the four bits
		if((perm & ~PTE_SYSCALL) != 0)
			return -E_INVAL;
		pte_t* pte_addr = NULL;
		struct PageInfo* page = NULL;
		page = page_lookup(curenv->env_pgdir, srcva, &pte_addr);
		// srcva is not mapped
		if(page == NULL)
			return -E_INVAL;
		// the page is read-only, but perm contains write
		if((perm & PTE_W) && !((*pte_addr) & PTE_W))
			return -E_INVAL;
		// Now start to do the real stuff
		if((error_code = page_insert(recv->env_pgdir, page, recv->env_ipc_dstva, perm)) < 0)
			return error_code;
		recv->env_ipc_perm = perm;
	}
	// unblock and make it running
	// 解锁并使其运行
	recv->env_ipc_recving = 0;
	recv->env_tf.tf_regs.reg_eax = 0;
	recv->env_status = ENV_RUNNABLE;
	return 0;
}

// Block until a value is ready.  Record that you want to receive
// using the env_ipc_recving and env_ipc_dstva fields of struct Env,
// mark yourself not runnable, and then give up the CPU.
// 
//块，直到值就绪。使用结构env的env_ipc_recving和env_ipc_dstva字段记录要接收的内容
// ，将自己标记为不可运行，然后放弃CPU。
// If 'dstva' is < UTOP, then you are willing to receive a page of data.
// 'dstva' is the virtual address at which the sent page should be mapped.
//如果“dstva”小于UTOP，则您愿意接收一页数据“dstva”是发送页面应映射到的虚拟地址。
// This function only returns on error, but the system call will eventually
// return 0 on success.
// Return < 0 on error.  Errors are:
//	-E_INVAL if dstva < UTOP but dstva is not page-aligned.
static int
sys_ipc_recv(void *dstva)
{
	// LAB 4: Your code here.
	if((uintptr_t)dstva < UTOP && (ROUNDDOWN((uintptr_t)dstva, PGSIZE) != (uintptr_t)dstva))
		return -E_INVAL;
	// Only when dstva is below UTOP, record it in struct Env
	//  仅当dstva低于UTOP时，将其记录在结构Env中 
	if((uintptr_t)dstva < UTOP)
		curenv->env_ipc_dstva = dstva;
	curenv->env_ipc_recving = true;
	// mark yourself as not runnable, give up CPU
	curenv->env_status = ENV_NOT_RUNNABLE;
	sched_yield();
	// This sentence will never be executed
	return 0;
}
// Dispatches to the correct kernel function, passing the arguments.
int32_t
syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
	// Call the function corresponding to the 'syscallno' parameter.
	// Return any appropriate return value.
	// LAB 3: Your code here.

	// panic("syscall not implemented");

	switch (syscallno) {
	case  SYS_cputs:
	{
		sys_cputs((char*)(a1),a2);
		break;
	}
	case SYS_cgetc:
		return sys_cgetc();
	case SYS_getenvid:
		return sys_getenvid();
	case SYS_env_destroy:
		return sys_env_destroy(a1);
	case SYS_yield:
		 sys_yield();
		 break;
	case SYS_env_set_status:
		return sys_env_set_status((envid_t) a1, (int) a2);
	case SYS_page_alloc:
		return sys_page_alloc((envid_t)a1, (void * )a2, (int )a3);
	case SYS_page_map:
		return sys_page_map((envid_t) a1, (void *) a2, (envid_t) a3, (void *) a4, (int) a5);
	case SYS_page_unmap:
		return sys_page_unmap((envid_t) a1, (void *) a2);
	case SYS_exofork:
		return sys_exofork();
	case SYS_env_set_pgfault_upcall:
		return sys_env_set_pgfault_upcall((envid_t) a1, (void *) a2);
	case SYS_ipc_recv:
		return sys_ipc_recv((void*)a1);
	case SYS_ipc_try_send:
		return sys_ipc_try_send((envid_t)a1,a2,(void*)a3,a4);
	default:
		return -E_INVAL;
	}
	return 0;
}

