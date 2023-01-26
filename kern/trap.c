#include <inc/mmu.h>
#include <inc/x86.h>
#include <inc/assert.h>

#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/env.h>
#include <kern/syscall.h>
#include <kern/sched.h>
#include <kern/kclock.h>
#include <kern/picirq.h>
#include <kern/cpu.h>
#include <kern/spinlock.h>
#include <kern/time.h>

static struct Taskstate ts;

/* For debugging, so print_trapframe can distinguish between printing
 * a saved trapframe and printing the current trapframe and print some
 * additional information in the latter case.
 */
static struct Trapframe *last_tf;

/* Interrupt descriptor table.  (Must be built at run time because
 * shifted function addresses can't be represented in relocation records.)
 */
// 中断描述符表。（必须在运行时构建，因为移位的函数地址不能在重新定位记录中表示。）
struct Gatedesc idt[256] = { { 0 } };
struct Pseudodesc idt_pd = {
	sizeof(idt) - 1, (uint32_t) idt
};


static const char *trapname(int trapno)
{
	static const char * const excnames[] = {
		"Divide error",
		"Debug",
		"Non-Maskable Interrupt",
		"Breakpoint",
		"Overflow",
		"BOUND Range Exceeded",
		"Invalid Opcode",
		"Device Not Available",
		"Double Fault",
		"Coprocessor Segment Overrun",
		"Invalid TSS",
		"Segment Not Present",
		"Stack Fault",
		"General Protection",
		"Page Fault",
		"(unknown trap)",
		"x87 FPU Floating-Point Error",
		"Alignment Check",
		"Machine-Check",
		"SIMD Floating-Point Exception"
	};

	if (trapno < ARRAY_SIZE(excnames))
		return excnames[trapno];
	if (trapno == T_SYSCALL)
		return "System call";
	if (trapno >= IRQ_OFFSET && trapno < IRQ_OFFSET + 16)
		return "Hardware Interrupt";
	return "(unknown trap)";
}

void
trap_init(void)
{
	extern struct Segdesc gdt[];

	// LAB 3: Your code here.
	void divide_handler();
	void debug_handler();
	void nmi_handler();
	void brkpt_handler();
	void oflow_handler();
	void bound_hander();
	void illop_handler();
	void device_handler();
	void dblflt_handler();
	void tss_handler();
	void segnp_handler();
	void stack_handler();
	void gpflt_handler();
	void pgflt_handler();
	void fperr_handler();
	void align_handler();
	void mchk_handler();
	void simderr_handler();
	void syscall_handler();
	
	void irq_timer_handler();
	void irq_kbd_handler();
	void irq2_handler();
	void irq3_handler();
	void irq_serial_handler();
	void irq5_handler();
	void irq6_handler();
	void irq_spurious_handler();
	void irq8_handler();
	void irq9_handler();
	void irq10_handler();
	void irq11_handler();
	void irq12_handler();
	void irq13_handler();
	void irq_ide_handler();
	void irq15_handler();
    SETGATE(idt[T_DIVIDE], 0, GD_KT, divide_handler, 0)
    SETGATE(idt[T_DEBUG], 1, GD_KT, debug_handler, 0)
    SETGATE(idt[T_NMI], 0, GD_KT, nmi_handler, 0)
    SETGATE(idt[T_BRKPT], 1, GD_KT, brkpt_handler, 3)
    SETGATE(idt[T_OFLOW], 1, GD_KT, oflow_handler, 0)
    SETGATE(idt[T_BOUND], 0, GD_KT, bound_hander, 0)
    SETGATE(idt[T_ILLOP], 1, GD_KT, illop_handler, 0)
    SETGATE(idt[T_DEVICE], 1, GD_KT, device_handler, 0)
    SETGATE(idt[T_DBLFLT], 1, GD_KT, dblflt_handler, 0)
    SETGATE(idt[T_TSS], 0, GD_KT, tss_handler, 0)
    SETGATE(idt[T_SEGNP], 0, GD_KT, segnp_handler, 0)
    SETGATE(idt[T_STACK], 0, GD_KT, stack_handler, 0)
    SETGATE(idt[T_GPFLT], 0, GD_KT, gpflt_handler, 0)
    SETGATE(idt[T_PGFLT], 0, GD_KT, pgflt_handler, 0)
    SETGATE(idt[T_FPERR], 1, GD_KT, fperr_handler, 0)
    SETGATE(idt[T_ALIGN], 0, GD_KT, align_handler, 0)
    SETGATE(idt[T_MCHK], 0, GD_KT, mchk_handler, 0)
    SETGATE(idt[T_SIMDERR], 0, GD_KT, simderr_handler, 0)
    SETGATE(idt[T_SYSCALL], 0, GD_KT, syscall_handler, 3)
	
	SETGATE(idt[IRQ_OFFSET + IRQ_TIMER],    0, GD_KT, irq_timer_handler, 3);
	SETGATE(idt[IRQ_OFFSET + IRQ_KBD],      0, GD_KT, irq_kbd_handler,3);
	SETGATE(idt[IRQ_OFFSET + 2],      0, GD_KT, irq2_handler,3);
	SETGATE(idt[IRQ_OFFSET + 3],      0, GD_KT, irq3_handler,3);
	SETGATE(idt[IRQ_OFFSET + IRQ_SERIAL],   0, GD_KT, irq_serial_handler,  3);
	SETGATE(idt[IRQ_OFFSET + 5],      0, GD_KT, irq5_handler,3);
	SETGATE(idt[IRQ_OFFSET + 6],      0, GD_KT, irq6_handler,3);
	SETGATE(idt[IRQ_OFFSET + IRQ_SPURIOUS], 0, GD_KT, irq_spurious_handler, 3);
	SETGATE(idt[IRQ_OFFSET + 8],      0, GD_KT, irq8_handler,3);
	SETGATE(idt[IRQ_OFFSET + 9],      0, GD_KT, irq9_handler,3);
	SETGATE(idt[IRQ_OFFSET + 10],      0, GD_KT, irq10_handler,3);
	SETGATE(idt[IRQ_OFFSET + 11],      0, GD_KT, irq11_handler,3);
	SETGATE(idt[IRQ_OFFSET + 12],      0, GD_KT, irq12_handler,3);
	SETGATE(idt[IRQ_OFFSET + 13],      0, GD_KT, irq13_handler,3);
	SETGATE(idt[IRQ_OFFSET + IRQ_IDE],      0, GD_KT, irq_ide_handler,3);
	SETGATE(idt[IRQ_OFFSET + 15],    0, GD_KT, irq15_handler,3);

	// Per-CPU setup 
	trap_init_percpu();
}

// Initialize and load the per-CPU TSS and IDT
void
trap_init_percpu(void)
{
	// The example code here sets up the Task State Segment (TSS) and
	// the TSS descriptor for CPU 0. But it is incorrect if we are
	// running on other CPUs because each CPU has its own kernel stack.
	// Fix the code so that it works for all CPUs.
	// 这里的示例代码为CPU 0设置任务状态段（TSS）和TSS描述符。但如果我们在其他CPU上运行，这是不正确的，因为每个CPU都有自己的内核堆栈。请修复代码，使其适用于所有CPU。
	//
	// Hints:
	//   - The macro "thiscpu" always refers to the current CPU's
	//     struct CpuInfo;
	//   - The ID of the current CPU is given by cpunum() or
	//     thiscpu->cpu_id;
	//   - Use "thiscpu->cpu_ts" as the TSS for the current CPU,
	//     rather than the global "ts" variable;
	//   - Use gdt[(GD_TSS0 >> 3) + i] for CPU i's TSS descriptor;
	//   - You mapped the per-CPU kernel stacks in mem_init_mp()
	//   - Initialize cpu_ts.ts_iomb to prevent unauthorized environments
	//     from doing IO (0 is not the correct value!)
	//
	// ltr sets a 'busy' flag in the TSS selector, so if you
	// accidentally load the same TSS on more than one CPU, you'll
	// get a triple fault.  If you set up an individual CPU's TSS
	// wrong, you may not get a fault until you try to return from
	// user space on that CPU.
	//
	// LAB 4: Your code here:

	// Setup a TSS so that we get the right stack
	// when we trap to the kernel.
	//  设置一个TSS，以便在捕获内核时获得正确的堆栈。 
	thiscpu->cpu_ts.ts_esp0 = (uintptr_t)(percpu_kstacks[cpunum()] + KSTKSIZE);
	thiscpu->cpu_ts.ts_ss0 = GD_KD;
	thiscpu->cpu_ts.ts_iomb = sizeof(struct Taskstate);

	// Initialize the TSS slot of the gdt.
	gdt[(GD_TSS0 >> 3) + cpunum()] = SEG16(STS_T32A, (uint32_t)(&(thiscpu->cpu_ts)),
					sizeof(struct Taskstate) - 1, 0);
	gdt[(GD_TSS0 >> 3) + cpunum()].sd_s = 0;

	// Load the TSS selector (like other segment selectors, the
	// bottom three bits are special; we leave them 0)
	//  加载TSS选择器（与其他段选择器一样，底部的三位是特殊的；我们将其保留为0） 
	ltr(GD_TSS0 + (cpunum() << 3));

	// Load the IDT
	lidt(&idt_pd);
}

void
print_trapframe(struct Trapframe *tf)
{
	cprintf("TRAP frame at %p from CPU %d\n", tf, cpunum());
	print_regs(&tf->tf_regs);
	cprintf("  es   0x----%04x\n", tf->tf_es);
	cprintf("  ds   0x----%04x\n", tf->tf_ds);
	cprintf("  trap 0x%08x %s\n", tf->tf_trapno, trapname(tf->tf_trapno));
	// If this trap was a page fault that just happened
	// (so %cr2 is meaningful), print the faulting linear address.
	if (tf == last_tf && tf->tf_trapno == T_PGFLT)
		cprintf("  cr2  0x%08x\n", rcr2());
	cprintf("  err  0x%08x", tf->tf_err);
	// For page faults, print decoded fault error code:
	// U/K=fault occurred in user/kernel mode
	// W/R=a write/read caused the fault
	// PR=a protection violation caused the fault (NP=page not present).
	if (tf->tf_trapno == T_PGFLT)
		cprintf(" [%s, %s, %s]\n",
			tf->tf_err & 4 ? "user" : "kernel",
			tf->tf_err & 2 ? "write" : "read",
			tf->tf_err & 1 ? "protection" : "not-present");
	else
		cprintf("\n");
	cprintf("  eip  0x%08x\n", tf->tf_eip);
	cprintf("  cs   0x----%04x\n", tf->tf_cs);
	cprintf("  flag 0x%08x\n", tf->tf_eflags);
	if ((tf->tf_cs & 3) != 0) {
		cprintf("  esp  0x%08x\n", tf->tf_esp);
		cprintf("  ss   0x----%04x\n", tf->tf_ss);
	}
}

void
print_regs(struct PushRegs *regs)
{
	cprintf("  edi  0x%08x\n", regs->reg_edi);
	cprintf("  esi  0x%08x\n", regs->reg_esi);
	cprintf("  ebp  0x%08x\n", regs->reg_ebp);
	cprintf("  oesp 0x%08x\n", regs->reg_oesp);
	cprintf("  ebx  0x%08x\n", regs->reg_ebx);
	cprintf("  edx  0x%08x\n", regs->reg_edx);
	cprintf("  ecx  0x%08x\n", regs->reg_ecx);
	cprintf("  eax  0x%08x\n", regs->reg_eax);
}

static void
trap_dispatch(struct Trapframe *tf)
{
	// Handle processor exceptions.  处理处理器异常。 
	// LAB 3: Your code here.

	// Handle spurious interrupts
	// The hardware sometimes raises these because of noise on the
	// IRQ line or other reasons. We don't care.
	if (tf->tf_trapno == IRQ_OFFSET + IRQ_SPURIOUS) {
		cprintf("Spurious interrupt on irq 7\n");
		print_trapframe(tf);
		return;
	}
	if (tf->tf_trapno == IRQ_OFFSET + IRQ_TIMER) {
		lapic_eoi();
		time_tick();
		sched_yield();
		return;
	}

	// Handle clock interrupts. Don't forget to acknowledge the
	// interrupt using lapic_eoi() before calling the scheduler!
	// LAB 4: Your code here.

	// Add time tick increment to clock interrupts.
	// Be careful! In multiprocessors, clock interrupts are
	// triggered on every CPU.
	// LAB 6: Your code here.


	// Handle keyboard and serial interrupts.
	// LAB 5: Your code here.
	//kern/trap.c/trap_dispatch()
	if (tf->tf_trapno == IRQ_OFFSET + IRQ_KBD){
		kbd_intr();
		return;
	} 
	else if (tf->tf_trapno == IRQ_OFFSET + IRQ_SERIAL){
		serial_intr();
		return;
	}

	// Unexpected trap: The user process or the kernel has a bug.
	switch (tf->tf_trapno)
	{
	case T_PGFLT:
		page_fault_handler(tf);
		break;
	
	case T_BRKPT:
		monitor(tf);
		break;
	case T_SYSCALL:
		tf->tf_regs.reg_eax = syscall(tf->tf_regs.reg_eax,
									  tf->tf_regs.reg_edx,
									  tf->tf_regs.reg_ecx,
									  tf->tf_regs.reg_ebx,
									  tf->tf_regs.reg_edi,
									  tf->tf_regs.reg_esi);
		return;
	}
	// Unexpected trap: The user process or the kernel has a bug. 
	//  意外陷阱：用户进程或内核存在错误。 
	print_trapframe(tf);
	if (tf->tf_cs == GD_KT)
		panic("unhandled trap in kernel");
	else {
		env_destroy(curenv);
		return;
	}
}

void
trap(struct Trapframe *tf)
{
	// The environment may have set DF and some versions
	// of GCC rely on DF being clear
	//  环境可能设置了DF，某些版本的GCC依赖于DF清晰 
	asm volatile("cld" ::: "cc");

	// Halt the CPU if some other CPU has called panic()
	//  如果其他CPU调用了panic（），则停止CPU 
	extern char *panicstr;
	if (panicstr)
		asm volatile("hlt");

	// Re-acqurie the big kernel lock if we were halted in
	// sched_yield()
	if (xchg(&thiscpu->cpu_status, CPU_STARTED) == CPU_HALTED)
		lock_kernel();
	// Check that interrupts are disabled.  If this assertion
	// fails, DO NOT be tempted to fix it by inserting a "cli" in
	// the interrupt path.
	// 

	// 检查中断是否已禁用。
	// 如果这个断言失败，不要试图通过在中断路径中插入“cli”来修复它。 
	assert(!(read_eflags() & FL_IF));

	if ((tf->tf_cs & 3) == 3) {
		// Trapped from user mode.
		// Acquire the big kernel lock before doing any
		// serious kernel work.
		// LAB 4: Your code here.
		lock_kernel();
		//  从用户模式捕获。 
		assert(curenv);

		// Garbage collect if current enviroment is a zombie
		if (curenv->env_status == ENV_DYING) {
			env_free(curenv);
			curenv = NULL;
			sched_yield();
		}

		// Copy trap frame (which is currently on the stack)
		// into 'curenv->env_tf', so that running the environment
		// will restart at the trap point.
		// 将陷阱帧（当前在堆栈中）复制到“curenv->env_tf”中，以便在陷阱点重新启动运行环境。
		curenv->env_tf = *tf;
		// The trapframe on the stack should be ignored from here on.
		//  从这里开始，堆栈上的trapframe应该被忽略。 
		tf = &curenv->env_tf;
	}

	// Record that tf is the last real trapframe so
	// print_trapframe can print some additional information.
	 //记录tf是最后一个真正的trapframe，以便print_trapframe可以打印一些附加信息。 
	last_tf = tf;

	// Dispatch based on what type of trap occurred
	//  根据发生的陷阱类型进行调度 
	trap_dispatch(tf);

	// If we made it to this point, then no other environment was
	// scheduled, so we should return to the current environment
	// if doing so makes sense.
	if (curenv && curenv->env_status == ENV_RUNNING)
		env_run(curenv);
	else
		sched_yield();
}


void
page_fault_handler(struct Trapframe *tf)
{
	uint32_t fault_va;

	// Read processor's CR2 register to find the faulting address
	//  读取处理器的CR2寄存器以查找错误地址 
	fault_va = rcr2();

	// Handle kernel-mode page faults.

	// LAB 3: Your code here.
	if(tf->tf_cs ==3){
          panic("page fault in kernel node, fault address %d\n",fault_va);
        }
	// We've already handled kernel-mode exceptions, so if we get here,
	// the page fault happened in user mode.
	// 我们已经处理了内核模式异常，所以如果我们到达这里，页面错误发生在用户模式

	// Call the environment's page fault upcall, if one exists.  Set up a
	// page fault stack frame on the user exception stack (below
	// UXSTACKTOP), then branch to curenv->env_pgfault_upcall.
	// 调用环境的页面错误upcall（如果存在）。在用户异常堆栈（UXSTACKTOP下方）
	// 上设置一个页面错误堆栈框架，
	// 然后分支到curenv->env_pgfault_upcall。
	//
	// The page fault upcall might cause another page fault, in which case
	// we branch to the page fault upcall recursively, pushing another
	// page fault stack frame on top of the user exception stack.
	// 页面错误上调可能会导致另一个页面错误，
	// 在这种情况下，我们递归地分支到页面错误上调，将另一个页错误堆栈帧推到用户异常堆栈的顶部。
	//
	// It is convenient for our code which returns from a page fault
	// (lib/pfentry.S) to have one word of scratch space at the top of the
	// trap-time stack; it allows us to more easily restore the eip/esp. In
	// the non-recursive case, we don't have to worry about this because
	// the top of the regular user stack is free.  In the recursive case,
	// this means we have to leave an extra word between the current top of
	// the exception stack and the new stack frame because the exception
	// stack _is_ the trap-time stack.
	// 从页面错误（lib/pfentry.S）返回的代码在陷阱时间堆栈的顶部有一个字的暂存空间是很方便的；
	// 它使我们能够更容易地恢复eip/esp。在非递归的情况下，我们不必担心这一点，
	// 因为常规用户堆栈的顶部是自由的。在递归情况下，
	// 这意味着我们必须在异常堆栈的当前顶部和新堆栈帧之间留下一个额外的字
	// 因为异常堆栈是陷阱时间堆栈。
	//
	// If there's no page fault upcall, the environment didn't allocate a
	// page for its exception stack or can't write to it, or the exception
	// stack overflows, then destroy the environment that caused the fault.
	// Note that the grade script assumes you will first check for the page
	// fault upcall and print the "user fault va" message below if there is
	// none.  The remaining three checks can be combined into a single test.
	//
	// Hints:
	//   user_mem_assert() and env_run() are useful here.
	//   To change what the user environment runs, modify 'curenv->env_tf'
	//   (the 'tf' variable points at 'curenv->env_tf').

	// LAB 4: Your code here.
	// First check preconditions, shall we pass the control to user-level page
	// fault handler? flag means whether a user-level page fault handler is needed
	bool flag = true;
	// check whether there exists a page fault upcall
	//  检查是否存在页面错误调用 
	if(curenv->env_pgfault_upcall == NULL)
		flag = false;
	// ckeck whether exception stack fails
	//  检查异常堆栈是否失败 
	if((USTACKTOP <= fault_va) && (fault_va < UXSTACKTOP - PGSIZE))
		flag = false;
	// Now start to do the real stuff
	if(flag)
	{
		struct UTrapframe* trapframe = NULL;
		// where do we put the struct UTrapFrame? It depends on whether the page
		// fault happens on user exception stack
		//  我们将结构UTrapFrame放在哪里？这取决于用户异常堆栈上是否发生页面错误 
		if((curenv->env_tf.tf_esp < UXSTACKTOP) && (curenv->env_tf.tf_esp >= UXSTACKTOP - PGSIZE))
			trapframe = (struct UTrapframe*)(curenv->env_tf.tf_esp - sizeof(struct UTrapframe) - 4);
		else
			trapframe = (struct UTrapframe*)(UXSTACKTOP - sizeof(struct UTrapframe));
		// check whether the env has a page mapped at exception stack, and has write 
		// permission to it. user_mem_assert will automacally destory the env and will
		// not return if the check fails.
		// 检查env是否有一个在异常堆栈中映射的页面，并对其具有写权限。
		// usermemassert将自动销毁env，如果检查失败，则不会返回。
		user_mem_assert(curenv, trapframe, sizeof(struct UTrapframe), PTE_W);
		// construct the user trap frame for user-level page fault handler
		//  为用户级页面错误处理程序构造用户陷阱框架 
		trapframe->utf_eflags = curenv->env_tf.tf_eflags;
		trapframe->utf_eip = curenv->env_tf.tf_eip;
		trapframe->utf_err = curenv->env_tf.tf_err;
		trapframe->utf_esp = curenv->env_tf.tf_esp;
		trapframe->utf_fault_va = fault_va;
		trapframe->utf_regs = curenv->env_tf.tf_regs;
		// modify the curenv->env_tf to make it return to user-level page fault 
		// handler, and set the new esp
		//  修改curenv->env_tf，使其返回到用户级页面错误处理程序，并设置新的esp 
		curenv->env_tf.tf_eip = (uintptr_t)curenv->env_pgfault_upcall;
		curenv->env_tf.tf_esp = (uintptr_t)trapframe;
		// Finally, return to user space, run the user-level page fault handler
		// This function will never return
		//  最后，返回用户空间，运行用户级页面错误处理程序此函数将永远不会返回 
		env_run(curenv);
	}
	// Destroy the environment that caused the fault.
	cprintf("[%08x] user fault va %08x ip %08x\n",
		curenv->env_id, fault_va, tf->tf_eip);
	print_trapframe(tf);
	env_destroy(curenv);
}

