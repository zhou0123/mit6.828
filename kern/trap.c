#include <inc/mmu.h>
#include <inc/x86.h>
#include <inc/assert.h>

#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/env.h>
#include <kern/syscall.h>

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
	return "(unknown trap)";
}

void
trap_init(void)
{
	extern struct Segdesc gdt[];

	// LAB 3: Your code here.
    SETGATE(idt[T_DIVIDE], 1, GD_KT, divide_handler, 0)
    SETGATE(idt[T_DEBUG], 1, GD_KT, debug_handler, 0)
    SETGATE(idt[T_NMI], 0, GD_KT, nmi_handler, 0)
    SETGATE(idt[T_BRKPT], 1, GD_KT, brkpt_handler, 3)
    SETGATE(idt[T_OFLOW], 1, GD_KT, oflow_handler, 0)
    SETGATE(idt[T_BOUND], 1, GD_KT, bound_hander, 0)
    SETGATE(idt[T_ILLOP], 1, GD_KT, illop_handler, 0)
    SETGATE(idt[T_DEVICE], 1, GD_KT, device_handler, 0)
    SETGATE(idt[T_DBLFLT], 1, GD_KT, dblflt_handler, 0)
    SETGATE(idt[T_TSS], 1, GD_KT, tss_handler, 0)
    SETGATE(idt[T_SEGNP], 1, GD_KT, segnp_handler, 0)
    SETGATE(idt[T_STACK], 1, GD_KT, stack_handler, 0)
    SETGATE(idt[T_GPFLT], 1, GD_KT, gpflt_handler, 0)
    SETGATE(idt[T_PGFLT], 1, GD_KT, pgflt_handler, 0)
    SETGATE(idt[T_FPERR], 1, GD_KT, fperr_handler, 0)
    SETGATE(idt[T_ALIGN], 0, GD_KT, align_handler, 0)
    SETGATE(idt[T_MCHK], 0, GD_KT, mchk_handler, 0)
    SETGATE(idt[T_SIMDERR], 0, GD_KT, simderr_handler, 0)
    SETGATE(idt[T_SYSCALL], 0, GD_KT, syscall_handler, 3)
	// Per-CPU setup 
	trap_init_percpu();
}

// Initialize and load the per-CPU TSS and IDT
void
trap_init_percpu(void)
{
	// Setup a TSS so that we get the right stack
	// when we trap to the kernel.
	//  设置一个TSS，以便在捕获内核时获得正确的堆栈。 
	ts.ts_esp0 = KSTACKTOP;
	ts.ts_ss0 = GD_KD;
	ts.ts_iomb = sizeof(struct Taskstate);

	// Initialize the TSS slot of the gdt.
	//  初始化gdt的TSS插槽。 
	gdt[GD_TSS0 >> 3] = SEG16(STS_T32A, (uint32_t) (&ts),
					sizeof(struct Taskstate) - 1, 0);
	gdt[GD_TSS0 >> 3].sd_s = 0;

	// Load the TSS selector (like other segment selectors, the
	// bottom three bits are special; we leave them 0)
	//  加载TSS选择器 
	//  与其他段选择器一样，底部三位是特殊的；我们让他们0 
	ltr(GD_TSS0);

	// Load the IDT
	lidt(&idt_pd);
}

void
print_trapframe(struct Trapframe *tf)
{
	cprintf("TRAP frame at %p\n", tf);
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

	// Check that interrupts are disabled.  If this assertion
	// fails, DO NOT be tempted to fix it by inserting a "cli" in
	// the interrupt path.
	// 

	// 检查中断是否已禁用。
	// 如果这个断言失败，不要试图通过在中断路径中插入“cli”来修复它。 
	assert(!(read_eflags() & FL_IF));

	cprintf("Incoming TRAP frame at %p\n", tf);

	if ((tf->tf_cs & 3) == 3) {
		// Trapped from user mode.
		//  从用户模式捕获。 
		assert(curenv);

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

	// Return to the current environment, which should be running.
	//  返回当前环境，该环境应该正在运行。 
	assert(curenv && curenv->env_status == ENV_RUNNING);
	env_run(curenv);
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

	// Destroy the environment that caused the fault.
	cprintf("[%08x] user fault va %08x ip %08x\n",
		curenv->env_id, fault_va, tf->tf_eip);
	print_trapframe(tf);
	env_destroy(curenv);
}

