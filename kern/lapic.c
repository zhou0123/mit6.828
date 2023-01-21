// The local APIC manages internal (non-I/O) interrupts.
// See Chapter 8 & Appendix C of Intel processor manual volume 3.

#include <inc/types.h>
#include <inc/memlayout.h>
#include <inc/trap.h>
#include <inc/mmu.h>
#include <inc/stdio.h>
#include <inc/x86.h>
#include <kern/pmap.h>
#include <kern/cpu.h>

// Local APIC registers, divided by 4 for use as uint32_t[] indices.
#define ID      (0x0020/4)   // ID
#define VER     (0x0030/4)   // Version
#define TPR     (0x0080/4)   // Task Priority
#define EOI     (0x00B0/4)   // EOI
#define SVR     (0x00F0/4)   // Spurious Interrupt Vector
	#define ENABLE     0x00000100   // Unit Enable
#define ESR     (0x0280/4)   // Error Status
#define ICRLO   (0x0300/4)   // Interrupt Command
	#define INIT       0x00000500   // INIT/RESET
	#define STARTUP    0x00000600   // Startup IPI
	#define DELIVS     0x00001000   // Delivery status
	#define ASSERT     0x00004000   // Assert interrupt (vs deassert)
	#define DEASSERT   0x00000000
	#define LEVEL      0x00008000   // Level triggered
	#define BCAST      0x00080000   // Send to all APICs, including self.
	#define OTHERS     0x000C0000   // Send to all APICs, excluding self.
	#define BUSY       0x00001000
	#define FIXED      0x00000000
#define ICRHI   (0x0310/4)   // Interrupt Command [63:32]
#define TIMER   (0x0320/4)   // Local Vector Table 0 (TIMER)
	#define X1         0x0000000B   // divide counts by 1
	#define PERIODIC   0x00020000   // Periodic
#define PCINT   (0x0340/4)   // Performance Counter LVT
#define LINT0   (0x0350/4)   // Local Vector Table 1 (LINT0)
#define LINT1   (0x0360/4)   // Local Vector Table 2 (LINT1)
#define ERROR   (0x0370/4)   // Local Vector Table 3 (ERROR)
	#define MASKED     0x00010000   // Interrupt masked
#define TICR    (0x0380/4)   // Timer Initial Count
#define TCCR    (0x0390/4)   // Timer Current Count
#define TDCR    (0x03E0/4)   // Timer Divide Configuration

physaddr_t lapicaddr;        // Initialized in mpconfig.c
volatile uint32_t *lapic;

static void
lapicw(int index, int value)
{
	lapic[index] = value;
	lapic[ID];  // wait for write to finish, by reading 通过阅读等待写入完成
}

void
lapic_init(void)
{
	if (!lapicaddr)
		return;

	// lapicaddr is the physical address of the LAPIC's 4K MMIO
	// region.  Map it in to virtual memory so we can access it.
	// lapicaddr是LAPIC的4K MMIO区域的物理地址。将其映射到虚拟内存，以便我们可以访问它。
	lapic = mmio_map_region(lapicaddr, 4096);

	// Enable local APIC; set spurious interrupt vector.  启用本地APIC；设置假中断向量。 
	lapicw(SVR, ENABLE | (IRQ_OFFSET + IRQ_SPURIOUS));

	// The timer repeatedly counts down at bus frequency
	// from lapic[TICR] and then issues an interrupt.  
	// If we cared more about precise timekeeping,
	// TICR would be calibrated using an external time source.
	// 计时器从lapic[TICR]以总线频率重复倒计时，然后发出中断。如果我们更关心精确的计时，TICR将使用外部时间源进行校准。
	lapicw(TDCR, X1);
	lapicw(TIMER, PERIODIC | (IRQ_OFFSET + IRQ_TIMER));
	lapicw(TICR, 10000000); 

	// Leave LINT0 of the BSP enabled so that it can get
	// interrupts from the 8259A chip.
	// 使BSP的LINT0处于启用状态，以便它可以从8259A芯片获得中断。 
	// According to Intel MP Specification, the BIOS should initialize
	// BSP's local APIC in Virtual Wire Mode, in which 8259A's
	// INTR is virtually connected to BSP's LINTIN0. In this mode,
	// we do not need to program the IOAPIC.
	// 根据Intel MP规范，BIOS应在虚拟线模式下初始化BSP的本地APIC，其中8259A的INTR虚拟连接到BSP的LINTIN0。
	// 在此模式下，我们不需要对IOAPIC进行编程。
	if (thiscpu != bootcpu)
		lapicw(LINT0, MASKED);

	// Disable NMI (LINT1) on all CPUs  在所有CPU上禁用NMI（LINT1） 
	lapicw(LINT1, MASKED);

	// Disable performance counter overflow interrupts
	// on machines that provide that interrupt entry.
	//  在提供中断项的计算机上禁用性能计数器溢出中断。 
	if (((lapic[VER]>>16) & 0xFF) >= 4)
		lapicw(PCINT, MASKED);

	// Map error interrupt to IRQ_ERROR.
	lapicw(ERROR, IRQ_OFFSET + IRQ_ERROR);

	// Clear error status register (requires back-to-back writes).
	lapicw(ESR, 0);
	lapicw(ESR, 0);

	// Ack any outstanding interrupts.
	lapicw(EOI, 0);

	// Send an Init Level De-Assert to synchronize arbitration ID's.
	lapicw(ICRHI, 0);
	lapicw(ICRLO, BCAST | INIT | LEVEL);
	while(lapic[ICRLO] & DELIVS)
		;

	// Enable interrupts on the APIC (but not on the processor).
	lapicw(TPR, 0);
}

int
cpunum(void)
{
	if (lapic)
		return lapic[ID] >> 24;
	return 0;
}

// Acknowledge interrupt.  确认中断。 
void
lapic_eoi(void)
{
	if (lapic)
		lapicw(EOI, 0);
}

// Spin for a given number of microseconds.
// On real hardware would want to tune this dynamically.
static void
microdelay(int us)
{
}

#define IO_RTC  0x70

// Start additional processor running entry code at addr.
// See Appendix B of MultiProcessor Specification.
//  在addr处启动额外的处理器运行入口代码。请参阅《多处理器规范》附录B。 
void
lapic_startap(uint8_t apicid, uint32_t addr)
{
	int i;
	uint16_t *wrv;

	// "The BSP must initialize CMOS shutdown code to 0AH
	// and the warm reset vector (DWORD based at 40:67) to point at
	// the AP startup code prior to the [universal startup algorithm]."
	outb(IO_RTC, 0xF);  // offset 0xF is shutdown code
	outb(IO_RTC+1, 0x0A);
	wrv = (uint16_t *)KADDR((0x40 << 4 | 0x67));  // Warm reset vector
	wrv[0] = 0;
	wrv[1] = addr >> 4;

	// "Universal startup algorithm."
	// Send INIT (level-triggered) interrupt to reset other CPU.
	lapicw(ICRHI, apicid << 24);
	lapicw(ICRLO, INIT | LEVEL | ASSERT);
	microdelay(200);
	lapicw(ICRLO, INIT | LEVEL);
	microdelay(100);    // should be 10ms, but too slow in Bochs!

	// Send startup IPI (twice!) to enter code.
	// Regular hardware is supposed to only accept a STARTUP
	// when it is in the halted state due to an INIT.  So the second
	// should be ignored, but it is part of the official Intel algorithm.
	// Bochs complains about the second one.  Too bad for Bochs.
	for (i = 0; i < 2; i++) {
		lapicw(ICRHI, apicid << 24);
		lapicw(ICRLO, STARTUP | (addr >> 12));
		microdelay(200);
	}
}

void
lapic_ipi(int vector)
{
	lapicw(ICRLO, OTHERS | FIXED | vector);
	while (lapic[ICRLO] & DELIVS)
		;
}
