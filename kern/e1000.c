#include <kern/e1000.h>
#include <kern/pmap.h>
uint32_t *pci_e1000;
#define E1000_STATUS   0x00008  /* Device Status - RO */
// LAB 6: Your driver code here
struct tx_desc tx_list[TX_MAX];//描述符
struct packets{
        char buffer[BUFSIZE];//16对齐
}__attribute__((packed));
struct packets tx_buf[TX_MAX];//缓冲区
struct rx_desc rx_list[RX_MAX];
struct packets rx_buf[RX_MAX];

int
e1000_init(struct pci_func *pcif)
{
        pci_func_enable(pcif);
        pci_e1000 = mmio_map_region(pcif->reg_base[0], pcif->reg_size[0]);
        cprintf("the E1000 status register: [%08x]\n", *(pci_e1000+(E1000_STATUS>>2)));
        e1000_transmit_init();
        e1000_receive_init();
        // fit_txd_for_E1000_transmit("I'm here", 10);
        return 1;
}

void
e1000_transmit_init(){
//别忘了要加到e1000_init()里面才起作用
        memset(tx_list, 0, sizeof(struct tx_desc)*TX_MAX);
        memset(tx_buf, 0, sizeof(struct packets)*TX_MAX);
        for(int i=0; i<TX_MAX; i++){
                tx_list[i].addr = PADDR(tx_buf[i].buffer); //不太懂为什么可以用PADDR
                tx_list[i].cmd = (E1000_TXD_CMD_EOP>>24) | (E1000_TXD_CMD_RS>>24);
                tx_list[i].status = E1000_TXD_STAT_DD;
        }
        pci_e1000[E1000_TDBAL>>2] = PADDR(tx_list);
        pci_e1000[E1000_TDBAH>>2] = 0;
        pci_e1000[E1000_TDLEN>>2] = TX_MAX*sizeof(struct tx_desc);
        pci_e1000[E1000_TDH>>2] = 0;
        pci_e1000[E1000_TDT>>2] = 0;
        //pci_e1000[E1000_TCTL>>2] |= 0x4010A;
        pci_e1000[E1000_TCTL>>2] |= (E1000_TCTL_EN | E1000_TCTL_PSP |
                                     (E1000_TCTL_CT & (0x10<<4)) |
                                     (E1000_TCTL_COLD & (0x40<<12)));
        pci_e1000[E1000_TIPG>>2] |= (10) | (4<<10) | (6<<20);
}
//kern/e1000.c
int
fit_txd_for_E1000_transmit(void *addr, int length){
        int tail = pci_e1000[E1000_TDT>>2];
		
		/* 这样写很明显是错的，因为对tx_next的修改并没有写回tx_list[tail]，
			因为tx_next是个新对象，并不是对tx_list[tail]的引用
        struct tx_desc tx_next = tx_list[tail];
        if(length > sizeof(struct packets))
                length = sizeof(struct packets); //最大也只能2048 bytes
        if(tx_next.status & E1000_TXD_STAT_DD){
                memmove(KADDR(tx_next.addr), addr, length);
                tx_next.status = 0; //表示现在该描述符还没被处理
                tx_next.length = length;
                pci_e1000[E1000_TDT>>2] = (tail + 1)%TX_MAX;
                memcpy(&tx_list[tail], &tx_next, sizeof(struct tx_desc));//就算我在这复制回去了，也还是不行，真的不懂了
                return 0;
        }*/

		//正确写法
		struct tx_desc *tx_next = &tx_list[tail];
        if(length > sizeof(struct packets))
                length = sizeof(struct packets); //最大也只能2048 bytes
        if((tx_next->status & E1000_TXD_STAT_DD) == E1000_TXD_STAT_DD){
                //memmove(tx_buf[tail].buffer, addr, length);
                memmove(KADDR(tx_next->addr), addr, length);
                tx_next->status &= !E1000_TXD_STAT_DD; //表示现在该描述符还没被处理
                tx_next->length = (uint16_t)length;
                pci_e1000[E1000_TDT>>2] = (tail + 1)%TX_MAX;
                //memcpy(&tx_list[tail], &tx_next, sizeof(struct tx_desc));     
                cprintf("my message:%s, %d, %02x\n", tx_buf[tail].buffer, tx_list[tail].length, tx_list[tail].status);
                return 0;
        }
        return -1;
}


void
e1000_receive_init()
{
        for(int i=0; i<RX_MAX; i++){
                memset(&rx_list[i], 0, sizeof(struct rx_desc));
                memset(&rx_buf[i], 0, sizeof(struct packets));
                rx_list[i].addr = PADDR(rx_buf[i].buffer); 
        }
        pci_e1000[E1000_MTA>>2] = 0;
        pci_e1000[E1000_RDBAL>>2] = PADDR(rx_list);
        pci_e1000[E1000_RDBAH>>2] = 0;
        pci_e1000[E1000_RDLEN>>2] = RX_MAX*sizeof(struct rx_desc);
        pci_e1000[E1000_RDH>>2] = 0;
        pci_e1000[E1000_RDT>>2] = RX_MAX - 1;
        pci_e1000[E1000_RCTL>>2] = (E1000_RCTL_EN | E1000_RCTL_BAM |
                                     E1000_RCTL_SZ_2048 |
                                     E1000_RCTL_SECRC);
        pci_e1000[E1000_RA>>2] = 0x52 | (0x54<<8) | (0x00<<16) | (0x12<<24);
        pci_e1000[(E1000_RA>>2) + 1] = (0x34) | (0x56<<8) | E1000_RAH_AV;
}

int
read_rxd_after_E1000_receive(void *addr)
{
        int head = pci_e1000[E1000_RDH>>2];
        int tail = pci_e1000[E1000_RDT>>2];
        tail = (tail + 1) % RX_MAX;
        struct rx_desc *rx_hold = &rx_list[tail];
        if((rx_hold->status & E1000_TXD_STAT_DD) == E1000_TXD_STAT_DD){
                int len = rx_hold->length;
                memcpy(addr, rx_buf[tail].buffer, len);
                pci_e1000[E1000_RDT>>2] = tail;
                return len;
        }
        return -1;
}


