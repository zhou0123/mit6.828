#ifndef JOS_KERN_E1000_H
#define JOS_KERN_E1000_H

#include <kern/pci.h>
int e1000_init(struct pci_func *pcif);
#define E1000_TCTL     0x00400  /* TX Control - RW */
#define E1000_TDBAL    0x03800  /* TX Descriptor Base Address Low - RW */
#define E1000_TDBAH    0x03804  /* TX Descriptor Base Address High - RW */
#define E1000_TDLEN    0x03808  /* TX Descriptor Length - RW */
#define E1000_TDH      0x03810  /* TX Descriptor Head - RW */
#define E1000_TDT      0x03818  /* TX Descripotr Tail - RW */
#define E1000_TIPG     0x00410  /* TX Inter-packet gap -RW */
#define E1000_TCTL_EN            0x00000002    /* enable tx */
#define E1000_TCTL_BCE           0x00000004    /* busy check enable */
#define E1000_TCTL_PSP           0x00000008    /* pad short packets */
#define E1000_TCTL_CT            0x00000ff0    /* collision threshold */
#define E1000_TCTL_COLD          0x003ff000    /* collision distance */
#define E1000_TXD_CMD_RS         0x08000000     /* Report Status */
#define E1000_TXD_STAT_DD        0x00000001     /* Descriptor Done */
#define E1000_TXD_CMD_EOP         0x01000000 /* End of Packet */
#define TX_MAX         64	//发送包的最大数量
#define BUFSIZE        2048
struct tx_desc
{
	uint64_t addr;
	uint16_t length;
	uint8_t cso;
	uint8_t cmd;
	uint8_t status;
	uint8_t css;
	uint16_t special;
}__attribute__((packed));

void e1000_transmit_init();

int
fit_txd_for_E1000_transmit(void *addr, int length);

#define RX_MAX          128
#define E1000_RCTL_EN             0x00000002    /* enable */
#define E1000_RCTL_SBP            0x00000004    /* store bad packet */
#define E1000_RCTL_UPE            0x00000008    /* unicast promiscuous enable */
#define E1000_RCTL_MPE            0x00000010    /* multicast promiscuous enab */
#define E1000_RCTL_LPE            0x00000020    /* long packet enable */
#define E1000_RCTL_LBM_NO         0x00000000    /* no loopback mode */
#define E1000_RCTL_BAM            0x00008000    /* broadcast enable */
#define E1000_RCTL_SZ_2048        0x00000000    /* rx buffer size 2048 */
#define E1000_RCTL_SECRC          0x04000000    /* Strip Ethernet CRC */
#define E1000_RXD_STAT_DD       0x01    /* Descriptor Done */
#define E1000_RXD_STAT_EOP      0x02    /* End of Packet */
#define E1000_RCTL     0x00100  /* RX Control - RW */
#define E1000_RDBAL    0x02800  /* RX Descriptor Base Address Low - RW */
#define E1000_RDBAH    0x02804  /* RX Descriptor Base Address High - RW */
#define E1000_RDLEN    0x02808  /* RX Descriptor Length - RW */
#define E1000_RDH      0x02810  /* RX Descriptor Head - RW */
#define E1000_RDT      0x02818  /* RX Descriptor Tail - RW */

#define E1000_MTA      0x05200  /* Multicast Table Array - RW Array */
#define E1000_RA       0x05400  /* Receive Address - RW Array */
#define E1000_RAH_AV  0x80000000        /* Receive descriptor valid */
struct rx_desc
{
        uint64_t addr;
        uint16_t length;
        uint16_t pcs;
        uint8_t status;
        uint8_t errors;
        uint16_t special;
}__attribute__((packed));
int read_rxd_after_E1000_receive(void *addr);
void e1000_receive_init();
int read_rxd_after_E1000_receive(void *addr);

#endif  // SOL >= 6
