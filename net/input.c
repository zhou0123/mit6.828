#include "ns.h"

extern union Nsipc nsipcbuf;

void
sleep(int msec)//简单的延迟函数
{
       unsigned now = sys_time_msec();
       unsigned end = now + msec;

       if ((int)now < 0 && (int)now > -MAXERROR)
               panic("sys_time_msec: %e", (int)now);
       while (sys_time_msec() < end)
               sys_yield();
}

void
input(envid_t ns_envid)
{
	binaryname = "ns_input";

	// LAB 6: Your code here:
	// 	- read a packet from the device driver
	//	- send it to the network server
	// Hint: When you IPC a page to the network server, it will be
	// reading from it for a while, so don't immediately receive
	// another packet in to the same physical page.
	char my_buf[2048];
	int length;
	while(1){       
        while((length = sys_packet_recv(my_buf))<0)
            sys_yield();
		nsipcbuf.pkt.jp_len=length;
        memcpy(nsipcbuf.pkt.jp_data, my_buf, length);
		ipc_send(ns_envid, NSREQ_INPUT, &nsipcbuf, PTE_U | PTE_P);
		sleep(50);
	}
}
