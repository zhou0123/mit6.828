/*
 * File system server main loop -
 * serves IPC requests from other environments.
 */

#include <inc/x86.h>
#include <inc/string.h>

#include "fs.h"


#define debug 0

// The file system server maintains three structures
// for each open file.
//  文件系统服务器为每个打开的文件维护三个结构。 
//
// 1. The on-disk 'struct File' is mapped into the part of memory
//    that maps the disk.  This memory is kept private to the file
//    server.
//  1.磁盘上的“struct File”映射到映射磁盘的内存部分。此内存对文件服务器保持专用。 
// 2. Each open file has a 'struct Fd' as well, which sort of
//    corresponds to a Unix file descriptor.  This 'struct Fd' is kept
//    on *its own page* in memory, and it is shared with any
//    environments that have the file open.
//  2.每个打开的文件也有一个“structFd”，这与Unix文件描述符相对应。
//  此“struct Fd”保存在内存中的*它自己的页面*上，并与任何打开文件的环境共享。 
// 3. 'struct OpenFile' links these other two structures, and is kept
//    private to the file server.  The server maintains an array of
//    all open files, indexed by "file ID".  (There can be at most
//    MAXOPEN files open concurrently.)  The client uses file IDs to
//    communicate with the server.  File IDs are a lot like
//    environment IDs in the kernel.  Use openfile_lookup to translate
//    file IDs to struct OpenFile.
// 3.“structOpenFile”链接其他两个结构，并对文件服务器保持私有。
// 服务器维护所有打开文件的数组，按“文件ID”进行索引。
// （最多可以同时打开MAXOPEN文件。）客户端使用文件ID与服务器通信。
// 文件ID与内核中的环境ID非常相似。使用openfile_lookup将文件ID转换为结构openfile。 

struct OpenFile {
	uint32_t o_fileid;	// file id
	struct File *o_file;	// mapped descriptor for open file
	int o_mode;		// open mode
	struct Fd *o_fd;	// Fd page
};

// Max number of open files in the file system at once
#define MAXOPEN		1024
#define FILEVA		0xD0000000

// initialize to force into data section
struct OpenFile opentab[MAXOPEN] = {
	{ 0, 0, 1, 0 }
};

// Virtual address at which to receive page mappings containing client requests.
//  接收包含客户端请求的页面映射的虚拟地址。 
union Fsipc *fsreq = (union Fsipc *)0x0ffff000;

void
serve_init(void)
{
	int i;
	uintptr_t va = FILEVA;
	for (i = 0; i < MAXOPEN; i++) {
		opentab[i].o_fileid = i;
		opentab[i].o_fd = (struct Fd*) va;
		va += PGSIZE;
	}
}

// Allocate an open file.
int
openfile_alloc(struct OpenFile **o)
{
	int i, r;

	// Find an available open-file table entry
	for (i = 0; i < MAXOPEN; i++) {
		switch (pageref(opentab[i].o_fd)) {
		case 0:
			if ((r = sys_page_alloc(0, opentab[i].o_fd, PTE_P|PTE_U|PTE_W)) < 0)
				return r;
			/* fall through */
		case 1:
			opentab[i].o_fileid += MAXOPEN;
			*o = &opentab[i];
			memset(opentab[i].o_fd, 0, PGSIZE);
			return (*o)->o_fileid;
		}
	}
	return -E_MAX_OPEN;
}

// Look up an open file for envid.
//  查找envid的打开文件。 
int
openfile_lookup(envid_t envid, uint32_t fileid, struct OpenFile **po)
{
	struct OpenFile *o;

	o = &opentab[fileid % MAXOPEN];
	if (pageref(o->o_fd) <= 1 || o->o_fileid != fileid)
		return -E_INVAL;
	*po = o;
	return 0;
}

// Open req->req_path in mode req->req_omode, storing the Fd page and
// permissions to return to the calling environment in *pg_store and
// *perm_store respectively.
//  在req->req_omode模式下打开req->req_path，
// 分别在*pg_store和*perm_store中存储Fd页面和返回调用环境的权限。 
int
serve_open(envid_t envid, struct Fsreq_open *req,
	   void **pg_store, int *perm_store)
{
	char path[MAXPATHLEN];
	struct File *f;
	int fileid;
	int r;
	struct OpenFile *o;

	if (debug)
		cprintf("serve_open %08x %s 0x%x\n", envid, req->req_path, req->req_omode);

	// Copy in the path, making sure it's null-terminated
	// 在路径中复制，确保其以空结尾 
	memmove(path, req->req_path, MAXPATHLEN);
	path[MAXPATHLEN-1] = 0;

	// Find an open file ID
	if ((r = openfile_alloc(&o)) < 0) {
		if (debug)
			cprintf("openfile_alloc failed: %e", r);
		return r;
	}
	fileid = r;

	// Open the file
	if (req->req_omode & O_CREAT) {
		if ((r = file_create(path, &f)) < 0) {
			if (!(req->req_omode & O_EXCL) && r == -E_FILE_EXISTS)
				goto try_open;
			if (debug)
				cprintf("file_create failed: %e", r);
			return r;
		}
	} else {
try_open:
		if ((r = file_open(path, &f)) < 0) {
			if (debug)
				cprintf("file_open failed: %e", r);
			return r;
		}
	}

	// Truncate  截断 
	if (req->req_omode & O_TRUNC) {
		if ((r = file_set_size(f, 0)) < 0) {
			if (debug)
				cprintf("file_set_size failed: %e", r);
			return r;
		}
	}
	if ((r = file_open(path, &f)) < 0) {
		if (debug)
			cprintf("file_open failed: %e", r);
		return r;
	}

	// Save the file pointer
	o->o_file = f;

	// Fill out the Fd structure
	o->o_fd->fd_file.id = o->o_fileid;
	o->o_fd->fd_omode = req->req_omode & O_ACCMODE;
	o->o_fd->fd_dev_id = devfile.dev_id;
	o->o_mode = req->req_omode;

	if (debug)
		cprintf("sending success, page %08x\n", (uintptr_t) o->o_fd);

	// Share the FD page with the caller by setting *pg_store,
	// store its permission in *perm_store
	*pg_store = o->o_fd;
	*perm_store = PTE_P|PTE_U|PTE_W|PTE_SHARE;

	return 0;
}

// Set the size of req->req_fileid to req->req_size bytes, truncating
// or extending the file as necessary.
//  将req->req_fileid的大小设置为req->req_size字节，根据需要截断或扩展文件。 
int
serve_set_size(envid_t envid, struct Fsreq_set_size *req)
{
	struct OpenFile *o;
	int r;

	if (debug)
		cprintf("serve_set_size %08x %08x %08x\n", envid, req->req_fileid, req->req_size);

	// Every file system IPC call has the same general structure.
	// Here's how it goes.

	// First, use openfile_lookup to find the relevant open file.
	// On failure, return the error code to the client with ipc_send.
	if ((r = openfile_lookup(envid, req->req_fileid, &o)) < 0)
		return r;

	// Second, call the relevant file system function (from fs/fs.c).
	// On failure, return the error code to the client.
	return file_set_size(o->o_file, req->req_size);
}

// Read at most ipc->read.req_n bytes from the current seek position
// in ipc->read.req_fileid.  Return the bytes read from the file to
// the caller in ipc->readRet, then update the seek position.  Returns
// the number of bytes successfully read, or < 0 on error.
// 从ipc->Read.req_fileid中的当前查找位置读取最多ipc->Read_req_n字节。
// 将从文件读取的字节返回到ipc->readRet中的调用者，然后更新查找位置。
// 返回成功读取的字节数，或出现错误时小于0。
int
serve_read(envid_t envid, union Fsipc *ipc)
{
	struct Fsreq_read *req = &ipc->read;
	struct Fsret_read *ret = &ipc->readRet;

	if (debug)
		cprintf("serve_read %08x %08x %08x\n", envid, req->req_fileid, req->req_n);

	// Lab 5: Your code here:
	struct OpenFile* o = NULL;
	int r = openfile_lookup(envid, req->req_fileid, &o);
	if(r < 0) return r;
	r = file_read(o->o_file, ret->ret_buf, req->req_n, o->o_fd->fd_offset);
	// We need to update the seek position
	//  我们需要更新搜索位置 
	if(r > 0)o->o_fd->fd_offset += r;
	return r;
}


// Write req->req_n bytes from req->req_buf to req_fileid, starting at
// the current seek position, and update the seek position
// accordingly.  Extend the file if necessary.  Returns the number of
// bytes written, or < 0 on error.
// 从当前寻道位置开始，将req->req_n字节从req->req_buf写入req_fileid，
// 并相应地更新寻道位置。如有必要，扩展文件。返回写入的字节数，或出错时小于0。 
int serve_write(envid_t envid, struct Fsreq_write *req)
{
        if (debug)
                cprintf("serve_write %08x %08x %08x\n", envid, req->req_fileid, req->req_n);

        // LAB 5: Your code here.
        int r;
        struct OpenFile *o; 
        if ((r = openfile_lookup(envid, req->req_fileid, &o)) < 0)
                return r;
        // 多于的就扔掉，确实不太合理，感觉应该循环写入的
        int req_n = req->req_n > PGSIZE ? PGSIZE : req->req_n;
        if((r = file_write(o->o_file, req->req_buf, req_n, o->o_fd->fd_offset))<0)
                return r;
        o->o_fd->fd_offset += r;
        return r;
        panic("serve_write not implemented");
}


// Stat ipc->stat.req_fileid.  Return the file's struct Stat to the
// caller in ipc->statRet.
int
serve_stat(envid_t envid, union Fsipc *ipc)
{
	struct Fsreq_stat *req = &ipc->stat;
	struct Fsret_stat *ret = &ipc->statRet;
	struct OpenFile *o;
	int r;

	if (debug)
		cprintf("serve_stat %08x %08x\n", envid, req->req_fileid);

	if ((r = openfile_lookup(envid, req->req_fileid, &o)) < 0)
		return r;

	strcpy(ret->ret_name, o->o_file->f_name);
	ret->ret_size = o->o_file->f_size;
	ret->ret_isdir = (o->o_file->f_type == FTYPE_DIR);
	return 0;
}

// Flush all data and metadata of req->req_fileid to disk.
//  将req->req_fileid的所有数据和元数据刷新到磁盘。 
int
serve_flush(envid_t envid, struct Fsreq_flush *req)
{
	struct OpenFile *o;
	int r;

	if (debug)
		cprintf("serve_flush %08x %08x\n", envid, req->req_fileid);

	if ((r = openfile_lookup(envid, req->req_fileid, &o)) < 0)
		return r;
	file_flush(o->o_file);
	return 0;
}


int
serve_sync(envid_t envid, union Fsipc *req)
{
	fs_sync();
	return 0;
}

typedef int (*fshandler)(envid_t envid, union Fsipc *req);

fshandler handlers[] = {
	// Open is handled specially because it passes pages
	/* [FSREQ_OPEN] =	(fshandler)serve_open, */
	[FSREQ_READ] =		serve_read,
	[FSREQ_STAT] =		serve_stat,
	[FSREQ_FLUSH] =		(fshandler)serve_flush,
	[FSREQ_WRITE] =		(fshandler)serve_write,
	[FSREQ_SET_SIZE] =	(fshandler)serve_set_size,
	[FSREQ_SYNC] =		serve_sync
};

void
serve(void)
{
	uint32_t req, whom;
	int perm, r;
	void *pg;

	while (1) {
		perm = 0;
		req = ipc_recv((int32_t *) &whom, fsreq, &perm);
		if (debug)
			cprintf("fs req %d from %08x [page %08x: %s]\n",
				req, whom, uvpt[PGNUM(fsreq)], fsreq);

		// All requests must contain an argument page
		if (!(perm & PTE_P)) {
			cprintf("Invalid request from %08x: no argument page\n",
				whom);
			continue; // just leave it hanging...
		}

		pg = NULL;
		if (req == FSREQ_OPEN) {
			r = serve_open(whom, (struct Fsreq_open*)fsreq, &pg, &perm);
		} else if (req < ARRAY_SIZE(handlers) && handlers[req]) {
			r = handlers[req](whom, fsreq);
		} else {
			cprintf("Invalid request code %d from %08x\n", req, whom);
			r = -E_INVAL;
		}
		ipc_send(whom, r, pg, perm);
		sys_page_unmap(0, fsreq);
	}
}

void
umain(int argc, char **argv)
{
	static_assert(sizeof(struct File) == 256);
	binaryname = "fs";
	cprintf("FS is running\n");

	// Check that we are able to do I/O
	outw(0x8A00, 0x8A00);
	cprintf("FS can do I/O\n");

	serve_init();
	fs_init();
	serve();
}

