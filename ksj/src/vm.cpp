#ifdef __linux__
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

typedef int SOCKET;

#else
#include <stdio.h>

#include <WinSock2.h>
#include <winsock.h>

#pragma comment(lib, "Ws2_32.lib")

#include <malloc.h>
#include <inttypes.h>
#include <string.h>
#endif

#include "../../shared/vm_windows.h"

#include <malloc.h>

#define SOCKET_NAME "vm"
#define IOCTL_READPHYS   1
#define IOCTL_WRITEPHYS  2
#define IOCTL_VIRT2PHYS  3
#define IOCTL_READVIRT   4
#define IOCTL_WRITEVIRT  5
#define IOCTL_CR3        6
#define IOCTL_NTOSKRNL   7

struct _vm_handle {
	QWORD cr3;
	QWORD object;
	QWORD exit_status;
	QWORD wow64_process;
	QWORD peb;
} ;

namespace vm
{
	static SOCKET            fd;
	static struct _vm_handle system_proc;
	static QWORD             PsInitialSystemProcess;
	static QWORD             PsLoadedModuleList;
	static DWORD             offset_PsGetProcessExitProcessCalled;
	static DWORD             offset_PsGetProcessImageFileName;
	static DWORD             offset_ActiveProcessLinks;
	static DWORD             offset_PsGetProcessWow64Process;
	static DWORD             offset_PsGetProcessPeb;
	static BOOL initialize(void);
}

namespace client
{
	namespace pm
	{
		BOOL  read(SOCKET fd, QWORD address, PVOID buffer, QWORD length);
		BOOL  write(SOCKET fd, QWORD address, PVOID buffer, QWORD length);
		template <typename t>
		t read(SOCKET fd, QWORD address)
		{
			t b;
			if (!client::pm::read(fd, address, &b, sizeof(b)))
			{
				b = 0;
			}
			return b;
		}
	}

	namespace vm
	{
		QWORD get_physical_address(SOCKET fd, QWORD cr3, QWORD virtual_address);
		BOOL  read(SOCKET fd, QWORD cr3, QWORD address, PVOID buffer, QWORD length);
		BOOL  write(SOCKET fd, QWORD cr3, QWORD address, PVOID buffer, QWORD length);
	}
	QWORD get_system_cr3(SOCKET fd);
	QWORD get_ntoskrnl_base(SOCKET fd);
}

VmOs vm::get_target_os()
{
	return VmOs::Windows;
}

static QWORD PsLookupProcessByProcessName(const char *process_name)
{
	QWORD entry;
	char image_name[15]={0};

	entry = vm::PsInitialSystemProcess;
	do {
		vm::read(&vm::system_proc, entry + vm::offset_PsGetProcessImageFileName, image_name, 15);
		image_name[14]=0;
		
		DWORD exitcalled = vm::read_i32(&vm::system_proc, entry + vm::offset_PsGetProcessExitProcessCalled);
		exitcalled = exitcalled >> 2;
		exitcalled = exitcalled & 1;

		if (!exitcalled && strcmpi_imp(process_name, image_name) == 0)
		{
			return entry;
		}

		entry = vm::read_i64(&vm::system_proc, entry + vm::offset_ActiveProcessLinks);
		if (entry == 0)
			break;

		entry = entry - vm::offset_ActiveProcessLinks;
	} while (entry != vm::PsInitialSystemProcess) ;
	return 0;
}

BOOL vm::process_exists(PCSTR process_name)
{
	if (!vm::initialize())
	{
		return 0;
	}
	return PsLookupProcessByProcessName(process_name) != 0;
}

vm_handle vm::open_process(PCSTR process_name)
{
	if (!vm::initialize())
	{
		return 0;
	}

	if (process_name == 0 || *process_name == '\0') {
		return (vm_handle)&system_proc;
	}

	QWORD process_object = PsLookupProcessByProcessName(process_name);
	if (process_object == 0)
	{
		return 0;
	}

	struct _vm_handle *temp_handle = (struct _vm_handle*)malloc(sizeof(struct _vm_handle));
	temp_handle->object=process_object;
	temp_handle->cr3=vm::read_i64(&system_proc, process_object + 0x28);
	temp_handle->exit_status=client::vm::get_physical_address(fd, system_proc.cr3, process_object + offset_PsGetProcessExitProcessCalled);
	temp_handle->wow64_process=client::vm::get_physical_address(fd, system_proc.cr3,process_object + vm::offset_PsGetProcessWow64Process);
	temp_handle->peb=client::vm::get_physical_address(fd, system_proc.cr3,process_object + vm::offset_PsGetProcessPeb);
	return temp_handle;
}

vm_handle vm::open_process_ex(PCSTR process_name, PCSTR dll_name)
{
	return open_process(process_name);
}

vm_handle vm::open_process_by_module_name(PCSTR dll_name)
{
	return 0;
}

void vm::close(vm_handle process)
{
	free(process);
}

BOOL vm::running(vm_handle process)
{
	if (process == 0)
		return 0;

	struct _vm_handle *proc = (struct _vm_handle *)process;
	DWORD eax = client::pm::read<DWORD>(fd, proc->exit_status);
	eax = eax >> 2;
	eax = eax & 1;
	return eax == 0;
}

BOOL vm::read(vm_handle process, QWORD address, PVOID buffer, QWORD length)
{
	struct _vm_handle *proc = (struct _vm_handle*)process;
	return client::vm::read(fd, proc->cr3, address, buffer, length);
}

BOOL vm::write(vm_handle process, QWORD address, PVOID buffer, QWORD length)
{
	struct _vm_handle *proc = (struct _vm_handle*)process;
	return client::vm::write(fd, proc->cr3, address, buffer, length);
}

QWORD vm::get_peb(vm_handle process)
{
	if (process == 0)
		return 0;

	struct _vm_handle *proc = (struct _vm_handle *)process;

	return client::pm::read<QWORD>(fd, proc->peb);
}

QWORD vm::get_wow64_process(vm_handle process)
{
	if (process == 0)
		return 0;

	struct _vm_handle *proc = (struct _vm_handle *)process;
	QWORD rax = client::pm::read<QWORD>(fd, proc->wow64_process);

	return vm::read_i64(&vm::system_proc, rax);
}

QWORD vm::get_module(vm_handle process, PCSTR dll_name)
{
	return vmwin::get_module(process, dll_name);
}

QWORD vm::get_module_export(vm_handle process, QWORD base, PCSTR export_name)
{
	return vmwin::get_module_export(process, base, export_name);
}

PVOID vm::dump_module(vm_handle process, QWORD base, VM_MODULE_TYPE module_type)
{
	return vmwin::dump_module(process, base, module_type);
}

void vm::free_module(PVOID dumped_module)
{
	return vmwin::free_module(dumped_module);
}

QWORD vm::get_dump_export(PVOID dumped_module, PCSTR export_name)
{
	return vmwin::get_dump_export(dumped_module, export_name);
}

QWORD vm::scan_pattern(PVOID dumped_module, PCSTR pattern, PCSTR mask, QWORD length)
{
	return vmwin::scan_pattern(dumped_module, pattern, mask, length);
}

QWORD vm::scan_pattern_direct(vm_handle process, QWORD base, PCSTR pattern, PCSTR mask, DWORD length)
{
	return vmwin::scan_pattern_direct(process, base, pattern, mask, length);
}

static void socket_close(SOCKET fd)
{
#ifdef __linux__
	close(fd);
#else
	closesocket(fd);
#endif
}

static SOCKET socket_open(void)
{
#ifndef __linux__
	WSADATA data;
	WSAStartup(MAKEWORD(2, 2), &data);
#endif // !__linux__

	
	struct sockaddr addr{}; 

	SOCKET data_socket = socket(AF_UNIX, SOCK_STREAM, 0);


	addr.sa_family = AF_UNIX;
	memcpy(addr.sa_data, SOCKET_NAME, strlen(SOCKET_NAME));

	int ret = connect (data_socket, (const struct sockaddr *) &addr, sizeof(struct sockaddr));

	if (ret == -1)
	{
		socket_close(data_socket);
		data_socket = 0;
	}

	return data_socket;
}

static QWORD socket_read(SOCKET fd, PVOID buffer, QWORD length)
{
	#ifdef __linux__
	return recv(fd, (char *)buffer, (int)length, MSG_WAITALL);
	#else
	return recv(fd, (char *)buffer, (int)length, 0);
	#endif
}

static QWORD socket_write(SOCKET fd, PVOID buffer, QWORD length)
{
#ifdef __linux__
	return write(fd, buffer, length);
#else
	return send(fd, (const char*)buffer, (int)length, 0);
#endif
}

#ifdef __linux__
#define FIELD_OFFSET(type, field)    (DWORD)((long)&(((type *)0)->field))
#endif

namespace client
{
#ifdef __linux__
	typedef struct __attribute__((__packed__)) {
#else
#pragma pack(1)
	typedef struct {
#endif
		unsigned char ioctl;
	} SERVER_PACKET;

#ifdef __linux__
	typedef struct __attribute__((__packed__)) {
#else
#pragma pack(1)
	typedef struct {
#endif
		SERVER_PACKET header;
		QWORD         cr3;
		QWORD         virtual_address;
	} SERVER_VIRT2PHYS;

#ifdef __linux__
	typedef struct __attribute__((__packed__)) {
#else
#pragma pack(1)
	typedef struct {
#endif
		SERVER_PACKET header;
		QWORD         address;
		DWORD         size;
	} SERVER_READWRITEPHYS;

#ifdef __linux__
	typedef struct __attribute__((__packed__)) {
#else
#pragma pack(1)
	typedef struct {
#endif
		SERVER_PACKET header;
		QWORD         cr3;
		QWORD         address;
		DWORD         size;
	} SERVER_READWRITEVIRT;

	namespace pm
	{
		BOOL read(SOCKET fd, QWORD address, PVOID buffer, QWORD length)
		{
			SERVER_READWRITEPHYS packet;
			packet.header.ioctl = IOCTL_READPHYS;
			packet.address = address;
			packet.size = (DWORD)length;
			socket_write(fd, &packet, sizeof(packet));

			BOOLEAN status=0;
			if (socket_read(fd, &status, sizeof(status)) != sizeof(status))
			{
				return 0;
			}

			if (status == 0)
			{
				return 0;
			}

			return socket_read(fd, buffer, length) == length;
		}

		BOOL write(SOCKET fd, QWORD address, PVOID buffer, QWORD length)
		{
			QWORD packet_size = length + sizeof(SERVER_READWRITEPHYS);

			SERVER_READWRITEPHYS *packet = (SERVER_READWRITEPHYS *)malloc(packet_size);
			packet->header.ioctl = IOCTL_WRITEPHYS;
			packet->address = address;
			packet->size = (DWORD)length;

			DWORD offset = FIELD_OFFSET(SERVER_READWRITEPHYS, size) + 4;

			memcpy(
				(char*)packet + offset,
				buffer,
				length
			);

			socket_write(fd, (void *)packet, packet_size);

			free(packet);

			unsigned char status=0;
			socket_read(fd, &status, 1);

			return (BOOL)status;
		}
	}

	namespace vm
	{
		QWORD get_physical_address(SOCKET fd, QWORD cr3, QWORD virtual_address)
		{
			SERVER_VIRT2PHYS packet{};
			packet.header.ioctl = IOCTL_VIRT2PHYS;
			packet.cr3 = cr3;
			packet.virtual_address = virtual_address;
			socket_write(fd, &packet, sizeof(packet));

			QWORD physical_address = 0;
			socket_read(fd, &physical_address, sizeof(physical_address));

			return physical_address;
		}

		BOOL read(SOCKET fd, QWORD cr3, QWORD address, PVOID buffer, QWORD length)
		{
			SERVER_READWRITEVIRT packet{};
			packet.header.ioctl = IOCTL_READVIRT;
			packet.cr3 = cr3;
			packet.address = address;
			packet.size = (DWORD)length;
			socket_write(fd, &packet, sizeof(packet));

			BOOLEAN status=0;
			if (socket_read(fd, &status, sizeof(status)) != sizeof(status))
			{
				return 0;
			}

			if (status == 0)
			{
				return 0;
			}
			return socket_read(fd, buffer, length) == length;
		}

		BOOL write(SOCKET fd, QWORD cr3, QWORD address, PVOID buffer, QWORD length)
		{
			QWORD packet_size = length + sizeof(SERVER_READWRITEVIRT);

			SERVER_READWRITEVIRT *packet = (SERVER_READWRITEVIRT *)malloc(packet_size);
			packet->header.ioctl = IOCTL_WRITEVIRT;
			packet->cr3 = cr3;
			packet->address = address;
			packet->size = (DWORD)length;

			DWORD offset = FIELD_OFFSET(SERVER_READWRITEVIRT, size) + 4;

			memcpy(
				(char*)packet + offset,
				buffer,
				length
			);

			socket_write(fd, (void *)packet, packet_size);

			free(packet);

			unsigned char status=0;
			socket_read(fd, &status, 1);

			return (BOOL)status;
		}
	}

	QWORD get_system_cr3(SOCKET fd)
	{
		SERVER_PACKET packet;
		packet.ioctl = IOCTL_CR3;
		socket_write(fd, &packet, sizeof(packet));

		QWORD cr3 = 0;
		socket_read(fd, &cr3, sizeof(cr3));
		
		return cr3;
	}

	QWORD get_ntoskrnl_base(SOCKET fd)
	{
		SERVER_PACKET packet;
		packet.ioctl = IOCTL_NTOSKRNL;
		socket_write(fd, &packet, sizeof(packet));

		QWORD base = 0;
		socket_read(fd, &base, sizeof(base));

		return base;
	}
}

static BOOL vm::initialize(void)
{
	//
	// if we are ready for vm calls
	//
	if (fd != 0)
	{
		return 1;
	}

	fd = socket_open();
	if (fd == 0)
	{
		return 0;
	}

	QWORD cr3      = client::get_system_cr3(fd);
	QWORD ntoskrnl = client::get_ntoskrnl_base(fd);

	if (cr3 == 0 || ntoskrnl == 0)
	{
	E0:
		socket_close(fd);
		fd = 0;
		return 0;
	}

	struct _vm_handle process{};
	process.cr3 = cr3;

	PVOID ntoskrnl_dump = vm::dump_module(&process, ntoskrnl, VM_MODULE_TYPE::ReadOnly);
	if (ntoskrnl_dump == 0)
	{
		goto E0;
	}

	QWORD PsGetProcessId,PsGetProcessExitProcessCalled,PsGetProcessImageFileName,PsGetProcessWow64Process,PsGetProcessPeb;

	PsInitialSystemProcess               = vm::get_dump_export(ntoskrnl_dump, "PsInitialSystemProcess");
	PsLoadedModuleList                   = vm::get_dump_export(ntoskrnl_dump, "PsLoadedModuleList");
	PsGetProcessId                       = vm::get_dump_export(ntoskrnl_dump, "PsGetProcessId");
	PsGetProcessExitProcessCalled        = vm::get_dump_export(ntoskrnl_dump, "PsGetProcessExitProcessCalled");
	PsGetProcessImageFileName            = vm::get_dump_export(ntoskrnl_dump, "PsGetProcessImageFileName");
	PsGetProcessWow64Process             = vm::get_dump_export(ntoskrnl_dump, "PsGetProcessWow64Process");
	PsGetProcessPeb                      = vm::get_dump_export(ntoskrnl_dump, "PsGetProcessPeb");

	vm::free_module(ntoskrnl_dump);

	offset_PsGetProcessExitProcessCalled = vm::read_i32(&process, PsGetProcessExitProcessCalled + 2);
	offset_PsGetProcessImageFileName     = vm::read_i32(&process, PsGetProcessImageFileName + 3);
	offset_ActiveProcessLinks            = vm::read_i32(&process, PsGetProcessId + 3) + 8;
	offset_PsGetProcessWow64Process      = vm::read_i32(&process, PsGetProcessWow64Process + 3);
	offset_PsGetProcessPeb               = vm::read_i32(&process, PsGetProcessPeb + 3);
	PsInitialSystemProcess               = vm::read_i64(&process, PsInitialSystemProcess);
	PsLoadedModuleList                   = vm::read_i64(&process, PsLoadedModuleList);

	process.object = PsInitialSystemProcess;
	system_proc = process;
	
	return fd != 0;
}

