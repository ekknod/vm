#include "../shared/vm_linux.h"
#include <stdio.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>

int get_process_id(const char *process_name)
{
	int process_id = 0;

	DIR *dir = opendir("/proc/");
	if (dir == 0)
	{
		return 0;
	}

	struct dirent *a0;
	while ((a0 = readdir(dir)))
	{
		if (a0->d_type != DT_DIR)
		{
			continue;
		}
		
		char buffer[266]{};
		snprintf(buffer, sizeof(buffer), "/proc/%s/exe", a0->d_name);

		if (readlink(buffer, buffer, sizeof(buffer)) == -1)
		{
			continue;
		}

		const char *name = strrchr(buffer, '/');
		if (name == 0)
		{
			continue;
		}

		int pid = atoi(a0->d_name);
		if (pid < 1 || pid > 2147483647)
		{
			continue;
		}

		if (!strcmp(name + 1, process_name))
		{
			process_id = pid;
			break;
		}
	}
	closedir(dir);
	return process_id;
}

static size_t
read_line(int fd, char *buffer, size_t length)
{
	size_t pos = 0;
	while (--length > 0 && read(fd, &buffer[pos], 1))
	{
		if (buffer[pos] == '\n')
		{
			buffer[pos] = '\0';
			return pos;
		}
		pos++;
	}
	return 0;
}

QWORD get_module_base(int process_id, const char *module_name)
{
	QWORD base = 0;

	char buffer[512]{};
	snprintf(buffer, sizeof(buffer), "/proc/%d/maps", process_id);

	int fd = open(buffer, O_RDONLY);
	if (fd == -1)
	{
		return 0;
	}

	while (read_line(fd, buffer, sizeof(buffer)))
	{
		const char *name = strrchr(buffer, '/');

		if (name == 0)
		{
			continue;
		}

		if (!strcmpi_imp(name + 1, module_name))
		{
			name = buffer;
			base = strtoul(buffer, (char**)&name, 16);
			break;
		}
	}

	close(fd);

	return base;
}

VmOs vm::get_target_os(void)
{
	return VmOs::Linux;
}

BOOL vm::process_exists(PCSTR process_name)
{
	return get_process_id(process_name) != 0;
}

vm_handle vm::open_process(PCSTR process_name)
{
	int pid = get_process_id(process_name);
	if (pid == 0)
	{
		return 0;
	}

	char dir[23];
	snprintf(dir, sizeof(dir), "/proc/%d/mem", pid);

	int fd = open(dir, O_RDWR);
	if (fd == -1)
	{
		return 0;
	}

	vm_handle process = 0;
	((int*)&process)[0] = fd;
	((int*)&process)[1] = pid;

	return process;
}

vm_handle vm::open_process_ex(PCSTR process_name, PCSTR dll_name)
{
	int pid = get_process_id(process_name);

	if (pid == 0)
	{
		return 0;
	}

	if (get_module_base(pid, dll_name) == 0)
	{
		return 0;
	}

	char dir[23];
	snprintf(dir, sizeof(dir), "/proc/%d/mem", pid);

	int fd = open(dir, O_RDWR);
	if (fd == -1)
	{
		return 0;
	}

	vm_handle process = 0;
	((int*)&process)[0] = fd;
	((int*)&process)[1] = pid;

	return process;
}

inline void close_file(int fd)
{
	close(fd);
}

void vm::close(vm_handle process)
{
	close_file(((int*)&process)[0]);
}

BOOL vm::running(vm_handle process)
{
	return fcntl(((int*)&process)[0], F_GETFD) == 0;
}

BOOL vm::read(vm_handle process, QWORD address, PVOID buffer, QWORD length)
{
	return pread(((int*)&process)[0], buffer, length, address) == length;
}

BOOL vm::write(vm_handle process, QWORD address, PVOID buffer, QWORD length)
{
	return pwrite(((int*)&process)[0], buffer, length, address) == length;
}

QWORD vm::get_module(vm_handle process, PCSTR dll_name)
{
	return get_module_base(((int*)&process)[1], dll_name);
}

QWORD vm::get_module_export(vm_handle process, QWORD base, PCSTR export_name)
{
	return vmlinux::get_module_export(process, base, export_name);
}

PVOID vm::dump_module(vm_handle process, QWORD base, VM_MODULE_TYPE module_type)
{
	return vmlinux::dump_module(process, base, module_type);
}

void vm::free_module(PVOID dumped_module)
{
	return vmlinux::free_module(dumped_module);
}

QWORD vm::get_dump_export(PVOID dumped_module, PCSTR export_name)
{
	return 0;
}

QWORD vm::scan_pattern(PVOID dumped_module, PCSTR pattern, PCSTR mask, QWORD length)
{
	return vmlinux::scan_pattern(dumped_module, pattern, mask, length);
}

QWORD vm::scan_pattern_direct(vm_handle process, QWORD base, PCSTR pattern, PCSTR mask, DWORD length)
{
	return vmlinux::scan_pattern_direct(process, base, pattern, mask, length);
}
