#include <sys/ptrace.h>
#include <sys/user.h>
#include <wait.h>

#include <dlfcn.h>
#include <unistd.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <time.h>   //nanosleep
#include <limits.h>

// linux kernel hack
// forces compile time error if condition is true
#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))
#define BUILD_BUG_ON_ZERO(e) (sizeof(char[1 - 2 * !!(e)]) - 1)

void
ptrace_attach(pid_t process)
{
    int status;

    if(ptrace(PTRACE_ATTACH, process, NULL, NULL) == -1)
    {
        fprintf(stderr, "ptrace attach failed\n");
        exit(1);
    }

    if(waitpid(process, &status, WUNTRACED != process))
    {
        fprintf(stderr, "waitpid(%d) failed\n", process);
        exit(1);
    }
}

void
ptrace_detach(pid_t process)
{
	if(ptrace(PTRACE_DETACH, process, NULL, NULL) == -1)
	{
		fprintf(stderr, "ptrace detach failed\n");
		exit(1);
	}
}

static inline
void
ptrace_getregs(pid_t target, struct user_regs_struct *regs)
{
	if(ptrace(PTRACE_GETREGS, target, NULL, regs) == -1)
	{
		fprintf(stderr, "ptrace(PTRACE_GETREGS) failed\n");
		exit(1);
	}
}

void
ptrace_write(int pid, unsigned long addr, void *vptr, int len)
{
	int cnt = 0;
	long word = 0;
	
	while(cnt < len)
	{
            memcpy(&word, vptr + cnt, sizeof(word));
            word = ptrace(PTRACE_POKETEXT, pid, addr + cnt, word);
            if(word == -1)
                exit(1);
            cnt += sizeof(word);
	}
}

void
ptrace_read(int pid, unsigned long addr, void *vptr, int len)
{
	int bytesRead = 0;
	int i = 0;
	long word = 0;
	long *ptr = (long *) vptr;

	while (bytesRead < len)
	{
		word = ptrace(PTRACE_PEEKTEXT, pid, addr + bytesRead, NULL);
		if(word == -1)
		{
			fprintf(stderr, "ptrace(PTRACE_PEEKTEXT) failed\n");
			exit(1);
		}
		bytesRead += sizeof(word);
		ptr[i++] = word;
	}
}

static inline
void
ptrace_setregs(pid_t target, struct user_regs_struct *regs)
{
	if(ptrace(PTRACE_SETREGS, target, NULL, regs) == -1)
	{
		fprintf(stderr, "ptrace(PTRACE_SETREGS) failed\n");
		exit(1);
	}
}

void
ptrace_cleanup(pid_t target, unsigned long addr, void* backup, int datasize, struct user_regs_struct backup_regs)
{
	// restore original state and detach
	ptrace_write(target, addr, backup, datasize);
	ptrace_setregs(target, &backup_regs);
	ptrace_detach(target);
}

void
ptrace_cont(pid_t target)
{
	struct timespec* sleeptime = malloc(sizeof(struct timespec));

	sleeptime->tv_sec = 0;
	sleeptime->tv_nsec = 5000000;

	if(ptrace(PTRACE_CONT, target, NULL, NULL) == -1)
	{
		fprintf(stderr, "ptrace(PTRACE_CONT) failed\n");
		exit(1);
	}

	nanosleep(sleeptime, NULL);
}

int
checkloaded(pid_t pid, char* libname)
{
	FILE *fp;
	char filename[30];
	char line[850];
	long addr;
	sprintf(filename, "/proc/%d/maps", pid);
	fp = fopen(filename, "r");
	if(fp == NULL)
		exit(1);
	while(fgets(line, 850, fp) != NULL)
	{
		sscanf(line, "%lx-%*lx %*s %*s %*s %*d", &addr);
		if(strstr(line, libname) != NULL)
		{
			fclose(fp);
			return 1;
		}
	}
	fclose(fp);
	return 0;
}

long
get_free_space_addr(pid_t pid)
{
	FILE *fp;
	char filename[30];
	char line[850];
	long addr;
	char str[20];
	char perms[5];
	sprintf(filename, "/proc/%d/maps", pid);
	fp = fopen(filename, "r");
	if(fp == NULL)
		exit(1);
	while(fgets(line, 850, fp) != NULL)
	{
		sscanf(line, "%lx-%*lx %s %*s %s %*d", &addr, perms, str);

		if(strstr(perms, "x") != NULL)
		{
			break;
		}
	}
	fclose(fp);
	return addr;
}

long
get_libc_offset(pid_t pid)
{
	FILE *fp;
	char filename[100];
	char line[1000];
	long addr;
	sprintf(filename, "/proc/%d/maps", pid);
	
	if(!(fp = fopen(filename, "r")))
		exit(1);
	
	while(fgets(line, 1000, fp) != NULL)
	{
		sscanf(line, "%lx-%*lx %*s %*s %*s %*d", &addr);
		if(strstr(line, "libc-"))
			break;
	}
	fclose(fp);
	return addr;
}

unsigned char*
find_ret(unsigned char *end_addr)
{
//retry:
    for(; *end_addr != 0xC3; end_addr--);
    //if((void*) != 0xC3000000) goto retry;

    return end_addr;
}

static inline
long
get_func_offset(char *name)
{
	void* libc = dlopen("libc.so.6", RTLD_LAZY);
	void* addr = dlsym(libc, name);
	return (long)addr;
}


void
__attribute__((used))
inject_so_asm(long mallocp, long freep, long dlopenp)
{
    asm
    (
        "push %rsi \n"
        "push %rdx"
    );

    asm
    (
        "push %r9 \n"
        "mov %rdi, %r9 \n"
        "mov %rcx, %rdi \n"
        "callq *%r9 \n"
        "pop %r9 \n"
        "int $3"
    );

    asm
    (
        "pop %rdx \n"
        "push %r9 \n"
        "mov %rdx,%r9 \n"
        "mov %rax,%rdi \n"
        "movabs $1,%rsi \n"
        "callq *%r9 \n"
        "pop %r9 \n"
        "int $3"
    );

    asm
    (
        "mov %rax,%rdi \n"
        "pop %rsi \n"
        "push %rbx \n"
        "mov %rsi,%rbx \n"
        "xor %rsi,%rsi \n"
        "int $3 \n"
        "callq *%rbx \n"
        "pop %rbx"
    );
    return;
}
// this is a dummy function used to calculate size of above
// if this step fails compiler reordered function pointers differently
// unfortunatedly there is no clean&portable way to do this in C afaik
__attribute__((used))
void inject_so_asm_end() {};

void inject_so(pid_t target_pid, char *lib_name)
{
    char *lib_path = realpath(lib_name, NULL);
    size_t lib_path_len = strlen(lib_path);
    long local_libc_offset = get_libc_offset(getpid());
    long target_libc_offset = get_libc_offset(target_pid);
    
    long target_dlopen_addr = target_libc_offset + (get_func_offset("__libc_dlopen_mode") - local_libc_offset);
    long target_free_addr = target_libc_offset + (get_func_offset("free") - local_libc_offset);
    long target_malloc_addr = target_libc_offset + (get_func_offset("malloc") - local_libc_offset);
    
    struct user_regs_struct backup_regs = {0}, new_regs={0};

    ptrace_attach(target_pid);
    ptrace_getregs(target_pid, &backup_regs);
    memcpy(&new_regs, &backup_regs, sizeof(struct user_regs_struct));

    long addr = get_free_space_addr(target_pid) + sizeof(long);
    new_regs.rip = addr + 2;
    new_regs.rdi = target_malloc_addr;
    new_regs.rsi = target_free_addr;
    new_regs.rdx = target_dlopen_addr;
    new_regs.rcx = 100;

    ptrace_setregs(target_pid, &new_regs);
 
    size_t injection_code_size = (intptr_t)inject_so_asm_end - (intptr_t)inject_so_asm;

    char* free_space_backup = malloc(injection_code_size);
    ptrace_read(target_pid, addr, free_space_backup, injection_code_size);

    char* injection_code = malloc(injection_code_size);
    memcpy(injection_code, inject_so_asm, injection_code_size-1);
    injection_code[injection_code_size] = 0xCC;

    ptrace_write(target_pid, addr, injection_code, injection_code_size);

    ptrace_cont(target_pid);

    struct user_regs_struct malloc_regs;
    memset(&malloc_regs, 0, sizeof(struct user_regs_struct));
    ptrace_getregs(target_pid, &malloc_regs);
    unsigned long long targetBuf = malloc_regs.rax;
    if(targetBuf == 0)
    {
    	fprintf(stderr, "malloc() failed to allocate memory\n");
    	ptrace_cleanup(target_pid, addr, free_space_backup, injection_code_size, backup_regs);
    	free(free_space_backup);
	free(injection_code);
        exit(1);
    }

    ptrace_write(target_pid, targetBuf, lib_path, lib_path_len);

    ptrace_cont(target_pid);

    struct user_regs_struct dlopen_regs;
    memset(&dlopen_regs, 0, sizeof(struct user_regs_struct));
    ptrace_getregs(target_pid, &dlopen_regs);
    unsigned long long libAddr = dlopen_regs.rax;

    if(libAddr == 0)
    {
	fprintf(stderr, "__libc_dlopen_mode() failed to load %s\n", lib_name);
	ptrace_cleanup(target_pid, addr, free_space_backup, injection_code_size, backup_regs);
	free(free_space_backup);
	free(injection_code);
        exit(1);
    }

    if(checkloaded(target_pid, lib_name))
    	printf("\"%s\" successfully injected\n", lib_name);
    else
    	fprintf(stderr, "could not inject \"%s\"\n", lib_name);

    ptrace_cont(target_pid);

    ptrace_cleanup(target_pid, addr, free_space_backup, injection_code_size, backup_regs);
    free(free_space_backup);
    free(injection_code);
}

int
main(int argc, char **argv)
{
    inject_so(atoi(argv[1]), "test_lib.so");
    return 0;
}
