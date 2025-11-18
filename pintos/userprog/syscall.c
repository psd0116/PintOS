#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	int syscall_num = f->R.rax;

	switch (syscall_num)
	{
		case SYS_HALT:
			handler_halt();
			break;
		// case SYS_EXEC:
		// 	hander_exec();
		// 	break;
		case SYS_EXIT:
			handler_exit(f->R.rdi);
			break;
		// case SYS_FORK:
		// 	break;
		// case SYS_WAIT:
		// 	break;
		// case SYS_CREATE:
		// 	break;
		// case SYS_REMOVE:
		// 	break;
		// case SYS_FILESIZE:
		// 	break;
		// case SYS_READ:
		// 	break;
		case SYS_WRITE:
			f->R.rax = handler_write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		// case SYS_SEEK:
		// 	break;
		// case SYS_TELL:
		// 	break;
		// case SYS_CLOSE:
		// 	break;
		default:
			break;
	}
}

// 주소가 유효한지 유효성을 검사하는 함수
static void check_address(const void *addr){
	struct thread *cur = thread_current();

	if (addr == NULL || !is_user_vaddr(addr) || pml4_get_page(cur->pml4, addr) == NULL){
		handler_exit(-1);
	}
}

// halt는 return 값이 존재하지 않는다.
void handler_halt(void){
	power_off();
}

// 현재 동작중인 유저 프로그램을 종료한다. 부모 프로세스가 현재 유저 프로그램의
// 종료를 기디리던 중이라면, 종료되면서 상태를 반환한다.
void handler_exit(int status){
	struct thread *cur = thread_current();
	cur->exit_status = status; // 자식 프로세스의 종료상태 저장
	thread_exit();
}

int handler_write(int fd, const void *buffer, unsigned size){
	if (size == 0) {
		return 0;
		}
	// 버퍼의 시작 주소 확인
	check_address(buffer);
	// 버퍼의 마지막 바이트 주소 확인
	check_address((const char*)buffer + size - 1);
	
	if (fd == 1){
		putbuf(buffer, size);
		return size;
	} else if (fd == 0){
		return -1;
	} else {
		return -1;
	}
}



// halt랑 exit
// enum {
// 	/* Projects 2 and later. */
// 	SYS_HALT,                   /* Clone current process. */
// 	SYS_EXEC,                     /* Halt the operating system. */
// 	SYS_EXIT,                   /* Terminate this process. */
// 	SYS_FORK,                 /* Switch current process. */
// 	SYS_WAIT,                   /* Wait for a child process to die. */
// 	SYS_CREATE,                 /* Create a file. */
// 	SYS_REMOVE,                 /* Delete a file. */
// 	SYS_OPEN,                   /* Open a file. */
// 	SYS_FILESIZE,               /* Obtain a file's size. */
// 	SYS_READ,                   /* Read from a file. */
// 	SYS_WRITE,                  /* Write to a file. */
// 	SYS_SEEK,                   /* Change position in a file. */
// 	SYS_TELL,                   /* Report current position in a file. */
// 	SYS_CLOSE,                  /* Close a file. */