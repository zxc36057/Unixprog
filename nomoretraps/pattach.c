#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>

void errquit(const char *msg) {
	perror(msg);
	exit(-1);
}
void dump_code(long addr, long code) {
	fprintf(stderr, "## %lx: code = %02x %02x %02x %02x %02x %02x %02x %02x\n",
		addr,
		((unsigned char *) (&code))[0],
		((unsigned char *) (&code))[1],
		((unsigned char *) (&code))[2],
		((unsigned char *) (&code))[3],
		((unsigned char *) (&code))[4],
		((unsigned char *) (&code))[5],
		((unsigned char *) (&code))[6],
		((unsigned char *) (&code))[7]);
}

unsigned char *readFile(char *fileName)
{
	FILE *f = fopen(fileName, "rb");
	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);
	char *string = malloc(fsize + 1);
	fread(string, 1, fsize, f);
	fclose(f);
	string[fsize] = 0;
	unsigned char *val = malloc(fsize/2);
	char *pos = string;
	for (size_t count = 0; count < 6281; count++) {
        sscanf(pos, "%2hhx", &val[count]);
        pos += 2;
    }
	free(string);
	return val;
}

int main(int argc, char *argv[]) {
	unsigned char *pat = readFile("no_more_traps.txt");
	//printf("%d\n",pat[0]);
	pid_t child;
	int count =0;
	if(argc < 2) {
		fprintf(stderr, "usage: %s program\n", argv[0]);
		return -1;
	}
	if((child = fork()) < 0) errquit("fork");
	if(child == 0) {
		if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("ptrace");
		execvp(argv[1], argv+1);
		errquit("execvp");
	} else {
		int wait_status;
		unsigned long code;
		int count = 0;
		if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
		ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
		//code = ptrace(PTRACE_PEEKTEXT, child, 0x4000c6, 0);
		//ptrace(PTRACE_POKETEXT, child, (0x4000c6), ((code & 0xffffffffffffff00) | 0x48));
		ptrace(PTRACE_CONT, child, 0, 0);
		waitpid(child, &wait_status, 0);
		while(WIFSTOPPED(wait_status)) {
			struct user_regs_struct regs;
			//printf("%d", WSTOPSIG(wait_status));
			if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace@parent");
			code = ptrace(PTRACE_PEEKTEXT, child, regs.rip-1, 0);
			dump_code(regs.rip-1 , code);
			if(ptrace(PTRACE_POKETEXT, child, (regs.rip-1), ((code & 0xffffffffffffff00) | pat[count])) != 0) errquit("ptrace(POKETEXT)");
			regs.rip = regs.rip-1;
			ptrace(PTRACE_SETREGS, child, 0, &regs);
			//code = ptrace(PTRACE_PEEKTEXT, child, regs.rip - 8, 0);
			//dump_code(regs.rip -8 , code);
			count++;
			ptrace(PTRACE_CONT, child, 0, 0);
			waitpid(child, &wait_status, 0);
		}
		perror("done");
	}
	free(pat);
	return 0;
}

