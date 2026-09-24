/* Copyright: the NTPsec project contributors
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

// This following list are all the possible syscalls that NTPsec allows.

	SCMP_SYS(prlimit64),	/* 64 bit Fedora 26 with early_droproot*/
	SCMP_SYS(accept),
	SCMP_SYS(access),
	SCMP_SYS(adjtimex),
	SCMP_SYS(bind),
	SCMP_SYS(brk),
	SCMP_SYS(chdir),
	SCMP_SYS(clock_adjtime),
	SCMP_SYS(clock_gettime),
	SCMP_SYS(clock_settime),
	SCMP_SYS(close),
	SCMP_SYS(connect),
	SCMP_SYS(exit),
	SCMP_SYS(exit_group),
	SCMP_SYS(fcntl),
	SCMP_SYS(fstat),
	SCMP_SYS(fsync),
	SCMP_SYS(futex),	/* sem_xxx, used by threads */
	SCMP_SYS(getdents),	/* Scanning /etc/ntp.d/ */
	SCMP_SYS(getegid),	/* Needed on Alpine */
	SCMP_SYS(getgid),	/* Needed on Alpine */
	SCMP_SYS(getdents64),
	SCMP_SYS(getrandom),	/* Added in 3.17 kernel */
	SCMP_SYS(ugetrlimit),	/* sysconf */
	SCMP_SYS(getrlimit),	/* sysconf */
	SCMP_SYS(setrlimit),
	SCMP_SYS(getrusage),
	SCMP_SYS(getsockname),
	SCMP_SYS(getsockopt),
	SCMP_SYS(gettimeofday), /* mkstemp */
	SCMP_SYS(getuid),	/* Needed on Alpine */
	SCMP_SYS(ioctl),
	SCMP_SYS(link),
	SCMP_SYS(listen),
	SCMP_SYS(lseek),
	SCMP_SYS(membarrier),	/* Needed on Alpine 3.11.3 */
	SCMP_SYS(munmap),
	SCMP_SYS(newfstatat),
	SCMP_SYS(open),
	SCMP_SYS(openat),	/* SUSE */
	SCMP_SYS(poll),
	SCMP_SYS(pselect6),
	SCMP_SYS(read),
	SCMP_SYS(readv),	/* nscd getaddrinfo() provider */
	SCMP_SYS(recvfrom),
	SCMP_SYS(recvmsg),
	SCMP_SYS(rename),
	SCMP_SYS(rt_sigaction),
	SCMP_SYS(rt_sigprocmask),
	SCMP_SYS(rt_sigreturn),
	SCMP_SYS(rseq),		/* needed by glibc-2.35+ for resumable sequences */
	SCMP_SYS(sigaction),
	SCMP_SYS(sigprocmask),
	SCMP_SYS(sigreturn),
	SCMP_SYS(select),	/* not in ARM */
	SCMP_SYS(sendto),
	SCMP_SYS(setsid),
	SCMP_SYS(setsockopt),	/* not in old kernels */
	SCMP_SYS(socket),
	SCMP_SYS(socketcall),	/* old kernels */
	SCMP_SYS(stat),
	SCMP_SYS(statfs64),	/* from getaddrinfo after lid open */
	SCMP_SYS(time),		/* not in ARM */
	SCMP_SYS(sysinfo),
	SCMP_SYS(timer_create),
	SCMP_SYS(timer_gettime),
	SCMP_SYS(timer_settime),
	SCMP_SYS(getitimer),
	SCMP_SYS(setitimer),
	SCMP_SYS(write),
	SCMP_SYS(writev),	/* Needed on Alpine 3.11.3 */
	SCMP_SYS(unlink),
	SCMP_SYS(clone),	/* threads */
	SCMP_SYS(clone3),	/* Doesn't exist on 4.19.66, Raspbian 9 (stretch) */
	SCMP_SYS(kill),		/* generate signal */
	SCMP_SYS(madvise),
	SCMP_SYS(mprotect),
	SCMP_SYS(set_robust_list),
	SCMP_SYS(sendmmsg),	/* DNS lookup */
	SCMP_SYS(socketpair),
	SCMP_SYS(statfs),
	SCMP_SYS(uname),
	SCMP_SYS(nanosleep),
	SCMP_SYS(shmget),
	SCMP_SYS(shmat),
	SCMP_SYS(shmdt),
	SCMP_SYS(fcntl64),
	SCMP_SYS(fstat64),
	SCMP_SYS(getpid),
	SCMP_SYS(gettid),
	SCMP_SYS(geteuid),
	SCMP_SYS(ppoll),
	SCMP_SYS(sendmsg),
	SCMP_SYS(geteuid32),
	SCMP_SYS(mmap),		 /* gentoo 64-bit and 32-bit, Intel and Arm use mmap */
	SCMP_SYS(faccessat),
	SCMP_SYS(renameat),
	SCMP_SYS(linkat),
	SCMP_SYS(unlinkat),
	SCMP_SYS(_newselect),
	SCMP_SYS(_llseek),
	SCMP_SYS(mmap2),
	SCMP_SYS(send),
	SCMP_SYS(stat64),
	SCMP_SYS(timer_settime64),
	SCMP_SYS(clock_gettime64),
	SCMP_SYS(stat64),
	SCMP_SYS(statx),
	SCMP_SYS(clock_settime64),
	SCMP_SYS(timer_gettime64),
	SCMP_SYS(clock_adjtime64),
	SCMP_SYS(clock_getres_time64),
	SCMP_SYS(readlink),
	SCMP_SYS(readlinkat),
	SCMP_SYS(pipe2),
	SCMP_SYS(getresuid),
	SCMP_SYS(getresgid),
	SCMP_SYS(pipe2),
	SCMP_SYS(getresuid32),
	SCMP_SYS(getresgid32),
	SCMP_SYS(clock_nanosleep),

// These additions are not found in NTPsec but are necessary for ntpd-rs.

	SCMP_SYS(sigaltstack),
	SCMP_SYS(epoll_create1),
	SCMP_SYS(epoll_ctl),
	SCMP_SYS(epoll_wait),
	SCMP_SYS(eventfd2),
	SCMP_SYS(prctl),
	SCMP_SYS(sched_getaffinity),
