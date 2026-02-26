#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef MAX_FDS
#define MAX_FDS 50
#endif

#define MAX_MSG 256
#define SHM_SIZE 4096

typedef enum {
	K_MEMFD = 1,
	K_SHM = 2,
	K_SOCKETPAIR = 3,
	K_PIPE_W = 4,
	K_PIPE_R = 5,
} fd_kind_t;

typedef struct {
	int flag_fd;
	int fds[MAX_FDS];
	fd_kind_t kinds[MAX_FDS];
	int n;
} state_t;

typedef struct {
	int fd;
} child_sock_t;

typedef struct {
	int in_r;
	int out_w;
} child_pipe_t;

static void die(const char *msg) {
	perror(msg);
	_exit(1);
}

static void diex(const char *msg) {
	fprintf(stderr, "%s\n", msg);
	_exit(1);
}

static uint32_t urand32(void) {
	uint32_t v = 0;
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		die("open(/dev/urandom)");
	}
	ssize_t n = read(fd, &v, sizeof(v));
	close(fd);
	if (n != (ssize_t)sizeof(v)) {
		die("read(/dev/urandom)");
	}
	return v;
}

static void rand_bytes(uint8_t *out, size_t n) {
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		die("open(/dev/urandom)");
	}
	size_t off = 0;
	while (off < n) {
		ssize_t r = read(fd, out + off, n - off);
		if (r < 0) {
			die("read(/dev/urandom)");
		}
		if (r == 0) {
			diex("short read from /dev/urandom");
		}
		off += (size_t)r;
	}
	close(fd);
}

static ssize_t write_full(int fd, const void *buf, size_t n) {
	const uint8_t *p = (const uint8_t *)buf;
	size_t off = 0;
	while (off < n) {
		ssize_t w = write(fd, p + off, n - off);
		if (w < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		off += (size_t)w;
	}
	return (ssize_t)off;
}

static ssize_t read_full(int fd, void *buf, size_t n) {
	uint8_t *p = (uint8_t *)buf;
	size_t off = 0;
	while (off < n) {
		ssize_t r = read(fd, p + off, n - off);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (r == 0) {
			break;
		}
		off += (size_t)r;
	}
	return (ssize_t)off;
}

static int add_fd(state_t *st, int fd, fd_kind_t kind, const char *desc) {
	if (st->n >= MAX_FDS) {
		close(fd);
		return -1;
	}
	int idx = st->n++;
	st->fds[idx] = fd;
	st->kinds[idx] = kind;
	printf("[+] created %-10s at index %d (fd=%d)\n", desc, idx, fd);
	return idx;
}

static void xor_buf(uint8_t *buf, size_t n, const uint8_t *key, size_t key_n) {
	for (size_t i = 0; i < n; i++) {
		buf[i] ^= key[i % key_n];
	}
}

static int make_encrypted_flag_memfd(state_t *st) {
	int enc_fd = memfd_create("fiddle_flag", 0);
	if (enc_fd < 0) {
		die("memfd_create");
	}

	uint8_t flagbuf[512];
	memset(flagbuf, 0, sizeof(flagbuf));
	if (lseek(st->flag_fd, 0, SEEK_SET) < 0) {
		die("lseek(/flag)");
	}
	ssize_t n = read(st->flag_fd, flagbuf, sizeof(flagbuf));
	if (n < 0) {
		die("read(/flag)");
	}

	uint8_t key[32];
	rand_bytes(key, sizeof(key));

	xor_buf(flagbuf, (size_t)n, key, sizeof(key));
	if (write_full(enc_fd, flagbuf, (size_t)n) < 0) {
		die("write(enc_flag)");
	}
	if (lseek(enc_fd, 0, SEEK_SET) < 0) {
		die("lseek(enc_flag)");
	}

	int idx = add_fd(st, enc_fd, K_MEMFD, "memfd(flag)");
	if (idx < 0) {
		diex("too many fds");
	}
	printf("[i] to get the encrypted flag, use index %d as your FINAL index\n", idx);
	return idx;
}

static int mk_shm(state_t *st) {
	char name[64];
	snprintf(name, sizeof(name), "/fiddle_%d_%u", getpid(), urand32());
	int fd = shm_open(name, O_CREAT | O_EXCL | O_RDWR, 0600);
	if (fd < 0) {
		die("shm_open");
	}
	(void)shm_unlink(name);
	if (ftruncate(fd, SHM_SIZE) < 0) {
		die("ftruncate(shm)");
	}
	return add_fd(st, fd, K_SHM, "shm");
}

static int mk_memfd(state_t *st) {
	int fd = memfd_create("fiddle", 0);
	if (fd < 0) {
		die("memfd_create");
	}
	return add_fd(st, fd, K_MEMFD, "memfd");
}

static int mk_socketpair(state_t *st, child_sock_t *child_socks, int *child_socks_n) {
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
		die("socketpair");
	}
	int idx = add_fd(st, sv[0], K_SOCKETPAIR, "socketpair");
	if (idx < 0) {
		close(sv[0]);
		close(sv[1]);
		return -1;
	}
	child_socks[*child_socks_n].fd = sv[1];
	(*child_socks_n)++;
	return idx;
}

static int mk_pipepair(state_t *st, child_pipe_t *child_pipes, int *child_pipes_n) {
	int p2c[2];
	int c2p[2];
	if (pipe(p2c) < 0) {
		die("pipe(p2c)");
	}
	if (pipe(c2p) < 0) {
		die("pipe(c2p)");
	}

	int w_idx = add_fd(st, p2c[1], K_PIPE_W, "pipe(w)");
	int r_idx = add_fd(st, c2p[0], K_PIPE_R, "pipe(r)");
	if (w_idx < 0 || r_idx < 0) {
		close(p2c[0]);
		close(p2c[1]);
		close(c2p[0]);
		close(c2p[1]);
		return -1;
	}

	child_pipes[*child_pipes_n].in_r = p2c[0];
	child_pipes[*child_pipes_n].out_w = c2p[1];
	(*child_pipes_n)++;
	return w_idx;
}

static void child_echo_loop(child_sock_t *socks, int socks_n, child_pipe_t *pipes, int pipes_n) {
	alarm(90);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	int total = socks_n + pipes_n;
	if (total <= 0) {
		_exit(0);
	}

	struct pollfd *pfds = calloc((size_t)total, sizeof(struct pollfd));
	if (!pfds) {
		_exit(1);
	}

	for (int i = 0; i < socks_n; i++) {
		pfds[i].fd = socks[i].fd;
		pfds[i].events = POLLIN;
	}
	for (int i = 0; i < pipes_n; i++) {
		pfds[socks_n + i].fd = pipes[i].in_r;
		pfds[socks_n + i].events = POLLIN;
	}

	uint8_t buf[1024];

	for (;;) {
		int pr = poll(pfds, (nfds_t)total, 5000);
		if (pr < 0) {
			if (errno == EINTR)
				continue;
			_exit(0);
		}
		if (pr == 0) {
			continue;
		}

		for (int i = 0; i < total; i++) {
			if (!(pfds[i].revents & POLLIN)) {
				continue;
			}

			ssize_t r = read(pfds[i].fd, buf, sizeof(buf));
			if (r <= 0) {
				continue;
			}

			if (i < socks_n) {
				(void)write_full(socks[i].fd, buf, (size_t)r);
			} else {
				int pi = i - socks_n;
				(void)write_full(pipes[pi].out_w, buf, (size_t)r);
			}
		}
	}
}

static int stage_write(state_t *st, int idx, const uint8_t *msg, size_t msg_n) {
	int fd = st->fds[idx];
	fd_kind_t kind = st->kinds[idx];

	switch (kind) {
	case K_MEMFD:
	case K_SHM:
		if (ftruncate(fd, 0) < 0) {
			return -1;
		}
		if (lseek(fd, 0, SEEK_SET) < 0) {
			return -1;
		}
		return write_full(fd, msg, msg_n) < 0 ? -1 : 0;
	case K_SOCKETPAIR:
	case K_PIPE_W:
		return write_full(fd, msg, msg_n) < 0 ? -1 : 0;
	case K_PIPE_R:
	default:
		return -1;
	}
}

static int stage_read(state_t *st, int idx, uint8_t *out, size_t out_n) {
	int fd = st->fds[idx];
	fd_kind_t kind = st->kinds[idx];

	switch (kind) {
	case K_MEMFD:
	case K_SHM:
		if (lseek(fd, 0, SEEK_SET) < 0) {
			return -1;
		}
		return read_full(fd, out, out_n) != (ssize_t)out_n ? -1 : 0;
	case K_SOCKETPAIR:
	case K_PIPE_R:
		return read_full(fd, out, out_n) != (ssize_t)out_n ? -1 : 0;
	case K_PIPE_W:
	default:
		return -1;
	}
}

static void print_fd_contents(int fd) {
	if (lseek(fd, 0, SEEK_SET) < 0) {
		puts("[-] cannot seek this fd");
		return;
	}
	uint8_t buf[256];
	for (;;) {
		ssize_t r = read(fd, buf, sizeof(buf));
		if (r < 0) {
			puts("[-] read error");
			return;
		}
		if (r == 0) {
			break;
		}
		(void)write_full(STDOUT_FILENO, buf, (size_t)r);
	}
}

int main(void) {
	alarm(90);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	state_t st;
	memset(&st, 0, sizeof(st));
	st.n = 0;

	st.flag_fd = open("/flag", O_RDONLY);
	if (st.flag_fd < 0) {
		die("open(/flag)");
	}

	printf("=== Fiddle ===\n");
	printf("This service creates lots of FDs (shm, socketpair, pipes, memfd).\n");
	printf("You will send a message through them by index.\n\n");

	child_sock_t child_socks[MAX_FDS];
	child_pipe_t child_pipes[MAX_FDS];
	int child_socks_n = 0;
	int child_pipes_n = 0;

	// Ensure at least one of each type exists.
	(void)mk_shm(&st);
	(void)mk_memfd(&st);
	(void)mk_socketpair(&st, child_socks, &child_socks_n);
	(void)mk_pipepair(&st, child_pipes, &child_pipes_n);

	// Add some random extras, but keep total < 50.
	int extras = (int)(urand32() % 20U); // 0..19
	for (int i = 0; i < extras; i++) {
		switch (urand32() % 4U) {
		case 0:
			(void)mk_shm(&st);
			break;
		case 1:
			(void)mk_memfd(&st);
			break;
		case 2:
			(void)mk_socketpair(&st, child_socks, &child_socks_n);
			break;
		case 3:
		default:
			(void)mk_pipepair(&st, child_pipes, &child_pipes_n);
			break;
		}
	}

	(void)make_encrypted_flag_memfd(&st);

	pid_t pid = fork();
	if (pid < 0) {
		die("fork");
	}

	if (pid == 0) {
		// Child: close parent's fds; keep only the child ends we recorded.
		close(st.flag_fd);
		for (int i = 0; i < st.n; i++) {
			close(st.fds[i]);
		}
		child_echo_loop(child_socks, child_socks_n, child_pipes, child_pipes_n);
		_exit(0);
	}

	// Parent: close child-only endpoints.
	for (int i = 0; i < child_socks_n; i++) {
		// Child uses socks[i].fd; parent keeps the other end already stored in st.
		// Close child end in parent.
		close(child_socks[i].fd);
	}
	for (int i = 0; i < child_pipes_n; i++) {
		close(child_pipes[i].in_r);
		close(child_pipes[i].out_w);
	}

	char msg_line[MAX_MSG + 4];
	printf("\nEnter a message (max %d bytes): ", MAX_MSG);
	if (!fgets(msg_line, sizeof(msg_line), stdin)) {
		puts("bye");
		return 0;
	}
	size_t msg_n = strcspn(msg_line, "\n");
	msg_line[msg_n] = '\0';
	if (msg_n == 0) {
		puts("empty message not allowed");
		return 0;
	}

	int k = 0;
	printf("How many indices? (>= 2): ");
	if (scanf("%d", &k) != 1) {
		puts("bad input");
		return 0;
	}
	if (k < 2 || k > 100) {
		puts("nope");
		return 0;
	}

	int *idxs = calloc((size_t)k, sizeof(int));
	if (!idxs) {
		puts("oom");
		return 0;
	}

	printf("Enter %d integers (the LAST one selects the output FD index):\n", k);
	for (int i = 0; i < k; i++) {
		if (scanf("%d", &idxs[i]) != 1) {
			puts("bad input");
			free(idxs);
			return 0;
		}
	}

	const uint8_t *msg = (const uint8_t *)msg_line;
	uint8_t tmp[MAX_MSG];
	int expect_write = 1;

	for (int i = 0; i < k - 1; i++) {
		int idx = idxs[i];
		if (idx < 0 || idx >= st.n) {
			puts("index out of range");
			free(idxs);
			return 0;
		}

		if (expect_write) {
			if (stage_write(&st, idx, msg, msg_n) < 0) {
				puts("write failed");
				free(idxs);
				return 0;
			}
		} else {
			memset(tmp, 0, sizeof(tmp));
			if (stage_read(&st, idx, tmp, msg_n) < 0) {
				puts("read failed");
				free(idxs);
				return 0;
			}
			if (memcmp(tmp, msg, msg_n) != 0) {
				puts("message mismatch");
				free(idxs);
				return 0;
			}
		}
		expect_write = !expect_write;
	}

	puts("\n[+] ok, here's your result:\n");

	// BUG: no bounds check on the final index. If it's -1, it becomes the fd just
	// before the array in memory (the /flag fd in this struct layout).
	int out_idx = idxs[k - 1];
	int out_fd = st.fds[out_idx]; // <-- vulnerability
	print_fd_contents(out_fd);
	puts("");

	free(idxs);
	(void)kill(pid, SIGKILL);
	(void)waitpid(pid, NULL, 0);
	return 0;
}

