/*
 * Fuzz harness for configuration file parsing.
 * Exercises parse_config() via a temporary file.
 */

#define THINPROXY_NO_MAIN
#include "../thinproxy.c"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char path[] = "/tmp/thinproxy-fuzz-XXXXXX";
	int fd;
	ssize_t w;

	if (size == 0 || size > 8192)
		return 0;

	fd = mkstemp(path);
	if (fd == -1)
		return 0;

	w = write(fd, data, size);
	close(fd);

	if (w == (ssize_t)size) {
		/* reset global state before each parse */
		acl_mode = ACL_NONE;
		nacl = 0;
		nconnect_ports = 0;
		cfg_maxconns = MAX_CONNS;
		cfg_timeout = 300;
		cfg_maxconns_per_ip = 0;
		cfg_deny_private = 0;
		vflag = 0;
		dflag = 0;
		(void)snprintf(cfg_addr, sizeof(cfg_addr), "%s",
		    DEFAULT_ADDR);
		(void)snprintf(cfg_port, sizeof(cfg_port), "%s",
		    DEFAULT_PORT);
		cfg_user[0] = '\0';

		parse_config(path, 1);
	}

	unlink(path);
	return 0;
}
