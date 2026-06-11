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
		/* parse_config() calls config_reset() first, so no manual
		 * global reset is needed between iterations */
		parse_config(path, 1);
	}

	unlink(path);
	return 0;
}
