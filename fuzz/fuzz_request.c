/*
 * Fuzz harness for HTTP request parsing and rewriting.
 * Exercises parse_request() and build_request().
 */

#define THINPROXY_NO_MAIN
#include "../thinproxy.c"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char method[16], host[256], port[8], path[BUF_SIZE];
	uint8_t out[BUF_SIZE];
	char *req;
	int is_connect;

	if (size == 0 || size >= BUF_SIZE)
		return 0;

	req = malloc(size + 1);
	if (req == NULL)
		return 0;
	memcpy(req, data, size);
	req[size] = '\0';

	if (parse_request(req, size, method, sizeof(method),
	    host, sizeof(host), port, sizeof(port),
	    path, sizeof(path), &is_connect) == 0) {
		if (!is_connect) {
			build_request(req, size, out, sizeof(out),
			    method, path);
		}
	}

	free(req);
	return 0;
}
