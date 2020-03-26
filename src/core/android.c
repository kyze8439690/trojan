#include <sys/un.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ancillary.h>
#include <android/log.h>

int
    protect_socket(int fd)
{
    int sock;
    struct sockaddr_un addr;

    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        __android_log_print(ANDROID_LOG_ERROR, "trojan",
                "[android] socket() failed: %s (socket fd = %d)\n", strerror(errno), sock);
        return -1;
    }

    // Set timeout to 1s
    struct timeval tv;
    tv.tv_sec  = 1;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(struct timeval));

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "protect_path", sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        __android_log_print(ANDROID_LOG_ERROR, "trojan",
                "[android] connect() failed for protect_path: %s (socket fd = %d)\n",
                            strerror(errno), sock);
        close(sock);
        return -1;
    }

    if (ancil_send_fd(sock, fd)) {
        __android_log_print(ANDROID_LOG_ERROR, "trojan", "[android] ancil_send_fd: %s", strerror(errno));
        close(sock);
        return -1;
    }

    char ret = 0;

    if (recv(sock, &ret, 1, 0) == -1) {
        __android_log_print(ANDROID_LOG_ERROR, "trojan", "[android] recv: %s", strerror(errno));
        close(sock);
        return -1;
    }

    close(sock);
    return ret;
}