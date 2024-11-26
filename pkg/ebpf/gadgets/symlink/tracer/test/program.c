#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>

int main() {
    if (symlink("/tmp/juju-mk05084ff7d3c97400202c9eef1baad3487c773a", "/tmp/passwd_link") == -1) {
        perror("symlink");
    }

    if (symlinkat("/tmp/juju-mk05084ff7d3c97400202c9eef1baad3487c773a", AT_FDCWD, "/tmp/passwd_link2") == -1) {
        perror("symlinkat");
    }
    return 0;
}
