#include <stdio.h>
#include <syslog.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>

int main(int argc, char** argv) {

    openlog("writer", LOG_PID | LOG_CONS, LOG_USER);

    if(argc != 3) {
        syslog(LOG_ERR, "ERROR - please specify 2 arguments. 1: writefile, 2: writestr"); 
        closelog();
        return 1;
    }

    char* writefile = argv[1];
    char* writestr = argv[2];

    int fd = open(writefile, O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU | S_IRWXG | S_IROTH);
    if(fd == -1) {
        syslog(LOG_ERR, "ERROR - unable to open %s", writefile);
        closelog();
        return 1;
    }

    int write_status = write(fd, writestr, strlen(writestr));
    if(write_status == -1) {
        syslog(LOG_ERR, "ERROR - writing %s to %s failed", writestr, writefile);
        closelog();
        return 1;
    }

    int close_status = close(fd);
    if(close_status == -1) {
        syslog(LOG_ERR, "ERROR - unable to close %d", fd);
		closelog();
		return 1;
    }

    syslog(LOG_DEBUG, "Writing %s to %s", writestr, writefile);
    closelog();

    return 0;
}

