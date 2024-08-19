#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

int server_socket_fd = -1;
int client_socket_fd = -1;
int run_as_daemon = 0;

int receive_data(int client_socket_fd);
void signal_handler(int sig);
void cleanup();

int main(int argc, char** argv) {

	openlog("socket", LOG_PID | LOG_CONS, LOG_USER);
	syslog(LOG_INFO, "server program start");

	if(argc == 2 && (strcmp(argv[1],"-d") == 0)) {
		syslog(LOG_INFO, "running as daemon");
		run_as_daemon = 1;
	}

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	server_socket_fd = socket(PF_INET, SOCK_STREAM, 0);
	if(server_socket_fd == -1) {
		syslog(LOG_ERR, "ERROR - socket created failed");
		closelog();
		return -1;
	}

	struct sockaddr_in server_sockaddrin;
	memset(&server_sockaddrin, 0, sizeof(server_sockaddrin));
	server_sockaddrin.sin_family = PF_INET;
	server_sockaddrin.sin_addr.s_addr = INADDR_ANY;
	server_sockaddrin.sin_port = htons(9000);

	int ret = bind(server_socket_fd, (struct sockaddr*)&server_sockaddrin, sizeof(server_sockaddrin));
	if(ret == -1) {
		syslog(LOG_ERR, "ERROR - bind failed");
		cleanup();
		return -1;
	}

	// Referenced Linux System Programming page 174
	if(run_as_daemon) {
		pid_t pid = fork();
		if(pid == -1) {
			return -1;
		}
		else if(pid != 0) {
			exit(0);
		}

		if(setsid() == -1) {
			return -1;
		}

		if(chdir("/") == -1) {
			return -1;
		}

		open("/dev/null", O_RDWR);
		dup(0);
		dup(0);
	}

	ret = listen(server_socket_fd, 3);
	if(ret == -1) {
		syslog(LOG_ERR, "ERROR - listen failed");
		cleanup();
		return -1;
	}

	struct sockaddr_in client_sockaddrin;
	socklen_t client_addr_len = sizeof(client_sockaddrin);

	while(1) {
		client_socket_fd = accept(server_socket_fd, (struct sockaddr*)&client_sockaddrin, &client_addr_len);
		if(client_socket_fd == -1) {
			syslog(LOG_ERR, "ERROR - accept failed");
			cleanup();
			return -1;
		}

		char client_ip_addr[INET_ADDRSTRLEN];
		inet_ntop(PF_INET, &client_sockaddrin.sin_addr, client_ip_addr, INET_ADDRSTRLEN);
		syslog(LOG_INFO, "Accepted connection from %s", client_ip_addr);

		receive_data(client_socket_fd);

		syslog(LOG_INFO, "Closed connection from %s", client_ip_addr);
	}

	cleanup();
	return 0;
}

int receive_data(int client_socket_fd) {
	int file_fd = open("/var/tmp/aesdsocketdata", O_WRONLY | O_APPEND | O_CREAT, S_IRWXU | S_IRWXG | S_IROTH);
	if(file_fd == -1) {
		syslog(LOG_ERR, "ERROR - creating /var/tmp/aesdsocketdata failed");
		cleanup();
		return -1;
	}

	char receive_buffer[512];
	memset(receive_buffer, 0, sizeof(receive_buffer));
	ssize_t bytes_received;

	while ((bytes_received = recv(client_socket_fd, receive_buffer, sizeof(receive_buffer) - 1, 0)) > 0) {
		char* newline_char = strchr(receive_buffer, '\n');
		if(newline_char == NULL) {
			// No new line character
			int write_status = write(file_fd, receive_buffer, bytes_received);
			if(write_status == -1) {
				syslog(LOG_ERR, "ERROR - writing w/o newline to /var/tmp/aesdsocketdata failed");
				close(file_fd);
				cleanup();
				return -1;
			}
		}
		else {
			*newline_char = '\0';
			int write_status = write(file_fd, receive_buffer, newline_char - receive_buffer);
			if(write_status == -1) {
				syslog(LOG_ERR, "ERROR - writing w/ newline to /var/tmp/aesdsocketdata failed");
				close(file_fd);
				cleanup();
				return -1;
			}
			write(file_fd, "\n", 1);
			close(file_fd);

			file_fd = open("/var/tmp/aesdsocketdata", O_RDONLY, S_IRWXU | S_IRWXG | S_IROTH);
			if(file_fd == -1) {
				syslog(LOG_ERR, "ERROR - open for read /var/tmp/aesdsocketdata failed");
				close(client_socket_fd);
				cleanup();
				return -1;
			}

			char read_buffer[512];
			ssize_t bytes_read;
			while((bytes_read = read(file_fd, read_buffer, sizeof(read_buffer))) > 0) {
				int send_status = send(client_socket_fd, read_buffer, bytes_read, 0);
				if(send_status == -1) {
					syslog(LOG_ERR, "ERROR - sending file content failed");
					cleanup();
					return -1;
				}
			}
		}
	}
	close(file_fd);
	close(client_socket_fd);

	return 0;
}

void signal_handler(int sig) {
	if(sig == SIGINT || sig == SIGTERM) {
		syslog(LOG_INFO, "Caught signal, exiting");

		if(server_socket_fd != -1) {
			shutdown(server_socket_fd, SHUT_RDWR);
		}
		cleanup();

		exit(0);
	}
}

void cleanup() {
	int remove_status = remove("/var/tmp/aesdsocketdata");
	if(remove_status) {
		syslog(LOG_ERR, "ERROR - failed to remove file at cleanup");
	}

	if(server_socket_fd != -1) {
		close(server_socket_fd);
		server_socket_fd = -1;
	}

	if(client_socket_fd != -1) {
		close(client_socket_fd);
		client_socket_fd = -1;
	}

	closelog();
}

