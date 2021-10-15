#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <vcl/vppcom.h>

int
main (int argc, char **argv)
{
  int rv, i;
  int ctrl_fd, client_fd;
  struct sockaddr_in server_addr, client_addr;
  vppcom_endpt_t endpt, client_endpt;
  char buf[1024];

  /* initialize the server socket address */
  memset (&server_addr, 0, sizeof (server_addr));
  server_addr.sin_family = AF_INET;
  inet_pton (AF_INET, argv[1], &server_addr.sin_addr);
  server_addr.sin_port = atoi(argv[2]);

  /* initialize the VCL server endpoint data structure with the server address details */
  memset (&endpt, 0, sizeof (endpt));
  endpt.is_ip4 = 1;
  endpt.ip = (uint8_t *) &server_addr.sin_addr;
  endpt.port = (uint16_t) server_addr.sin_port;

  printf ("Server IP = %s Port = %d\n", inet_ntoa(server_addr.sin_addr), server_addr.sin_port);

  printf ("Creating VCL app....\n");
  /* this will show up as "simple_server" in vpp with "sh app" */
  rv = vppcom_app_create ("simple_server");
  if (rv) {
    printf ("vppcom_app_create() failed:%d", rv);
    exit(1);
  }

  printf ("Creating VCL session...\n");
  ctrl_fd = vppcom_session_create (VPPCOM_PROTO_TCP, 0 /* is_blocking */);
  if (ctrl_fd < 0) {
    printf ("vppcom_session_create() failed:%d\n", ctrl_fd);
    exit(1);
  }

  printf ("Bind...\n");
  rv = vppcom_session_bind (ctrl_fd, &endpt);
  if (rv < 0) {
    printf ("vppcom_session_bind() failed:%d\n", rv);
    exit(1);
  }

  printf ("Listen...\n");
  rv = vppcom_session_listen (ctrl_fd, 10);
  if (rv < 0) {
    printf ("vppcom_session_listen() failed:%d\n", rv);
    exit(1);
  }

  printf ("Waiting for client connection...\n");
  client_fd = vppcom_session_accept (ctrl_fd, &client_endpt, 0);
  if (client_fd < 0) {
    printf ("vppcom_session_accept() failed:%d\n", client_fd);
    exit(1);
  }

  printf ("Got a client connection!!!!\n\n");

  memset (buf, 0, sizeof(buf));
  rv = vppcom_session_read (client_fd, buf, sizeof(buf));
  if (rv < 0) {
    printf ("vppcom_session_read() failed:%d\n", rv);
    exit(1);
  }
  printf ("Received from client: %s\n", buf);

  printf ("Echoing it back to client...\n\n");
  rv = vppcom_session_write (client_fd, buf, strlen(buf));

  printf ("Cleaning up app...\n");
  vppcom_app_destroy ();
  printf ("DONE!\n");

  return 0;
}