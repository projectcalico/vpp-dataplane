#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>
#include <vcl/vppcom.h>

int
main (int argc, char **argv)
{
  int rv;
  int fd;
  struct sockaddr_in server_addr;
  vppcom_endpt_t server_endpt;
  char buf[1024];

  printf("server ip = %s port = %s\n\n", argv[1], argv[2]);

  /* initialize server socket address */
  memset (&server_addr, 0, sizeof (server_addr));
  server_addr.sin_family = AF_INET;
  inet_pton (AF_INET, argv[1], &server_addr.sin_addr);
  //server_addr.sin_port = htons (atoi (argv[2]));
  server_addr.sin_port = atoi (argv[2]);

  /* initialize the VCL server endpoint data structure with the server address details */
  memset (&server_endpt, 0, sizeof (server_endpt));
  server_endpt.is_ip4 = 1;
  server_endpt.ip = (uint8_t *) & server_addr.sin_addr;
  server_endpt.port = (uint16_t) server_addr.sin_port;

  printf ("Creating VCL app...\n");
  /* this will show up as "simple_client" in vpp with "sh app" */
  rv = vppcom_app_create ("simple_client");
  if (rv < 0) {
    printf ("vppcom_app_create() failed: %d", rv);
    exit(1);
  }

  printf("Creating VCL session...\n");
  if ( (fd = vppcom_session_create (VPPCOM_PROTO_TCP, 0 /* is_blocking */)) < 0 ) {
    printf("vppcom_session_create() ctrl session: %d", fd);
    exit(1);
  }

  printf("Connecting to server...\n");
  rv = vppcom_session_connect (fd, &server_endpt);
  if (rv < 0 ) {
    printf("vppcom_session_connect() failed: %d\n", rv);
    exit(1);
  }

  /* send some data to server */
  char *s = "Hello there!";
  printf("Sending data to server: %s\n\n", s);
  rv = vppcom_session_write (fd, s, strlen(s));
  if ( rv < 0 ) {
    printf("write failed: %d\n", rv);
    exit(1);
  }

  /* read server's reply */
  memset (buf, 0, sizeof(buf));
  rv = vppcom_session_read (fd, buf, sizeof(buf));
  if ( rv < 0 ) {
    printf("read failed: %d\n", rv);
    exit(1);
  }
  printf("Server replied with: %s\n", buf);

  /* cleanup */
  vppcom_app_destroy ();
  return 0;
}