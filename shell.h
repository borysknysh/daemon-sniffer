/*
 * Interface which can interact with daemon through log files and pid of daemonizing process.
 * 
 */
#include <sys/wait.h>
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<sys/socket.h>
#include<arpa/inet.h>
#include <ifaddrs.h>
#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h> //For standard things
#include<stdlib.h>    //malloc
#include<string.h>    //strlen
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/if_ether.h>  //For ETH_P_ALL
#include<net/ethernet.h>  //For ether_header
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>
#include "binaryTree.h"
/*
  Function Declarations for builtin shell commands:
 */
int lsh_cd(char **args);
int lsh_help(char **args);
int lsh_exit(char **args);
int lsh_start(char **args);
int lsh_stop(char **args);
int lsh_showCount(char **args);
int lsh_selectIface(char **args);
int lsh_num_builtins();
int lsh_launch(char **args);
int lsh_execute(char **args);
char *lsh_read_line(void);
char **lsh_split_line(char *line);
void lsh_loop(void);
void initCLI(void);