/*
 * Daemon itself --- child process executed in background mode
 */

#include "sniffer.h"

int main(int argc, char **argv)
{
    FILE* logfileIP=openLogIP("IPlog.txt");
    FILE* logfile=openGlobalLog("log.txt");
    if(logfile==NULL) 
    {
        printf("Unable to create log.txt file.");
    }
//     Part of daemonizing program...
    fprintf(logfile,"Starting...\n");
    pid_t pid, sid; 
    pid = fork();

    if (pid < 0) {
      fprintf(logfile,"pid < 0");
      exit(EXIT_FAILURE);
      
    }

    //We got a good pid, Close the Parent Process
    if (pid > 0) { exit(EXIT_SUCCESS); }

    //Change File Mask
    umask(0);

    //Create a new Signature Id for our child
    sid = setsid();
    if (sid < 0) {
      fprintf(logfile,"pid < 0");
      exit(EXIT_FAILURE);
      
    }

    //Change Directory
    //If we cant find the directory we exit with failure.
    if ((chdir("/")) < 0) {
      fprintf(logfile,"can't change");
      exit(EXIT_FAILURE); 
      
    }

    //Close Standard File Descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    int saddr_size , data_size;
    struct sockaddr saddr;
         
    unsigned char *buffer = (unsigned char *) malloc(65536); //Its Big!
    
//   Sniff incoming ip , which includes all kinds of IP packets.
    int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_IP)) ;
    
    if(argc > 1)
      setsockopt(sock_raw , SOL_SOCKET , SO_BINDTODEVICE , argv[1] , strlen(argv[1])+ 1 );
     
    if(sock_raw < 0)
    {
        //Print the error with proper message
        perror("Socket Error");
        return 1;
    }
    
 struct ifaddrs *addrs,*tmp;

    getifaddrs(&addrs);
    tmp = addrs;

    while (tmp)
    {
      if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET)
        fprintf(logfile,"%s\n", tmp->ifa_name);
  
      tmp = tmp->ifa_next;
    }

    freeifaddrs(addrs);
    while(1)
    {
        saddr_size = sizeof saddr;
        //Receive a packet
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
        if(data_size <0 )
        {
            fprintf(logfile,"Recvfrom error , failed to get packets\n");
            return 1;
        }
        //Now process the packet
        ProcessPacket(buffer , data_size);
    }
    close(sock_raw);
    fprintf(logfile,"Finished");
    fclose(logfile);
    fclose(logfileIP);
    
  return 0;
}