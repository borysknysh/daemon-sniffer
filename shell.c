
#include "shell.h"
/*
  Function Declarations for builtin shell commands:
 */
int status;
int lines, globalNLines;
node* tree;
char ch;
char buffer[20];
int ip[4];
char iface[20];
char ifaces[20][20];
int nInterfaces;
/*
  List of builtin commands, followed by their corresponding functions.
 */
char *builtin_str[] = {
  "cd",
  "help",
  "exit",
  "start",
  "stop",
  "showcnt",
  "selIface"
};

char *descriptionOfBuiltIn[] = {
  "change directory",
  "inforation about available files and commands",
  "move out of the program",
  "make service to collect information about ip addresses and packets",
  "stop collecting data from the incoming packets",
  "display number of packets come from all ip addresses if certain ip is not specified",
  "choose interface which interact with packets"
};

int (*builtin_func[]) (char **) = {
  &lsh_cd,
  &lsh_help,
  &lsh_exit,
  &lsh_start,
  &lsh_stop,
  &lsh_showCount,
  &lsh_selectIface
};

/**
   @brief Initializes cli: prints welcome screen, gives command to compile daemon, 
   reads all available interfaces
   @param args no arguments
   @return no return value
 */
void initCLI()
{
  int i;
  printf("*******************************************\n");
  printf("*                                         *\n");
  printf("*       WELCOME to DAEMON-SNIFFER         *\n");
  printf("*                                         *\n");
  printf("*    Version  1.0           15 June 2017  *\n");
  printf("*                                         *\n");
  printf("*  You are welcome to contact developer   *\n");
  printf("*          borys.knysh@gmail.com          *\n");
  printf("*                                         *\n");
  printf("*                                         *\n");
  printf("*******************************************\n");
  printf("Use [help] for more details\n");
  system("gcc -o daemon daemon.c sniffer.c");
  globalNLines = 0;
  tree = NULL;
  struct ifaddrs *addrs,*tmp;

    getifaddrs(&addrs);
    tmp = addrs;

    i = 0;
    while (tmp)
    {
      if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET)
      {
        strncpy(ifaces[i], tmp->ifa_name, sizeof ifaces[i]);
        i++;
      }
      tmp = tmp->ifa_next;
    }
    nInterfaces = i;
    freeifaddrs(addrs);
}

int lsh_num_builtins() {
  return sizeof(builtin_str) / sizeof(char *);
}

/*
  Builtin function implementations.
*/

/**
   @brief Bultin command: change directory.
   @param args List of args.  args[0] is "cd".  args[1] is the directory.
   @return Always returns 1, to continue executing.
 */
int lsh_cd(char **args)
{
  if (args[1] == NULL) {
    fprintf(stderr, "lsh: expected argument to \"cd\"\n");
  } else {
    if (chdir(args[1]) != 0) {
      perror("lsh");
    }
  }
  return 1;
}

/**
   @brief Builtin command: print help.
   @param args List of args.  Not examined.
   @return Always returns 1, to continue executing.
 */
int lsh_help(char **args)
{
  int i;
  printf("Type program names and arguments, and hit enter.\n");
  printf("The following are built in:\n");

  for (i = 0; i < lsh_num_builtins(); i++) {
    printf("  %s --- %s\n", builtin_str[i], descriptionOfBuiltIn[i]);
  }
  printf("Use the man command for information on other programs.\n");
  printf("Following interfaces are available:\n");
  for(i = 0; i < nInterfaces; i++)
    printf("  %s\n", ifaces[i]);
  printf("Following files are used:\n");
  printf("-IPlog.txt --- here list of ip addresses is writen by deamon\n");
  printf("-log.txt --- here whole information about each packet is written by daemon\n");
  return 1;
}

/**
   @brief Builtin command: exit.
   @param args List of args.  Not examined.
   @return Always returns 0, to terminate execution.
 */
int lsh_exit(char **args)
{
  system("rm *.txt 2> /dev/null ");
  return 0;
}


int lsh_start(char **args)
{
  char* exec = "./daemon ";
  char *result = malloc(strlen(exec)+strlen(iface)+1);
  strcpy(result, exec);
  strcat(result, iface);
  printf("Starting daemon...\n");
  printf("For monitoring process use top or htop\n");
  printf("%s\n", result);
  system(result);
  return 2;
  free(exec);
  free(result);
}

int lsh_stop(char **args)
{
  printf("Stoppping daemon...\n");
  status = 1;
  system("kill `pidof ./daemon` 2> /dev/null");
  return 1;
}

/**
  @brief Shows number of packets incoming from all ip addresses. If pid is specified prints number packets received from given ip. 
  @param args takes pid as second element
  @return Always returns 1, to continue execution.
 */

int lsh_showCount(char **args)
{
  int nPacks;
  lines = 0;
  FILE* fp = fopen("IPlog.txt", "r");
  if(!fp)
  {
    printf("Unable to read file of IP addresses.\n");
    return 1;
  }
  while (fgets(buffer, sizeof(buffer), fp)) 
  {
        /* note that fgets don't strip the terminating \n, checking its
           presence would allow to handle lines longer that sizeof(line) */
    lines++;
    if(lines > globalNLines && sscanf(buffer, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3]) == 4)
      btAddNode(ip, &tree);
  }
  globalNLines = lines;
  if(args[1] == NULL)
  {
    printf("________________________Tree displaying:______________________\n");
    btShow(&tree, fp);
    return 1;
  }
  nPacks = sscanf(args[1], "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3]);
  if(nPacks != 4)
  {
    printf("Wrong format of ip address (MUST BE n.n.n.n)\n");
    return 1;
  }
  if(btSearch(ip,tree) == NULL)
  {
    printf("Given IP %d.%d.%d.%d doesn't exists in binary search tree\n", ip[0], ip[1], ip[2], ip[3]);
    return 1;
  }
  printf("Number of packets received from %s is %d\n",args[1], btSearch(ip,tree)->nPackets);
  fclose(fp);
  return 1;
}

/**
  @brief Select interface which phones packets (eth, wlan, etc.)
  @param args takes as second element (args[1]) name of interface.
  @return Always returns 1, to continue execution.
 */
int lsh_selectIface(char** args)
{
  int i;
  for(i = 0; i < nInterfaces; i++)
  {
    if(args[1] == NULL || strcmp(args[1],ifaces[i])!=0)
      strncpy(iface, "",sizeof iface);
    else
    {
      strncpy(iface, args[1],sizeof iface);
      break;
    }
  }
  return 1;
}
/**
  @brief Launch a program and wait for it to terminate.
  @param args Null terminated list of arguments (including program).
  @return Always returns 1, to continue execution.
 */
int lsh_launch(char **args)
{
  pid_t pid, wpid;
  int status;

  pid = fork();
  if (pid == 0) {
    // Child process
    if (execvp(args[0], args) == -1) {
      perror("lsh");
    }
    exit(EXIT_FAILURE);
  } else if (pid < 0) {
    // Error forking
    perror("lsh");
  } else {
    // Parent process
    do {
      wpid = waitpid(pid, &status, WUNTRACED);
    } while (!WIFEXITED(status) && !WIFSIGNALED(status));
  }
  return 1;
}

/**
   @brief Execute shell built-in or launch program.
   @param args Null terminated list of arguments.
   @return 1 if the shell should continue running, 0 if it should terminate
 */
int lsh_execute(char **args)
{
  int i;

  if (args[0] == NULL) {
    // An empty command was entered.
    return 1;
  }

  for (i = 0; i < lsh_num_builtins(); i++) {
    if (strcmp(args[0], builtin_str[i]) == 0) {
      return (*builtin_func[i])(args);
    }
  }
  return lsh_launch(args);
}

#define LSH_RL_BUFSIZE 1024
/**
   @brief Read a line of input from stdin.
   @return The line from stdin.
 */
char *lsh_read_line(void)
{
  int bufsize = LSH_RL_BUFSIZE;
  int position = 0;
  char *buffer = malloc(sizeof(char) * bufsize);
  int c;

  if (!buffer) {
    fprintf(stderr, "lsh: allocation error\n");
    exit(EXIT_FAILURE);
  }

  while (1) {
    // Read a character
    c = getchar();

    // If we hit EOF, replace it with a null character and return.
    if (c == EOF || c == '\n') {
      buffer[position] = '\0';
      return buffer;
    } else {
      buffer[position] = c;
    }
    position++;

    // If we have exceeded the buffer, reallocate.
    if (position >= bufsize) {
      bufsize += LSH_RL_BUFSIZE;
      buffer = realloc(buffer, bufsize);
      if (!buffer) {
        fprintf(stderr, "lsh: allocation error\n");
        exit(EXIT_FAILURE);
      }
    }
  }
}

#define LSH_TOK_BUFSIZE 64
#define LSH_TOK_DELIM " \t\r\n\a"
/**
   @brief Split a line into tokens.
   @param line The line.
   @return Null-terminated array of tokens.
 */
char **lsh_split_line(char *line)
{
  int bufsize = LSH_TOK_BUFSIZE, position = 0;
  char **tokens = malloc(bufsize * sizeof(char*));
  char *token;

  if (!tokens) {
    fprintf(stderr, "lsh: allocation error\n");
    exit(EXIT_FAILURE);
  }

  token = strtok(line, LSH_TOK_DELIM);
  while (token != NULL) {
    tokens[position] = token;
    position++;

    if (position >= bufsize) {
      bufsize += LSH_TOK_BUFSIZE;
      tokens = realloc(tokens, bufsize * sizeof(char*));
      if (!tokens) {
        fprintf(stderr, "lsh: allocation error\n");
        exit(EXIT_FAILURE);
      }
    }

    token = strtok(NULL, LSH_TOK_DELIM);
  }
  tokens[position] = NULL;
  return tokens;
}

/**
   @brief Loop getting input and executing it.
 */
void lsh_loop(void)
{
  char *line;
  char **args;
  int status;
    
  do {
    printf(">>> ");
    line = lsh_read_line();
    args = lsh_split_line(line);
    status = lsh_execute(args);    
    free(line);
    free(args);
  } while (status);
}
