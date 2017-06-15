/*
 * Since complecity of ip search should be log(N), 
 * for keeping data binary tree has been chosen.
 * It saves ip addresses and number of packets came from
 * each ip
 */
#include <stdio.h>
#include <stdlib.h>

struct bin_tree
{
   int ip[4];
   int nPackets;
   struct bin_tree *ln,*rn;
};
typedef struct bin_tree node;
int btCompareIP(int ip1[], int ip2[]);
void btShow(node **tree, FILE* log);
void btDel(node *tree);
void btAddNode(int ip[], node **tree);
node* btSearch(int ip[], node *tree);

