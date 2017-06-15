/*
 * Implementation data structure for data keeping
 */


#include "binaryTree.h" 


/**
   @brief compare 4 numbers
   @param args takes 2 ip addresses
   @return -1 (ip1 < ip2), 0 (ip1 == ip2), 1 (ip1> ip2)
 */
int btCompareIP(int ip1[], int ip2[])
{
  int i;
  int res;
  for(i = 0; i < 4; i++)
  {
    if(*(ip1+i) > *(ip2+i))
    {
      res = 1;
      break;
    }
    else if(*(ip1+i) < *(ip2+i))
    {
      res = -1;
      break;
    }
    else 
    {
      res = 0;
    }
  }
  return res;
}

/**
   @brief prints tree
   @param args takes pointer to pointer to tree since tree address is changed in this function
   @return no return value
 */

void btShow(node **tree, FILE* log)
{
        if ((*tree)!=NULL)
        {
           btShow(&(*tree)->ln, log);
           printf("From ip %d.%d.%d.%d  %d packets has been received\n", (*tree)->ip[0], (*tree)->ip[1], (*tree)->ip[2], (*tree)->ip[3], (*tree)->nPackets);
           btShow(&(*tree)->rn, log);
        }
}
 
 /**
   @brief deletes tree
   @param args takes pointer to tree since tree address is not changed in this function
   @return no return value
 */
 
void btDel(node *tree){
   if ((tree)!=NULL)
        {
           btDel(tree->ln);
           btDel(tree->rn);
           free(tree);
           tree = NULL;
        }
 
}
 
 
  /**
   @brief adds node to tree
   @param args takes ip and pointer to pointer to tree since tree address is changed in this function
   @return no return value
 */
void btAddNode(int ip[], node **tree)
{ 
  int cntr;
  int flag;
  flag = 0;
//   if no tree --- put seed
        if (NULL==(*tree))
        {
                (*tree)=(node *)malloc(sizeof(node));
                for(cntr = 0; cntr < 4; cntr++)
                  (*tree)->ip[cntr]=ip[cntr];    
                (*tree)->ln=(*tree)->rn=NULL;
                flag = 1;
                (*tree)->nPackets = 1;
        }
//       if incoming ip less than head ip value --- go left  
        if (btCompareIP(ip, (*tree)->ip) == -1) 
        {
//           if child left node's address is not null --- call itself
          if ((*tree)->ln!=NULL)
            btAddNode(ip, &((*tree)->ln)); 
//            if child left node's address is null --- initialize left node with non-zero address and fill it
          else
          {
            (*tree)->ln=(node *)malloc(sizeof(node));
            (*tree)->ln->ln=(*tree)->ln->rn=NULL;
            for(cntr = 0; cntr < 4; cntr++)
              (*tree)->ln->ip[cntr]=ip[cntr];
            (*tree)->ln->nPackets = 1;
          }
        }
//           if child right node's address is not null --- call itself
        if (btCompareIP(ip, (*tree)->ip) == 1) 
        {
//       if incoming ip less than head ip value --- go left  
          if ((*tree)->rn!=NULL) 
            btAddNode(ip,&(*tree)->rn);
//            if child right node's address is null --- initialize right node with non-zero address and fill it
          else
          {
            (*tree)->rn=(node *)malloc(sizeof(node));
            (*tree)->rn->ln=(*tree)->rn->rn=NULL; 
            for(cntr = 0; cntr < 4; cntr++)
              (*tree)->rn->ip[cntr]=ip[cntr];
            (*tree)->rn->nPackets = 1;
          }
        }
//         case of repeating ips (several packets come from the same ip) --- increase number of packets
        if(btCompareIP(ip, (*tree)->ip) == 0 && flag == 0)
          ++((*tree)->nPackets);
}

  /**
   @brief searches given ip in the tree
   @param args takes ip and pointer to tree since tree address is not changed in this function
   @return no return value
 */
node* btSearch(int ip[], node *tree)
{
//   check whether tree address initialized or seed is already our ip
  if(tree == NULL || btCompareIP(ip, tree->ip) == 0)
    return tree;
//   if given ip more than seed ip move right
  if(btCompareIP(ip, tree->ip) == 1)
    return btSearch(ip, tree->rn);
  //   if given ip less than seed ip move left
  if(btCompareIP(ip, tree->ip) == -1)
    return btSearch(ip, tree->ln);
}