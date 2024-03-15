#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int * alea(int n){
  time_t t;
  srand((unsigned) time(&t));
  int * tab = malloc(n*sizeof(int));
  while(n){
    n--;
    tab[n]=rand()%2;}
  return tab;
}

int main(){
  int * tab = alea(3);
  
  if (tab[0]==0){
    if(tab[1]==0){
      if(tab[2]==0)
        printf("000\n");
      if(tab[2]==1)
        printf("001\n");
      }
    if(tab[1]==1){
      if(tab[2]==0)
        printf("010\n");
      if(tab[2]==1)
        printf("011\n");
      }
  }
      
  else if (tab[0]==1){
    if(tab[1]==0){
      if(tab[2]==0)
        printf("100\n");
      if(tab[2]==1)
        printf("101\n");
      }
    if(tab[1]==1){
      if(tab[2]==0)
        printf("110\n");
      if(tab[2]==1)
        printf("111\n");
      }
  }
    
  free(tab);
  return 0;
}
