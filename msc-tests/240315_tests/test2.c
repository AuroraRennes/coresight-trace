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
  int * tab = alea(2);
  
  if (tab[0]==0){
    if(tab[1]==0)
      printf("00\n");
    if(tab[1]==1)
      printf("01\n");
  }
      
  else if (tab[1]==1){
    if(tab[1]==0)
      printf("10\n");
    if(tab[1]==1)
      printf("11\n");
  }
    
  free(tab);
  return 0;
}
