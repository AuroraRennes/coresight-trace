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
  int * tab = alea(1);
  
  if (tab[0]==0)
    printf("0\n");
  else if (tab[0]==1)
    printf("1\n");
    
  free(tab);
  return 0;
}
