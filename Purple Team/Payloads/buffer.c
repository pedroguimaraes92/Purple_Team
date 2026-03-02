#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main (int argc, char *argv[]){

          char buffer1 [10] = {'S','P','E','E','D','S','T','A','R','\0'};
          char buffer2 [10] = {'S','P','E','E','D','S','T','E','R','\0'};

          strcpy(buffer2, argv[1]);
          system(buffer2);

          printf("\nSecondBuffer: %s\n", buffer2);
          printf("\nFirstBuffer: %s\n", buffer1);

          return 0;
}
