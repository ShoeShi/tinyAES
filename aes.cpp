//************************************
//  Author: Johnny Xie
//  Class: Introduction to Cryptography
//  Assignment 3
//  11.15.15
//
//  Please see the README for details.
//  
//************************************

#include <stdio.h>
#include <stdlib.h>
#include "helper.h"

static unsigned char plaintextBuffer[4][4];
static unsigned char keyBuffer[4][4];
static unsigned char sboxBuffer[16][16];
static unsigned char sboxInvBuffer[16][16];

//depending on what endian, I will store the buffers of files differently.
static _Array state[NB];//4 rows
static _Array words[NB*(NR + 1)]; //44 rows


/**************************************************
 * Methods
**************************************************/

void printStateMatrix(){
   int i, j;
   //Plaintext and key
   if (!LITTLEENDIAN){
      printf("\n");
      for (i = 0; i < NB; i++){
         for (j = 0; j < NB; j++)
            printf("%02x ", state[j].c[i]);
         printf("  ");
      }
   }
   else {
      printf("\n");
      for (i = NB-1; i >= 0; i--){
         for (j = 0; j < NB; j++)
            printf("%02x ", state[j].c[i]);
         printf("  ");
      }
   }
}

unsigned char xtime(unsigned char a, unsigned char coeff){
   unsigned char base = (coeff & 0x01) * a;

   while (coeff >>= 1)
   {
      a = (a<<1) ^ (((a>>7) & 1) * 0x1b);
      /*unsigned char carry = 0x80 & base;*/
      //base = (base << 1) & 0xFF;
      //if (carry)
      //base ^= 0x1b;

      //if (coeff & 0x01)
      /*a ^= base;*/

      if (coeff & 0x01)
         base ^= a;
   }
   return base;
}


/**************************************************
 * Encryption methods
**************************************************/

void subBytes(){
   int i, j;
   for (i = 0; i < NB; i++){
      for (j = 0; j < NB; j++){
         unsigned char _x = (state[i].c[j] & 0xF0) >> 4;
         unsigned char _y = state[i].c[j] & 0x0F;
         state[i].c[j] = sboxBuffer[_x][_y];
      }
   }

}

void shiftRowsI(_Array *a, int i){
   unsigned int temp = a->entireRow >> (32 - i * 8);
   a->entireRow <<= i*8;
   a->entireRow |= temp;
}

void shiftRows(){
   int i;
   for (i = 0; i < NB; i++)
      shiftRowsI(&state[i], i);
}

void mixColumns(){
   _Array mixCoeff;
   if (!LITTLEENDIAN)
      mixCoeff.entireRow = 0x01010302; //Row 1 Matrix 5.6, fips-197 AES-Standard.
   else
      mixCoeff.entireRow = 0x02030101;

   int i, j;
   unsigned int buffer;

   //d4->04
   //state[0].c[3] = xtime(state[0].c[3], 0x02) ^
   //	xtime(state[1].c[3], 0x03) ^
   //	xtime(state[2].c[3], 0x01) ^
   //	xtime(state[3].c[3], 0x01);

   unsigned char newState[4];
   for (i = NB-1; i >= 0; i--){
      for (j = 0; j < NB; j++){
         newState[j] = xtime(state[0].c[i], mixCoeff.c[3]) ^ xtime(state[1].c[i], mixCoeff.c[2]) ^
            xtime(state[2].c[i], mixCoeff.c[1]) ^ xtime(state[3].c[i], mixCoeff.c[0]);

         //rotate
         buffer = mixCoeff.entireRow << 24;
         mixCoeff.entireRow >>= 8;
         mixCoeff.entireRow |= buffer;
      }
      //copy to state
      int k;
      for (k = 0; k < NB; k++){
         state[k].c[i] = newState[k];
      }
   }
}

void addRoundKey(int round){
   int i, j;
   for (i = 0; i < NB; i++){
      for (j = NB - 1; j >= 0; j--){ 
         state[i].c[j] ^= words[(NB - 1 - j) + (round * 4)].c[(NB - 1 - i)];
      }
   }
}

void encrypt(){
   //State, Roundkey(var words) are static global to the file

   int round = 0;
   addRoundKey(round); // See Sec. 5.1.4
   for (round = 1; round < NR; round++){
      printf("\nRound %d", round);
      printStateMatrix();
      printf("\n");
      subBytes(); // See Sec. 5.1.1
      shiftRows(); // See Sec. 5.1.2
      mixColumns(); // See Sec. 5.1.3
      addRoundKey(round);
   }
   printf("\nRound %d", round);
   printStateMatrix();
   printf("\n");

   subBytes();
   shiftRows();
   addRoundKey(round);

   printf("\nRound %d", round+1);
   printStateMatrix();
   printf("\n");
}

/**************************************************
 * Decryption Methods
**************************************************/
void invSubBytes(){
   int i, j;
   for (i = 0; i < NB; i++){
      for (j = 0; j < NB; j++){
         unsigned char _x = (state[i].c[j] & 0xF0) >> 4;
         unsigned char _y = state[i].c[j] & 0x0F;
         state[i].c[j] = sboxInvBuffer[_x][_y];
      }
   }
}

void invShiftRowsI(_Array *a, int i){
   unsigned int temp = a->entireRow >> i * 8;
   a->entireRow <<= (32 - i * 8);
   a->entireRow |= temp;
}

void invShiftRows(){
   int i;
   for (i = 0; i < NB; i++)
      invShiftRowsI(&state[i], i);
}

void invMixColumns(){
   _Array mixCoeff;
   if (!LITTLEENDIAN)
      mixCoeff.entireRow = 0x090d0b0e; //Row 1 Matrix 5.6, fips-197 AES-Standard.
   else
      mixCoeff.entireRow = 0x0e0b0d09;

   int i, j;
   unsigned int buffer;

   /*   // 47 -> 87*/
   //state[0].c[3] = xtime(state[0].c[3], 0x0e) ^
   //xtime(state[1].c[3], 0x0b) ^
   //xtime(state[2].c[3], 0x0d) ^
   /*xtime(state[3].c[3], 0x09);*/

   unsigned char newState[4];
   for (i = NB - 1; i >= 0; i--){
      for (j = 0; j < NB; j++){
         newState[j] = xtime(state[0].c[i], mixCoeff.c[3]) ^
            xtime(state[1].c[i], mixCoeff.c[2]) ^
            xtime(state[2].c[i], mixCoeff.c[1]) ^
            xtime(state[3].c[i], mixCoeff.c[0]);

         //rotate
         buffer = mixCoeff.entireRow << 24;
         mixCoeff.entireRow >>= 8;
         mixCoeff.entireRow |= buffer;
      }

      //copy to state
      int k;
      for (k = 0; k < NB; k++){
         state[k].c[i] = newState[k];
      }
   }
}

void decrypt(){

   int round = NR;
   printf("\nEncrypted message:");
   printStateMatrix();
   printf("\n");

   addRoundKey(NR); // See Sec. 5.1.4
   for (round = NR - 1; round > 0; round--){
      invShiftRows(); // See Sec. 5.3.1
      invSubBytes(); // See Sec. 5.3.2
      printf("\nRound %d", round);
      printStateMatrix();
      printf("\n");
      addRoundKey(round);
      invMixColumns(); // See Sec. 5.3.3
   }
   invShiftRows();
   invSubBytes();
   printf("\nRound %d", round);
   printStateMatrix();
   printf("\n");
   addRoundKey(round);

   printf("\nDecrypted cipher: ");
   printStateMatrix();
   printf("\n");
}

/**************************************************
 * Key Expansion methods
**************************************************/

unsigned int rcon(int i){
   unsigned int x = 0x01000000 << (i - 1);
   if (x == 0)
      x = 0x1b000000 << (i - 1) % 8;
   return x;
}

_Array rotWord(_Array a){
   unsigned int temp = 0xFF000000 & a.entireRow;
   a.entireRow <<= 8;
   a.entireRow |= (temp >> 24);

   return a ;
}

_Array subWord(_Array temp){
   int i;
   for (i = 0; i < NB; i++){
      unsigned char _x = (temp.c[i] & 0xF0) >> 4;
      unsigned char _y = temp.c[i] & 0x0F;
      temp.c[i] = sboxBuffer[_x][_y];
   }
   return temp;
}

void keyExpansion(){
   _Array temp;

   int i, j;
   //columnwise parse
   for (i = 0; i < NK; i++)
      for (j = 0; j < NK; j++)
         words[i].c[j] = keyBuffer[j][i];

   for (i = NK; i < NB * (NR + 1); i++){

      temp.entireRow = words[i - 1].entireRow;
      if (i%NK == 0){
         temp = rotWord(temp);
         temp = subWord(temp);
         temp.entireRow ^= rcon(i / NK);
      }
      //else if (NK > 6 && i%NK == 4) not required for 128 bit keys
      //temp.entireRow = subWord(temp.entireRow);

      words[i].entireRow = words[i - NK].entireRow ^ temp.entireRow;
      //printf("\n%d ", i);
      //printf("%08x", words[i].entireRow);
   }
}

//====================Main====================
int main(){

   loadFiles(plaintextBuffer, keyBuffer, sboxBuffer, sboxInvBuffer, &state[0]);
   printf("\nLITTLE ENDIAN? %d", LITTLEENDIAN);

   keyExpansion();
   printBeginning(&state[0], &words[0]);
   //printSBox(sboxBuffer, sboxInvBuffer);

   printf("\n\nAES Encryption 128-bit");
   printf("\n-----------------------");
   encrypt();

   printf("\n\nAES Decryption 128-bit");
   printf("\n-----------------------");
   decrypt();

   printf("\n\nEnd of program.");

   /*printf("\n\nTest 57 x 83 = %02x", xtime(0x57, 0x83));
     printf("\n %02x %02x %02x %02x", xtime(0x57, 0x02), xtime(0x57, 0x04), xtime(0x57, 0x08), xtime(0x57, 0x10));
     printf("\n %02x %02x %02x %02x", xtime(0x57, 0x0e), xtime(0x57, 0x0b), xtime(0x57, 0x0d), xtime(0x57, 0x09));*/
   getchar();
   return 0;
}
