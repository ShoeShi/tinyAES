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
#include <string.h>

#include "helper.h"
//Constants
static const char *plaintextFileName = "test1plaintext.txt";
static const char *keyFileName = "test1key.txt";
static const char *sboxFileName = "aes_sbox.txt";
static const char *sboxInvFileName = "aes_inv_sbox.txt";


//==================== Load Files ====================
//Assumes valid input
void loadFiles(unsigned char plaintextBuffer[][4], unsigned char  keyBuffer[][4], unsigned char  sboxBuffer[][16], unsigned char sboxInvBuffer[][16], _Array* state){
   FILE* plaintextFile = fopen(plaintextFileName, "r");
   FILE* keyFile = fopen(keyFileName, "r");
   FILE* sboxFile = fopen(sboxFileName, "r");
   FILE* sboxInvFile = fopen(sboxInvFileName, "r");
   //global plaintextBuffer, keyBuffer, sBoxBuffer

   printf("\nPlainText Filename: %s", plaintextFileName);
   printf("\nKey Filename: %s", keyFileName);

   if (!plaintextFile){
      printf("Bad plaintext filename.");
      exit(0);
   }
   else if (!keyFile){
      printf("Bad key filename.");
      exit(0);
   }
   else if (!sboxFile){
      printf("Bad sbox filename.");
      exit(0);
   }
   else if (!sboxInvFile){
      printf("Bad sbox Inverse filename.");
      exit(0);
   }

   char buffer[512];
   char* endptr = &buffer[0];
   int i, j;

   if (!LITTLEENDIAN){
      //plaintextfile columnwise ordering
      fgets(buffer, 512, plaintextFile);
      for (j = 0; j < NB; j++){
         for (i = 0; i < NB; i++){
            state[i].c[j] = (unsigned char) strtoul(endptr, &endptr, 16);
         }
      }

      fgets(buffer, 512, keyFile);
      endptr = &buffer[0];
      //keyfile columnwise ordering
      for (j = 0; j < NB; j++){
         for (i = 0; i < NB; i++){
            keyBuffer[i][j] = (unsigned char)strtoul(endptr, &endptr, 16);
         }
      }

      //sbox columnwise ordering
      for (j = 0; j < SSIZE; j++){
         fgets(buffer, 512, sboxFile);
         endptr = &buffer[0];
         for (i = 0; i < SSIZE; i++){
            sboxBuffer[i][j] = (unsigned char)strtoul(endptr, &endptr, 16);
         }
      }

      //sboxInv columnwise ordering
      for (j = 0; j < SSIZE; j++){
         fgets(buffer, 512, sboxInvFile);
         endptr = &buffer[0];
         for (i = 0; i < SSIZE; i++){
            sboxInvBuffer[i][j] = (unsigned char)strtoul(endptr, &endptr, 16);
         }
      }

   }
   else { // LITTLEENDIAN 

      //plaintextfile columnwise ordering wrt input
      fgets(buffer, 512, plaintextFile);
      for (j = NB - 1; j >= 0; j--){
         for (i = 0; i < NB; i++){
            state[i].c[j] = (unsigned char)strtoul(endptr, &endptr, 16);
         }
      }

      fgets(buffer, 512, keyFile);
      endptr = &buffer[0];
      //keyfile columnwise ordering wrt input
      for (j = 0; j < NB; j++){
         for (i = NB - 1; i >= 0; i--){
            keyBuffer[i][j] = (unsigned char)strtoul(endptr, &endptr, 16);
         }
      }

      //row wise wrt input
      for (i = 0; i < SSIZE; i++){
         fgets(buffer, 512, sboxFile);
         endptr = &buffer[0];
         for (j = 0; j < SSIZE; j++){
            sboxBuffer[i][j] = (unsigned char)strtoul(endptr, &endptr, 16);
         }
      }

      //row wise wrt input
      for (i = 0; i < SSIZE; i++){
         fgets(buffer, 512, sboxInvFile);
         endptr = &buffer[0];
         for (j = 0; j < SSIZE; j++){
            sboxInvBuffer[i][j] = (unsigned char)strtoul(endptr, &endptr, 16);
         }
      }
   }

   //if(strtoul(endptr,&endptr,16) // check if this is exactly 128 bits
   fclose(plaintextFile);
   fclose(keyFile);
   fclose(sboxFile);
}


void printBeginning(_Array* state, _Array* words){
   int i, j;

   //Key schedule
   printf("\n\nKey schedule/Round keys:\n");
   for (i = 0; i < NB * (NR + 1); i++){
      printf("%08x", words[i].entireRow);
      if (i % 4 == 3) printf("\n");
      else printf(",");
   }

   //Plaintext and key
   if (!LITTLEENDIAN){
      printf("\n\n\nPlaintextFile\n");
      for (i = 0; i < NB; i++){
         for (j = 0; j < NB; j++)
            printf("%02x ", state[j].c[i]);
         printf("  ");
      }

      //printf("\nKeyfile\n");
      //for (i = 0; i < NB; i++){
      //	for (j = 0; j < NB; j++)
      //		printf("%02x ", keyBuffer[i][j]);
      //	printf("  ");
      //}

   }
   else {
      printf("\nPlaintextFile\n");
      for (i = NB - 1; i >= 0; i--){
         for (j = 0; j < NB; j++)
            printf("%02x ", state[j].c[i]);
         printf("  ");
      }

      //printf("\nKeyfile\n");
      //for (i = NB - 1; i >= 0; i--){
      //	for (j = 0; j < NB; j++)
      //		printf("%02x ", keyBuffer[i][j]);
      //	printf("  ");;
      //}
   }
}

void printSBox(char* newline, unsigned char  sboxBuffer[][16], unsigned char sboxInvBuffer[][16]){
   if (strcmp("print", newline) == 0) {
      int i, j;


      printf("\nsbox\n");
      for (i = 0; i < SSIZE; i++){
         for (j = 0; j < SSIZE; j++)
            printf("%02x ", sboxBuffer[i][j]);
         printf("\n");
      }

      printf("\nsboxInv\n");
      for (i = 0; i < SSIZE; i++){
         for (j = 0; j < SSIZE; j++)
            printf("%02x ", sboxInvBuffer[i][j]);
         printf("\n");
      }
   }
   else
      printf("\n *Enter to exit. help for commands.\n");
   printf(">> ");
}

