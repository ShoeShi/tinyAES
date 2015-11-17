#ifndef HELPER_H
#define HELPER_H

//************************************
//  Author: Johnny Xie
//  Class: Introduction to Cryptography
//  Assignment 3
//  11.15.15
//
//  Please see the README for details.
//  
//************************************



#define NB 4  //word num
#define NK 4 //keysize
#define NR 10 //rounds
#define SSIZE 16 // 16by16 matrix


#include "order32.h"
//http://stackoverflow.com/questions/2100331/c-macro-definition-to-determine-big-endian-or-little-endian-machine
#define LITTLEENDIAN (O32_HOST_ORDER == O32_LITTLE_ENDIAN)

//Endian matters in my union
typedef union specialArray {
   unsigned int entireRow;
   unsigned char c[NB];
}_Array;


//====================Helper Functions====================

void loadFiles(unsigned char plaintextBuffer[][4], unsigned char  keyBuffer[][4], unsigned char  sboxBuffer[][16], unsigned char sboxInvBuffer[][16], _Array* state);
void printBeginning(_Array* state, _Array* words);
void printSBox(char* newline, unsigned char  sboxBuffer[][16], unsigned char sboxInvBuffer[][16]);

#endif
