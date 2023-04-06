#pragma once

//#define LOG printf
#include <stdio.h>

typedef unsigned char byte;

#define ASSERTIT(x) if(x!=0){printf("error %d\n",x);return x;}
#define SAFE_FREE( ptr )		if( ptr ) { delete ptr; ptr = NULL; }

