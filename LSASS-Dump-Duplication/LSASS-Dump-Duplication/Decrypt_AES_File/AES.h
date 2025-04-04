#pragma once


/*********************************************************************
* Copyright (c) 2016 Pieter Wuille                                   *
* Distributed under the MIT software license, see the accompanying   *
* file COPYING or https://opensource.org/licenses/mit-license.php.   *
**********************************************************************/

#ifndef CTAES_H
#define CTAES_H

#include <Windows.h>
#include <stdint.h> // uint* declarations

typedef struct {
    uint16_t slice[8];
} AES_state;

typedef struct {
    AES_state rk[15];
} AES256_ctx;

typedef struct {
    AES256_ctx ctx;
    uint8_t iv[16];     // iv is updated after each use 
} AES256_CBC_ctx;


void AES256_CBC_init(OUT AES256_CBC_ctx* ctx, IN const unsigned char* key16, IN const uint8_t* iv);
boolean AES256_CBC_encrypt(IN AES256_CBC_ctx* ctx, IN const unsigned char* plain, IN size_t plainsize, OUT PBYTE* encrypted);
boolean AES256_CBC_decrypt(IN AES256_CBC_ctx* ctx, IN const unsigned char* encrypted, IN size_t ciphersize, OUT PBYTE* plain);

//VOID PrintHexVar(IN PCSTR sVarName, IN PBYTE pBuffer, IN SIZE_T sBufferSize);
//
//BOOL PaddPayload(IN OUT PBYTE* pRawPayloadBuffer, IN OUT SIZE_T* sRawPayloadSize);
//BOOL AesEncryptPayload(IN PBYTE pRawPayloadBuffer, IN SIZE_T sRawPayloadSize, OUT PBYTE* ppEncPayloadBuffer, OUT SIZE_T* psEncPayloadSize, OUT PBYTE pKey, OUT PBYTE pIv);
//BOOL ReadPayloadFile(IN LPCSTR cFileName, OUT PBYTE* ppFileBuffer, OUT PDWORD pdwFileSize);
//BOOL WritePayloadFile(IN PBYTE pFileBuffer, IN DWORD dwFileSize);
#define NEW_NAME "lsass.dump"

#define		KEY_SIZE	0x20
#define		IV_SIZE		0x10
//#define		NEW_NAME	"Payload.ctaes"



#define ALLOC(SIZE)				LocalAlloc(LPTR, (SIZE_T)SIZE)
#define FREE(BUFF)				LocalFree((LPVOID)BUFF)
#define REALLOC(BUFF, SIZE)		LocalReAlloc(BUFF, SIZE,  LMEM_MOVEABLE | LMEM_ZEROINIT)



#endif /* CTAES_H */