#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>


int ListProcess();
int EnableDebugPriv(const WCHAR *);

int _tmain(int argc, TCHAR *argv[], TCHAR *env[])
{
	//Ϊ�˳ɹ�ʹ��CreateRemoteThread()���������룺
	//1.����OpenProcess()���Զ�̽��̵ľ��
	//2.����VirtualAllocEx(),WriteProcessMemory()д��DLL·���ַ���
	//3.���Զ�̽�����LoadLibrary()��ȷ�е�ַ

	//�������ID��ý��̾��
	char YesNo;
	printf("�Ƿ�鿴��ǰ�����б��ý���ID: Y or N?");
	scanf("%c", &YesNo);
	Sleep(250);
	if (YesNo == 'Y' || YesNo == 'y')
		ListProcess();
	printf("������Ҫע��Ľ���ID��������ʾ������̡���\n");
	DWORD dwRemoteProcessId;
	scanf("%d", &dwRemoteProcessId);
	//������롰0����ʾ���������ע��
	if (dwRemoteProcessId == 0)
		dwRemoteProcessId = GetCurrentProcessId();

	//��õ���Ȩ��
	if (EnableDebugPriv(SE_DEBUG_NAME))
	{
		printf("Add Privilege error\n");
		return -1;
	}
	//����OpenProcess()��þ��
	HANDLE hRemoteProcess;
	if ((hRemoteProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwRemoteProcessId)) == NULL)
	{
		printf("OpenProcess error\n");
		printf("Error Code:%d\n", GetLastError());
		system("pause");
		return -2;
	}

	//��Զ�̽����з����ڴ棬׼������DLL·���ַ���
	//ȡ�õ�ǰDLL·��
	char DllPath[260]; //Windows·�����Ϊ
	GetCurrentDirectoryA(260, DllPath);  //��ȡ��ǰ����ִ��Ŀ¼
	printf("Proces***e Directory is %s\n", DllPath);
	strcat(DllPath, "\\..\\Debug\\dll.dll"); //���ӵ�DLL·��
	LPVOID pRemoteDllPath = VirtualAllocEx(hRemoteProcess, NULL, strlen(DllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
	if (pRemoteDllPath == NULL)
	{
		printf("VirtualAllocEx error\n");
		return -3;
	}

	//��Զ�̽��̿ռ���д��DLL·���ַ���
	printf("DllPath is %s\n", DllPath);
	DWORD Size;
	if (WriteProcessMemory(hRemoteProcess, pRemoteDllPath, DllPath, strlen(DllPath) + 1, &Size) == NULL)
	{
		printf("WriteProcessMemory error\n");
		return -4;
	}
	printf("WriteRrmoyrProcess Size is %d\n\n", Size);

	//���Զ�̽�����LoadLibrary()�ĵ�ַ
	LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryA");
	if (pLoadLibrary == NULL)
	{
		printf("GetProcAddress error\n");
		return -5;
	}
	else
	{
		printf("LoadLibrary's Address is 0x%x\n\n", pLoadLibrary);
	}

	//����Զ���߳�
	DWORD dwThreadId;
	HANDLE hThread;
	if ((hThread = CreateRemoteThread(hRemoteProcess, NULL, 0, pLoadLibrary, pRemoteDllPath, 0, &dwThreadId)) == NULL)
	{
		printf("CreateRemoteThread error\n");
		return -6;
	}
	else
	{
		WaitForSingleObject(hThread, INFINITE);
		printf("dwThreadId is %d\n\n", dwThreadId);
		printf("Inject is done\n");
	}

	//�ͷŷ����ڴ�
	if (VirtualFreeEx(hRemoteProcess, pRemoteDllPath, 0, MEM_RELEASE) == 0)
	{
		printf("VitualFreeEx error\n");
		return -8;
	}

	//�ͷž��
	if (hThread != NULL) CloseHandle(hThread);
	if (hRemoteProcess != NULL) CloseHandle(hRemoteProcess);

	system("pause");
	return 0;
}



int ListProcess()
{
	//��ȡϵͳ����
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //��Ҫд��CreateToolhelp32Snapshot()
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		printf("CreateToolHelp32Snapshot error!\n");
		return -1;
	}

	//�����������̿��սṹ�壬��ʼ����С
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);  //�����ǰ��ʼ��������Ĭ�ϵĴ�С��һ������Ҫ��

	//��ʼ��������
	WCHAR buff[1024] = { 0 }; //PROCESSENTRY32�е�szExeFileΪWCHAR�������飬�˴�Ӧһ�£�ʹ��Unicode��

	//ö��ϵͳ���������еĵ�һ��������Ŀ
	BOOL bProcess = Process32First(hProcessSnap, &pe32);
	while (bProcess)
	{

		//��ʽ���������ͽ���ID������Ҫʹ��printf�Ŀ��ַ���
		//��ʽ�ַ�����������Ҫ��Lת��Ϊ���ַ���ʽ
		wsprintf(buff, L"FileName:%-30sID:%-6d\r\n", pe32.szExeFile, pe32.th32ProcessID);
		wprintf(L"%s\n", buff);
		//��������λ
		memset(buff, 0, sizeof(buff));
		//����ö����һ������
		bProcess = Process32Next(hProcessSnap, &pe32);
	}

	CloseHandle(hProcessSnap);
	return 0;
}

int EnableDebugPriv(const WCHAR *name)
{
	HANDLE hToken;   //�������ƾ��
	TOKEN_PRIVILEGES tp;  //TOKEN_PRIVILEGES�ṹ�壬���а���һ��������+��������Ȩ������
	LUID luid;       //�����ṹ���е�����ֵ

	//�򿪽������ƻ�
	//GetCurrentProcess()��ȡ��ǰ���̵�α�����ֻ��ָ��ǰ���̻����߳̾������ʱ�仯
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		printf("OpenProcessToken error\n");
		return -8;
	}

	//��ñ��ؽ���name�������Ȩ�����͵ľֲ�ΨһID
	if (!LookupPrivilegeValue(NULL, name, &luid))
	{
		printf("LookupPrivilegeValue error\n");
	}

	tp.PrivilegeCount = 1;    //Ȩ��������ֻ��һ����Ԫ�ء�
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;  //Ȩ�޲���
	tp.Privileges[0].Luid = luid;   //Ȩ������

	//��������Ȩ��
	if (!AdjustTokenPrivileges(hToken, 0, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{
		printf("AdjustTokenPrivileges error!\n");
		return -9;
	}

	return 0;
}