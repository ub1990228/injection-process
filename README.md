一、概述
为了隐藏自身的进程信息，我们希望将进程作为一个合法进程的线程运行。由于系统进程间不允许直接操作资源，因而我们需要在合法进程内部创建一个线程，为其指定要执行的代码。一种简单的方式是令远程线程载入一个我们编写的DLL，通过DllMain()函数执行我们需要的代码。基本思路是将LoadLibrary()函数作为一个线程函数来调用：
CreateRemoteThread()---->LoadLibrary()---->DllMain()
这里的核心函数是CreateRemoteThread()，它用来在远程进程中创建一新线程。我们来看一下这个函数：
HANDLE WINAPI CreateRemoteThread(
    HANDLE hProcess, //要创建远程线程的进程句柄
    LPSECURITY_ATTRIBUTES lpThreadAttributes, //用于定义新线程的安全属性，这里设为NULL采用默认值即可
    SIZE_T dwStackSize,  //初始化线程堆栈大小，NULL为默认大小
    LPTHREAD_START_ROUTINE lpStartAddress, //线程函数开始的地址
    LPVOID lpParameter,  //线程函数参数
    DWORD dwCreationFlags,  //函数表示创建线程后线程的运行状态
    LPDWORD lpThreadId  //返回线程ID，不关心可以设为NULL不返回
);
使用这个函数关键要解决三个参数问题：
l  获得远程线程的进程句柄，而且要确保相应权限
l  获取远程进程中线程函数的开始地址，而非本地地址
l  向远程线程成功传入DLL路径字符串
解决了这三个问题，我们的远程注入DLL就基本完成了。接下来，这篇笔记的组织结构如下：
F  获取远程进程句柄
l  枚举系统进程
l  提升进程权限
F  获取LoadLibrary()函数在远程进程中的地址
F  向远程线程中写入DLL路径字符串
l  利用VirtualAllocEx()分配远程地址空间
l  利用WriteProcessMemory()写入远程地址空间
F  程序源码
F  运行测试
 
 
 
 
 
 
二、获取远程进程句柄
我们主要利用OpenProcess()函数来获得要注入的进程的句柄，句柄是系统中可以起到唯一标识作用的一个对象。我们来看一下OpenProcess()函数：
HANDLE WINAPI OpenProcess(
    DWORD dwDesiredAccess,  //获取的句柄的访问权限
    BOOL bInheritHandle,    //是否可为新进程继承
    DWORD dwProcessId       //要获取句柄的进程ID
);
句柄的访问权限是指我们要使用该进程的句柄做哪些访问操作，对于远程注入DLL来说，主要有：
PROCESS_CREATE_THREAD |  //For CreateRemoteThread()
PROCESS_VM_OPERATION |  //For VirtualAllocEx()/VirtualFreeEx()
PROCESS_VM_WRITE       //For WriteProcessMemory(0
当然，我们也可以直接设为最高权限：PROCESS_ALL_ACCESS。
第二个参数说明了是否可为新进程继承，第三个参数需要借助我们编写的子函数ListProcess()来获得。另外需要注意的是，对于很多系统和服务进程而言，获取其带有写权限的句柄需要主调进程拥有调试权限，我们利用子函数EnableDebugPriv()来提升权限。这样在XP下就足够了，在VISTA之后的系统中需要进一步提升另一个隐藏权限，这里只讨论在XP上的情况。
l  ListProcess()
我们使用ToolHelpAPI获取当前运行程序的信息，从而编写适合自己需要的工具（@MSDN）。它支持的平台比较广泛，可以在 Windows CE 下使用。在 Windows Mobile SDK 的 Samples 里面有一个 PViewCE 的样例程序，就是用这个来查看进程和线程信息的。
使用方法就是先用 CreateToolhelp32Snapshot 将当前系统的进程、线程、DLL、堆的信息保存到一个缓冲区，这就是一个系统快照。如果你只是对进程信息感兴趣，那么只要包含 TH32CS_SNAPPROCESS 标志即可。 常见标志如下：
TH32CS_SNAPHEAPLIST：列举th32ProcessID指定进程中的堆
TH32CS_SNAPMODULE：列举th32ProcessID指定进程中的模块
TH32CS_SNAPPROCESS：列举系统范围内的所有进程
TH32CS_SNAPTHREAD：列举系统范围内的所有线程
函数执行成功返回快照句柄，否则返回INVALID_HANDLE_VALUE。
得到系统快照句柄后，我们调用Process32First和Process32Next来依次获取系统中每个进程的信息，将信息存入PROCESSENTRY32结构体中，该结构体中存放着进程的主要信息，如
DWORD  th32ProcessID;  //进程ID
DWORD  th32ModuleID;  //进程模块ID
CHAR   szExeFile[MAX_PATH];  //进程的可执行文件名
这两个函数当枚举到进程时返回TRUE，否则返回FALSE。
然后调用一次 Process32First 函数，从快照中获取第一个进程，然后重复调用 Process32Next，直到函数返回 FALSE 为止，这样将遍历快照中进程列表。这两个函数都带两个参数，它们分别是快照句柄和一个 PROCESSENTRY32 结构。调用完 Process32First 或 Process32Next 之后，PROCESSENTRY32 中将包含系统中某个进程的关键信息。其中进程 ID 就存储在此结构的 th32ProcessID。此 ID 传给 OpenProcess API 可以获得该进程的句柄。对应的可执行文件名及其存放路径存放在 szExeFile 结构成员中。在该结构中还可以找到其它一些有用的信息。
需要注意的是：在调用 Process32First() 之前，要将 PROCESSENTRY32 结构的 dwSize 成员设置成 sizeof(PROCESSENTRY32)。 然后再用 Process32First、Process32Next 来枚举进程。使用结束后要调用 CloseHandle 来释放保存的系统快照。具体程序代码如下：
//利用ToolHelp32库来枚举当前系统进程
#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include <tlhelp32.h>
 
int ListProcess()
{
    //获取系统快照
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //不要写错CreateToolhelp32Snapshot()
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
       printf("CreateToolHelp32Snapshot error!\n");
       return -1;
    }
 
    //创建单个进程快照结构体，初始化大小
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);  //务必提前初始化，否则默认的大小不一定满足要求
 
    //初始化缓冲区
    WCHAR buff[1024] = {0}; //PROCESSENTRY32中的szExeFile为WCHAR类型数组，此处应一致，使用Unicode码
 
    //枚举系统快照链表中的第一个进程项目
    BOOL bProcess = Process32First(hProcessSnap, &pe32);
    while (bProcess)
    {
 
       //格式化进程名和进程ID，这里要使用printf的宽字符版
       //格式字符串“”都需要用L转换为宽字符形式
       wsprintf(buff, L"FileName:%-30sID:%-6d\r\n", pe32.szExeFile, pe32.th32ProcessID);
       wprintf(L"%s\n",buff);
       //缓冲区复位
       memset(buff, 0, sizeof(buff));
       //继续枚举下一个进程
       bProcess = Process32Next(hProcessSnap, &pe32);
    }
 
    CloseHandle(hProcessSnap);
    return 0;
}
l  EnableDebugPriv()
提升权限主要利用下面四个函数：
GetCurrentProcessID()        //得到当前进程的ID  
OpenProcessToken()          //得到进程的令牌句柄
LookupPrivilegeValue()       //查询进程的权限
AdjustTokenPrivileges()        //调整令牌权限 
进程的权限设置存储在令牌句柄中，我们需要先获取进程的令牌句柄，其次获取进程中权限类型的LUID值，利用此值来设置进程新的权限，具体函数调用顺序如下：
OpenProcessToken()---->LookupPrivilegeValue()---->AdjustTokenPrivileges()
具体代码如下：
#include <windows.h>
#include <stdio.h>
 
int EnableDebugPriv(const WCHAR *name)
{
    HANDLE hToken;   //进程令牌句柄
    TOKEN_PRIVILEGES tp;  //TOKEN_PRIVILEGES结构体，其中包含一个【类型+操作】的权限数组
    LUID luid;       //上述结构体中的类型值
 
    //打开进程令牌环
    //GetCurrentProcess()获取当前进程的伪句柄，只会指向当前进程或者线程句柄，随时变化
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &hToken))
    {
       printf("OpenProcessToken error\n");
       return -8;
    }
 
    //获得本地进程name所代表的权限类型的局部唯一ID
    if (!LookupPrivilegeValue(NULL, name, &luid))
    {
       printf("LookupPrivilegeValue error\n");
    }
 
    tp.PrivilegeCount = 1;    //权限数组中只有一个“元素”
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;  //权限操作
    tp.Privileges[0].Luid = luid;   //权限类型
 
    //调整进程权限
    if (!AdjustTokenPrivileges(hToken, 0, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
       printf("AdjustTokenPrivileges error!\n");
       return -9;
    }
 
    return 0;
}
 
三、获取LoadLibrary()的远程地址
对于Windows系统而言，本地进程和远程进程中的Kernel32.dll被映射到地址空间的同一内存地址，因而只要获取本地进程中LoadLibrary()的地址，在远程进程中也同样是这个地址，可以直接传给CreateRemoteThread()：
LPTHREAD_START_ROUTINE pLoadLibrary
=
(LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryA");
GetProcAddress函数检索指定的动态链接库(DLL)中的输出库函数地址。
函数原型：
　　FARPROC GetProcAddress(
　　HMODULE hModule, // DLL模块句柄
　　LPCSTR lpProcName // 函数名，以NULL结尾的字符串
);
返回值：
　　如果函数调用成功，返回值是DLL中的输出函数地址。
　　如果函数调用失败，返回值是NULL。得到进一步的错误信息，调用函数GetLastError。
 
四、向远程进程中写入DLL路径字符串
l  VirtualAllocEx()
如果直接向CreateRemoteThread()传入DLL路径，如”C:\\Windows\\System32\\MyDLL.dll”那么实际向远程线程传递的是一个本地的指针值，这个值在远程进程的地址空间中是没有意义的。所以我们需要使用VirtualAllocEx()函数在远程进程中先分配一段空间，用于直接写入我们的DLL路径。
函数原形：
　　LPVOID VirtualAllocEx(
　　HANDLE hProcess,
　　LPVOID lpAddress,
　　SIZE_T dwSize,
　　DWORD flAllocationType,
　　DWORD flProtect
　　);
　　hProcess：
　　申请内存所在的进程句柄。
　　lpAddress：
　　保留页面的内存地址；一般用NULL自动分配 。
　　dwSize：
欲分配的内存大小，字节单位；注意实际分 配的内存大小是页内存大小的整数倍。
我们这里的实际代码为：
//在远程进程中分配内存，准备拷入DLL路径字符串
//取得当前DLL路径
char DllPath[260]; //Windows路径最大为
GetCurrentDirectoryA(260, DllPath);  //获取当前进程执行目录
printf("Proces***e Directory is %s\n", DllPath); 
strcat(DllPath, "\\..\\Debug\\MyDLL.dll"); //链接到DLL路径
LPVOID pRemoteDllPath = VirtualAllocEx(hRemoteProcess, NULL, strlen(DllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
if (pRemoteDllPath == NULL)
{
    printf("VirtualAllocEx error\n");
    return -3;
}
l  WriteProcessMemory()
我们利用该函数直接向远程进程中分配好的空间中写入DLL路径字符串
BOOL WriteProcessMemory(
    HANDLE hProcess,      // 进程的句柄，是用OpenProcess打开的
    LPVOID lpBaseAddress, // 要写入的起始地址
    LPVOID lpBuffer,      // 写入的缓存区
    DWORD nSize, // 要写入缓存区的大小
    LPDWORD lpNumberOfBytesWritten          // 这个是返回实际写入的字节。
   );
我们这里的实际代码为：
//向远程进程空间中写入DLL路径字符串
printf("DllPath is %s\n", DllPath);
DWORD Size;
if (WriteProcessMemory(hRemoteProcess, pRemoteDllPath, DllPath, strlen(DllPath) +1, &Size) == NULL)
    {
       printf("WriteProcessMemory error\n");
       return -4;
    }
printf("WriteRrmoyrProcess Size is %d\n\n", Size);
 
五、程序源码
F  DLL源码：
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
 
 
 
BOOL APIENTRY DllMain(HINSTANCE hInstDll, DWORD fdwReason, PVOID fImpLoad)
{
    switch (fdwReason)
    {
       case DLL_PROCESS_ATTACH :
    {
       //The DLL is being mapped into the process's address space.
       //DWORD ThreadId;
       //CreateThread(NULL, NULL, MessageThread, NULL, NULL, &ThreadId);
       MessageBox(NULL, L"DLL has been mapped!", L"1st RemoteThread", MB_OK);
       //打开文件，定义文件指针，指定打开方式为写+追加
       FILE *fp = fopen("C:\\test.txt", "w");     //打开方式参数为字符串
       //文件读写函数：
       //读写字符：getc(), putc(); 读写字符串：fgets(), fputs()
       //向标准输入输出读入写出：
       //getchar(), putchar();  gets(0, puts(0;
        fputs("一个DLL测试文本\n", fp);
        //printf("Test finished\n");
       //关闭文件指针，释放内存
        fclose(fp);
    }
      
       case DLL_THREAD_ATTACH:
       //A Thread is being created.
       MessageBox(NULL, L"RemoteThread has been created!", L"2nd RemoteThread", MB_OK);
       break;
       case DLL_THREAD_DETACH:
       //A Thtread is exiting cleanly.
       MessageBox(NULL, L"RemoteThread exit!", L"13rd RemoteThread", MB_OK);
       break;
       case DLL_PROCESS_DETACH:
       //The DLL is being ummapped from the process' address space
       MessageBox(NULL, L"DLL has been unmapped!", L"4th RemoteThread", MB_OK);
       break;
    }
    return TRUE;  //Used only for DLL_PROCESS_ATTACH
}
 
 
F  RemoteInjectExe.cpp
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
 
extern int ListProcess();
extern int EnableDebugPriv(const WCHAR *);
 
int _tmain(int argc, TCHAR *argv[], TCHAR *env[])
{
    //为了成功使用CreateRemoteThread()函数，必须：
    //1.利用OpenProcess()获得远程进程的句柄
    //2.利用VirtualAllocEx(),WriteProcessMemory()写入DLL路径字符串
    //3.获得远程进程中LoadLibrary()的确切地址
 
    //输入进程ID获得进程句柄
    char YesNo;
    printf("是否查看当前进程列表获得进程ID: Y or N?");
    scanf("%c", &YesNo);
    Sleep(250);
    if (YesNo == 'Y' || YesNo == 'y')
       ListProcess();
    printf("请输入要注入的进程ID【‘’表示自身进程】：\n");
    DWORD dwRemoteProcessId;
    scanf("%d",&dwRemoteProcessId);
    //如果输入“”表示向自身进程注入
    if (dwRemoteProcessId == 0)
       dwRemoteProcessId = GetCurrentProcessId();
 
    //获得调试权限
    if (EnableDebugPriv(SE_DEBUG_NAME))
    {
       printf("Add Privilege error\n");
       return -1;
    }
    //调用OpenProcess()获得句柄
    HANDLE hRemoteProcess;
    if ((hRemoteProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwRemoteProcessId)) == NULL)
    {
       printf("OpenProcess error\n");
       printf("Error Code:%d\n",GetLastError());
       system("pause");
       return -2;
    }
 
    //在远程进程中分配内存，准备拷入DLL路径字符串
    //取得当前DLL路径
    char DllPath[260]; //Windows路径最大为
    GetCurrentDirectoryA(260, DllPath);  //获取当前进程执行目录
    printf("Proces***e Directory is %s\n", DllPath); 
    strcat(DllPath, "\\..\\Debug\\MyDLL.dll"); //链接到DLL路径
    LPVOID pRemoteDllPath = VirtualAllocEx(hRemoteProcess, NULL, strlen(DllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (pRemoteDllPath == NULL)
    {
       printf("VirtualAllocEx error\n");
       return -3;
    }
 
    //向远程进程空间中写入DLL路径字符串
    printf("DllPath is %s\n", DllPath);
    DWORD Size;
    if (WriteProcessMemory(hRemoteProcess, pRemoteDllPath, DllPath, strlen(DllPath) +1, &Size) == NULL)
    {
       printf("WriteProcessMemory error\n");
       return -4;
    }
    printf("WriteRrmoyrProcess Size is %d\n\n", Size);
 
    //获得远程进程中LoadLibrary()的地址
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
 
    //启动远程线程
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
 
    //释放分配内存
    if (VirtualFreeEx(hRemoteProcess, pRemoteDllPath, 0, MEM_RELEASE) == 0)
    {
       printf("VitualFreeEx error\n");
       return -8;
    }
 
    //释放句柄
    if (hThread != NULL) CloseHandle(hThread);
    if (hRemoteProcess != NULL) CloseHandle(hRemoteProcess);
 
    system("pause");
    return 0;
}