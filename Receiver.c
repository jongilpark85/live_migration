#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <linux/userfaultfd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>
#include <ucontext.h>
#include "Common_Header.h"

#define NEW_STACK_ADDRESSS 0x53000010000 // An arbitrary address for a new stack
#define MAX_PATH_NAME 256 // The buffer length for a path name 

// Global Variables
int g_iUserFaultFD = -1; // Userfualt File Descriptor
int g_iEpollFD = -1;	// Epoll Descriptor
int g_iListenSock;		// Listening socket to accept incoming connection from the source process.
int g_iSourceSock;
long int g_iPageSize;	// Page size of the system uses
pthread_t g_uiThread;	// ID returned by pthread_create()
ucontext_t g_stContext;	// Context of the source process
bool g_bContextSwitchReady = false; // Indicate whether it is ready to run in the context of the source process

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Functions

// Create and Enable userfaultfd object
int SetupUserfaultFD(int iEpollFD_); 

// Set up a TCP listening socket to communicate with the source process
int SetupListenSocket(int iEpollFD_, unsigned short int uiPort_); 

// Register a file descriptor to an epoll instance
int AddToEpoll(int iEpollFD_, int iDescriptor_); 

// Deregister a file descriptor from an epoll instance
int RemoveFromEpoll(int iEpollFD_, int iDescriptor_); 

// Enable socket options
int SetSocketOptions(int iSockFD_); 

// Convert a hexadecimal string to an unsigned long integer
unsigned long int HexStringToInteger(char* szHexString_); 
 
// Send a page request to the source process
int SendPageRequest(struct uffd_msg* pUffdMsg_, int iSourceSock_, long int iPageSize_);

// Get the information of the original stack from maps file (/proc/self/maps)
int GetStackInfo(struct Memory_Region_Info* pMemoryRegion_); 

// Accept incoming connections from the source process
void AcceptConnection(int* pSourceSock_, int iEpollFD_, int iListenSock_); 

// Wrapper for recv() 
int RecvWrapper(int iSockFD_, void* pRecvBuff_, size_t uiBuffSize_); 

// Get memory region information by parsing each line of /proc/self/maps file 
int GetMemoryRegionInfo(char* pLine_, struct Memory_Region_Info* pMemoryRegion_, char* pPathName_); 

// Handle a page fault event and send a corresponding page request to the source process
void HandlePageFault(int iEpollFD_, int iUserFaultFD_, int iSourceSock_, long int iPageSize_);

// Copy recevied page data to the address of the same page on the source process
void CopyPageToMemory(unsigned char* pPacket_, int iUserFaultFD_, long int iPageSize_); 

//  Copy received page data to the adrress where the page fault occurred.
void CopyFaultedPageToMemory(unsigned char* pPacket_, int iUserFaultFD_, long int iPageSize_); 

// Create mappings and register the mapped area to get notified for page faults occured in that area
void AddMappingForPageFault(unsigned char* pPacket_, int iEpollFD_, int iUserFaultFD_, int iSourceSock_);  

// Receive packets from the source process and perform corresponding operations to each packet type
void HandleSourcePacket(int iEpollFD_, int iSourceSock_, int iUserFaultFD_, long int iPageSize_);

// Migration Hanlding function that will be invoked at the time of pthread_create() call. 
// Receive maps file data, pages, and context information of the source process.
// Send a page request corresponding to a page fault to the source process.
void* MigrationThreadHanlder(void* pArg_); 

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


// main function
int main(int argc, char *argv[])
{	
	// If port number is provided at command line, then use it.
	// Otherwise, use the pre-defiend port number.
	unsigned short int usPort = DEFAULT_RECEIVER_PORT;
	if (2 <= argc)
		usPort = atoi(argv[1]);

	// Get the size of a page in byte
	g_iPageSize = sysconf(_SC_PAGESIZE);
	if (-1 == g_iPageSize)
		g_iPageSize = DEFAULT_PAGE_SIZE;
	
	// Create an epoll instance
	g_iEpollFD = epoll_create1(0);
	if (-1 == g_iEpollFD)
	{
		perror("epoll_create1()");
		exit(EXIT_FAILURE);
	}
		
	// Create and Enable userfaultfd object
	// Register the userfault fd to the epoll instance to handle page faults in user space. 
	g_iUserFaultFD = SetupUserfaultFD(g_iEpollFD);
	if (-1 == g_iUserFaultFD)
	{
		printf("SetupUserfaultFD() Failed\n");
		exit(EXIT_FAILURE);
	}
	
	// Set up a TCP listening socket to communicate with the source process
	g_iListenSock = SetupListenSocket(g_iEpollFD, usPort);
	if (-1 == g_iListenSock)
	{
		printf("SetupListenSocket() Failed!\n");
		exit(EXIT_FAILURE);
	}

	// Crete a new mapping for a new stack
	char* pNewStack = (char*) NEW_STACK_ADDRESSS;
	void* pMappedArea = mmap(pNewStack, g_iPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_GROWSDOWN | MAP_ANONYMOUS, -1, 0);
	if (MAP_FAILED == pMappedArea)
	{
		perror("mmap() for new stack");
		exit(EXIT_FAILURE);
	}
		
	// Get the information of the original stack from maps file (/proc/self/maps)
	struct Memory_Region_Info stMemoryRegion;
	if (-1 == GetStackInfo(&stMemoryRegion))
	{
		printf("GetStackInfo() Failed\n");
		exit(EXIT_FAILURE);
	}

	void * pInitalStackStartAddr  = (void*)stMemoryRegion.uiStartAddress;
	unsigned long int uiInitalStackSize  = stMemoryRegion.uiLength;
	
	// Change the stack pointer
	char* pNewStackBase = (char*)pMappedArea + g_iPageSize;
	asm volatile("mov %0, %%rsp;" : : "g" (pNewStackBase) : "memory");
	
	// Remove the mappings of the initial/original stack
	// After unmappings, local variables declared in main() becomes invalidated.
	if (-1 == munmap(pInitalStackStartAddr, uiInitalStackSize))
	{
		perror("munmap() for the orinal stack");
		exit(EXIT_FAILURE);
	}
	
	// Create a migration handling thread
	if (0 != pthread_create(&g_uiThread, NULL, MigrationThreadHanlder, NULL))
	{
		perror("pthread_create()");
		exit(EXIT_FAILURE);
	}

	// Context switch should be done in the main thread, so waiting until it is ready.
	// Even after performing setcontext(), the migration thread will still be running.( For post copy approach)
	while (g_bContextSwitchReady == false)
		;
	
	// Run in the context of the source process.
	setcontext(&g_stContext);
	
	return 0;
}

// Send a page request to the source process (when a page fault occurs
// Return -1 on Failure
// Return 0 on Success
int SendPageRequest(struct uffd_msg* pUffdMsg_, int iSourceSock_, long int iPageSize_)
{
	size_t uiDataLength = sizeof(unsigned long int);
	const size_t uiPacketLength = sizeof(struct Packet_Header) + uiDataLength;
	unsigned char szSendBuff[uiPacketLength];
	struct Packet_Header* pHeader = (struct Packet_Header*)szSendBuff;
	pHeader->iType = EPT_FAULTED_PAGE_REQUEST;
	pHeader->uiSize = uiDataLength;

	unsigned long int* pData = (unsigned long int*)(szSendBuff + sizeof(struct Packet_Header));
	*pData = (unsigned long int)pUffdMsg_->arg.pagefault.address & ~(iPageSize_ - 1);

	int iBytesSent = send(iSourceSock_, (void*)szSendBuff, uiPacketLength, 0);
	if (-1 == iBytesSent)
	{
		perror("send()");
		return -1;
	}
	else if (uiPacketLength != iBytesSent)
	{
		printf("send() Unexpected Result\n");
		return -1;
	}
	
	return 0;
}

// Handle a page fault event and send a corresponding page request to the source process
void HandlePageFault(int iEpollFD_, int iUserFaultFD_, int iSourceSock_, long int iPageSize_)
{
	// Read an event from userfaultfd
	struct uffd_msg stUffdMsg;
	int iBytesRead = read(iUserFaultFD_, &stUffdMsg, sizeof(stUffdMsg));
	
	if (0 == iBytesRead) 
	{
		printf("EOF on Userfaultfd!\n");
		return;
	}	
	else if (-1 == iBytesRead)
	{
		perror("read() in HandlePageFault()");
		exit(EXIT_FAILURE);
	}
	
	// Event Type Check
	if (stUffdMsg.event != UFFD_EVENT_PAGEFAULT)
	{
		printf("Unexpected Event\n");
		exit(EXIT_FAILURE);
	}
	
	// Request the source process to send a page corresponding to a page fault
	if (-1 == SendPageRequest(&stUffdMsg, iSourceSock_, iPageSize_))
	{
		printf("SendPageRequest() Failed\n");
		exit(EXIT_FAILURE);

		return;
	}

	return;
}

// Accept incoming connections from the source process
void AcceptConnection(int* pSourceSock_, int iEpollFD_, int iListenSock_)
{
	struct sockaddr_in stServerAddr;
	socklen_t stAddrLen = sizeof(stServerAddr);
	int iSourceSock = accept(iListenSock_, (struct sockaddr *)&stServerAddr, &stAddrLen);
	if (-1 == iSourceSock)
	{
		perror("accept()");
		exit(EXIT_FAILURE);
	}
					
				
	if (-1 == AddToEpoll(iEpollFD_, iSourceSock))
		exit(EXIT_FAILURE);
	
	*pSourceSock_ = iSourceSock;
}

// Copy recevied page data to the address of the same page on the source process
void CopyPageToMemory(unsigned char* pPacket_, int iUserFaultFD_, long int iPageSize_)
{
	unsigned long int uiStartAddress = *((unsigned long int*)pPacket_);
	struct uffdio_range stUffdioRange;
	stUffdioRange.start = uiStartAddress;
	stUffdioRange.len = iPageSize_;
					
	if (-1 == ioctl(iUserFaultFD_, UFFDIO_UNREGISTER, &stUffdioRange))
	{
		perror("ioctl() in CopyPageToMemory()");
		exit(EXIT_FAILURE);
	}

	memcpy((void*)uiStartAddress, (void*)(pPacket_ + sizeof(unsigned long int)), iPageSize_);
}

//  Copy received page data to the adrress where the page fault occurred.
void CopyFaultedPageToMemory(unsigned char* pPacket_, int iUserFaultFD_, long int iPageSize_)
{
	struct uffdio_copy stUffdioCopy;
	stUffdioCopy.src = (unsigned long int)(pPacket_ + sizeof(unsigned long int));
	stUffdioCopy.dst = *((unsigned long int*)pPacket_);
	stUffdioCopy.len = iPageSize_;
	stUffdioCopy.mode = 0;
	stUffdioCopy.copy = 0;
	if (-1 == ioctl(iUserFaultFD_, UFFDIO_COPY, &stUffdioCopy))
	{
		perror("ioctl() in CopyFaultedPageToMemory()");
		exit(EXIT_FAILURE);
	}
}

// Create mappings and register the mapped area to get notified for page faults occured in that area
void AddMappingForPageFault(unsigned char* pPacket_, int iEpollFD_, int iUserFaultFD_, int iSourceSock_)
{
	struct Memory_Region_Info stRegion;
	if (-1 == GetMemoryRegionInfo((char*)pPacket_, &stRegion, NULL))
	{
		printf("GetMemoryRegionInfo(): Parsing received data Failed\n");
		if (-1 == RemoveFromEpoll(iEpollFD_, iSourceSock_))
		{
			printf("AddMappingForPageFault() Failed");
			exit(EXIT_FAILURE);
		}
		
		close(iSourceSock_);
			
		return;
	}

	void* pStartAddr = (void*)(stRegion.uiStartAddress);
	//printf("pStartAddr : %p\n", pStartAddr);
	void *pRegion = mmap(pStartAddr, stRegion.uiLength, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
	if (MAP_FAILED == pRegion)
	{
		perror("mmap() in AddMappingForPageFault()");
		exit(EXIT_FAILURE);
	}	
	else if (pRegion != (void*)stRegion.uiStartAddress)
	{
		printf("Mapped area is not exaclty same as the start address");
		exit(EXIT_FAILURE);
	}
			
			
	struct uffdio_register stUffdioRegister;
	stUffdioRegister.range.start = (unsigned long)pRegion;
	stUffdioRegister.range.len = stRegion.uiLength;
	stUffdioRegister.mode = UFFDIO_REGISTER_MODE_MISSING;
	if (-1 == ioctl(iUserFaultFD_, UFFDIO_REGISTER, &stUffdioRegister))
	{
		perror("ioctl() UFFDIO_REGISTER in AddMappingForPageFault()");
		exit(EXIT_FAILURE);
	}
	
	return;
}

// Wrapper for recv() 
int RecvWrapper(int iSockFD_, void* pRecvBuff_, size_t uiBuffSize_)
// Return -1 on Failure
// Return a non-negative integer on Success
{
	int iFlags = 0;
	
	int iReadBytes = recv(iSockFD_, pRecvBuff_, uiBuffSize_, iFlags);					
	if (-1 == iReadBytes)
	{
		perror("recv()");
	}	
	else if (uiBuffSize_ != iReadBytes)
	{
		printf("recv() Unexpected Result\n");
		return -1;
	}
		
	return iReadBytes;
}


// Receive packets from the source process and perform corresponding operations to each packet type
void HandleSourcePacket(int iEpollFD_, int iSourceSock_, int iUserFaultFD_, long int iPageSize_)
{
	// Recv TCP packet from the Source process
	struct Packet_Header stHeader;

	// Receive the header section first
	if (-1 == RecvWrapper(iSourceSock_, (void*)&stHeader, sizeof(stHeader)))
	{
		printf("RecvWrapper() Packet Header in  HandleSourcePacket() Failed!\n");
		exit(EXIT_FAILURE);
	}
	
	// Receive the data section
	const size_t uiDataLength = stHeader.uiSize;
	unsigned char szPacketData[uiDataLength];
	if (-1 == RecvWrapper(iSourceSock_, (void*)szPacketData, uiDataLength))
	{
		printf("RecvWrapper() Packet Data in  HandleSourcePacket() Failed!\n");
		exit(EXIT_FAILURE);
	}

	// Perform corresponding operations to the packet type
	if (EPT_PAGE == stHeader.iType)	
	{
		// Packet contains a page of the source process
		CopyPageToMemory(szPacketData, iUserFaultFD_, iPageSize_);
	}
	else if (EPT_FAULTED_PAGE_RESPONSE == stHeader.iType)
	{		
		// In post-copy, when a page fault occurs, this receiver send a page request to the source process.
		// This packet is a respond to the request and contains a page of the source process
		CopyFaultedPageToMemory(szPacketData, iUserFaultFD_, iPageSize_);
	}	
	else if (EPT_MAPS_LINE == stHeader.iType)
	{
		// Create mappings and register the mapped area to get notified for page faults occured in that area.
		AddMappingForPageFault(szPacketData, iEpollFD_, iUserFaultFD_, iSourceSock_);
	}
	else if  (EPT_MAPSINFO_DONE == stHeader.iType)
	{
		// For future use
	}
	else if (EPT_CONTEXT_INFO == stHeader.iType)
	{
		// Context information of the source process
		memcpy(&g_stContext, szPacketData, sizeof(g_stContext));
		g_bContextSwitchReady = true;					
	}
	else
	{
		// Unexpected Packet Type
		printf("Unexpected Packet Type: %ld\n", stHeader.iType);
		if (-1 == RemoveFromEpoll(iEpollFD_, iSourceSock_))
		{
			printf("in HandleSourcePacket() Failed\n");
			exit(EXIT_FAILURE);
		}
		
		close(iSourceSock_);
		return;
	}

	return;
}

// Migration Hanlding function that will be invoked at the time of pthread_create() call. 
// Receive maps file data, pages, and context information of the source process.
// Send a page request corresponding to a page fault to the source process.
void* MigrationThreadHanlder(void* pArg_)
{
	int iEpollFD = g_iEpollFD;
	int iUserFaultFD = g_iUserFaultFD;
	long int iPageSize = g_iPageSize;
	int iListenSock = g_iListenSock;
	int iSourceSock = g_iSourceSock;
	
	struct epoll_event stEPollEvents[100];
	memset(stEPollEvents, 0, sizeof(stEPollEvents));
	
	do
	{
		int iEventCounts = epoll_wait(iEpollFD, stEPollEvents, 100, -1);
		for (int i = 0; i < iEventCounts; ++i)
		{
			if (stEPollEvents[i].data.fd == iUserFaultFD)
				HandlePageFault(iEpollFD, iUserFaultFD, iSourceSock, iPageSize);
			else if (stEPollEvents[i].data.fd == iListenSock)
				AcceptConnection(&iSourceSock, iEpollFD, iListenSock);
			else if (stEPollEvents[i].data.fd == iSourceSock)
				HandleSourcePacket(iEpollFD, iSourceSock, iUserFaultFD, iPageSize);
		}
		
	} while (1);
	
	return NULL;
}

// Create and Enable userfaultfd object
// Return -1 on Failure
// Return a non-negative integer( usefault fd) on Success
int SetupUserfaultFD(int iEpollFD_)
{
	int iUserFaultFD = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
	if (-1 == iUserFaultFD) 
	{
		perror("syscall/userfaultfd");
		return -1;
	}
	
	struct uffdio_api uffdio_api;
	uffdio_api.api = UFFD_API;
	uffdio_api.features = 0;
	if (ioctl(iUserFaultFD, UFFDIO_API, &uffdio_api) == -1) {
		perror("ioctl/uffdio_api");
		close(iUserFaultFD);
		return -1;
	}

	if (UFFD_API != uffdio_api.api) {
		printf("unsupported userfaultfd api\n");
		close(iUserFaultFD);
		return -1;
	}
	
	unsigned long int ioctl_mask = (unsigned long int)1 << _UFFDIO_REGISTER | (unsigned long int)1 << _UFFDIO_UNREGISTER;
	if ((uffdio_api.ioctls & ioctl_mask) != ioctl_mask) {
		printf("ioctl_mask: userfualt fd\n");
		close(iUserFaultFD);
		return -1;
	}
	
	int iResult = AddToEpoll(iEpollFD_, iUserFaultFD);
	if (-1 == iResult)
	{
		perror("epoll_ctl");
		close(iUserFaultFD);
		return -1;
	}
	
	return iUserFaultFD;
}

// Enable socket options
// Return -1 on Failure
// Return 0 on Success
int SetSocketOptions(int iSockFD_)
{
	const int enable = 1;
	if (-1 == setsockopt(iSockFD_, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)))
	{
		perror("setsockopt() SO_REUSEADDR");
		return -1;
	}

	/*
	if (-1 == setsockopt(iSockFD_, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable)))
	{
		perror("setsockopt() SO_REUSEPORT");
		return -1;
	}
	*/
	
	return 0;
}

// Set up a TCP listening socket to communicate with the source process
// Return -1 on Failure
// Return a non-negative integer( socket descriptor ) on Success
int SetupListenSocket(int iEpollFD_, unsigned short int uiPort_)
{
	int iListenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (-1 == iListenSock)
	{
		perror("socket() Listening Socket");
		return -1;
	}
	
	if (-1 == SetSocketOptions(iListenSock))
	{
		close(iListenSock);
		return -1;
	}

	struct sockaddr_in stSockAddr;
	stSockAddr.sin_family = AF_INET;
	stSockAddr.sin_port = htons(uiPort_);
	stSockAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (-1 == bind(iListenSock, (struct sockaddr*)&stSockAddr, sizeof(stSockAddr)))
	{
		close(iListenSock);
		perror("bind() Listening Socket");
		return -1;	
	}
	
	if (-1 == listen(iListenSock, SOMAXCONN))
	{
		close(iListenSock);
		perror("listen() Listening Socket");
		return -1;	
	}
	
	// Register TCP Listening Socket to the EPoll descriptor
	if (-1 == AddToEpoll(iEpollFD_, iListenSock))
	{
		close(iListenSock);
		perror("listen() Listening Socket");
		return -1;
	}

	return iListenSock;
}


// Register a file descriptor to an epoll instance
// Return -1 on Failure
// Return 0 on Success
int AddToEpoll(int iEpollFD_, int iDescriptor_)
{
	struct epoll_event event;
	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN;
	event.data.fd = iDescriptor_;
	
	// Register TCP Listening Socket to the EPoll descriptor
	if( -1 == epoll_ctl(iEpollFD_, EPOLL_CTL_ADD, iDescriptor_, &event))
	{
		perror("epoll_ctl() EPOLL_CTL_ADD");
		return -1;
	}
		
	return 0;
}


// Deregister a file descriptor from an epoll instance
// Return -1 on Failure
// Return 0 on Success
int RemoveFromEpoll(int iEpollFD_, int iDescriptor_)
{
	struct epoll_event event;
	if (-1 == epoll_ctl(iEpollFD_, EPOLL_CTL_DEL, iDescriptor_, &event))
		perror("epoll_ctl() EPOLL_CTL_DEL");
	
	return 0;
}

// Get the address and size of the initial stack 
// Return -1 on Failure
// Return 0 on Success
int GetStackInfo(struct Memory_Region_Info* pMemoryRegion_)
{
	FILE *fp = NULL;
	char* pLine = (char*)malloc(512);
	size_t uiLen = 512;
	ssize_t iRead;
	
	fp = fopen("/proc/self/maps", "r");
	if (NULL == fp)
		return false;
	
	int iRessult = -1;
	while ((iRead = getline(&pLine, &uiLen, fp)) != -1)
	{
		char szPathName[MAX_PATH_NAME];
		if (-1 == GetMemoryRegionInfo(pLine, pMemoryRegion_, szPathName))
			break;	
		
		if (0 == strcmp(szPathName, "[stack]"))
		{
			iRessult = 0;
			break;
		}
	}
	
	free(pLine);
	fclose(fp);
	return iRessult;
}

// Get memory region information by parsing each line of /proc/self/maps file 
// Return -1 on Failure
// Return 0 on Success
int GetMemoryRegionInfo(char* pLine_, struct Memory_Region_Info* pMemoryRegion_, char* pPathName_)
{
	char* pLine = pLine_;
	char* pFound;
	int iLastIndex;
		
	// Get the start address of the memory region
	pFound = strchr(pLine, '-');
	if (NULL == pFound)
		return -1;
	
	iLastIndex = pFound - pLine;
	pLine[iLastIndex] = '\0';
	
	pMemoryRegion_->uiStartAddress = HexStringToInteger(pLine);
	
	// Get the end address of the memory region
	pLine = pFound + 1;
	pFound = strchr(pLine, ' ');
	if (NULL == pFound)
		return -1;
	
	iLastIndex =  pFound - pLine;
	pLine[iLastIndex] = '\0';
	unsigned long int uiEndAddress = HexStringToInteger(pLine);
	pMemoryRegion_->uiLength = uiEndAddress - pMemoryRegion_->uiStartAddress;
	
	// Get the permissions of the memory region
	pLine = pFound + 1;
	pFound = strchr(pLine, ' ');
	if (NULL == pFound)
		return -1;
	
	iLastIndex =  pFound - pLine;
	pLine[iLastIndex] = '\0';
	
	strncpy(pMemoryRegion_->szPermissions, pLine, sizeof(pMemoryRegion_->szPermissions));
	
	// Get the offset of the memory region
	pLine = pFound + 1;
	pFound = strchr(pLine, ' ');
	if (NULL == pFound)
		return -1;
	
	iLastIndex =  pFound - pLine;
	pLine[iLastIndex] = '\0';
	
	pMemoryRegion_->uiOffset = HexStringToInteger(pLine);
	
	// Get the path name of the memory region
	if (pPathName_)
	{
		pLine = pFound + 1;
		// Get the path name of the memory region
		pFound = strrchr(pLine, ' ');
		if (NULL == pFound)
			return -1;
	
		strncpy(pPathName_, pFound + 1, MAX_PATH_NAME);
		// Remove the new line character
		pPathName_[strlen(pPathName_) - 1] = '\0';
	}
	
	return 0;
}

// Convert a hexadecimal string to an unsigned long integer
unsigned long int HexStringToInteger(char* szHexString_)
{
	size_t uiLength = strlen(szHexString_);
	unsigned long int uiValue = 0;
	int iBase = 16;

	for (int i = 0; i < uiLength; ++i)
	{
		char c = szHexString_[i];
		
		if ((c >= '0') && (c <= '9')) 
			c -= '0';
		else if ((c >= 'a') && (c <= 'f')) 
			c -= 'a' - 10;
		else if ((c >= 'A') && (c <= 'F')) 
			c -= 'A' - 10;
		
		uiValue = uiValue * iBase + c;
	}
	
	return uiValue;
}

