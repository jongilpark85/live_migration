#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <signal.h>
#include <ucontext.h>
#include "Common_Header.h"
#include <fcntl.h>

// Create a TCP scoket and connect to the receiver
int SetUpConnection(struct sockaddr_in* pSockAddr, socklen_t uiAddrLen_);

// Send /proc/self/maps file data to the receiver
int SendMapsFileData(int iSockFD_);

// Send the context information of the source process to the receiver
int SendContextInfo(int iSockFD_, ucontext_t* pContext_, size_t uiContextLen_);

// Receive a page request and send back the corresponding page to the receiver.
int RespondPageRequest(int iSockFD_, long int iPageSize_);

// Check whether the memory region should be filtered
int CheckMemoryRegion(char* pLine_);

// This library does not take command line arguments
// Get IP and Port of the receiver from receiver_info.txt file (avoid re-compile)
int GetReceiverAddr(struct sockaddr_in* pSockAddr_);

// Perform a live migration (Post Copy Approach)
// Send /proc/self/maps file data, receive pages requests, and send back the coressponding pages.
void DoMigration(ucontext_t* pContext_, size_t uiContextLen_);

// Signal Handler
void SignalHandler(int iSignal_)
{
	// Get the process id of the source process
	pid_t iPID = getpid();
	ucontext_t stContext;
	if (-1 == getcontext(&stContext))
	{
		perror("getcontext()");
		return;
	}

    // When the receiver perfroms a context switch to run as the source process, 
	// g_iPID will have the different value from getpid().
	if (iPID != getpid())
		return;
	
	// The code below will not be excuted on the receiver.
	// Send /proc/self/maps file data, receive pages requests, and send back the coressponding pages.
	DoMigration(&stContext,sizeof(stContext));
}

// Contructor
__attribute__((constructor))
void MigrationConstructor()
{
	if (SIG_ERR == signal(SIGUSR2, SignalHandler))
		perror("signal() SIGUSR2");
	
	return;
}

// Perform a live migration (Post Copy Approach)
// Send /proc/self/maps file data, receive page requests, and send back the coressponding pages.
void DoMigration(ucontext_t* pContext_, size_t uiContextLen_)
{
	// Get the page size the system uses
	long int iPageSize = sysconf(_SC_PAGESIZE);
	if (-1 == iPageSize)
		iPageSize = DEFAULT_PAGE_SIZE;
	
	// Create a TCP socket to communicate with the receiver
	struct sockaddr_in stReceiverAddr;
	int iSockFD = SetUpConnection(&stReceiverAddr, sizeof(stReceiverAddr));
	if (-1 == iSockFD)
	{
		printf("SetUpConnection() Failed\n");
		exit(EXIT_FAILURE);
	}
	
	// Send /proc/self/maps file data
	if (-1 == SendMapsFileData(iSockFD))
	{
		printf("SendMapsFileData() Failed\n");
		exit(EXIT_FAILURE);
	}
	
	// Send Context information
	if (-1 == SendContextInfo(iSockFD, pContext_, uiContextLen_))
	{
		close(iSockFD);
		printf("SendContextInfo() Failed\n");
		exit(EXIT_FAILURE);
	}

	// Receive page requests and send back the coressponding pages.
	if (-1 == RespondPageRequest(iSockFD, iPageSize))
	{
		close(iSockFD);
		//printf("RespondPageRequest Failed\n");
		exit(EXIT_FAILURE);
	}

	exit(EXIT_SUCCESS);;
}

// This library does not take command line arguments
// Get IP and Port of the receiver from receiver_info.txt file (avoid re-compile)
// return -1 on Failure
// return 0 on Success
int GetReceiverAddr(struct sockaddr_in* pSockAddr_)
{
	FILE* pFile = fopen("receiver_info.txt", "r");
	if (NULL == pFile)
		return -1;
	
	char szIP[16] = { 0, };
	unsigned int uiPort;
	int iRet = fscanf(pFile, "%s %u", szIP, &uiPort);
	fclose(pFile);
	
	if (2 != iRet)	
		return -1;
	
	if (0 == inet_aton(szIP, &pSockAddr_->sin_addr))
		return -1;
	
	if (uiPort > 65535)
		return -1;
	
	pSockAddr_->sin_port = htons((unsigned short)uiPort);

	return 0;
}

// Create a TCP scoket and connect to the receiver
// return -1 on Failure
// return a non-negative integer (socket descripotr) on Success
int SetUpConnection(struct sockaddr_in* pSockAddr, socklen_t uiAddrLen_)
{
	// Create a TCP socket to communicate with the receiver
	int iSockFD = socket(AF_INET, SOCK_STREAM, 0);
	if (-1 == iSockFD)
	{
		perror("socket()");
		return -1;
	}
	
	pSockAddr->sin_family = AF_INET;
	if (-1 == GetReceiverAddr(pSockAddr))
	{
		pSockAddr->sin_port = htons(DEFAULT_RECEIVER_PORT);
		pSockAddr->sin_addr.s_addr = inet_addr(DEFAULT_RECEIVER_IP);
	}

	//Connect to the receiver
	if (-1 == connect(iSockFD, (struct sockaddr*)pSockAddr, uiAddrLen_))
	{
		perror("connect()");
		close(iSockFD);
		return -1;
	}
	
	return iSockFD;
}

// Send /proc/self/maps file data
// return -1 on Failure
// return 0 on Success
int SendMapsFileData(int iSockFD_)
{
	FILE *fp = NULL;
	char* pLine = (char*)malloc(512);
	size_t uiLen = 512;
	ssize_t iRead;
	
	fp = fopen("/proc/self/maps", "r");
	if (NULL == fp)
	{
		perror("fopen()");
		return -1;
	}
	
	while ((iRead = getline(&pLine, &uiLen, fp)) != -1)
	{
		if (0 == iRead || 4 == iRead)
			continue;
		
		if (-1 == CheckMemoryRegion(pLine))
			continue;
		
		size_t uiDataLength = iRead + 1;
		const size_t uiPacketLength = sizeof(struct Packet_Header) + uiDataLength;
		unsigned char szSendBuff[uiPacketLength];
		struct Packet_Header* pHeader = (struct Packet_Header*)szSendBuff;
		pHeader->iType = EPT_MAPS_LINE;
		pHeader->uiSize = uiDataLength;	
		memcpy((void*)(szSendBuff + sizeof(struct Packet_Header)), (void*)pLine, uiDataLength);

		if (-1 == send(iSockFD_, (void*)szSendBuff, uiPacketLength, 0))
		{
			perror("send() maps file data");
			free(pLine);
			fclose(fp);
			return -1;
		}	
	}
	
	free(pLine);
	fclose(fp);

	// Notify the receiver that maps file transmission is done
	size_t uiDataLength = sizeof(unsigned long int);
	const size_t uiPacketLength = sizeof(struct Packet_Header) + uiDataLength;
	unsigned char szSendBuff[uiPacketLength];
	struct Packet_Header* pHeader = (struct Packet_Header*)szSendBuff;
	pHeader->iType = EPT_MAPSINFO_DONE;
	pHeader->uiSize = uiDataLength;	

	if (-1 == send(iSockFD_, (void*)szSendBuff, uiPacketLength, 0))
	{
		perror("send() maps file done packet failed");
		return -1;
	}	
	
	return 0;
}

// Send the context information of the source process to the receiver
// return -1 on Failure
// return 0 on Success
int SendContextInfo(int iSockFD_, ucontext_t* pContext_, size_t uiContextLen_)
{
	const size_t uiPacketLength = sizeof(struct Packet_Header) + uiContextLen_;
	unsigned char szSendBuff[uiPacketLength];
	struct Packet_Header* pHeader = (struct Packet_Header*)szSendBuff;
	pHeader->iType = EPT_CONTEXT_INFO;
	pHeader->uiSize = uiContextLen_;	
	memcpy((void*)(szSendBuff + sizeof(struct Packet_Header)), (void*)pContext_, uiContextLen_);

	
	if (-1 == send(iSockFD_, (void*)szSendBuff, uiPacketLength, 0))
	{
		perror("send() context");
		return -1;
	}
	
	return 0;
}


// Receive a page request and send back the corresponding page to the receiver.
// return -1 on Failure
// return 0 on Success
int RespondPageRequest(int iSockFD_, long int iPageSize_)
{
	// This live-migration library does not support multi-threaded applications currently.
	// That means the library itself also cannot use multi-threads.
	ssize_t iByteRead = 0;
	ssize_t iByteSent = 0;
	while (1)
	{
		struct Packet_Header stHeader;
		//Receive the header first
		iByteRead = recv(iSockFD_, (void*)&stHeader, sizeof(stHeader), 0);
		if (-1 == iByteRead)
		{
			perror("recv()");
			return -1;
		}
		else if (iByteRead != sizeof(stHeader))
		{
			//printf("Unexpected Result: %ld\n", iByteRead);
			return -1;
		}
        
		// Type Check
		if (EPT_FAULTED_PAGE_REQUEST != stHeader.iType)
		{
			printf("A wrong type\n");
			return -1;
		}

		const size_t uiRecvBuffLen = stHeader.uiSize;
		unsigned char szRecvBuff[uiRecvBuffLen];
		// Receive the data section
		iByteRead = recv(iSockFD_, (void*)szRecvBuff, uiRecvBuffLen, 0);
		if (-1 == iByteRead)
		{
			perror("recv()");
			return -1;
		}
		else if ((size_t)iByteRead != uiRecvBuffLen)
		{
			//printf("Unexpected Result: %ld\n", iByteRead);
			return -1;
		}

		unsigned long int uiFaultedAddress = *((unsigned long int*)szRecvBuff);
		size_t uiDataLength = sizeof(unsigned long int) + iPageSize_;
		const size_t uiPacketLength = sizeof(struct Packet_Header) + uiDataLength;
		unsigned char szSendBuff[uiPacketLength];
		struct Packet_Header* pHeader = (struct Packet_Header*)szSendBuff;
		pHeader->iType = EPT_FAULTED_PAGE_RESPONSE;
		pHeader->uiSize = uiDataLength;	
		unsigned long int* pData = (unsigned long int*)(szSendBuff + sizeof(struct Packet_Header));
		*pData = uiFaultedAddress;
		memcpy((void*)(pData + 1), (void*)uiFaultedAddress, iPageSize_);

		iByteSent = send(iSockFD_, (void*)szSendBuff, uiPacketLength, 0);  
		if (-1 == iByteSent)
		{
			perror("send() Page");
			return -1;
		}
		else if ((size_t)iByteSent != uiPacketLength)
		{
			//printf("Unexpected Result\n");
			return -1;
		}
	}
	
	return 0;
}


// Fillter out memory regions that are currently not supported
// return -1 when the memory region should be filtered
// Otherwise, return 0
int CheckMemoryRegion(char* pLine_)
{
	if (NULL != strstr(pLine_, "[vvar]") || 
		NULL != strstr(pLine_, "[vdso]")  ||
		NULL != strstr(pLine_, "[vsyscall]"))
		return -1;
	
	return 0;
}
