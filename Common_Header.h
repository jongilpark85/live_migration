// For Testing
#define DEFAULT_RECEIVER_IP "127.0.0.1" // Default IP of the receiver 
#define DEFAULT_RECEIVER_PORT 43000 // Default listening port number of the receiver.
#define DEFAULT_PAGE_SIZE 4096 // Default Page size of the system

// Packet Types
enum PACKET_TYPE
{
    EPT_MAPS_LINE = 0, // A line of /proc/self/maps file
    EPT_MAPSINFO_DONE, // Maps file transmission is done
    EPT_CONTEXT_INFO, // Context information of the orignal process
    EPT_FAULTED_PAGE_REQUEST, // Faulted page request
    EPT_FAULTED_PAGE_RESPONSE, // Actual content of a faulted page 
    EPT_PAGE, //Actual content of a page 
    EPT_MIGRATION_DONE, // All the pages of the orignal process are transferred
    EPT_MAX,
};

// PACKET HEDAER
struct Packet_Header
{
	ssize_t iType; // the type of a packet
	size_t uiSize; // the size of data section followed by this header
};

//////////////////////////////////////////////////////////////////////////////////////////
// DATA_STRUCTURE for each type
//////////////////////////////////////////////////////////////////////////////////////////

// EPT_MAPS_LINE
// undetermined length of char[]

// EPT_MAPSINFO_DONE
// No data section is needed becuase EPT_MAPSINFO_DONE is just a signal packet
// We can still send a magic number for verification (Just set a proper size to the packet header)

// EPT_CONTEXT_INFO 
// Context information of the orignal process

// EPT_FAULTED_PAGE_REQUEST, 
// The start address of the page where the page fault occurred 

// EPT_FAULTED_PAGE_RESPONSE
// The start address of the faulted page and the content of that page

// EPT_PAGE
// The actual content of a page
// We should use sysconf(_SC_PAGESIZE) to the page size the system uses.

// EPT_MIGRATION_DONE
// This is just a signal packet to notify the receiver that all the pages have been transferred
// This is not used in the current implementation


#define PERMISSION_MAX 5
// Information of a memory region (from /proc/self/maps file)
struct Memory_Region_Info
{
	unsigned long int uiStartAddress;
	unsigned long int uiLength;
	char szPermissions[PERMISSION_MAX];
	int iPermissions;
	unsigned long uiOffset;
};

