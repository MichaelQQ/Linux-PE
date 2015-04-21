#ifndef LINUX_SHIM_H
#define LINUX_SHIM_H

#define SHIMNAMSIZ 16
struct rtshim
{
	char name[SHIMNAMSIZ+1];
	short datalen;
	char data[0];
};

#endif
