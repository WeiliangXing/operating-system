#include <linux/ioctl.h>
#define IOC_MAGIC 0xb550ca22

struct user_pattern{
	int pat_len;
	char *pat;
};

#define IOCTL_ADD _IOW(IOC_MAGIC, 0, struct user_pattern *)
#define IOCTL_REMOVE _IOW(IOC_MAGIC, 1, struct user_pattern *)
#define IOCTL_LIST _IOW(IOC_MAGIC, 2, char *)
#define IOCTL_SIZE _IOW(IOC_MAGIC, 3, int *)
#define IOCTL_PASSWD _IOW(IOC_MAGIC, 4, char *)


