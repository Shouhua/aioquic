/**
 * gcc -Wall -Wextra -pedantic -o getlocaladdr netlink_get_local_address.c
 */
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <linux/rtnetlink.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define SEQ 1

struct nlmsg
{
	struct nlmsghdr snlmsghdr;
	struct rtmsg srtmsg;
	struct rtattr srtattr;
	uint32_t dst_addr;
};

int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		fprintf(stderr, "USAGE: ./netlink_get_local_address REMOTE_IP\n");
		return -1;
	}
	struct nlmsg nlmsg;
	struct iovec siov, riov;
	struct msghdr smsghdr, rmsghdr;
	struct sockaddr_nl ssa, rsa;
	uint8_t rbuf[8192];
	int fd, res;

	memset(&nlmsg, 0, sizeof(struct nlmsg));
	memset(&siov, 0, sizeof(struct iovec));
	memset(&ssa, 0, sizeof(struct sockaddr_nl));
	memset(&smsghdr, 0, sizeof(struct msghdr));

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

	if (fd == -1)
	{
		perror("socket create");
	}

	ssa.nl_family = AF_NETLINK;

	res = bind(fd, (struct sockaddr *)&ssa, sizeof(ssa));
	if (res == -1)
	{
		perror("bind failed");
		close(fd);
		return -1;
	}

	nlmsg.snlmsghdr.nlmsg_type = RTM_GETROUTE;
	nlmsg.snlmsghdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlmsg.snlmsghdr.nlmsg_seq = SEQ;
	nlmsg.snlmsghdr.nlmsg_pid = getpid();

	nlmsg.srtmsg.rtm_family = AF_INET;
	nlmsg.srtmsg.rtm_protocol = RTPROT_KERNEL;

	nlmsg.srtattr.rta_type = RTA_DST;
	nlmsg.srtattr.rta_len = RTA_LENGTH(sizeof(uint32_t));

	uint32_t ipbuf;
	res = inet_pton(AF_INET, argv[1], &ipbuf);
	if (res <= 0)
	{
		if (res == 0)
			fprintf(stderr, "Not in presentation format");
		else
			perror("inet_pton");
		close(fd);
		return -1;
	}
	memcpy(RTA_DATA(&nlmsg.srtattr), &ipbuf, sizeof(uint32_t));
	nlmsg.snlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg) + nlmsg.srtattr.rta_len);

	siov.iov_base = &nlmsg;
	siov.iov_len = nlmsg.snlmsghdr.nlmsg_len;

	smsghdr.msg_name = &ssa;
	smsghdr.msg_namelen = sizeof(ssa);
	smsghdr.msg_iov = &siov;
	smsghdr.msg_iovlen = 1;

	do
	{
		res = sendmsg(fd, &smsghdr, 0);
	} while (res == -1 && errno == EINTR);

	if (res == -1)
	{
		perror("sendmsg failed");
		close(fd);
		return -1;
	}

	/* receive msg */
	memset(&riov, 0, sizeof(riov));
	memset(&rsa, 0, sizeof(rsa));
	memset(&rmsghdr, 0, sizeof(rmsghdr));

	riov.iov_base = rbuf;
	riov.iov_len = 8192;

	rmsghdr.msg_name = &rsa;
	rmsghdr.msg_namelen = sizeof(rsa);
	rmsghdr.msg_iov = &riov;
	rmsghdr.msg_iovlen = 1;

	do
	{
		res = recvmsg(fd, &rmsghdr, 0);
	} while (res == -1 && errno == EINTR);

	if (res == -1)
	{
		perror("recvmsg 1 failed");
		close(fd);
		return -1;
	}

	for (struct nlmsghdr *rnlmsghdr = (struct nlmsghdr *)rbuf;
		 NLMSG_OK(rnlmsghdr, res);
		 rnlmsghdr = NLMSG_NEXT(rnlmsghdr, res))
	{
#ifdef DEBUG
		fprintf(stdout, "seq: %d, flags: %d, type: %d\n", rnlmsghdr->nlmsg_seq, rnlmsghdr->nlmsg_flags, rnlmsghdr->nlmsg_type);
#endif
		assert(rnlmsghdr->nlmsg_seq == SEQ);
		assert(!(rnlmsghdr->nlmsg_flags & NLM_F_MULTI));

		switch (rnlmsghdr->nlmsg_type)
		{
		case NLMSG_DONE:
			fprintf(stderr, "netlink: unexpected NLMSG_DONE\n");
			close(fd);
			return -1;
		case NLMSG_ERROR:
			fprintf(stderr, "netlink: %s\n", strerror(-((struct nlmsgerr *)NLMSG_DATA(rnlmsghdr))->error));
			close(fd);
			return -1;
		case NLMSG_NOOP:
			continue;
		}

		int attrlen = rnlmsghdr->nlmsg_len - NLMSG_SPACE(sizeof(struct rtmsg));
		for (struct rtattr *rrtattr = (struct rtattr *)((uint8_t *)NLMSG_DATA(rnlmsghdr) + sizeof(struct rtmsg));
			 RTA_OK(rrtattr, attrlen);
			 rrtattr = RTA_NEXT(rrtattr, attrlen))
		{
#ifdef DEBUG
			fprintf(stdout, "type: %d, len: %d, RTA_LENGTH: %ld\n", rrtattr->rta_type, rrtattr->rta_len, RTA_LENGTH(4));
#endif
			if (rrtattr->rta_type != RTA_PREFSRC)
				continue;

			uint32_t ipbuf;
			memcpy(&ipbuf, RTA_DATA(rrtattr), 4);

			char ipstr[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &ipbuf, ipstr, INET_ADDRSTRLEN);
			fprintf(stdout, "IP: %u %s\n", ipbuf, ipstr);
			break;
		}
	}

	/* read ACK*/
	memset(&rsa, 0, sizeof(struct sockaddr_nl));
	memset(&rmsghdr, 0, sizeof(struct msghdr));
	rmsghdr.msg_name = &rsa;
	rmsghdr.msg_namelen = sizeof(struct sockaddr_nl);
	rmsghdr.msg_iov = &riov;
	rmsghdr.msg_iovlen = 1;

	do
	{
		res = recvmsg(fd, &rmsghdr, 0);
	} while (res == -1 && errno == EINTR);

	if (res == -1)
	{
		perror("recvmsg 2 failed");
		close(fd);
		return -1;
	}

	for (struct nlmsghdr *rnlmsghdr = (struct nlmsghdr *)rbuf;
		 NLMSG_OK(rnlmsghdr, res);
		 rnlmsghdr = NLMSG_NEXT(rnlmsghdr, res))
	{
		assert(rnlmsghdr->nlmsg_seq == SEQ);
		assert(!(rnlmsghdr->nlmsg_flags & NLM_F_MULTI));
		switch (rnlmsghdr->nlmsg_type)
		{
		case NLMSG_DONE:
			fprintf(stderr, "netlink: unexpected NLMSG_DONE\n");
			close(fd);
			return -1;
		case NLMSG_ERROR:
			res = -((struct nlmsgerr *)NLMSG_DATA(rnlmsghdr))->error;
			if (res == 0)
			{
#ifdef DEBUG
				fprintf(stdout, "exit error == 0\n");
#endif
				break;
			}
			fprintf(stderr, "netlink: %s\n", strerror(res));
			close(fd);
			return -1;
		case NLMSG_NOOP:
			continue;
		}
	}
	if (res != 0)
		return -1;

	return 0;
}