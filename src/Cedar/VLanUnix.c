// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// VLanUnix.c
// Virtual device driver library for UNIX

#ifdef UNIX

#include "VLanUnix.h"

#include "Connection.h"
#include "Session.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/TunTap.h"
#include "Mayaqua/Unix.h"

#ifdef UNIX_BSD
// For "sockaddr" in <net/if_arp.h>
#include <sys/socket.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <sys/ioctl.h>

#if defined(UNIX_OPENBSD) || defined(UNIX_SOLARIS)
#include <netinet/if_ether.h>
#else
#include <net/ethernet.h>
#endif

#ifdef	UNIX_MACOS
#include <net/bpf.h>
#endif	// UNIX_MACOS

static LIST *unix_vlan = NULL;

#ifdef	UNIX_MACOS
// Size of the BPF read buffer used to back the macOS feth-based virtual NIC
#define	MACOS_BPF_BUFSIZE			(128 * 1024)

// fd -> feth interface names + BPF read buffer state.
// When no tun/tap kext is available (e.g. Apple Silicon), the macOS fd is a
// /dev/bpf descriptor bound to a feth (if_fake) peer pair instead of a tap
// device; see the implementation block further down for how the pair is built.
// BPF read() returns packets prefixed with struct bpf_hdr and may batch several
// per read(), so we buffer a whole read and hand out one frame at a time. That
// per-fd state lives here (keyed by fd) instead of in the shared VLAN struct,
// so VLanUnix.h needs no macOS-specific fields.
typedef struct MACOS_FETH_ENTRY
{
	int fd;				// /dev/bpf fd (same value as VLAN->fd)
	char host[16];		// host-side feth (carries the IP, OS routes through it)
	char dev[16];		// dev-side feth (BPF attached)
	UCHAR *BpfBuffer;	// Read batch buffer
	UINT BpfBufferSize;	// Allocated size of BpfBuffer
	UINT BpfBufferUsed;	// Valid bytes from the last read()
	UINT BpfBufferOff;	// Current parse offset within BpfBuffer
} MACOS_FETH_ENTRY;

// Look up the feth/BPF entry for a bpf fd (linear scan; the list normally
// holds just 1-2 entries). Returns NULL if none.
static MACOS_FETH_ENTRY *MacOsFethFind(int fd);
#endif	// UNIX_MACOS

#ifndef NO_VLAN

// Get the PACKET_ADAPTER
PACKET_ADAPTER *VLanGetPacketAdapter()
{
	PACKET_ADAPTER *pa;

	pa = NewPacketAdapter(VLanPaInit, VLanPaGetCancel,
		VLanPaGetNextPacket, VLanPaPutPacket, VLanPaFree);
	if (pa == NULL)
	{
		return NULL;
	}

	return pa;
}

// PA initialization
bool VLanPaInit(SESSION *s)
{
	VLAN *v;
	// Validate arguments
	if (s == NULL)
	{
		return false;
	}

	// Connect to the driver
	v = NewVLan(s->ClientOption->DeviceName, NULL);
	if (v == NULL)
	{
		// Failure
		return false;
	}

	s->PacketAdapter->Param = v;

	return true;
}

// Get the cancel object
CANCEL *VLanPaGetCancel(SESSION *s)
{
	VLAN *v;
	// Validate arguments
	if ((s == NULL) || ((v = s->PacketAdapter->Param) == NULL))
	{
		return NULL;
	}

	return VLanGetCancel(v);
}

// Release the packet adapter
void VLanPaFree(SESSION *s)
{
	VLAN *v;
	// Validate arguments
	if ((s == NULL) || ((v = s->PacketAdapter->Param) == NULL))
	{
		return;
	}

	// End the virtual LAN card
	FreeVLan(v);

	s->PacketAdapter->Param = NULL;
}

// Write a packet
bool VLanPaPutPacket(SESSION *s, void *data, UINT size)
{
	VLAN *v;
	// Validate arguments
	if ((s == NULL) || ((v = s->PacketAdapter->Param) == NULL))
	{
		return false;
	}

	return VLanPutPacket(v, data, size);
}

// Get the next packet
UINT VLanPaGetNextPacket(SESSION *s, void **data)
{
	VLAN *v;
	UINT size;
	// Validate arguments
	if (data == NULL || (s == NULL) || ((v = s->PacketAdapter->Param) == NULL))
	{
		return INFINITE;
	}

	if (VLanGetNextPacket(v, data, &size) == false)
	{
		return INFINITE;
	}

	return size;
}

// Write a packet to the virtual LAN card
bool VLanPutPacket(VLAN *v, void *buf, UINT size)
{
	UINT ret;
	// Validate arguments
	if (v == NULL)
	{
		return false;
	}
	if (v->Halt)
	{
		return false;
	}
	if (size > MAX_PACKET_SIZE)
	{
		return false;
	}
	if (buf == NULL || size == 0)
	{
		if (buf != NULL)
		{
			Free(buf);
		}
		return true;
	}

	ret = write(v->fd, buf, size);

	if (ret >= 1)
	{
		Free(buf);
		return true;
	}

	if (errno == EAGAIN || ret == 0)
	{
		Free(buf);
		return true;
	}

	return false;
}

// Get the next packet from the virtual LAN card
bool VLanGetNextPacket(VLAN *v, void **buf, UINT *size)
{
	UCHAR tmp[TAP_READ_BUF_SIZE];
	int ret;
	// Validate arguments
	if (v == NULL || buf == NULL || size == 0)
	{
		return false;
	}
	if (v->Halt)
	{
		return false;
	}

#ifdef	UNIX_MACOS
	// If the fd is a feth-backed BPF descriptor, each read() returns zero or
	// more frames, each prefixed by a struct bpf_hdr and padded to BPF_WORDALIGN.
	// Hand out one frame per call, refilling the buffer when it drains.
	// The buffer state is kept in the per-fd feth side-table, not in VLAN.
	// A tap fd has no entry and falls through to the plain read below.
	{
		MACOS_FETH_ENTRY *e = MacOsFethFind(v->fd);

		while (e != NULL)
		{
			struct bpf_hdr *bh;
			UCHAR *frame;
			UINT caplen;

			if (e->BpfBufferOff < e->BpfBufferUsed)
			{
				bh = (struct bpf_hdr *)(e->BpfBuffer + e->BpfBufferOff);
				caplen = bh->bh_caplen;
				frame = e->BpfBuffer + e->BpfBufferOff + bh->bh_hdrlen;
				e->BpfBufferOff += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);

				if (caplen == 0 || caplen > TAP_READ_BUF_SIZE)
				{
					// Skip empty / oversized frames
					continue;
				}

				*buf = Malloc(caplen);
				Copy(*buf, frame, caplen);
				*size = caplen;
				return true;
			}

			// Buffer drained: pull a fresh batch
			ret = read(v->fd, e->BpfBuffer, e->BpfBufferSize);
			if (ret == 0 || (ret == -1 && errno == EAGAIN))
			{
				// No packet
				*buf = NULL;
				*size = 0;
				return true;
			}
			else if (ret == -1)
			{
				return false;
			}

			e->BpfBufferUsed = ret;
			e->BpfBufferOff = 0;
		}
	}
#endif	// UNIX_MACOS

	// Read
	ret = read(v->fd, tmp, sizeof(tmp));

	if (ret == 0 ||
		(ret == -1 && errno == EAGAIN))
	{
		// No packet
		*buf = NULL;
		*size = 0;
		return true;
	}
	else if (ret == -1 || ret > TAP_READ_BUF_SIZE)
	{
		// Error
		return false;
	}
	else
	{
		// Reading packet success
		*buf = Malloc(ret);
		Copy(*buf, tmp, ret);
		*size = ret;
		return true;
	}
}

// Get the cancel object
CANCEL *VLanGetCancel(VLAN *v)
{
	CANCEL *c;
	int fd;
	int yes = 0;
	// Validate arguments
	if (v == NULL)
	{
		return NULL;
	}

	c = NewCancel();
	UnixDeletePipe(c->pipe_read, c->pipe_write);
	c->pipe_read = c->pipe_write = -1;

	fd = v->fd;

	UnixSetSocketNonBlockingMode(fd, true);

	c->SpecialFlag = true;
	c->pipe_read = fd;

	return c;
}

// Close the Virtual LAN card
void FreeVLan(VLAN *v)
{
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	Free(v->InstanceName);

	Free(v);
}

// Create a tap
VLAN *NewBridgeTap(char *name, char *mac_address, bool create_up)
{
	int fd;
	VLAN *v;
	// Validate arguments
	if (name == NULL || mac_address == NULL)
	{
		return NULL;
	}

	fd = UnixCreateTapDeviceEx(name, UNIX_VLAN_BRIDGE_IFACE_PREFIX, mac_address, create_up);
	if (fd == -1)
	{
		return NULL;
	}

	v = ZeroMalloc(sizeof(VLAN));
	v->Halt = false;
	v->InstanceName = CopyStr(name);
	v->fd = fd;

	return v;
}

// Close the tap
void FreeBridgeTap(VLAN *v)
{
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	UnixCloseTapDevice(v->fd);
#ifdef	UNIX_BSD
	UnixDestroyBridgeTapDevice(v->InstanceName);
#endif

	FreeVLan(v);
}

// Get the Virtual LAN card list
VLAN *NewVLan(char *instance_name, VLAN_PARAM *param)
{
	int fd;
	VLAN *v;
	// Validate arguments
	if (instance_name == NULL)
	{
		return NULL;
	}

	// Open the tap
	fd = UnixVLanGet(instance_name);
	if (fd == -1)
	{
		return NULL;
	}

	v = ZeroMalloc(sizeof(VLAN));
	v->Halt = false;
	v->InstanceName = CopyStr(instance_name);
	v->fd = fd;

	return v;
}

// Generate TUN interface name
void GenerateTunName(char *name, char *prefix, char *tun_name, size_t tun_name_len)
{
	char instance_name_lower[MAX_SIZE];

	// Generate the device name
	StrCpy(instance_name_lower, sizeof(instance_name_lower), name);
	Trim(instance_name_lower);
	StrLower(instance_name_lower);
	Format(tun_name, tun_name_len, "%s_%s", prefix, instance_name_lower);

	tun_name[15] = 0;
}

#ifdef	UNIX_MACOS

// macOS has no usable tap kext on Apple Silicon. When no tap device can be
// opened, we build an equivalent L2 endpoint out of a feth (if_fake) peer pair
// plus a /dev/bpf descriptor, which needs no kernel extension:
//
//   <host feth>  <== peer ==>  <dev feth>  <-- BPF attached here
//
// The OS treats the host-side feth as the VPN virtual NIC (the user assigns
// it an IP / DHCP). Frames the OS transmits on the host feth arrive on the
// dev feth, where BPF read() delivers them to us. Frames we BPF write() on
// the dev feth are delivered to the host feth as if received, reaching the
// host IP stack.

// fd -> feth interface names + BPF read buffer state (MACOS_FETH_ENTRY is
// declared near the top of this file). The create/destroy paths and the
// per-frame read path (MacOsFethFind) touch this list.
static LIST *macos_feth_list = NULL;

static void MacOsFethInit()
{
	if (macos_feth_list == NULL)
	{
		macos_feth_list = NewList(NULL);
	}
}

// Look up the feth/BPF entry for a bpf fd (linear scan; the list normally
// holds just 1-2 entries). Returns NULL if none.
static MACOS_FETH_ENTRY *MacOsFethFind(int fd)
{
	UINT i;

	if (macos_feth_list == NULL)
	{
		return NULL;
	}

	for (i = 0; i < LIST_NUM(macos_feth_list); i++)
	{
		MACOS_FETH_ENTRY *e = LIST_DATA(macos_feth_list, i);
		if (e->fd == fd)
		{
			return e;
		}
	}

	return NULL;
}

// Run "ifconfig <args>" and return the first output line (caller frees), or NULL.
static char *MacOsIfconfig(char *args, bool capture)
{
	char cmd[MAX_SIZE];
	TOKEN_LIST *t;
	char *ret = NULL;

	Format(cmd, sizeof(cmd), "/sbin/ifconfig %s 2>/dev/null", args);
	t = UnixExec(cmd);
	if (t != NULL)
	{
		if (capture && t->NumTokens >= 1)
		{
			ret = CopyStr(t->Token[0]);
		}
		FreeToken(t);
	}
	return ret;
}

// Open a /dev/bpf device and bind it to the given interface.
static int MacOsOpenBpf(char *ifname)
{
	char dev[32];
	int fd = -1;
	int i;
	UINT blen = MACOS_BPF_BUFSIZE;
	UINT yes = 1, no = 0;
	struct ifreq ifr;

	for (i = 0; i < 256; i++)
	{
		Format(dev, sizeof(dev), "/dev/bpf%d", i);
		fd = open(dev, O_RDWR);
		if (fd >= 0)
		{
			break;
		}
		if (errno == EBUSY)
		{
			continue;
		}
		if (errno == ENOENT)
		{
			break;
		}
	}
	if (fd < 0)
	{
		return -1;
	}

	// Buffer length must be set before BIOCSETIF
	ioctl(fd, BIOCSBLEN, &blen);

	Zero(&ifr, sizeof(ifr));
	StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), ifname);
	if (ioctl(fd, BIOCSETIF, &ifr) < 0)
	{
		close(fd);
		return -1;
	}

	ioctl(fd, BIOCIMMEDIATE, &yes);	// return as soon as a packet arrives
	ioctl(fd, BIOCSHDRCMPLT, &yes);	// we supply complete link-layer headers
	ioctl(fd, BIOCSSEESENT, &no);	// don't loop back our own injected frames

	return fd;
}

// Create a feth peer pair, attach BPF, return the bpf fd (or -1).
static int MacOsCreateTap(UCHAR *mac_address)
{
	char *host = NULL, *dev = NULL;
	char args[MAX_SIZE];
	int fd = -1;
	MACOS_FETH_ENTRY *e;

	MacOsFethInit();

	// Auto-allocate two feth interfaces (ifconfig prints the chosen name)
	host = MacOsIfconfig("feth create", true);
	dev = MacOsIfconfig("feth create", true);
	if (host == NULL || dev == NULL || host[0] == 0 || dev[0] == 0)
	{
		goto FAILED;
	}

	// Peer them
	Format(args, sizeof(args), "%s peer %s", host, dev);
	MacOsIfconfig(args, false);

	// The OS originates frames on the host feth, so its MAC must be the
	// virtual NIC MAC that the VPN side sees.
	if (mac_address != NULL)
	{
		Format(args, sizeof(args), "%s lladdr %02x:%02x:%02x:%02x:%02x:%02x",
			host, mac_address[0], mac_address[1], mac_address[2],
			mac_address[3], mac_address[4], mac_address[5]);
		MacOsIfconfig(args, false);
	}

	// Bring both up
	Format(args, sizeof(args), "%s up", host);
	MacOsIfconfig(args, false);
	Format(args, sizeof(args), "%s up", dev);
	MacOsIfconfig(args, false);

	// Attach BPF to the dev side
	fd = MacOsOpenBpf(dev);
	if (fd == -1)
	{
		goto FAILED;
	}

	e = ZeroMalloc(sizeof(MACOS_FETH_ENTRY));
	e->fd = fd;
	StrCpy(e->host, sizeof(e->host), host);
	StrCpy(e->dev, sizeof(e->dev), dev);

	// Allocate the BPF read buffer, sized to the kernel's bpf buffer length.
	{
		UINT kernel_blen = 0;
		if (ioctl(fd, BIOCGBLEN, &kernel_blen) < 0 || kernel_blen == 0)
		{
			kernel_blen = MACOS_BPF_BUFSIZE;
		}
		e->BpfBuffer = Malloc(kernel_blen);
		e->BpfBufferSize = kernel_blen;
		e->BpfBufferUsed = 0;
		e->BpfBufferOff = 0;
	}

	Add(macos_feth_list, e);

	Debug("MacOsCreateTap: host=%s dev=%s bpf_fd=%d\n", host, dev, fd);

	Free(host);
	Free(dev);
	return fd;

FAILED:
	if (host != NULL)
	{
		Format(args, sizeof(args), "%s destroy", host);
		MacOsIfconfig(args, false);
		Free(host);
	}
	if (dev != NULL)
	{
		Format(args, sizeof(args), "%s destroy", dev);
		MacOsIfconfig(args, false);
		Free(dev);
	}
	return -1;
}

// Destroy the feth pair associated with the given bpf fd.
static void MacOsDestroyTap(int fd)
{
	UINT i;
	char args[MAX_SIZE];

	if (macos_feth_list == NULL)
	{
		return;
	}

	for (i = 0; i < LIST_NUM(macos_feth_list); i++)
	{
		MACOS_FETH_ENTRY *e = LIST_DATA(macos_feth_list, i);
		if (e->fd == fd)
		{
			Format(args, sizeof(args), "%s destroy", e->host);
			MacOsIfconfig(args, false);
			Format(args, sizeof(args), "%s destroy", e->dev);
			MacOsIfconfig(args, false);
			if (e->BpfBuffer != NULL)
			{
				Free(e->BpfBuffer);
			}
			Delete(macos_feth_list, e);
			Free(e);
			break;
		}
	}
}

#endif	// UNIX_MACOS

// Create a tap device
int UnixCreateTapDeviceEx(char *name, char *prefix, UCHAR *mac_address, bool create_up)
{
	int fd = -1, s = -1;
	char tap_name[MAX_SIZE], tap_path[MAX_SIZE];
	struct ifreq ifr;

	// Validate arguments
	if (name == NULL)
	{
		return -1;
	}

	GenerateTunName(name, prefix, tap_name, sizeof(tap_name));

	// Open the tun / tap
#ifndef	UNIX_BSD
	if (GetOsInfo()->OsType == OSTYPE_LINUX)
	{
		// Linux
		if (IsFile(TAP_FILENAME_1) == false)
		{
			char tmp[MAX_SIZE];

			Format(tmp, sizeof(tmp), "%s c 10 200", TAP_FILENAME_1);
			Run("mknod", tmp, true, true);

			Format(tmp, sizeof(tmp), "600 %s", TAP_FILENAME_1);
			Run("chmod", tmp, true, true);
		}
	}

	fd = open(TAP_FILENAME_1, O_RDWR);
	if (fd == -1)
	{
		// Failure
		fd = open(TAP_FILENAME_2, O_RDWR);
		if (fd == -1)
		{
			return -1;
		}
	}
#else	// UNIX_BSD
	{
		sprintf(tap_path, "%s", TAP_DIR TAP_NAME);
		for (int i = 0; i < TAP_MAX; i++) {
			sprintf(tap_path + StrLen(TAP_DIR TAP_NAME), "%d", i);
			fd = open(tap_path, O_RDWR);
			if (fd != -1)
			{
				break;
			}
		}

		if (fd == -1)
		{
#ifdef	UNIX_MACOS
			// No tap kext (e.g. Apple Silicon): build the L2 endpoint from a
			// feth pair + BPF instead (no kext required).
			return MacOsCreateTap(mac_address);
#else	// UNIX_MACOS
			return -1;
#endif	// UNIX_MACOS
		}
	}
#endif	// UNIX_BSD

#ifdef	UNIX_LINUX
	// Create a TAP device for Linux

	// Set the name and the flags
	Zero(&ifr, sizeof(ifr));
	StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), tap_name);
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	if (ioctl(fd, TUNSETIFF, &ifr) == -1)
	{
		// Failure
		close(fd);
		return -1;
	}

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s != -1)
	{
		// Set the MAC address
		if (mac_address != NULL)
		{
			Zero(&ifr, sizeof(ifr));
			StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), tap_name);
			ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
			Copy(&ifr.ifr_hwaddr.sa_data, mac_address, ETHER_ADDR_LEN);
			ioctl(s, SIOCSIFHWADDR, &ifr);
		}

		if (create_up)
		{
			Zero(&ifr, sizeof(ifr));
			StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), tap_name);
			ioctl(s, SIOCGIFFLAGS, &ifr);
			ifr.ifr_flags |= IFF_UP;
			ioctl(s, SIOCSIFFLAGS, &ifr);
		}

		close(s);
	}
#endif	// UNIX_LINUX

#ifdef	UNIX_BSD
	// Create a TAP device for BSD
	Zero(&ifr, sizeof(ifr));

	// Get the current name
	StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), tap_path + StrLen(TAP_DIR));

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s != -1)
	{
		// Set the name, if possible
#ifdef	SIOCSIFNAME
		ifr.ifr_data = tap_name;
		ioctl(s, SIOCSIFNAME, &ifr);
#else	// SIOCSIFNAME
		StrCpy(tap_name, sizeof(tap_name), ifr.ifr_name);
#endif	// SIOCSIFNAME

		// Set the MAC address
		if (mac_address != NULL)
		{
			Zero(&ifr, sizeof(ifr));
			StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), tap_name);
			ifr.ifr_addr.sa_len = ETHER_ADDR_LEN;
			ifr.ifr_addr.sa_family = AF_LINK;
			Copy(&ifr.ifr_addr.sa_data, mac_address, ETHER_ADDR_LEN);
			ioctl(s, SIOCSIFLLADDR, &ifr);
		}

		// Set interface description
#ifdef	SIOCSIFDESCR
		{
			char desc[] = CEDAR_PRODUCT_STR " Virtual Network Adapter";

			ifr.ifr_buffer.buffer = desc;
			ifr.ifr_buffer.length = StrLen(desc) + 1;
			ioctl(s, SIOCSIFDESCR, &ifr);
		}
#endif

		// Set interface group
		UnixSetIfGroup(s, tap_name, CEDAR_PRODUCT_STR);

		if (create_up)
		{
			Zero(&ifr, sizeof(ifr));
			StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), tap_name);
			ioctl(s, SIOCGIFFLAGS, &ifr);
			ifr.ifr_flags |= IFF_UP;
			ioctl(s, SIOCSIFFLAGS, &ifr);
		}

		close(s);
	}
#endif	// UNIX_BSD

#ifdef	UNIX_SOLARIS
	// Create a TAP device for Solaris
	{
		int ip_fd;
		int tun_fd;
		int ppa;

		tun_fd = open(tap_name, O_RDWR);
		if (tun_fd == -1)
		{
			// Failure
			close(fd);
			return -1;
		}

		ip_fd = open("/dev/ip", O_RDWR);
		if (ip_fd == -1)
		{
			// Failure
			close(tun_fd);
			close(fd);
			return -1;
		}

		ppa = -1;
		ppa = ioctl(tun_fd, TUNNEWPPA, ppa);
		if (ppa == -1)
		{
			// Failure
			close(tun_fd);
			close(fd);
			close(ip_fd);
			return -1;
		}

		if (ioctl(fd, I_PUSH, "ip") < 0)
		{
			// Failure
			close(tun_fd);
			close(fd);
			close(ip_fd);
			return -1;
		}

		if (ioctl(fd, IF_UNITSEL, (char *)&ppa) < 0)
		{
			// Failure
			close(tun_fd);
			close(fd);
			close(ip_fd);
			return -1;
		}

		if (ioctl(ip_fd, I_LINK, fd) < 0)
		{
			// Failure
			close(tun_fd);
			close(fd);
			close(ip_fd);
			return -1;
		}

		close(tun_fd);
		close(ip_fd);
	}
#endif	// UNIX_SOLARIS

	return fd;
}
int UnixCreateTapDevice(char *name, UCHAR *mac_address, bool create_up)
{
	return UnixCreateTapDeviceEx(name, UNIX_VLAN_CLIENT_IFACE_PREFIX, mac_address, create_up);
}

// Close the tap device
void UnixCloseTapDevice(int fd)
{
	// Validate arguments
	if (fd == -1)
	{
		return;
	}

#ifdef	UNIX_MACOS
	// Tear down the feth pair backing this bpf descriptor
	MacOsDestroyTap(fd);
#endif	// UNIX_MACOS

	close(fd);
}

// Destroy the tap device (for FreeBSD)
// FreeBSD tap device is still plumbed after closing fd so need to destroy after close
void UnixDestroyTapDeviceEx(char *name, char *prefix)
{
#ifdef UNIX_BSD
	struct ifreq ifr;
	char eth_name[MAX_SIZE];
	int s;

	Zero(&ifr, sizeof(ifr));
	GenerateTunName(name, prefix, eth_name, sizeof(eth_name));
	StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), eth_name);

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s == -1)
	{
		return;
	}
	ioctl(s, SIOCIFDESTROY, &ifr);

	close(s);
#endif	// UNIX_BSD
}

void UnixDestroyBridgeTapDevice(char *name)
{
#ifdef UNIX_BSD
	UnixDestroyTapDeviceEx(name, UNIX_VLAN_BRIDGE_IFACE_PREFIX);
#endif	// UNIX_BSD
}

void UnixDestroyClientTapDevice(char *name)
{
#ifdef UNIX_BSD
	UnixDestroyTapDeviceEx(name, UNIX_VLAN_CLIENT_IFACE_PREFIX);
#endif	// UNIX_BSD
}

void UnixSetIfGroup(int fd, const char *name, const char *group_name)
{
#ifdef	SIOCAIFGROUP
	struct ifgroupreq ifgr;
	char *tmp;

	tmp = CopyStr((char *)group_name);
	StrLower(tmp);
	Zero(&ifgr, sizeof(ifgr));

	StrCpy(ifgr.ifgr_name, sizeof(ifgr.ifgr_name), (char *) name);
	StrCpy(ifgr.ifgr_group, sizeof(ifgr.ifgr_group), tmp);
	ioctl(fd, SIOCAIFGROUP, &ifgr);

	Free(tmp);
#endif
}

#else	// NO_VLAN

void UnixCloseDevice(int fd)
{
}

void UnixDestroyTapDevice(char *name)
{
}

void UnixDestroyTapDeviceEx(char *name, char *prefix)
{
}

void UnixSetIfGroup()
{
}

int UnixCreateTapDeviceEx(char *name, char *prefix, UCHAR *mac_address, bool create_up)
{
	return -1;
}
int UnixCreateTapDevice(char *name, UCHAR *mac_address, bool create_up)
{
	return -1;
}

#endif	// NO_VLAN

// Comparison of the VLAN list entries
int UnixCompareVLan(void *p1, void *p2)
{
	UNIX_VLAN_LIST *v1, *v2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	v1 = *(UNIX_VLAN_LIST **)p1;
	v2 = *(UNIX_VLAN_LIST **)p2;
	if (v1 == NULL || v2 == NULL)
	{
		return 0;
	}

	return StrCmpi(v1->Name, v2->Name);
}

// Initialize the VLAN list
void UnixVLanInit()
{
	unix_vlan = NewList(UnixCompareVLan);
}

// Create a VLAN
bool UnixVLanCreateEx(char *name, char *prefix, UCHAR *mac_address, bool create_up)
{
	// Validate arguments
	char tmp[MAX_SIZE];
	if (name == NULL)
	{
		return false;
	}

	StrCpy(tmp, sizeof(tmp), name);
	Trim(tmp);
	name = tmp;

	LockList(unix_vlan);
	{
		UNIX_VLAN_LIST *t, tt;
		int fd;

		// Check whether a device with the same name exists
		Zero(&tt, sizeof(tt));
		StrCpy(tt.Name, sizeof(tt.Name), name);

		t = Search(unix_vlan, &tt);
		if (t != NULL)
		{
			// Already exist
			UnlockList(unix_vlan);
			return false;
		}

		// Create a tap device
		fd = UnixCreateTapDeviceEx(name, prefix, mac_address, create_up);
		if (fd == -1)
		{
			// Failure to create
			UnlockList(unix_vlan);
			return false;
		}

		t = ZeroMalloc(sizeof(UNIX_VLAN_LIST));
		t->fd = fd;
		StrCpy(t->Name, sizeof(t->Name), name);

		Insert(unix_vlan, t);
	}
	UnlockList(unix_vlan);

	return true;
}
bool UnixVLanCreate(char *name, UCHAR *mac_address, bool create_up)
{
	return UnixVLanCreateEx(name, UNIX_VLAN_CLIENT_IFACE_PREFIX, mac_address, create_up);
}

// Set a VLAN up/down
bool UnixVLanSetState(char* name, bool state_up)
{
#if defined(UNIX_LINUX) || defined(UNIX_BSD)
	UNIX_VLAN_LIST *t, tt;
	struct ifreq ifr;
	int s;
	char eth_name[MAX_SIZE];

	LockList(unix_vlan);
	{
		int result;
		// Find a device with the same name
		Zero(&tt, sizeof(tt));
		StrCpy(tt.Name, sizeof(tt.Name), name);

		t = Search(unix_vlan, &tt);
		if (t == NULL)
		{
			// No such device
			UnlockList(unix_vlan);
			return false;
		}

		GenerateTunName(name, UNIX_VLAN_CLIENT_IFACE_PREFIX, eth_name, sizeof(eth_name));
		Zero(&ifr, sizeof(ifr));
		StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), eth_name);

		s = socket(AF_INET, SOCK_DGRAM, 0);
		if (s == -1)
		{
			// Failed to create socket
			UnlockList(unix_vlan);
			return false;
		}

		ioctl(s, SIOCGIFFLAGS, &ifr);
		if (state_up)
		{
			ifr.ifr_flags |= IFF_UP;
		}
		else
		{
			ifr.ifr_flags &= ~IFF_UP;
		}
		result = ioctl(s, SIOCSIFFLAGS, &ifr);
		close(s);
	}
	UnlockList(unix_vlan);
#endif // UNIX_LINUX || UNIX_BSD

	return true;
}

// Enumerate VLANs
TOKEN_LIST *UnixVLanEnum()
{
	TOKEN_LIST *ret;
	UINT i;
	if (unix_vlan == NULL)
	{
		return NullToken();
	}

	ret = ZeroMalloc(sizeof(TOKEN_LIST));

	LockList(unix_vlan);
	{
		ret->NumTokens = LIST_NUM(unix_vlan);
		ret->Token = ZeroMalloc(sizeof(char *) * ret->NumTokens);

		for (i = 0;i < ret->NumTokens;i++)
		{
			UNIX_VLAN_LIST *t = LIST_DATA(unix_vlan, i);

			ret->Token[i] = CopyStr(t->Name);
		}
	}
	UnlockList(unix_vlan);

	return ret;
}

// Delete the VLAN
void UnixVLanDelete(char *name)
{
	// Validate arguments
	if (name == NULL || unix_vlan == NULL)
	{
		return;
	}

	LockList(unix_vlan);
	{
		UINT i;
		UNIX_VLAN_LIST *t, tt;

		Zero(&tt, sizeof(tt));
		StrCpy(tt.Name, sizeof(tt.Name), name);

		t = Search(unix_vlan, &tt);
		if (t != NULL)
		{
			UnixCloseTapDevice(t->fd);
#ifdef UNIX_BSD
			UnixDestroyClientTapDevice(t->Name);
#endif
			Delete(unix_vlan, t);
			Free(t);
		}
	}
	UnlockList(unix_vlan);
}

// Get the VLAN
int UnixVLanGet(char *name)
{
	int fd = -1;
	// Validate arguments
	if (name == NULL || unix_vlan == NULL)
	{
		return -1;
	}

	LockList(unix_vlan);
	{
		UINT i;
		UNIX_VLAN_LIST *t, tt;

		Zero(&tt, sizeof(tt));
		StrCpy(tt.Name, sizeof(tt.Name), name);

		t = Search(unix_vlan, &tt);
		if (t != NULL)
		{
			fd = t->fd;
		}
	}
	UnlockList(unix_vlan);

	return fd;
}

// Release the VLAN list
void UnixVLanFree()
{
	UINT i;

	for (i = 0;i < LIST_NUM(unix_vlan);i++)
	{
		UNIX_VLAN_LIST *t = LIST_DATA(unix_vlan, i);

		UnixCloseTapDevice(t->fd);
#ifdef UNIX_BSD
		UnixDestroyClientTapDevice(t->Name);
#endif
		Free(t);
	}

	ReleaseList(unix_vlan);
	unix_vlan = NULL;
}

#endif
