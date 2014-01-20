#ifndef _LINUX_IF_TRILL_H_
#define _LINUX_IF_TRILL_H_

#include <linux/types.h>

/*
 * trill_hdr structure
 *                                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                                | V | R |M|op-Length| Hop Count |
 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *|  Egress RBridge Nickname      |    Ingress RBridge Nickname   |
 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct trill_hdr {
  __be16          th_flags;
  __be16          th_egressnick;
  __be16          th_ingressnick;
} __attribute__((packed));

static inline u16 trill_get_version(u16 trill_flags)
{
  return ((trill_flags >> 14) & 0x0003);
}

static inline u16 trill_set_version(u16 v)
{
  return (v << 14);
}

static inline u16 trill_get_reserved(u16 trill_flags)
{
  return ((trill_flags >> 12) & 0x0003);
}

static inline u16 trill_set_reserved(u16 v)
{
  return (v << 12);
}

static inline u16 trill_get_multidest(u16 trill_flags)
{
  return ((trill_flags >> 11) & 0x0001);
}

static inline u16 trill_set_multidest(u16 flag)
{
  return (flag << 11);
}

static inline size_t trill_get_optslen(u16 trill_flags)
{
  return ((trill_flags & (0x001F << 6)) >> (6 - 2));
}

static inline u16 trill_set_optslen(u16 len)
{
  return (len << (6 - 2));
}

static inline u16 trill_get_hopcount(u16 trill_flags)
{
  return (trill_flags & 0x003F);
}

static inline u16 trill_set_hopcount(u16 count)
{
  return (count);
}

static inline void trillhdr_dec_hopcount(struct trill_hdr *trh)
{
  u8 *flags = (u8 *) &(trh->th_flags);
  if (flags[1] & 0x3F)
    flags[1] -= 1;
}
static inline size_t trill_header_len(struct trill_hdr *trh)
{
  return (sizeof(*trh) + trill_get_optslen(ntohs(trh->th_flags)));
}

/*trill_option structure
 *
 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *|Crit.|  CHbH   |   NCHbH   |CRSV | NCRSV |   CItE    |  NCItE  |
 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *|            Reserved             |          Flow ID            |
 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
struct trill_opt{
  __be32 opt_flag;
  __be32 opt_flow;
};

static inline u32 trill_opt_get_crit(u32 opt_flag)
{
  return ((opt_flag >> 29) & 0x00000007);
}

static inline u32 trill_opt_set_crit(u32 opt_flag)
{
  return ((opt_flag << 29) & 0xE0000000);
}

static inline u32 trill_opt_get_chbh(u32 opt_flag)
{
  return ((opt_flag >> 24) & 0x0000001F);
}

static inline u32 trill_opt_set_chbh(u32 opt_flag)
{
  return ((opt_flag << 24) & 0x1F000000);
}

static inline u32 trill_opt_get_nchbh(u32 opt_flag)
{
  return ((opt_flag >> 18) & 0x0000003F);
}

static inline u32 trill_opt_set_nchbh(u32 opt_flag)
{
  return ((opt_flag << 18) & 0xFC000000);
}

static inline u32 trill_opt_get_crsv(u32 opt_flag)
{
  return ((opt_flag >> 15) & 0x00000007);
}

static inline u32 trill_opt_set_crsv(u32 opt_flag)
{
  return ((opt_flag << 15) & 0x03800000);
}

static inline u32 trill_opt_get_ncrsv(u32 opt_flag)
{
  return ((opt_flag >> 11) & 0x0000000F);
}

static inline u32 trill_opt_set_ncrsv(u32 opt_flag)
{
  return ((opt_flag << 11) & 0x00007800);
}

static inline u32 trill_opt_get_cite(u32 opt_flag)
{
  return ((opt_flag >> 5) & 0x0000003F);
}

static inline u32 trill_opt_set_cite(u32 opt_flag)
{
  return ((opt_flag << 5) & 0x000007E0);
}

static inline u32 trill_opt_get_ncite(u32 opt_flag)
{
  return (opt_flag & 0x0000001F);
}

static inline u32 trill_opt_set_ncite(u32 opt_flag)
{
  return (opt_flag & 0x0000001F);
}

static inline u32 trill_opt_get_resv(u32 opt_flow)
{
  return ((opt_flow >> 14) & 0x0003FFFF);
}

static inline u32 trill_opt_set_resv(u32 opt_flow)
{
  return ((opt_flow << 14) & 0xFFFC0000);
}

static inline u32 trill_opt_get_flow(u32 opt_flow)
{
  return (opt_flow  & 0x00003FFF);
}

static inline u32 trill_opt_set_flow(u32 opt_flow)
{
  return (opt_flow & 0x00003FFF);
}
#endif /* !(_LINUX_IF_TRILL_H_) */