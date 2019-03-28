/* ipr_internal.h */

#ifndef IPR_INTERNAL_H
#define IPR_INTERNAL_H

#include "ipr.h"

/* PG version dependencies xxxxx */

#define INET_STRUCT_DATA(is_) ((inet_struct *)VARDATA_ANY(is_))

#define GISTENTRYCOUNT(v) ((v)->n)
#define GISTENTRYVEC(v) ((v)->vector)

/* hash_any_extended is new in pg11. On older pg, we don't care about what the
 * extended hash functions return, so just fake it.
 */

#if PG_VERSION_NUM < 110000

#ifndef ERRCODE_INVALID_PRECEDING_OR_FOLLOWING_SIZE
#define ERRCODE_INVALID_PRECEDING_OR_FOLLOWING_SIZE MAKE_SQLSTATE('2','2','0','1','3')
#endif

#ifndef DatumGetUInt64
#define DatumGetUInt64(d_) ((uint64) DatumGetInt64(d_))
#endif

#include "access/hash.h"

static inline
Datum hash_any_extended(register const unsigned char *k,
						register int keylen, uint64 seed)
{
	Datum d = hash_any(k, keylen);
	PG_RETURN_INT64((int64)(uint32) DatumGetInt32(d));
}

#endif

/* funcs */

Datum yip4_in(PG_FUNCTION_ARGS);
Datum yip4_out(PG_FUNCTION_ARGS);
Datum yip4_recv(PG_FUNCTION_ARGS);
Datum yip4_send(PG_FUNCTION_ARGS);
Datum yip4hash(PG_FUNCTION_ARGS);
Datum yip4_hash_extended(PG_FUNCTION_ARGS);
Datum yip4_cast_to_text(PG_FUNCTION_ARGS);
Datum yip4_cast_from_text(PG_FUNCTION_ARGS);
Datum yip4_cast_from_bit(PG_FUNCTION_ARGS);
Datum yip4_cast_to_bit(PG_FUNCTION_ARGS);
Datum yip4_cast_from_bytea(PG_FUNCTION_ARGS);
Datum yip4_cast_to_bytea(PG_FUNCTION_ARGS);
Datum yip4_cast_from_inet(PG_FUNCTION_ARGS);
Datum yip4_cast_to_cidr(PG_FUNCTION_ARGS);
Datum yip4_cast_to_bigint(PG_FUNCTION_ARGS);
Datum yip4_cast_to_numeric(PG_FUNCTION_ARGS);
Datum yip4_cast_from_bigint(PG_FUNCTION_ARGS);
Datum yip4_cast_from_numeric(PG_FUNCTION_ARGS);
Datum yip4_cast_to_double(PG_FUNCTION_ARGS);
Datum yip4_cast_from_double(PG_FUNCTION_ARGS);
Datum yip4r_in(PG_FUNCTION_ARGS);
Datum yip4r_out(PG_FUNCTION_ARGS);
Datum yip4r_recv(PG_FUNCTION_ARGS);
Datum yip4r_send(PG_FUNCTION_ARGS);
Datum yip4rhash(PG_FUNCTION_ARGS);
Datum yip4r_hash_extended(PG_FUNCTION_ARGS);
Datum yip4r_cast_to_text(PG_FUNCTION_ARGS);
Datum yip4r_cast_from_text(PG_FUNCTION_ARGS);
Datum yip4r_cast_from_bit(PG_FUNCTION_ARGS);
Datum yip4r_cast_to_bit(PG_FUNCTION_ARGS);
Datum yip4r_cast_from_cidr(PG_FUNCTION_ARGS);
Datum yip4r_cast_to_cidr(PG_FUNCTION_ARGS);
Datum yip4r_cast_from_ip4(PG_FUNCTION_ARGS);
Datum yip4r_from_ip4s(PG_FUNCTION_ARGS);
Datum yip4r_net_prefix(PG_FUNCTION_ARGS);
Datum yip4r_net_mask(PG_FUNCTION_ARGS);
Datum yip4r_lower(PG_FUNCTION_ARGS);
Datum yip4r_upper(PG_FUNCTION_ARGS);
Datum yip4r_is_cidr(PG_FUNCTION_ARGS);
Datum yip4r_cidr_split(PG_FUNCTION_ARGS);
Datum yip4_netmask(PG_FUNCTION_ARGS);
Datum yip4_net_lower(PG_FUNCTION_ARGS);
Datum yip4_net_upper(PG_FUNCTION_ARGS);
Datum yip4_plus_int(PG_FUNCTION_ARGS);
Datum yip4_plus_bigint(PG_FUNCTION_ARGS);
Datum yip4_plus_numeric(PG_FUNCTION_ARGS);
Datum yip4_minus_int(PG_FUNCTION_ARGS);
Datum yip4_minus_bigint(PG_FUNCTION_ARGS);
Datum yip4_minus_numeric(PG_FUNCTION_ARGS);
Datum yip4_minus_ip4(PG_FUNCTION_ARGS);
Datum yip4_and(PG_FUNCTION_ARGS);
Datum yip4_or(PG_FUNCTION_ARGS);
Datum yip4_xor(PG_FUNCTION_ARGS);
Datum yip4_not(PG_FUNCTION_ARGS);
Datum yip4_lt(PG_FUNCTION_ARGS);
Datum yip4_le(PG_FUNCTION_ARGS);
Datum yip4_gt(PG_FUNCTION_ARGS);
Datum yip4_ge(PG_FUNCTION_ARGS);
Datum yip4_eq(PG_FUNCTION_ARGS);
Datum yip4_neq(PG_FUNCTION_ARGS);
Datum yip4r_lt(PG_FUNCTION_ARGS);
Datum yip4r_le(PG_FUNCTION_ARGS);
Datum yip4r_gt(PG_FUNCTION_ARGS);
Datum yip4r_ge(PG_FUNCTION_ARGS);
Datum yip4r_eq(PG_FUNCTION_ARGS);
Datum yip4r_neq(PG_FUNCTION_ARGS);
Datum yip4r_overlaps(PG_FUNCTION_ARGS);
Datum yip4r_contains(PG_FUNCTION_ARGS);
Datum yip4r_contains_strict(PG_FUNCTION_ARGS);
Datum yip4r_contained_by(PG_FUNCTION_ARGS);
Datum yip4r_contained_by_strict(PG_FUNCTION_ARGS);
Datum yip4_contains(PG_FUNCTION_ARGS);
Datum yip4_contained_by(PG_FUNCTION_ARGS);
Datum yip4r_union(PG_FUNCTION_ARGS);
Datum yip4r_inter(PG_FUNCTION_ARGS);
Datum yip4r_size(PG_FUNCTION_ARGS);
Datum yip4r_size_exact(PG_FUNCTION_ARGS);
Datum yip4r_prefixlen(PG_FUNCTION_ARGS);
Datum yip4r_cmp(PG_FUNCTION_ARGS);
Datum yip4_cmp(PG_FUNCTION_ARGS);
Datum yip4_in_range_bigint(PG_FUNCTION_ARGS);
Datum yip4_in_range_ip4(PG_FUNCTION_ARGS);
Datum yip4r_left_of(PG_FUNCTION_ARGS);
Datum yip4r_right_of(PG_FUNCTION_ARGS);

Datum yip6_in(PG_FUNCTION_ARGS);
Datum yip6_out(PG_FUNCTION_ARGS);
Datum yip6_recv(PG_FUNCTION_ARGS);
Datum yip6_send(PG_FUNCTION_ARGS);
Datum yip6hash(PG_FUNCTION_ARGS);
Datum yip6_hash_extended(PG_FUNCTION_ARGS);
Datum yip6_cast_to_text(PG_FUNCTION_ARGS);
Datum yip6_cast_from_text(PG_FUNCTION_ARGS);
Datum yip6_cast_from_bit(PG_FUNCTION_ARGS);
Datum yip6_cast_to_bit(PG_FUNCTION_ARGS);
Datum yip6_cast_from_bytea(PG_FUNCTION_ARGS);
Datum yip6_cast_to_bytea(PG_FUNCTION_ARGS);
Datum yip6_cast_from_inet(PG_FUNCTION_ARGS);
Datum yip6_cast_to_cidr(PG_FUNCTION_ARGS);
Datum yip6_cast_to_numeric(PG_FUNCTION_ARGS);
Datum yip6_cast_from_numeric(PG_FUNCTION_ARGS);
Datum yip6r_in(PG_FUNCTION_ARGS);
Datum yip6r_out(PG_FUNCTION_ARGS);
Datum yip6r_recv(PG_FUNCTION_ARGS);
Datum yip6r_send(PG_FUNCTION_ARGS);
Datum yip6rhash(PG_FUNCTION_ARGS);
Datum yip6r_hash_extended(PG_FUNCTION_ARGS);
Datum yip6r_cast_to_text(PG_FUNCTION_ARGS);
Datum yip6r_cast_from_text(PG_FUNCTION_ARGS);
Datum yip6r_cast_from_bit(PG_FUNCTION_ARGS);
Datum yip6r_cast_to_bit(PG_FUNCTION_ARGS);
Datum yip6r_cast_from_cidr(PG_FUNCTION_ARGS);
Datum yip6r_cast_to_cidr(PG_FUNCTION_ARGS);
Datum yip6r_cast_from_ip6(PG_FUNCTION_ARGS);
Datum yip6r_from_ip6s(PG_FUNCTION_ARGS);
Datum yip6r_net_prefix(PG_FUNCTION_ARGS);
Datum yip6r_net_mask(PG_FUNCTION_ARGS);
Datum yip6r_lower(PG_FUNCTION_ARGS);
Datum yip6r_upper(PG_FUNCTION_ARGS);
Datum yip6r_is_cidr(PG_FUNCTION_ARGS);
Datum yip6r_cidr_split(PG_FUNCTION_ARGS);
Datum yip6_netmask(PG_FUNCTION_ARGS);
Datum yip6_net_lower(PG_FUNCTION_ARGS);
Datum yip6_net_upper(PG_FUNCTION_ARGS);
Datum yip6_plus_int(PG_FUNCTION_ARGS);
Datum yip6_plus_bigint(PG_FUNCTION_ARGS);
Datum yip6_plus_numeric(PG_FUNCTION_ARGS);
Datum yip6_minus_int(PG_FUNCTION_ARGS);
Datum yip6_minus_bigint(PG_FUNCTION_ARGS);
Datum yip6_minus_numeric(PG_FUNCTION_ARGS);
Datum yip6_minus_ip6(PG_FUNCTION_ARGS);
Datum yip6_and(PG_FUNCTION_ARGS);
Datum yip6_or(PG_FUNCTION_ARGS);
Datum yip6_xor(PG_FUNCTION_ARGS);
Datum yip6_not(PG_FUNCTION_ARGS);
Datum yip6_lt(PG_FUNCTION_ARGS);
Datum yip6_le(PG_FUNCTION_ARGS);
Datum yip6_gt(PG_FUNCTION_ARGS);
Datum yip6_ge(PG_FUNCTION_ARGS);
Datum yip6_eq(PG_FUNCTION_ARGS);
Datum yip6_neq(PG_FUNCTION_ARGS);
Datum yip6r_lt(PG_FUNCTION_ARGS);
Datum yip6r_le(PG_FUNCTION_ARGS);
Datum yip6r_gt(PG_FUNCTION_ARGS);
Datum yip6r_ge(PG_FUNCTION_ARGS);
Datum yip6r_eq(PG_FUNCTION_ARGS);
Datum yip6r_neq(PG_FUNCTION_ARGS);
Datum yip6r_overlaps(PG_FUNCTION_ARGS);
Datum yip6r_contains(PG_FUNCTION_ARGS);
Datum yip6r_contains_strict(PG_FUNCTION_ARGS);
Datum yip6r_contained_by(PG_FUNCTION_ARGS);
Datum yip6r_contained_by_strict(PG_FUNCTION_ARGS);
Datum yip6_contains(PG_FUNCTION_ARGS);
Datum yip6_contained_by(PG_FUNCTION_ARGS);
Datum yip6r_union(PG_FUNCTION_ARGS);
Datum yip6r_inter(PG_FUNCTION_ARGS);
Datum yip6r_size(PG_FUNCTION_ARGS);
Datum yip6r_size_exact(PG_FUNCTION_ARGS);
Datum yip6r_prefixlen(PG_FUNCTION_ARGS);
Datum yip6r_cmp(PG_FUNCTION_ARGS);
Datum yip6_cmp(PG_FUNCTION_ARGS);
Datum yip6_in_range_bigint(PG_FUNCTION_ARGS);
Datum yip6_in_range_ip6(PG_FUNCTION_ARGS);
#if 0
Datum yip6_in_range_numeric(PG_FUNCTION_ARGS);
#endif
Datum yip6r_left_of(PG_FUNCTION_ARGS);
Datum yip6r_right_of(PG_FUNCTION_ARGS);

Datum yipaddr_in(PG_FUNCTION_ARGS);
Datum yipaddr_out(PG_FUNCTION_ARGS);
Datum yipaddr_recv(PG_FUNCTION_ARGS);
Datum yipaddr_send(PG_FUNCTION_ARGS);
Datum yipaddr_hash(PG_FUNCTION_ARGS);
Datum yipaddr_hash_extended(PG_FUNCTION_ARGS);
Datum yipaddr_cast_to_text(PG_FUNCTION_ARGS);
Datum yipaddr_cast_from_text(PG_FUNCTION_ARGS);
Datum yipaddr_cast_from_bit(PG_FUNCTION_ARGS);
Datum yipaddr_cast_to_bit(PG_FUNCTION_ARGS);
Datum yipaddr_cast_from_bytea(PG_FUNCTION_ARGS);
Datum yipaddr_cast_to_bytea(PG_FUNCTION_ARGS);
Datum yipaddr_cast_from_inet(PG_FUNCTION_ARGS);
Datum yipaddr_cast_to_cidr(PG_FUNCTION_ARGS);
Datum yipaddr_cast_to_numeric(PG_FUNCTION_ARGS);
Datum yipaddr_cast_from_ip4(PG_FUNCTION_ARGS);
Datum yipaddr_cast_from_ip6(PG_FUNCTION_ARGS);
Datum yipaddr_cast_to_ip4(PG_FUNCTION_ARGS);
Datum yipaddr_cast_to_ip6(PG_FUNCTION_ARGS);
Datum yipaddr_net_lower(PG_FUNCTION_ARGS);
Datum yipaddr_net_upper(PG_FUNCTION_ARGS);
Datum yipaddr_family(PG_FUNCTION_ARGS);
Datum yipaddr_plus_int(PG_FUNCTION_ARGS);
Datum yipaddr_plus_bigint(PG_FUNCTION_ARGS);
Datum yipaddr_plus_numeric(PG_FUNCTION_ARGS);
Datum yipaddr_minus_int(PG_FUNCTION_ARGS);
Datum yipaddr_minus_bigint(PG_FUNCTION_ARGS);
Datum yipaddr_minus_numeric(PG_FUNCTION_ARGS);
Datum yipaddr_minus_ipaddr(PG_FUNCTION_ARGS);
Datum yipaddr_and(PG_FUNCTION_ARGS);
Datum yipaddr_or(PG_FUNCTION_ARGS);
Datum yipaddr_xor(PG_FUNCTION_ARGS);
Datum yipaddr_not(PG_FUNCTION_ARGS);
Datum yipaddr_lt(PG_FUNCTION_ARGS);
Datum yipaddr_le(PG_FUNCTION_ARGS);
Datum yipaddr_gt(PG_FUNCTION_ARGS);
Datum yipaddr_ge(PG_FUNCTION_ARGS);
Datum yipaddr_eq(PG_FUNCTION_ARGS);
Datum yipaddr_neq(PG_FUNCTION_ARGS);
Datum yipaddr_cmp(PG_FUNCTION_ARGS);

Datum yiprange_in(PG_FUNCTION_ARGS);
Datum yiprange_out(PG_FUNCTION_ARGS);
Datum yiprange_recv(PG_FUNCTION_ARGS);
Datum yiprange_send(PG_FUNCTION_ARGS);
Datum yiprange_hash(PG_FUNCTION_ARGS);
Datum yiprange_hash_new(PG_FUNCTION_ARGS);
Datum yiprange_hash_extended(PG_FUNCTION_ARGS);
Datum yiprange_cast_to_text(PG_FUNCTION_ARGS);
Datum yiprange_cast_from_text(PG_FUNCTION_ARGS);
Datum yiprange_cast_from_cidr(PG_FUNCTION_ARGS);
Datum yiprange_cast_to_cidr(PG_FUNCTION_ARGS);
Datum yiprange_cast_to_bit(PG_FUNCTION_ARGS);
Datum yiprange_cast_from_ip4(PG_FUNCTION_ARGS);
Datum yiprange_cast_from_ip6(PG_FUNCTION_ARGS);
Datum yiprange_cast_from_ipaddr(PG_FUNCTION_ARGS);
Datum yiprange_cast_from_ip4r(PG_FUNCTION_ARGS);
Datum yiprange_cast_from_ip6r(PG_FUNCTION_ARGS);
Datum yiprange_cast_to_ip4r(PG_FUNCTION_ARGS);
Datum yiprange_cast_to_ip6r(PG_FUNCTION_ARGS);
Datum yiprange_from_ip4s(PG_FUNCTION_ARGS);
Datum yiprange_from_ip6s(PG_FUNCTION_ARGS);
Datum yiprange_from_ipaddrs(PG_FUNCTION_ARGS);
Datum yiprange_net_prefix_ip4(PG_FUNCTION_ARGS);
Datum yiprange_net_prefix_ip6(PG_FUNCTION_ARGS);
Datum yiprange_net_prefix(PG_FUNCTION_ARGS);
Datum yiprange_net_mask_ip4(PG_FUNCTION_ARGS);
Datum yiprange_net_mask_ip6(PG_FUNCTION_ARGS);
Datum yiprange_net_mask(PG_FUNCTION_ARGS);
Datum yiprange_lower(PG_FUNCTION_ARGS);
Datum yiprange_upper(PG_FUNCTION_ARGS);
Datum yiprange_is_cidr(PG_FUNCTION_ARGS);
Datum yiprange_family(PG_FUNCTION_ARGS);
Datum yiprange_cidr_split(PG_FUNCTION_ARGS);
Datum yiprange_lt(PG_FUNCTION_ARGS);
Datum yiprange_le(PG_FUNCTION_ARGS);
Datum yiprange_gt(PG_FUNCTION_ARGS);
Datum yiprange_ge(PG_FUNCTION_ARGS);
Datum yiprange_eq(PG_FUNCTION_ARGS);
Datum yiprange_neq(PG_FUNCTION_ARGS);
Datum yiprange_overlaps(PG_FUNCTION_ARGS);
Datum yiprange_contains(PG_FUNCTION_ARGS);
Datum yiprange_contains_strict(PG_FUNCTION_ARGS);
Datum yiprange_contained_by(PG_FUNCTION_ARGS);
Datum yiprange_contained_by_strict(PG_FUNCTION_ARGS);
Datum yiprange_contains_ip(PG_FUNCTION_ARGS);
Datum yiprange_contains_ip4(PG_FUNCTION_ARGS);
Datum yiprange_contains_ip6(PG_FUNCTION_ARGS);
Datum yiprange_ip_contained_by(PG_FUNCTION_ARGS);
Datum yiprange_ip4_contained_by(PG_FUNCTION_ARGS);
Datum yiprange_ip6_contained_by(PG_FUNCTION_ARGS);
Datum yiprange_union(PG_FUNCTION_ARGS);
Datum yiprange_inter(PG_FUNCTION_ARGS);
Datum yiprange_size(PG_FUNCTION_ARGS);
Datum yiprange_size_exact(PG_FUNCTION_ARGS);
Datum yiprange_prefixlen(PG_FUNCTION_ARGS);
Datum yiprange_cmp(PG_FUNCTION_ARGS);

#endif
