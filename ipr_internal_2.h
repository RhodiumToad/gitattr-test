/* ipr_internal.h */
#ifndef IPR_INTERNAL_H
#define IPR_INTERNAL_H

#include "ipr.h"

/* PG version dependencies x */

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

Datum xip4_in(PG_FUNCTION_ARGS);
Datum xip4_out(PG_FUNCTION_ARGS);
Datum xip4_recv(PG_FUNCTION_ARGS);
Datum xip4_send(PG_FUNCTION_ARGS);
Datum xip4hash(PG_FUNCTION_ARGS);
Datum xip4_hash_extended(PG_FUNCTION_ARGS);
Datum xip4_cast_to_text(PG_FUNCTION_ARGS);
Datum xip4_cast_from_text(PG_FUNCTION_ARGS);
Datum xip4_cast_from_bit(PG_FUNCTION_ARGS);
Datum xip4_cast_to_bit(PG_FUNCTION_ARGS);
Datum xip4_cast_from_bytea(PG_FUNCTION_ARGS);
Datum xip4_cast_to_bytea(PG_FUNCTION_ARGS);
Datum xip4_cast_from_inet(PG_FUNCTION_ARGS);
Datum xip4_cast_to_cidr(PG_FUNCTION_ARGS);
Datum xip4_cast_to_bigint(PG_FUNCTION_ARGS);
Datum xip4_cast_to_numeric(PG_FUNCTION_ARGS);
Datum xip4_cast_from_bigint(PG_FUNCTION_ARGS);
Datum xip4_cast_from_numeric(PG_FUNCTION_ARGS);
Datum xip4_cast_to_double(PG_FUNCTION_ARGS);
Datum xip4_cast_from_double(PG_FUNCTION_ARGS);
Datum xip4r_in(PG_FUNCTION_ARGS);
Datum xip4r_out(PG_FUNCTION_ARGS);
Datum xip4r_recv(PG_FUNCTION_ARGS);
Datum xip4r_send(PG_FUNCTION_ARGS);
Datum xip4rhash(PG_FUNCTION_ARGS);
Datum xip4r_hash_extended(PG_FUNCTION_ARGS);
Datum xip4r_cast_to_text(PG_FUNCTION_ARGS);
Datum xip4r_cast_from_text(PG_FUNCTION_ARGS);
Datum xip4r_cast_from_bit(PG_FUNCTION_ARGS);
Datum xip4r_cast_to_bit(PG_FUNCTION_ARGS);
Datum xip4r_cast_from_cidr(PG_FUNCTION_ARGS);
Datum xip4r_cast_to_cidr(PG_FUNCTION_ARGS);
Datum xip4r_cast_from_ip4(PG_FUNCTION_ARGS);
Datum xip4r_from_ip4s(PG_FUNCTION_ARGS);
Datum xip4r_net_prefix(PG_FUNCTION_ARGS);
Datum xip4r_net_mask(PG_FUNCTION_ARGS);
Datum xip4r_lower(PG_FUNCTION_ARGS);
Datum xip4r_upper(PG_FUNCTION_ARGS);
Datum xip4r_is_cidr(PG_FUNCTION_ARGS);
Datum xip4r_cidr_split(PG_FUNCTION_ARGS);
Datum xip4_netmask(PG_FUNCTION_ARGS);
Datum xip4_net_lower(PG_FUNCTION_ARGS);
Datum xip4_net_upper(PG_FUNCTION_ARGS);
Datum xip4_plus_int(PG_FUNCTION_ARGS);
Datum xip4_plus_bigint(PG_FUNCTION_ARGS);
Datum xip4_plus_numeric(PG_FUNCTION_ARGS);
Datum xip4_minus_int(PG_FUNCTION_ARGS);
Datum xip4_minus_bigint(PG_FUNCTION_ARGS);
Datum xip4_minus_numeric(PG_FUNCTION_ARGS);
Datum xip4_minus_ip4(PG_FUNCTION_ARGS);
Datum xip4_and(PG_FUNCTION_ARGS);
Datum xip4_or(PG_FUNCTION_ARGS);
Datum xip4_xor(PG_FUNCTION_ARGS);
Datum xip4_not(PG_FUNCTION_ARGS);
Datum xip4_lt(PG_FUNCTION_ARGS);
Datum xip4_le(PG_FUNCTION_ARGS);
Datum xip4_gt(PG_FUNCTION_ARGS);
Datum xip4_ge(PG_FUNCTION_ARGS);
Datum xip4_eq(PG_FUNCTION_ARGS);
Datum xip4_neq(PG_FUNCTION_ARGS);
Datum xip4r_lt(PG_FUNCTION_ARGS);
Datum xip4r_le(PG_FUNCTION_ARGS);
Datum xip4r_gt(PG_FUNCTION_ARGS);
Datum xip4r_ge(PG_FUNCTION_ARGS);
Datum xip4r_eq(PG_FUNCTION_ARGS);
Datum xip4r_neq(PG_FUNCTION_ARGS);
Datum xip4r_overlaps(PG_FUNCTION_ARGS);
Datum xip4r_contains(PG_FUNCTION_ARGS);
Datum xip4r_contains_strict(PG_FUNCTION_ARGS);
Datum xip4r_contained_by(PG_FUNCTION_ARGS);
Datum xip4r_contained_by_strict(PG_FUNCTION_ARGS);
Datum xip4_contains(PG_FUNCTION_ARGS);
Datum xip4_contained_by(PG_FUNCTION_ARGS);
Datum xip4r_union(PG_FUNCTION_ARGS);
Datum xip4r_inter(PG_FUNCTION_ARGS);
Datum xip4r_size(PG_FUNCTION_ARGS);
Datum xip4r_size_exact(PG_FUNCTION_ARGS);
Datum xip4r_prefixlen(PG_FUNCTION_ARGS);
Datum xip4r_cmp(PG_FUNCTION_ARGS);
Datum xip4_cmp(PG_FUNCTION_ARGS);
Datum xip4_in_range_bigint(PG_FUNCTION_ARGS);
Datum xip4_in_range_ip4(PG_FUNCTION_ARGS);
Datum xip4r_left_of(PG_FUNCTION_ARGS);
Datum xip4r_right_of(PG_FUNCTION_ARGS);

Datum xip6_in(PG_FUNCTION_ARGS);
Datum xip6_out(PG_FUNCTION_ARGS);
Datum xip6_recv(PG_FUNCTION_ARGS);
Datum xip6_send(PG_FUNCTION_ARGS);
Datum xip6hash(PG_FUNCTION_ARGS);
Datum xip6_hash_extended(PG_FUNCTION_ARGS);
Datum xip6_cast_to_text(PG_FUNCTION_ARGS);
Datum xip6_cast_from_text(PG_FUNCTION_ARGS);
Datum xip6_cast_from_bit(PG_FUNCTION_ARGS);
Datum xip6_cast_to_bit(PG_FUNCTION_ARGS);
Datum xip6_cast_from_bytea(PG_FUNCTION_ARGS);
Datum xip6_cast_to_bytea(PG_FUNCTION_ARGS);
Datum xip6_cast_from_inet(PG_FUNCTION_ARGS);
Datum xip6_cast_to_cidr(PG_FUNCTION_ARGS);
Datum xip6_cast_to_numeric(PG_FUNCTION_ARGS);
Datum xip6_cast_from_numeric(PG_FUNCTION_ARGS);
Datum xip6r_in(PG_FUNCTION_ARGS);
Datum xip6r_out(PG_FUNCTION_ARGS);
Datum xip6r_recv(PG_FUNCTION_ARGS);
Datum xip6r_send(PG_FUNCTION_ARGS);
Datum xip6rhash(PG_FUNCTION_ARGS);
Datum xip6r_hash_extended(PG_FUNCTION_ARGS);
Datum xip6r_cast_to_text(PG_FUNCTION_ARGS);
Datum xip6r_cast_from_text(PG_FUNCTION_ARGS);
Datum xip6r_cast_from_bit(PG_FUNCTION_ARGS);
Datum xip6r_cast_to_bit(PG_FUNCTION_ARGS);
Datum xip6r_cast_from_cidr(PG_FUNCTION_ARGS);
Datum xip6r_cast_to_cidr(PG_FUNCTION_ARGS);
Datum xip6r_cast_from_ip6(PG_FUNCTION_ARGS);
Datum xip6r_from_ip6s(PG_FUNCTION_ARGS);
Datum xip6r_net_prefix(PG_FUNCTION_ARGS);
Datum xip6r_net_mask(PG_FUNCTION_ARGS);
Datum xip6r_lower(PG_FUNCTION_ARGS);
Datum xip6r_upper(PG_FUNCTION_ARGS);
Datum xip6r_is_cidr(PG_FUNCTION_ARGS);
Datum xip6r_cidr_split(PG_FUNCTION_ARGS);
Datum xip6_netmask(PG_FUNCTION_ARGS);
Datum xip6_net_lower(PG_FUNCTION_ARGS);
Datum xip6_net_upper(PG_FUNCTION_ARGS);
Datum xip6_plus_int(PG_FUNCTION_ARGS);
Datum xip6_plus_bigint(PG_FUNCTION_ARGS);
Datum xip6_plus_numeric(PG_FUNCTION_ARGS);
Datum xip6_minus_int(PG_FUNCTION_ARGS);
Datum xip6_minus_bigint(PG_FUNCTION_ARGS);
Datum xip6_minus_numeric(PG_FUNCTION_ARGS);
Datum xip6_minus_ip6(PG_FUNCTION_ARGS);
Datum xip6_and(PG_FUNCTION_ARGS);
Datum xip6_or(PG_FUNCTION_ARGS);
Datum xip6_xor(PG_FUNCTION_ARGS);
Datum xip6_not(PG_FUNCTION_ARGS);
Datum xip6_lt(PG_FUNCTION_ARGS);
Datum xip6_le(PG_FUNCTION_ARGS);
Datum xip6_gt(PG_FUNCTION_ARGS);
Datum xip6_ge(PG_FUNCTION_ARGS);
Datum xip6_eq(PG_FUNCTION_ARGS);
Datum xip6_neq(PG_FUNCTION_ARGS);
Datum xip6r_lt(PG_FUNCTION_ARGS);
Datum xip6r_le(PG_FUNCTION_ARGS);
Datum xip6r_gt(PG_FUNCTION_ARGS);
Datum xip6r_ge(PG_FUNCTION_ARGS);
Datum xip6r_eq(PG_FUNCTION_ARGS);
Datum xip6r_neq(PG_FUNCTION_ARGS);
Datum xip6r_overlaps(PG_FUNCTION_ARGS);
Datum xip6r_contains(PG_FUNCTION_ARGS);
Datum xip6r_contains_strict(PG_FUNCTION_ARGS);
Datum xip6r_contained_by(PG_FUNCTION_ARGS);
Datum xip6r_contained_by_strict(PG_FUNCTION_ARGS);
Datum xip6_contains(PG_FUNCTION_ARGS);
Datum xip6_contained_by(PG_FUNCTION_ARGS);
Datum xip6r_union(PG_FUNCTION_ARGS);
Datum xip6r_inter(PG_FUNCTION_ARGS);
Datum xip6r_size(PG_FUNCTION_ARGS);
Datum xip6r_size_exact(PG_FUNCTION_ARGS);
Datum xip6r_prefixlen(PG_FUNCTION_ARGS);
Datum xip6r_cmp(PG_FUNCTION_ARGS);
Datum xip6_cmp(PG_FUNCTION_ARGS);
Datum xip6_in_range_bigint(PG_FUNCTION_ARGS);
Datum xip6_in_range_ip6(PG_FUNCTION_ARGS);
#if 0
Datum xip6_in_range_numeric(PG_FUNCTION_ARGS);
#endif
Datum xip6r_left_of(PG_FUNCTION_ARGS);
Datum xip6r_right_of(PG_FUNCTION_ARGS);

Datum xipaddr_in(PG_FUNCTION_ARGS);
Datum xipaddr_out(PG_FUNCTION_ARGS);
Datum xipaddr_recv(PG_FUNCTION_ARGS);
Datum xipaddr_send(PG_FUNCTION_ARGS);
Datum xipaddr_hash(PG_FUNCTION_ARGS);
Datum xipaddr_hash_extended(PG_FUNCTION_ARGS);
Datum xipaddr_cast_to_text(PG_FUNCTION_ARGS);
Datum xipaddr_cast_from_text(PG_FUNCTION_ARGS);
Datum xipaddr_cast_from_bit(PG_FUNCTION_ARGS);
Datum xipaddr_cast_to_bit(PG_FUNCTION_ARGS);
Datum xipaddr_cast_from_bytea(PG_FUNCTION_ARGS);
Datum xipaddr_cast_to_bytea(PG_FUNCTION_ARGS);
Datum xipaddr_cast_from_inet(PG_FUNCTION_ARGS);
Datum xipaddr_cast_to_cidr(PG_FUNCTION_ARGS);
Datum xipaddr_cast_to_numeric(PG_FUNCTION_ARGS);
Datum xipaddr_cast_from_ip4(PG_FUNCTION_ARGS);
Datum xipaddr_cast_from_ip6(PG_FUNCTION_ARGS);
Datum xipaddr_cast_to_ip4(PG_FUNCTION_ARGS);
Datum xipaddr_cast_to_ip6(PG_FUNCTION_ARGS);
Datum xipaddr_net_lower(PG_FUNCTION_ARGS);
Datum xipaddr_net_upper(PG_FUNCTION_ARGS);
Datum xipaddr_family(PG_FUNCTION_ARGS);
Datum xipaddr_plus_int(PG_FUNCTION_ARGS);
Datum xipaddr_plus_bigint(PG_FUNCTION_ARGS);
Datum xipaddr_plus_numeric(PG_FUNCTION_ARGS);
Datum xipaddr_minus_int(PG_FUNCTION_ARGS);
Datum xipaddr_minus_bigint(PG_FUNCTION_ARGS);
Datum xipaddr_minus_numeric(PG_FUNCTION_ARGS);
Datum xipaddr_minus_ipaddr(PG_FUNCTION_ARGS);
Datum xipaddr_and(PG_FUNCTION_ARGS);
Datum xipaddr_or(PG_FUNCTION_ARGS);
Datum xipaddr_xor(PG_FUNCTION_ARGS);
Datum xipaddr_not(PG_FUNCTION_ARGS);
Datum xipaddr_lt(PG_FUNCTION_ARGS);
Datum xipaddr_le(PG_FUNCTION_ARGS);
Datum xipaddr_gt(PG_FUNCTION_ARGS);
Datum xipaddr_ge(PG_FUNCTION_ARGS);
Datum xipaddr_eq(PG_FUNCTION_ARGS);
Datum xipaddr_neq(PG_FUNCTION_ARGS);
Datum xipaddr_cmp(PG_FUNCTION_ARGS);

Datum xiprange_in(PG_FUNCTION_ARGS);
Datum xiprange_out(PG_FUNCTION_ARGS);
Datum xiprange_recv(PG_FUNCTION_ARGS);
Datum xiprange_send(PG_FUNCTION_ARGS);
Datum xiprange_hash(PG_FUNCTION_ARGS);
Datum xiprange_hash_new(PG_FUNCTION_ARGS);
Datum xiprange_hash_extended(PG_FUNCTION_ARGS);
Datum xiprange_cast_to_text(PG_FUNCTION_ARGS);
Datum xiprange_cast_from_text(PG_FUNCTION_ARGS);
Datum xiprange_cast_from_cidr(PG_FUNCTION_ARGS);
Datum xiprange_cast_to_cidr(PG_FUNCTION_ARGS);
Datum xiprange_cast_to_bit(PG_FUNCTION_ARGS);
Datum xiprange_cast_from_ip4(PG_FUNCTION_ARGS);
Datum xiprange_cast_from_ip6(PG_FUNCTION_ARGS);
Datum xiprange_cast_from_ipaddr(PG_FUNCTION_ARGS);
Datum xiprange_cast_from_ip4r(PG_FUNCTION_ARGS);
Datum xiprange_cast_from_ip6r(PG_FUNCTION_ARGS);
Datum xiprange_cast_to_ip4r(PG_FUNCTION_ARGS);
Datum xiprange_cast_to_ip6r(PG_FUNCTION_ARGS);
Datum xiprange_from_ip4s(PG_FUNCTION_ARGS);
Datum xiprange_from_ip6s(PG_FUNCTION_ARGS);
Datum xiprange_from_ipaddrs(PG_FUNCTION_ARGS);
Datum xiprange_net_prefix_ip4(PG_FUNCTION_ARGS);
Datum xiprange_net_prefix_ip6(PG_FUNCTION_ARGS);
Datum xiprange_net_prefix(PG_FUNCTION_ARGS);
Datum xiprange_net_mask_ip4(PG_FUNCTION_ARGS);
Datum xiprange_net_mask_ip6(PG_FUNCTION_ARGS);
Datum xiprange_net_mask(PG_FUNCTION_ARGS);
Datum xiprange_lower(PG_FUNCTION_ARGS);
Datum xiprange_upper(PG_FUNCTION_ARGS);
Datum xiprange_is_cidr(PG_FUNCTION_ARGS);
Datum xiprange_family(PG_FUNCTION_ARGS);
Datum xiprange_cidr_split(PG_FUNCTION_ARGS);
Datum xiprange_lt(PG_FUNCTION_ARGS);
Datum xiprange_le(PG_FUNCTION_ARGS);
Datum xiprange_gt(PG_FUNCTION_ARGS);
Datum xiprange_ge(PG_FUNCTION_ARGS);
Datum xiprange_eq(PG_FUNCTION_ARGS);
Datum xiprange_neq(PG_FUNCTION_ARGS);
Datum xiprange_overlaps(PG_FUNCTION_ARGS);
Datum xiprange_contains(PG_FUNCTION_ARGS);
Datum xiprange_contains_strict(PG_FUNCTION_ARGS);
Datum xiprange_contained_by(PG_FUNCTION_ARGS);
Datum xiprange_contained_by_strict(PG_FUNCTION_ARGS);
Datum xiprange_contains_ip(PG_FUNCTION_ARGS);
Datum xiprange_contains_ip4(PG_FUNCTION_ARGS);
Datum xiprange_contains_ip6(PG_FUNCTION_ARGS);
Datum xiprange_ip_contained_by(PG_FUNCTION_ARGS);
Datum xiprange_ip4_contained_by(PG_FUNCTION_ARGS);
Datum xiprange_ip6_contained_by(PG_FUNCTION_ARGS);
Datum xiprange_union(PG_FUNCTION_ARGS);
Datum xiprange_inter(PG_FUNCTION_ARGS);
Datum xiprange_size(PG_FUNCTION_ARGS);
Datum xiprange_size_exact(PG_FUNCTION_ARGS);
Datum xiprange_prefixlen(PG_FUNCTION_ARGS);
Datum xiprange_cmp(PG_FUNCTION_ARGS);

#endif
