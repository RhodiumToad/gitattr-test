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

Datum aip4_in(PG_FUNCTION_ARGS);
Datum aip4_out(PG_FUNCTION_ARGS);
Datum aip4_recv(PG_FUNCTION_ARGS);
Datum aip4_send(PG_FUNCTION_ARGS);
Datum aip4hash(PG_FUNCTION_ARGS);
Datum aip4_hash_extended(PG_FUNCTION_ARGS);
Datum aip4_cast_to_text(PG_FUNCTION_ARGS);
Datum aip4_cast_from_text(PG_FUNCTION_ARGS);
Datum aip4_cast_from_bit(PG_FUNCTION_ARGS);
Datum aip4_cast_to_bit(PG_FUNCTION_ARGS);
Datum aip4_cast_from_bytea(PG_FUNCTION_ARGS);
Datum aip4_cast_to_bytea(PG_FUNCTION_ARGS);
Datum aip4_cast_from_inet(PG_FUNCTION_ARGS);
Datum aip4_cast_to_cidr(PG_FUNCTION_ARGS);
Datum aip4_cast_to_bigint(PG_FUNCTION_ARGS);
Datum aip4_cast_to_numeric(PG_FUNCTION_ARGS);
Datum aip4_cast_from_bigint(PG_FUNCTION_ARGS);
Datum aip4_cast_from_numeric(PG_FUNCTION_ARGS);
Datum aip4_cast_to_double(PG_FUNCTION_ARGS);
Datum aip4_cast_from_double(PG_FUNCTION_ARGS);
Datum aip4r_in(PG_FUNCTION_ARGS);
Datum aip4r_out(PG_FUNCTION_ARGS);
Datum aip4r_recv(PG_FUNCTION_ARGS);
Datum aip4r_send(PG_FUNCTION_ARGS);
Datum aip4rhash(PG_FUNCTION_ARGS);
Datum aip4r_hash_extended(PG_FUNCTION_ARGS);
Datum aip4r_cast_to_text(PG_FUNCTION_ARGS);
Datum aip4r_cast_from_text(PG_FUNCTION_ARGS);
Datum aip4r_cast_from_bit(PG_FUNCTION_ARGS);
Datum aip4r_cast_to_bit(PG_FUNCTION_ARGS);
Datum aip4r_cast_from_cidr(PG_FUNCTION_ARGS);
Datum aip4r_cast_to_cidr(PG_FUNCTION_ARGS);
Datum aip4r_cast_from_ip4(PG_FUNCTION_ARGS);
Datum aip4r_from_ip4s(PG_FUNCTION_ARGS);
Datum aip4r_net_prefix(PG_FUNCTION_ARGS);
Datum aip4r_net_mask(PG_FUNCTION_ARGS);
Datum aip4r_lower(PG_FUNCTION_ARGS);
Datum aip4r_upper(PG_FUNCTION_ARGS);
Datum aip4r_is_cidr(PG_FUNCTION_ARGS);
Datum aip4r_cidr_split(PG_FUNCTION_ARGS);
Datum aip4_netmask(PG_FUNCTION_ARGS);
Datum aip4_net_lower(PG_FUNCTION_ARGS);
Datum aip4_net_upper(PG_FUNCTION_ARGS);
Datum aip4_plus_int(PG_FUNCTION_ARGS);
Datum aip4_plus_bigint(PG_FUNCTION_ARGS);
Datum aip4_plus_numeric(PG_FUNCTION_ARGS);
Datum aip4_minus_int(PG_FUNCTION_ARGS);
Datum aip4_minus_bigint(PG_FUNCTION_ARGS);
Datum aip4_minus_numeric(PG_FUNCTION_ARGS);
Datum aip4_minus_ip4(PG_FUNCTION_ARGS);
Datum aip4_and(PG_FUNCTION_ARGS);
Datum aip4_or(PG_FUNCTION_ARGS);
Datum aip4_xor(PG_FUNCTION_ARGS);
Datum aip4_not(PG_FUNCTION_ARGS);
Datum aip4_lt(PG_FUNCTION_ARGS);
Datum aip4_le(PG_FUNCTION_ARGS);
Datum aip4_gt(PG_FUNCTION_ARGS);
Datum aip4_ge(PG_FUNCTION_ARGS);
Datum aip4_eq(PG_FUNCTION_ARGS);
Datum aip4_neq(PG_FUNCTION_ARGS);
Datum aip4r_lt(PG_FUNCTION_ARGS);
Datum aip4r_le(PG_FUNCTION_ARGS);
Datum aip4r_gt(PG_FUNCTION_ARGS);
Datum aip4r_ge(PG_FUNCTION_ARGS);
Datum aip4r_eq(PG_FUNCTION_ARGS);
Datum aip4r_neq(PG_FUNCTION_ARGS);
Datum aip4r_overlaps(PG_FUNCTION_ARGS);
Datum aip4r_contains(PG_FUNCTION_ARGS);
Datum aip4r_contains_strict(PG_FUNCTION_ARGS);
Datum aip4r_contained_by(PG_FUNCTION_ARGS);
Datum aip4r_contained_by_strict(PG_FUNCTION_ARGS);
Datum aip4_contains(PG_FUNCTION_ARGS);
Datum aip4_contained_by(PG_FUNCTION_ARGS);
Datum aip4r_union(PG_FUNCTION_ARGS);
Datum aip4r_inter(PG_FUNCTION_ARGS);
Datum aip4r_size(PG_FUNCTION_ARGS);
Datum aip4r_size_exact(PG_FUNCTION_ARGS);
Datum aip4r_prefixlen(PG_FUNCTION_ARGS);
Datum aip4r_cmp(PG_FUNCTION_ARGS);
Datum aip4_cmp(PG_FUNCTION_ARGS);
Datum aip4_in_range_bigint(PG_FUNCTION_ARGS);
Datum aip4_in_range_ip4(PG_FUNCTION_ARGS);
Datum aip4r_left_of(PG_FUNCTION_ARGS);
Datum aip4r_right_of(PG_FUNCTION_ARGS);

Datum aip6_in(PG_FUNCTION_ARGS);
Datum aip6_out(PG_FUNCTION_ARGS);
Datum aip6_recv(PG_FUNCTION_ARGS);
Datum aip6_send(PG_FUNCTION_ARGS);
Datum aip6hash(PG_FUNCTION_ARGS);
Datum aip6_hash_extended(PG_FUNCTION_ARGS);
Datum aip6_cast_to_text(PG_FUNCTION_ARGS);
Datum aip6_cast_from_text(PG_FUNCTION_ARGS);
Datum aip6_cast_from_bit(PG_FUNCTION_ARGS);
Datum aip6_cast_to_bit(PG_FUNCTION_ARGS);
Datum aip6_cast_from_bytea(PG_FUNCTION_ARGS);
Datum aip6_cast_to_bytea(PG_FUNCTION_ARGS);
Datum aip6_cast_from_inet(PG_FUNCTION_ARGS);
Datum aip6_cast_to_cidr(PG_FUNCTION_ARGS);
Datum aip6_cast_to_numeric(PG_FUNCTION_ARGS);
Datum aip6_cast_from_numeric(PG_FUNCTION_ARGS);
Datum aip6r_in(PG_FUNCTION_ARGS);
Datum aip6r_out(PG_FUNCTION_ARGS);
Datum aip6r_recv(PG_FUNCTION_ARGS);
Datum aip6r_send(PG_FUNCTION_ARGS);
Datum aip6rhash(PG_FUNCTION_ARGS);
Datum aip6r_hash_extended(PG_FUNCTION_ARGS);
Datum aip6r_cast_to_text(PG_FUNCTION_ARGS);
Datum aip6r_cast_from_text(PG_FUNCTION_ARGS);
Datum aip6r_cast_from_bit(PG_FUNCTION_ARGS);
Datum aip6r_cast_to_bit(PG_FUNCTION_ARGS);
Datum aip6r_cast_from_cidr(PG_FUNCTION_ARGS);
Datum aip6r_cast_to_cidr(PG_FUNCTION_ARGS);
Datum aip6r_cast_from_ip6(PG_FUNCTION_ARGS);
Datum aip6r_from_ip6s(PG_FUNCTION_ARGS);
Datum aip6r_net_prefix(PG_FUNCTION_ARGS);
Datum aip6r_net_mask(PG_FUNCTION_ARGS);
Datum aip6r_lower(PG_FUNCTION_ARGS);
Datum aip6r_upper(PG_FUNCTION_ARGS);
Datum aip6r_is_cidr(PG_FUNCTION_ARGS);
Datum aip6r_cidr_split(PG_FUNCTION_ARGS);
Datum aip6_netmask(PG_FUNCTION_ARGS);
Datum aip6_net_lower(PG_FUNCTION_ARGS);
Datum aip6_net_upper(PG_FUNCTION_ARGS);
Datum aip6_plus_int(PG_FUNCTION_ARGS);
Datum aip6_plus_bigint(PG_FUNCTION_ARGS);
Datum aip6_plus_numeric(PG_FUNCTION_ARGS);
Datum aip6_minus_int(PG_FUNCTION_ARGS);
Datum aip6_minus_bigint(PG_FUNCTION_ARGS);
Datum aip6_minus_numeric(PG_FUNCTION_ARGS);
Datum aip6_minus_ip6(PG_FUNCTION_ARGS);
Datum aip6_and(PG_FUNCTION_ARGS);
Datum aip6_or(PG_FUNCTION_ARGS);
Datum aip6_xor(PG_FUNCTION_ARGS);
Datum aip6_not(PG_FUNCTION_ARGS);
Datum aip6_lt(PG_FUNCTION_ARGS);
Datum aip6_le(PG_FUNCTION_ARGS);
Datum aip6_gt(PG_FUNCTION_ARGS);
Datum aip6_ge(PG_FUNCTION_ARGS);
Datum aip6_eq(PG_FUNCTION_ARGS);
Datum aip6_neq(PG_FUNCTION_ARGS);
Datum aip6r_lt(PG_FUNCTION_ARGS);
Datum aip6r_le(PG_FUNCTION_ARGS);
Datum aip6r_gt(PG_FUNCTION_ARGS);
Datum aip6r_ge(PG_FUNCTION_ARGS);
Datum aip6r_eq(PG_FUNCTION_ARGS);
Datum aip6r_neq(PG_FUNCTION_ARGS);
Datum aip6r_overlaps(PG_FUNCTION_ARGS);
Datum aip6r_contains(PG_FUNCTION_ARGS);
Datum aip6r_contains_strict(PG_FUNCTION_ARGS);
Datum aip6r_contained_by(PG_FUNCTION_ARGS);
Datum aip6r_contained_by_strict(PG_FUNCTION_ARGS);
Datum aip6_contains(PG_FUNCTION_ARGS);
Datum aip6_contained_by(PG_FUNCTION_ARGS);
Datum aip6r_union(PG_FUNCTION_ARGS);
Datum aip6r_inter(PG_FUNCTION_ARGS);
Datum aip6r_size(PG_FUNCTION_ARGS);
Datum aip6r_size_exact(PG_FUNCTION_ARGS);
Datum aip6r_prefixlen(PG_FUNCTION_ARGS);
Datum aip6r_cmp(PG_FUNCTION_ARGS);
Datum aip6_cmp(PG_FUNCTION_ARGS);
Datum aip6_in_range_bigint(PG_FUNCTION_ARGS);
Datum aip6_in_range_ip6(PG_FUNCTION_ARGS);
#if 0
Datum aip6_in_range_numeric(PG_FUNCTION_ARGS);
#endif
Datum aip6r_left_of(PG_FUNCTION_ARGS);
Datum aip6r_right_of(PG_FUNCTION_ARGS);

Datum aipaddr_in(PG_FUNCTION_ARGS);
Datum aipaddr_out(PG_FUNCTION_ARGS);
Datum aipaddr_recv(PG_FUNCTION_ARGS);
Datum aipaddr_send(PG_FUNCTION_ARGS);
Datum aipaddr_hash(PG_FUNCTION_ARGS);
Datum aipaddr_hash_extended(PG_FUNCTION_ARGS);
Datum aipaddr_cast_to_text(PG_FUNCTION_ARGS);
Datum aipaddr_cast_from_text(PG_FUNCTION_ARGS);
Datum aipaddr_cast_from_bit(PG_FUNCTION_ARGS);
Datum aipaddr_cast_to_bit(PG_FUNCTION_ARGS);
Datum aipaddr_cast_from_bytea(PG_FUNCTION_ARGS);
Datum aipaddr_cast_to_bytea(PG_FUNCTION_ARGS);
Datum aipaddr_cast_from_inet(PG_FUNCTION_ARGS);
Datum aipaddr_cast_to_cidr(PG_FUNCTION_ARGS);
Datum aipaddr_cast_to_numeric(PG_FUNCTION_ARGS);
Datum aipaddr_cast_from_ip4(PG_FUNCTION_ARGS);
Datum aipaddr_cast_from_ip6(PG_FUNCTION_ARGS);
Datum aipaddr_cast_to_ip4(PG_FUNCTION_ARGS);
Datum aipaddr_cast_to_ip6(PG_FUNCTION_ARGS);
Datum aipaddr_net_lower(PG_FUNCTION_ARGS);
Datum aipaddr_net_upper(PG_FUNCTION_ARGS);
Datum aipaddr_family(PG_FUNCTION_ARGS);
Datum aipaddr_plus_int(PG_FUNCTION_ARGS);
Datum aipaddr_plus_bigint(PG_FUNCTION_ARGS);
Datum aipaddr_plus_numeric(PG_FUNCTION_ARGS);
Datum aipaddr_minus_int(PG_FUNCTION_ARGS);
Datum aipaddr_minus_bigint(PG_FUNCTION_ARGS);
Datum aipaddr_minus_numeric(PG_FUNCTION_ARGS);
Datum aipaddr_minus_ipaddr(PG_FUNCTION_ARGS);
Datum aipaddr_and(PG_FUNCTION_ARGS);
Datum aipaddr_or(PG_FUNCTION_ARGS);
Datum aipaddr_xor(PG_FUNCTION_ARGS);
Datum aipaddr_not(PG_FUNCTION_ARGS);
Datum aipaddr_lt(PG_FUNCTION_ARGS);
Datum aipaddr_le(PG_FUNCTION_ARGS);
Datum aipaddr_gt(PG_FUNCTION_ARGS);
Datum aipaddr_ge(PG_FUNCTION_ARGS);
Datum aipaddr_eq(PG_FUNCTION_ARGS);
Datum aipaddr_neq(PG_FUNCTION_ARGS);
Datum aipaddr_cmp(PG_FUNCTION_ARGS);

Datum aiprange_in(PG_FUNCTION_ARGS);
Datum aiprange_out(PG_FUNCTION_ARGS);
Datum aiprange_recv(PG_FUNCTION_ARGS);
Datum aiprange_send(PG_FUNCTION_ARGS);
Datum aiprange_hash(PG_FUNCTION_ARGS);
Datum aiprange_hash_new(PG_FUNCTION_ARGS);
Datum aiprange_hash_extended(PG_FUNCTION_ARGS);
Datum aiprange_cast_to_text(PG_FUNCTION_ARGS);
Datum aiprange_cast_from_text(PG_FUNCTION_ARGS);
Datum aiprange_cast_from_cidr(PG_FUNCTION_ARGS);
Datum aiprange_cast_to_cidr(PG_FUNCTION_ARGS);
Datum aiprange_cast_to_bit(PG_FUNCTION_ARGS);
Datum aiprange_cast_from_ip4(PG_FUNCTION_ARGS);
Datum aiprange_cast_from_ip6(PG_FUNCTION_ARGS);
Datum aiprange_cast_from_ipaddr(PG_FUNCTION_ARGS);
Datum aiprange_cast_from_ip4r(PG_FUNCTION_ARGS);
Datum aiprange_cast_from_ip6r(PG_FUNCTION_ARGS);
Datum aiprange_cast_to_ip4r(PG_FUNCTION_ARGS);
Datum aiprange_cast_to_ip6r(PG_FUNCTION_ARGS);
Datum aiprange_from_ip4s(PG_FUNCTION_ARGS);
Datum aiprange_from_ip6s(PG_FUNCTION_ARGS);
Datum aiprange_from_ipaddrs(PG_FUNCTION_ARGS);
Datum aiprange_net_prefix_ip4(PG_FUNCTION_ARGS);
Datum aiprange_net_prefix_ip6(PG_FUNCTION_ARGS);
Datum aiprange_net_prefix(PG_FUNCTION_ARGS);
Datum aiprange_net_mask_ip4(PG_FUNCTION_ARGS);
Datum aiprange_net_mask_ip6(PG_FUNCTION_ARGS);
Datum aiprange_net_mask(PG_FUNCTION_ARGS);
Datum aiprange_lower(PG_FUNCTION_ARGS);
Datum aiprange_upper(PG_FUNCTION_ARGS);
Datum aiprange_is_cidr(PG_FUNCTION_ARGS);
Datum aiprange_family(PG_FUNCTION_ARGS);
Datum aiprange_cidr_split(PG_FUNCTION_ARGS);
Datum aiprange_lt(PG_FUNCTION_ARGS);
Datum aiprange_le(PG_FUNCTION_ARGS);
Datum aiprange_gt(PG_FUNCTION_ARGS);
Datum aiprange_ge(PG_FUNCTION_ARGS);
Datum aiprange_eq(PG_FUNCTION_ARGS);
Datum aiprange_neq(PG_FUNCTION_ARGS);
Datum aiprange_overlaps(PG_FUNCTION_ARGS);
Datum aiprange_contains(PG_FUNCTION_ARGS);
Datum aiprange_contains_strict(PG_FUNCTION_ARGS);
Datum aiprange_contained_by(PG_FUNCTION_ARGS);
Datum aiprange_contained_by_strict(PG_FUNCTION_ARGS);
Datum aiprange_contains_ip(PG_FUNCTION_ARGS);
Datum aiprange_contains_ip4(PG_FUNCTION_ARGS);
Datum aiprange_contains_ip6(PG_FUNCTION_ARGS);
Datum aiprange_ip_contained_by(PG_FUNCTION_ARGS);
Datum aiprange_ip4_contained_by(PG_FUNCTION_ARGS);
Datum aiprange_ip6_contained_by(PG_FUNCTION_ARGS);
Datum aiprange_union(PG_FUNCTION_ARGS);
Datum aiprange_inter(PG_FUNCTION_ARGS);
Datum aiprange_size(PG_FUNCTION_ARGS);
Datum aiprange_size_exact(PG_FUNCTION_ARGS);
Datum aiprange_prefixlen(PG_FUNCTION_ARGS);
Datum aiprange_cmp(PG_FUNCTION_ARGS);

#endif
