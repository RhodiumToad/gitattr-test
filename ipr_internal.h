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

Datum zip4_in(PG_FUNCTION_ARGS);
Datum zip4_out(PG_FUNCTION_ARGS);
Datum zip4_recv(PG_FUNCTION_ARGS);
Datum zip4_send(PG_FUNCTION_ARGS);
Datum zip4hash(PG_FUNCTION_ARGS);
Datum zip4_hash_extended(PG_FUNCTION_ARGS);
Datum zip4_cast_to_text(PG_FUNCTION_ARGS);
Datum zip4_cast_from_text(PG_FUNCTION_ARGS);
Datum zip4_cast_from_bit(PG_FUNCTION_ARGS);
Datum zip4_cast_to_bit(PG_FUNCTION_ARGS);
Datum zip4_cast_from_bytea(PG_FUNCTION_ARGS);
Datum zip4_cast_to_bytea(PG_FUNCTION_ARGS);
Datum zip4_cast_from_inet(PG_FUNCTION_ARGS);
Datum zip4_cast_to_cidr(PG_FUNCTION_ARGS);
Datum zip4_cast_to_bigint(PG_FUNCTION_ARGS);
Datum zip4_cast_to_numeric(PG_FUNCTION_ARGS);
Datum zip4_cast_from_bigint(PG_FUNCTION_ARGS);
Datum zip4_cast_from_numeric(PG_FUNCTION_ARGS);
Datum zip4_cast_to_double(PG_FUNCTION_ARGS);
Datum zip4_cast_from_double(PG_FUNCTION_ARGS);
Datum zip4r_in(PG_FUNCTION_ARGS);
Datum zip4r_out(PG_FUNCTION_ARGS);
Datum zip4r_recv(PG_FUNCTION_ARGS);
Datum zip4r_send(PG_FUNCTION_ARGS);
Datum zip4rhash(PG_FUNCTION_ARGS);
Datum zip4r_hash_extended(PG_FUNCTION_ARGS);
Datum zip4r_cast_to_text(PG_FUNCTION_ARGS);
Datum zip4r_cast_from_text(PG_FUNCTION_ARGS);
Datum zip4r_cast_from_bit(PG_FUNCTION_ARGS);
Datum zip4r_cast_to_bit(PG_FUNCTION_ARGS);
Datum zip4r_cast_from_cidr(PG_FUNCTION_ARGS);
Datum zip4r_cast_to_cidr(PG_FUNCTION_ARGS);
Datum zip4r_cast_from_ip4(PG_FUNCTION_ARGS);
Datum zip4r_from_ip4s(PG_FUNCTION_ARGS);
Datum zip4r_net_prefix(PG_FUNCTION_ARGS);
Datum zip4r_net_mask(PG_FUNCTION_ARGS);
Datum zip4r_lower(PG_FUNCTION_ARGS);
Datum zip4r_upper(PG_FUNCTION_ARGS);
Datum zip4r_is_cidr(PG_FUNCTION_ARGS);
Datum zip4r_cidr_split(PG_FUNCTION_ARGS);
Datum zip4_netmask(PG_FUNCTION_ARGS);
Datum zip4_net_lower(PG_FUNCTION_ARGS);
Datum zip4_net_upper(PG_FUNCTION_ARGS);
Datum zip4_plus_int(PG_FUNCTION_ARGS);
Datum zip4_plus_bigint(PG_FUNCTION_ARGS);
Datum zip4_plus_numeric(PG_FUNCTION_ARGS);
Datum zip4_minus_int(PG_FUNCTION_ARGS);
Datum zip4_minus_bigint(PG_FUNCTION_ARGS);
Datum zip4_minus_numeric(PG_FUNCTION_ARGS);
Datum zip4_minus_ip4(PG_FUNCTION_ARGS);
Datum zip4_and(PG_FUNCTION_ARGS);
Datum zip4_or(PG_FUNCTION_ARGS);
Datum zip4_xor(PG_FUNCTION_ARGS);
Datum zip4_not(PG_FUNCTION_ARGS);
Datum zip4_lt(PG_FUNCTION_ARGS);
Datum zip4_le(PG_FUNCTION_ARGS);
Datum zip4_gt(PG_FUNCTION_ARGS);
Datum zip4_ge(PG_FUNCTION_ARGS);
Datum zip4_eq(PG_FUNCTION_ARGS);
Datum zip4_neq(PG_FUNCTION_ARGS);
Datum zip4r_lt(PG_FUNCTION_ARGS);
Datum zip4r_le(PG_FUNCTION_ARGS);
Datum zip4r_gt(PG_FUNCTION_ARGS);
Datum zip4r_ge(PG_FUNCTION_ARGS);
Datum zip4r_eq(PG_FUNCTION_ARGS);
Datum zip4r_neq(PG_FUNCTION_ARGS);
Datum zip4r_overlaps(PG_FUNCTION_ARGS);
Datum zip4r_contains(PG_FUNCTION_ARGS);
Datum zip4r_contains_strict(PG_FUNCTION_ARGS);
Datum zip4r_contained_by(PG_FUNCTION_ARGS);
Datum zip4r_contained_by_strict(PG_FUNCTION_ARGS);
Datum zip4_contains(PG_FUNCTION_ARGS);
Datum zip4_contained_by(PG_FUNCTION_ARGS);
Datum zip4r_union(PG_FUNCTION_ARGS);
Datum zip4r_inter(PG_FUNCTION_ARGS);
Datum zip4r_size(PG_FUNCTION_ARGS);
Datum zip4r_size_exact(PG_FUNCTION_ARGS);
Datum zip4r_prefixlen(PG_FUNCTION_ARGS);
Datum zip4r_cmp(PG_FUNCTION_ARGS);
Datum zip4_cmp(PG_FUNCTION_ARGS);
Datum zip4_in_range_bigint(PG_FUNCTION_ARGS);
Datum zip4_in_range_ip4(PG_FUNCTION_ARGS);
Datum zip4r_left_of(PG_FUNCTION_ARGS);
Datum zip4r_right_of(PG_FUNCTION_ARGS);

Datum zip6_in(PG_FUNCTION_ARGS);
Datum zip6_out(PG_FUNCTION_ARGS);
Datum zip6_recv(PG_FUNCTION_ARGS);
Datum zip6_send(PG_FUNCTION_ARGS);
Datum zip6hash(PG_FUNCTION_ARGS);
Datum zip6_hash_extended(PG_FUNCTION_ARGS);
Datum zip6_cast_to_text(PG_FUNCTION_ARGS);
Datum zip6_cast_from_text(PG_FUNCTION_ARGS);
Datum zip6_cast_from_bit(PG_FUNCTION_ARGS);
Datum zip6_cast_to_bit(PG_FUNCTION_ARGS);
Datum zip6_cast_from_bytea(PG_FUNCTION_ARGS);
Datum zip6_cast_to_bytea(PG_FUNCTION_ARGS);
Datum zip6_cast_from_inet(PG_FUNCTION_ARGS);
Datum zip6_cast_to_cidr(PG_FUNCTION_ARGS);
Datum zip6_cast_to_numeric(PG_FUNCTION_ARGS);
Datum zip6_cast_from_numeric(PG_FUNCTION_ARGS);
Datum zip6r_in(PG_FUNCTION_ARGS);
Datum zip6r_out(PG_FUNCTION_ARGS);
Datum zip6r_recv(PG_FUNCTION_ARGS);
Datum zip6r_send(PG_FUNCTION_ARGS);
Datum zip6rhash(PG_FUNCTION_ARGS);
Datum zip6r_hash_extended(PG_FUNCTION_ARGS);
Datum zip6r_cast_to_text(PG_FUNCTION_ARGS);
Datum zip6r_cast_from_text(PG_FUNCTION_ARGS);
Datum zip6r_cast_from_bit(PG_FUNCTION_ARGS);
Datum zip6r_cast_to_bit(PG_FUNCTION_ARGS);
Datum zip6r_cast_from_cidr(PG_FUNCTION_ARGS);
Datum zip6r_cast_to_cidr(PG_FUNCTION_ARGS);
Datum zip6r_cast_from_ip6(PG_FUNCTION_ARGS);
Datum zip6r_from_ip6s(PG_FUNCTION_ARGS);
Datum zip6r_net_prefix(PG_FUNCTION_ARGS);
Datum zip6r_net_mask(PG_FUNCTION_ARGS);
Datum zip6r_lower(PG_FUNCTION_ARGS);
Datum zip6r_upper(PG_FUNCTION_ARGS);
Datum zip6r_is_cidr(PG_FUNCTION_ARGS);
Datum zip6r_cidr_split(PG_FUNCTION_ARGS);
Datum zip6_netmask(PG_FUNCTION_ARGS);
Datum zip6_net_lower(PG_FUNCTION_ARGS);
Datum zip6_net_upper(PG_FUNCTION_ARGS);
Datum zip6_plus_int(PG_FUNCTION_ARGS);
Datum zip6_plus_bigint(PG_FUNCTION_ARGS);
Datum zip6_plus_numeric(PG_FUNCTION_ARGS);
Datum zip6_minus_int(PG_FUNCTION_ARGS);
Datum zip6_minus_bigint(PG_FUNCTION_ARGS);
Datum zip6_minus_numeric(PG_FUNCTION_ARGS);
Datum zip6_minus_ip6(PG_FUNCTION_ARGS);
Datum zip6_and(PG_FUNCTION_ARGS);
Datum zip6_or(PG_FUNCTION_ARGS);
Datum zip6_xor(PG_FUNCTION_ARGS);
Datum zip6_not(PG_FUNCTION_ARGS);
Datum zip6_lt(PG_FUNCTION_ARGS);
Datum zip6_le(PG_FUNCTION_ARGS);
Datum zip6_gt(PG_FUNCTION_ARGS);
Datum zip6_ge(PG_FUNCTION_ARGS);
Datum zip6_eq(PG_FUNCTION_ARGS);
Datum zip6_neq(PG_FUNCTION_ARGS);
Datum zip6r_lt(PG_FUNCTION_ARGS);
Datum zip6r_le(PG_FUNCTION_ARGS);
Datum zip6r_gt(PG_FUNCTION_ARGS);
Datum zip6r_ge(PG_FUNCTION_ARGS);
Datum zip6r_eq(PG_FUNCTION_ARGS);
Datum zip6r_neq(PG_FUNCTION_ARGS);
Datum zip6r_overlaps(PG_FUNCTION_ARGS);
Datum zip6r_contains(PG_FUNCTION_ARGS);
Datum zip6r_contains_strict(PG_FUNCTION_ARGS);
Datum zip6r_contained_by(PG_FUNCTION_ARGS);
Datum zip6r_contained_by_strict(PG_FUNCTION_ARGS);
Datum zip6_contains(PG_FUNCTION_ARGS);
Datum zip6_contained_by(PG_FUNCTION_ARGS);
Datum zip6r_union(PG_FUNCTION_ARGS);
Datum zip6r_inter(PG_FUNCTION_ARGS);
Datum zip6r_size(PG_FUNCTION_ARGS);
Datum zip6r_size_exact(PG_FUNCTION_ARGS);
Datum zip6r_prefixlen(PG_FUNCTION_ARGS);
Datum zip6r_cmp(PG_FUNCTION_ARGS);
Datum zip6_cmp(PG_FUNCTION_ARGS);
Datum zip6_in_range_bigint(PG_FUNCTION_ARGS);
Datum zip6_in_range_ip6(PG_FUNCTION_ARGS);
#if 0
Datum zip6_in_range_numeric(PG_FUNCTION_ARGS);
#endif
Datum zip6r_left_of(PG_FUNCTION_ARGS);
Datum zip6r_right_of(PG_FUNCTION_ARGS);

Datum zipaddr_in(PG_FUNCTION_ARGS);
Datum zipaddr_out(PG_FUNCTION_ARGS);
Datum zipaddr_recv(PG_FUNCTION_ARGS);
Datum zipaddr_send(PG_FUNCTION_ARGS);
Datum zipaddr_hash(PG_FUNCTION_ARGS);
Datum zipaddr_hash_extended(PG_FUNCTION_ARGS);
Datum zipaddr_cast_to_text(PG_FUNCTION_ARGS);
Datum zipaddr_cast_from_text(PG_FUNCTION_ARGS);
Datum zipaddr_cast_from_bit(PG_FUNCTION_ARGS);
Datum zipaddr_cast_to_bit(PG_FUNCTION_ARGS);
Datum zipaddr_cast_from_bytea(PG_FUNCTION_ARGS);
Datum zipaddr_cast_to_bytea(PG_FUNCTION_ARGS);
Datum zipaddr_cast_from_inet(PG_FUNCTION_ARGS);
Datum zipaddr_cast_to_cidr(PG_FUNCTION_ARGS);
Datum zipaddr_cast_to_numeric(PG_FUNCTION_ARGS);
Datum zipaddr_cast_from_ip4(PG_FUNCTION_ARGS);
Datum zipaddr_cast_from_ip6(PG_FUNCTION_ARGS);
Datum zipaddr_cast_to_ip4(PG_FUNCTION_ARGS);
Datum zipaddr_cast_to_ip6(PG_FUNCTION_ARGS);
Datum zipaddr_net_lower(PG_FUNCTION_ARGS);
Datum zipaddr_net_upper(PG_FUNCTION_ARGS);
Datum zipaddr_family(PG_FUNCTION_ARGS);
Datum zipaddr_plus_int(PG_FUNCTION_ARGS);
Datum zipaddr_plus_bigint(PG_FUNCTION_ARGS);
Datum zipaddr_plus_numeric(PG_FUNCTION_ARGS);
Datum zipaddr_minus_int(PG_FUNCTION_ARGS);
Datum zipaddr_minus_bigint(PG_FUNCTION_ARGS);
Datum zipaddr_minus_numeric(PG_FUNCTION_ARGS);
Datum zipaddr_minus_ipaddr(PG_FUNCTION_ARGS);
Datum zipaddr_and(PG_FUNCTION_ARGS);
Datum zipaddr_or(PG_FUNCTION_ARGS);
Datum zipaddr_xor(PG_FUNCTION_ARGS);
Datum zipaddr_not(PG_FUNCTION_ARGS);
Datum zipaddr_lt(PG_FUNCTION_ARGS);
Datum zipaddr_le(PG_FUNCTION_ARGS);
Datum zipaddr_gt(PG_FUNCTION_ARGS);
Datum zipaddr_ge(PG_FUNCTION_ARGS);
Datum zipaddr_eq(PG_FUNCTION_ARGS);
Datum zipaddr_neq(PG_FUNCTION_ARGS);
Datum zipaddr_cmp(PG_FUNCTION_ARGS);

Datum ziprange_in(PG_FUNCTION_ARGS);
Datum ziprange_out(PG_FUNCTION_ARGS);
Datum ziprange_recv(PG_FUNCTION_ARGS);
Datum ziprange_send(PG_FUNCTION_ARGS);
Datum ziprange_hash(PG_FUNCTION_ARGS);
Datum ziprange_hash_new(PG_FUNCTION_ARGS);
Datum ziprange_hash_extended(PG_FUNCTION_ARGS);
Datum ziprange_cast_to_text(PG_FUNCTION_ARGS);
Datum ziprange_cast_from_text(PG_FUNCTION_ARGS);
Datum ziprange_cast_from_cidr(PG_FUNCTION_ARGS);
Datum ziprange_cast_to_cidr(PG_FUNCTION_ARGS);
Datum ziprange_cast_to_bit(PG_FUNCTION_ARGS);
Datum ziprange_cast_from_ip4(PG_FUNCTION_ARGS);
Datum ziprange_cast_from_ip6(PG_FUNCTION_ARGS);
Datum ziprange_cast_from_ipaddr(PG_FUNCTION_ARGS);
Datum ziprange_cast_from_ip4r(PG_FUNCTION_ARGS);
Datum ziprange_cast_from_ip6r(PG_FUNCTION_ARGS);
Datum ziprange_cast_to_ip4r(PG_FUNCTION_ARGS);
Datum ziprange_cast_to_ip6r(PG_FUNCTION_ARGS);
Datum ziprange_from_ip4s(PG_FUNCTION_ARGS);
Datum ziprange_from_ip6s(PG_FUNCTION_ARGS);
Datum ziprange_from_ipaddrs(PG_FUNCTION_ARGS);
Datum ziprange_net_prefix_ip4(PG_FUNCTION_ARGS);
Datum ziprange_net_prefix_ip6(PG_FUNCTION_ARGS);
Datum ziprange_net_prefix(PG_FUNCTION_ARGS);
Datum ziprange_net_mask_ip4(PG_FUNCTION_ARGS);
Datum ziprange_net_mask_ip6(PG_FUNCTION_ARGS);
Datum ziprange_net_mask(PG_FUNCTION_ARGS);
Datum ziprange_lower(PG_FUNCTION_ARGS);
Datum ziprange_upper(PG_FUNCTION_ARGS);
Datum ziprange_is_cidr(PG_FUNCTION_ARGS);
Datum ziprange_family(PG_FUNCTION_ARGS);
Datum ziprange_cidr_split(PG_FUNCTION_ARGS);
Datum ziprange_lt(PG_FUNCTION_ARGS);
Datum ziprange_le(PG_FUNCTION_ARGS);
Datum ziprange_gt(PG_FUNCTION_ARGS);
Datum ziprange_ge(PG_FUNCTION_ARGS);
Datum ziprange_eq(PG_FUNCTION_ARGS);
Datum ziprange_neq(PG_FUNCTION_ARGS);
Datum ziprange_overlaps(PG_FUNCTION_ARGS);
Datum ziprange_contains(PG_FUNCTION_ARGS);
Datum ziprange_contains_strict(PG_FUNCTION_ARGS);
Datum ziprange_contained_by(PG_FUNCTION_ARGS);
Datum ziprange_contained_by_strict(PG_FUNCTION_ARGS);
Datum ziprange_contains_ip(PG_FUNCTION_ARGS);
Datum ziprange_contains_ip4(PG_FUNCTION_ARGS);
Datum ziprange_contains_ip6(PG_FUNCTION_ARGS);
Datum ziprange_ip_contained_by(PG_FUNCTION_ARGS);
Datum ziprange_ip4_contained_by(PG_FUNCTION_ARGS);
Datum ziprange_ip6_contained_by(PG_FUNCTION_ARGS);
Datum ziprange_union(PG_FUNCTION_ARGS);
Datum ziprange_inter(PG_FUNCTION_ARGS);
Datum ziprange_size(PG_FUNCTION_ARGS);
Datum ziprange_size_exact(PG_FUNCTION_ARGS);
Datum ziprange_prefixlen(PG_FUNCTION_ARGS);
Datum ziprange_cmp(PG_FUNCTION_ARGS);

#endif
