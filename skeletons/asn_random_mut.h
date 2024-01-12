#ifndef	ASN_RANDOM_MUT
#define	ASN_RANDOM_MUT

struct asn_TYPE_descriptor_s;
struct asn_encoding_constraints_s;

typedef void(asn_random_mut_f)(
    const struct asn_TYPE_descriptor_s *td, void **struct_ptr,
    const struct asn_encoding_constraints_s *memb_constraints,
    size_t max_length);

int asn_random_mut(const struct asn_TYPE_descriptor_s *td, void **struct_ptr,
                    size_t approx_max_length_limit);

#endif