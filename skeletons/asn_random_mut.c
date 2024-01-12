#include <constr_TYPE.h>


int
asn_random_mut(const struct asn_TYPE_descriptor_s *td, void **struct_ptr,
               size_t length) {
    if(td && td->op->random_mut) td->op->random_mut(td, struct_ptr, 0, length);
}