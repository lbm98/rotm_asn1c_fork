#include <assert.h>

#include <constr_SEQUENCE.h>

void
SEQUENCE_random_mut(const asn_TYPE_descriptor_t *td, void **sptr,
                    const asn_encoding_constraints_t *constr,
                    size_t max_length) {

//    printf("SEQUENCE (%s:%d)\n", __FILE__, __LINE__);

//    if(!sptr) {
//        printf("!sptr (%s:%d)\n", __FILE__, __LINE__);
//        return;
//    }

    assert(sptr != NULL);
    assert(*sptr != NULL);
    void *st = *sptr;

    for(size_t edx = 0; edx < td->elements_count; edx++) {
        const asn_TYPE_member_t *elm = &td->elements[edx];
        void *memb_ptr;
        void **memb_ptr2;

        if(elm->optional) {
            // Do what?
        }

        if(elm->flags & ATF_POINTER) {
            memb_ptr2 = (void **)((char *)st + elm->memb_offset);
        } else {
            memb_ptr = (char *)st + elm->memb_offset;
            memb_ptr2 = &memb_ptr;
        }

        if (elm->type->op->random_mut) {
            elm->type->op->random_mut(elm->type, memb_ptr2,
                                      &elm->encoding_constraints, max_length);
        }
    }

    *sptr = st;
}
