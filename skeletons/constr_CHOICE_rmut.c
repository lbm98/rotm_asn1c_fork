#include <assert.h>
#include <constr_CHOICE.h>

void
CHOICE_random_mut(const asn_TYPE_descriptor_t *td, void **sptr,
                  const asn_encoding_constraints_t *constr, size_t max_length) {

    /*
     * Operate on existing data
     */

    assert(sptr != NULL);
    assert(*sptr != NULL);
    assert(td->specifics != NULL);

    void *st = *sptr;

    const asn_CHOICE_specifics_t *specs =
        (const asn_CHOICE_specifics_t *)td->specifics;

    /*
     * Figure out which CHOICE element is encoded
     */

    unsigned present =
        _fetch_present_idx(st, specs->pres_offset, specs->pres_size);

    assert(present > 0 && present <= td->elements_count);

    asn_TYPE_member_t *elm = &td->elements[present - 1];

    /*
     * Figure out member pointer
     */

    void *memb_ptr;
    void **memb_ptr2;

    if(elm->flags & ATF_POINTER) {
        memb_ptr2 = (void **)((char *)st + elm->memb_offset);
    } else {
        memb_ptr = (char *)st + elm->memb_offset;
        memb_ptr2 = &memb_ptr;
    }

    /*
     * Recurse the tree if supported
     */

    if(elm->type->op->random_mut) {
        elm->type->op->random_mut(elm->type, memb_ptr2,
                                  &elm->encoding_constraints, max_length);
    }
}
