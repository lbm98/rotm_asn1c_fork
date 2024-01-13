#include <assert.h>

#include <NativeInteger.h>

void
NativeInteger_random_mut(const asn_TYPE_descriptor_t *td, void **sptr,
                          const asn_encoding_constraints_t *constraints,
                          size_t max_length) {

    /*
     * Operate on existing data
     */

    assert(sptr != NULL);
    assert(*sptr != NULL);

    long *st = *sptr;

#if defined(ASN_DISABLE_UPER_SUPPORT) && defined(ASN_DISABLE_APER_SUPPORT)
#error "random_mut requires PER mode"
#endif

    /*
     * Constraints are either direct or indirect
     */

    if(!constraints || !constraints->per_constraints)
        constraints = &td->encoding_constraints;

    /*
     * Constraints must exist
     */

    assert(constraints != NULL);
    assert(constraints->per_constraints != NULL);

    /*
     * NativeInteger uses the value constraints
     */

    const asn_per_constraint_t *pc = &constraints->per_constraints->value;

    /*
     * Perform mutation
     */

    *st = asn_random_between(pc->lower_bound, pc->upper_bound);
}
