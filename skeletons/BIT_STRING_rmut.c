#include <BIT_STRING.h>
#include <assert.h>

void
BIT_STRING_random_mut(const asn_TYPE_descriptor_t *td, void **sptr,
                      const asn_encoding_constraints_t *constraints,
                      size_t max_length) {

    /*
     * Operate on existing data
     */

    assert(sptr != NULL);
    assert(*sptr != NULL);
    assert(td->specifics != NULL);

    BIT_STRING_t *st = (BIT_STRING_t *)*sptr;

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
     * BIT_STRING uses the size constraints
     */

    size_t bit_to_flip = asn_random_between(0, st->size * 8 - st->bits_unused);
    size_t byte_in_buf = bit_to_flip / 8;
    size_t bit_in_byte = bit_to_flip % 8;

    st->buf[byte_in_buf] ^= (1 << bit_in_byte);
}
