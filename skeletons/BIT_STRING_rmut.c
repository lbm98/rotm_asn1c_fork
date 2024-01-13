#include <BIT_STRING.h>
#include <assert.h>

void
BIT_STRING_random_mut(const asn_TYPE_descriptor_t *td, void **sptr,
                      const asn_encoding_constraints_t *constraints,
                      size_t max_length) {
    /*
     * Debugging
     */

//    printf("BIT_STRING (%s:%d)\n", __FILE__, __LINE__);

    /*
     * Operate on existing data
     */

    assert(sptr != NULL);
    assert(*sptr != NULL);
    assert(td->specifics != NULL);

    BIT_STRING_t *st = (BIT_STRING_t *)*sptr;

    const asn_OCTET_STRING_specifics_t *specs =
        (const asn_OCTET_STRING_specifics_t *)td->specifics;

    printf("CONSTRAINTS ");

#if defined(ASN_DISABLE_UPER_SUPPORT) && defined(ASN_DISABLE_APER_SUPPORT)
#error "random_mut requires PER mode"
#endif

    assert(constraints != NULL);
    assert(constraints->per_constraints != NULL);

    const asn_per_constraint_t *pc = &constraints->per_constraints->size;

    size_t bit_to_flip = asn_random_between(0, st->size * 8 - st->bits_unused);
    size_t byte_in_buf = bit_to_flip / 8;
    size_t bit_in_byte = bit_to_flip % 8;

    st->buf[byte_in_buf] ^= (1 << bit_in_byte);
}
