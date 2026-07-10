//! Verifies the ML-DSA large-stack signing guard the NIF relies on.
//!
//! The signing/keygen NIFs (`nif_sign`, `nif_generate_signing_keypair*`,
//! `nif_derive_signing_public_key`) run on the BEAM dirty-CPU scheduler and wrap
//! their ML-DSA-bearing body in `metamorphic_crypto::on_signing_stack` to borrow
//! an ample worker stack (the dirty scheduler's ~320 KB default overflows to
//! SIGBUS otherwise). This test exercises that exact guarded path at Cat-5
//! (ML-DSA-87, the heaviest parameter set) and Cat-3, mirroring the NIF bodies
//! with owned/`Send` data crossing the thread boundary. It also pins the
//! `metamorphic-crypto` dependency to a version that exports the shared helper.

use metamorphic_crypto::{
    SignatureLevel, generate_signing_keypair_with_level, on_signing_stack, sign, verify,
};

fn guarded_roundtrip(level: SignatureLevel) {
    let ok = on_signing_stack(move || {
        let kp = generate_signing_keypair_with_level(level);
        let message = b"metamorphic_crypto NIF signing-stack regression";
        let context = "metamorphic.nif-signing-stack-test";
        let signature =
            sign(message, context, &kp.secret_key).expect("hybrid sign on guarded stack");
        verify(message, context, &signature, &kp.public_key).expect("verify")
    });
    assert!(ok, "hybrid signature must verify at {level:?}");
}

#[test]
fn guarded_sign_verify_cat3() {
    guarded_roundtrip(SignatureLevel::Cat3);
}

#[test]
fn guarded_sign_verify_cat5() {
    guarded_roundtrip(SignatureLevel::Cat5);
}
