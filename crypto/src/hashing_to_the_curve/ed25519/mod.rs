use noah_algebra::ed25519::Ed25519Fq;
use noah_algebra::new_ed25519_fq;

/// Elligator for ed25519.
pub mod elligator;

/// Simplified SWU map for ed25519.
pub mod sswu;

/// Shallue-van de Woestijne map for ed25519.
pub mod sw;

const Y_SCALE_FACTOR: Ed25519Fq = new_ed25519_fq!(
    "51042569399160536130206135233146329284152202253034631822681833788666877215207"
);
