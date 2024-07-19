/// Trait for the TimeLock Cryptographic Service (TLCS).
///
/// This trait defines the required functionality for generating and verifying key shares,
/// as well as aggregating public and secret keys in a time-locked cryptographic system.
pub trait TLCS {
    /// The type representing a key share.
    type KeyShareType;

    /// Generates a key share.
    ///
    /// # Returns
    ///
    /// A key share of type `Self::KeyShareType`.
    fn key_share_gen(&self) -> Self::KeyShareType;

    /// Verifies a secret key.
    ///
    /// # Arguments
    ///
    /// * `sk` - A string slice that holds the secret key to be verified.
    ///
    /// # Returns
    ///
    /// `true` if the secret key is valid, `false` otherwise.
    fn sk_verify(&self, sk: &str) -> bool;

    /// Verifies a key share.
    ///
    /// # Arguments
    ///
    /// * `key_share` - A reference to the key share to be verified.
    ///
    /// # Returns
    ///
    /// `true` if the key share is valid, `false` otherwise.
    fn key_share_verify(&self, key_share: &Self::KeyShareType) -> bool;

    /// Aggregates multiple key shares to generate a master public key.
    ///
    /// # Arguments
    ///
    /// * `shares` - A vector of references to key shares to be aggregated.
    ///
    /// # Returns
    ///
    /// A string representing the aggregated master public key.
    fn mpk_aggregation(&self, shares: Vec<&Self::KeyShareType>) -> String;

    /// Aggregates multiple key shares to generate a master secret key.
    ///
    /// # Arguments
    ///
    /// * `shares` - A vector of references to key shares to be aggregated.
    ///
    /// # Returns
    ///
    /// A string representing the aggregated master secret key.
    fn msk_aggregation(&self, shares: Vec<&Self::KeyShareType>) -> String;
}
