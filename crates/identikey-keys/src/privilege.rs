//! C2 privilege split (ADR-010).
//!
//! `bc-xid` will let anyone holding the in-memory `XIDDocument` call `add_key`.
//! The split is real only if we refuse to apply a key-graph change that was
//! not authorized by a key that already holds `Elect`.

use bc_components::PublicKeysProvider;
use bc_xid::{
    HasPermissions, Key, Privilege, XIDDocument, XIDGenesisMarkOptions, XIDInceptionKeyOptions,
};

/// Privileges the user holds at C2. `Elect` + `Transfer` are ADR-008;
/// `Verify` + `Update` travel with them so the user can change the document
/// and the resolver set (ADR-007 / ADR-010).
pub const USER_C2_PRIVILEGES: [Privilege; 4] = [
    Privilege::Elect,
    Privilege::Transfer,
    Privilege::Verify,
    Privilege::Update,
];

/// Privileges IdentiKey holds at C2. Day-to-day signing, not key-graph control.
pub const IDENTIKEY_C2_PRIVILEGES: [Privilege; 2] = [Privilege::Sign, Privilege::Auth];

/// Management privileges IdentiKey must not hold at C2.
const FORBIDDEN_ON_IDENTIKEY: [Privilege; 8] = [
    Privilege::All,
    Privilege::Elect,
    Privilege::Transfer,
    Privilege::Verify,
    Privilege::Update,
    Privilege::Delegate,
    Privilege::Burn,
    Privilege::Revoke,
];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PrivilegeError {
    #[error("document is not C1: {0}")]
    NotC1(&'static str),
    #[error("document is not C2: {0}")]
    NotC2(&'static str),
    #[error("signer is not authorized to Elect")]
    ElectDenied,
    #[error("inception, user, and operational keys must be three distinct keys")]
    KeysNotDistinct,
    #[error("no inception key in the document")]
    MissingInception,
    #[error("xid document: {0}")]
    Xid(String),
}

fn forbidden_on_identikey(key: &Key) -> bool {
    FORBIDDEN_ON_IDENTIKEY.iter().any(|privilege| match privilege {
        Privilege::All => HasPermissions::allow(key).contains(&Privilege::All),
        other => key_allows(key, other.clone()),
    })
}

/// True if `key` allows `privilege`, including via `Privilege::All`.
#[must_use]
pub fn key_allows(key: &Key, privilege: Privilege) -> bool {
    let allow = HasPermissions::allow(key);
    allow.contains(&Privilege::All) || allow.contains(&privilege)
}

/// A C2 document: one key holds `Elect` and not `Sign`, a different key holds
/// `Sign` and not `Elect`, and no key holds `All`.
#[must_use]
pub fn is_c2(doc: &XIDDocument) -> bool {
    let mut saw_elect = false;
    let mut saw_sign = false;
    for key in doc.keys() {
        if HasPermissions::allow(key).contains(&Privilege::All) {
            return false;
        }
        let elect = key_allows(key, Privilege::Elect);
        let sign = key_allows(key, Privilege::Sign);
        if elect && sign {
            return false;
        }
        if elect && key_allows(key, Privilege::Transfer) {
            saw_elect = true;
        }
        if sign && key_allows(key, Privilege::Auth) {
            if forbidden_on_identikey(key) {
                return false;
            }
            saw_sign = true;
        }
    }
    saw_elect && saw_sign
}

/// Authorize a key-graph change against the *previous* document.
///
/// `bc-xid` will not do this. Callers that skip this function can write any
/// document they want; that is C1 behaviour, not a library guarantee.
pub fn authorize_elect(
    previous: &XIDDocument,
    signer: &impl PublicKeysProvider,
) -> Result<(), PrivilegeError> {
    let Some(key) = previous.find_key_by_public_keys(signer) else {
        return Err(PrivilegeError::ElectDenied);
    };
    if key_allows(key, Privilege::Elect) {
        Ok(())
    } else {
        Err(PrivilegeError::ElectDenied)
    }
}

/// C2-native construction: the user's key is inception and holds `Elect` +
/// `Transfer`; IdentiKey's key is a separate operational key with `Sign` +
/// `Auth`. We never had the user's private key.
pub fn c2_native(
    user_public: &impl PublicKeysProvider,
    identikey_public: &impl PublicKeysProvider,
) -> Result<XIDDocument, PrivilegeError> {
    let user_public = user_public.public_keys();
    let identikey_public = identikey_public.public_keys();
    if user_public == identikey_public {
        return Err(PrivilegeError::KeysNotDistinct);
    }

    let mut doc = XIDDocument::new(
        XIDInceptionKeyOptions::PublicKeys(user_public.clone()),
        XIDGenesisMarkOptions::None,
    );
    set_privileges(&mut doc, &user_public, &USER_C2_PRIVILEGES)?;

    let mut ours = Key::new(&identikey_public);
    for privilege in IDENTIKEY_C2_PRIVILEGES {
        ours.add_permission(privilege);
    }
    doc.add_key(ours).map_err(|e| PrivilegeError::Xid(e.to_string()))?;

    if !is_c2(&doc) {
        return Err(PrivilegeError::NotC2(
            "native constructor did not produce a split document",
        ));
    }
    Ok(doc)
}

/// C1: IdentiKey's key is inception and holds `All`. The user has no Elect key.
pub fn c1(identikey_public: &impl PublicKeysProvider) -> XIDDocument {
    XIDDocument::new(
        XIDInceptionKeyOptions::PublicKeys(identikey_public.public_keys()),
        XIDGenesisMarkOptions::None,
    )
}

/// Promote C1 → C2.
///
/// Adds the user's `Elect` key and a *new* operational key for us, then
/// Transfers the inception key out of the document. `inception_private` is
/// taken by value and dropped — the caller cannot keep using it without
/// having cloned it first, which ADR-010 treats as a breach-class incident
/// rather than an API concern.
pub fn promote_c1_to_c2(
    mut doc: XIDDocument,
    inception_private: impl PublicKeysProvider,
    user_public: &impl PublicKeysProvider,
    operational_public: &impl PublicKeysProvider,
) -> Result<XIDDocument, PrivilegeError> {
    let inception_public = inception_private.public_keys();
    let user_public = user_public.public_keys();
    let operational_public = operational_public.public_keys();

    if inception_public == user_public
        || inception_public == operational_public
        || user_public == operational_public
    {
        return Err(PrivilegeError::KeysNotDistinct);
    }

    let Some(inception) = doc.inception_key() else {
        return Err(PrivilegeError::MissingInception);
    };
    if inception.public_keys() != &inception_public {
        return Err(PrivilegeError::NotC1(
            "supplied key is not the document's inception key",
        ));
    }
    if !key_allows(inception, Privilege::Elect)
        && !HasPermissions::allow(inception).contains(&Privilege::All)
    {
        return Err(PrivilegeError::NotC1(
            "inception key does not hold Elect or All",
        ));
    }

    let mut user_key = Key::new(&user_public);
    for privilege in USER_C2_PRIVILEGES {
        user_key.add_permission(privilege);
    }
    doc.add_key(user_key)
        .map_err(|e| PrivilegeError::Xid(e.to_string()))?;

    let mut operational = Key::new(&operational_public);
    for privilege in IDENTIKEY_C2_PRIVILEGES {
        operational.add_permission(privilege);
    }
    doc.add_key(operational)
        .map_err(|e| PrivilegeError::Xid(e.to_string()))?;

    // Transfer: inception leaves the document. Further updates must go through
    // Elect, not XIDVerifySignature::Inception.
    doc.remove_key(&inception_public)
        .map_err(|e| PrivilegeError::Xid(e.to_string()))?;
    drop(inception_private);

    if !is_c2(&doc) {
        return Err(PrivilegeError::NotC2(
            "promotion did not produce a split document",
        ));
    }
    Ok(doc)
}

fn set_privileges(
    doc: &mut XIDDocument,
    public: &impl PublicKeysProvider,
    privileges: &[Privilege],
) -> Result<(), PrivilegeError> {
    let mut key = doc
        .take_key(public)
        .ok_or(PrivilegeError::MissingInception)?;
    key.clear_all_permissions();
    for privilege in privileges {
        key.add_permission(privilege.clone());
    }
    doc.add_key(key).map_err(|e| PrivilegeError::Xid(e.to_string()))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "panicking on failure is the assertion in a test"
)]
mod tests {
    use bc_components::PrivateKeyBase;

    use super::*;

    fn pair() -> (PrivateKeyBase, PrivateKeyBase) {
        (PrivateKeyBase::new(), PrivateKeyBase::new())
    }

    #[test]
    fn native_c2_splits_privileges() {
        let (user, ours) = pair();
        let doc = c2_native(&user, &ours).unwrap();
        assert!(is_c2(&doc));

        let user_key = doc.find_key_by_public_keys(&user).unwrap();
        assert!(key_allows(user_key, Privilege::Elect));
        assert!(key_allows(user_key, Privilege::Transfer));
        assert!(!key_allows(user_key, Privilege::Sign));

        let our_key = doc.find_key_by_public_keys(&ours).unwrap();
        assert!(key_allows(our_key, Privilege::Sign));
        assert!(key_allows(our_key, Privilege::Auth));
        assert!(!key_allows(our_key, Privilege::Elect));
        assert!(!key_allows(our_key, Privilege::Transfer));
        assert!(!HasPermissions::allow(our_key).contains(&Privilege::All));
    }

    #[test]
    fn identikey_cannot_elect() {
        let (user, ours) = pair();
        let doc = c2_native(&user, &ours).unwrap();
        assert_eq!(
            authorize_elect(&doc, &ours),
            Err(PrivilegeError::ElectDenied)
        );
        assert!(authorize_elect(&doc, &user).is_ok());
    }

    #[test]
    fn c1_is_not_c2() {
        let ours = PrivateKeyBase::new();
        let doc = c1(&ours);
        assert!(!is_c2(&doc));
        // At C1 we *can* Elect — that is what makes it C1.
        assert!(authorize_elect(&doc, &ours).is_ok());
    }

    #[test]
    fn promote_transfers_inception_and_forgets_it() {
        let inception = PrivateKeyBase::new();
        let user = PrivateKeyBase::new();
        let operational = PrivateKeyBase::new();
        let c1_doc = c1(&inception);

        let c2_doc = promote_c1_to_c2(c1_doc, inception.clone(), &user, &operational).unwrap();
        assert!(is_c2(&c2_doc));
        assert!(c2_doc.inception_key().is_none());
        assert!(c2_doc.find_key_by_public_keys(&inception).is_none());
        assert_eq!(
            authorize_elect(&c2_doc, &operational),
            Err(PrivilegeError::ElectDenied)
        );
        assert_eq!(
            authorize_elect(&c2_doc, &inception),
            Err(PrivilegeError::ElectDenied)
        );
        assert!(authorize_elect(&c2_doc, &user).is_ok());
    }

    #[test]
    fn promote_rejects_reused_keys() {
        let inception = PrivateKeyBase::new();
        let user = PrivateKeyBase::new();
        let doc = c1(&inception);
        let err = promote_c1_to_c2(doc, inception.clone(), &user, &inception).unwrap_err();
        assert_eq!(err, PrivilegeError::KeysNotDistinct);
    }

    #[test]
    fn native_rejects_the_same_key_twice() {
        let key = PrivateKeyBase::new();
        assert_eq!(
            c2_native(&key, &key).unwrap_err(),
            PrivilegeError::KeysNotDistinct
        );
    }
}
