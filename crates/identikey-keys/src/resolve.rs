//! Threshold pick over already-fetched XID documents (ADR-007 §3–4).

use bc_xid::XIDDocument;
use dcbor::prelude::*;

/// Where a caller got the bytes. The library does not fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchedDocument<'a> {
    pub source: &'a str,
    pub bytes: &'a [u8],
    pub cached: bool,
}

/// Freshness the caller is allowed to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionTier {
    /// Ordinary login: a single previously fetched document is enough.
    Cached,
    /// Key-graph, delegation, climb, wallet-class: refuse cache-only input.
    Consequential,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    #[error("no valid XID document")]
    NoDocument,
    #[error("duplicity: valid documents are not on the same provenance chain")]
    Duplicity,
    #[error("consequential resolution cannot use cache-only input")]
    CachedOnly,
}

#[derive(Debug, Clone)]
pub struct WinningDoc {
    pub document: XIDDocument,
    pub bytes: Vec<u8>,
}

/// Parse independently, drop junk, take the highest mark on one chain.
pub fn resolve_documents(
    tier: ResolutionTier,
    docs: &[FetchedDocument<'_>],
) -> Result<WinningDoc, ResolveError> {
    if matches!(tier, ResolutionTier::Consequential)
        && !docs.is_empty()
        && docs.iter().all(|d| d.cached)
    {
        return Err(ResolveError::CachedOnly);
    }

    let mut valid: Vec<Parsed> = Vec::new();
    for doc in docs {
        if let Some(parsed) = parse(doc.bytes) {
            valid.push(parsed);
        }
    }
    if valid.is_empty() {
        return Err(ResolveError::NoDocument);
    }

    pick(valid)
}

struct Parsed {
    document: XIDDocument,
    bytes: Vec<u8>,
}

fn parse(bytes: &[u8]) -> Option<Parsed> {
    let cbor = CBOR::try_from_data(bytes).ok()?;
    let document = XIDDocument::try_from(cbor).ok()?;
    Some(Parsed {
        document,
        bytes: bytes.to_vec(),
    })
}

fn pick(valid: Vec<Parsed>) -> Result<WinningDoc, ResolveError> {
    let mut unmarked: Vec<Parsed> = Vec::new();
    let mut marked: Vec<Parsed> = Vec::new();
    for item in valid {
        if item.document.provenance().is_some() {
            marked.push(item);
        } else {
            unmarked.push(item);
        }
    }

    if marked.is_empty() {
        return pick_unmarked(unmarked);
    }
    if !unmarked.is_empty() {
        // An unmarked document cannot sit on a marked chain.
        return Err(ResolveError::Duplicity);
    }
    pick_marked(marked)
}

fn pick_unmarked(unmarked: Vec<Parsed>) -> Result<WinningDoc, ResolveError> {
    let Some(first) = unmarked.first() else {
        return Err(ResolveError::NoDocument);
    };
    if unmarked.iter().any(|item| item.bytes != first.bytes) {
        return Err(ResolveError::Duplicity);
    }
    let winner = unmarked
        .into_iter()
        .next()
        .ok_or(ResolveError::NoDocument)?;
    Ok(WinningDoc {
        document: winner.document,
        bytes: winner.bytes,
    })
}

fn pick_marked(marked: Vec<Parsed>) -> Result<WinningDoc, ResolveError> {
    let Some(first_mark) = marked.first().and_then(|item| item.document.provenance()) else {
        return Err(ResolveError::NoDocument);
    };
    let chain = first_mark.chain_id().to_vec();
    let mut best_seq = first_mark.seq();
    let mut best_idx = 0usize;

    for (idx, item) in marked.iter().enumerate() {
        let Some(mark) = item.document.provenance() else {
            return Err(ResolveError::Duplicity);
        };
        if mark.chain_id() != chain.as_slice() {
            return Err(ResolveError::Duplicity);
        }
        if mark.seq() > best_seq {
            best_seq = mark.seq();
            best_idx = idx;
        } else if mark.seq() == best_seq {
            let best = marked.get(best_idx).ok_or(ResolveError::NoDocument)?;
            if item.bytes != best.bytes {
                return Err(ResolveError::Duplicity);
            }
        }
    }

    let winner = marked
        .into_iter()
        .nth(best_idx)
        .ok_or(ResolveError::NoDocument)?;
    Ok(WinningDoc {
        document: winner.document,
        bytes: winner.bytes,
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "panicking on failure is the assertion in a test"
)]
mod tests {
    use bc_xid::{XIDDocument, XIDGenesisMarkOptions, XIDInceptionKeyOptions};
    use dcbor::prelude::*;

    use super::*;

    fn encode(doc: &XIDDocument) -> Vec<u8> {
        CBOR::from(doc.clone()).to_cbor_data()
    }

    fn marked(passphrase: &str) -> XIDDocument {
        XIDDocument::new(
            XIDInceptionKeyOptions::Default,
            XIDGenesisMarkOptions::Passphrase(passphrase.to_owned(), None, None, None),
        )
    }

    fn unmarked() -> XIDDocument {
        XIDDocument::new(XIDInceptionKeyOptions::Default, XIDGenesisMarkOptions::None)
    }

    fn fetched<'a>(source: &'a str, bytes: &'a [u8], cached: bool) -> FetchedDocument<'a> {
        FetchedDocument {
            source,
            bytes,
            cached,
        }
    }

    #[test]
    fn newer_mark_on_the_same_chain_wins() {
        let mut later = marked("same-chain");
        let earlier = encode(&later);
        later
            .next_provenance_mark_with_embedded_generator(None, None, None)
            .unwrap();
        let later_bytes = encode(&later);
        let got = resolve_documents(
            ResolutionTier::Cached,
            &[
                fetched("a", &earlier, false),
                fetched("b", &later_bytes, false),
            ],
        )
        .unwrap();
        assert_eq!(got.bytes, later_bytes);
        assert_eq!(got.document.provenance().unwrap().seq(), 1);
    }

    #[test]
    fn divergent_valid_documents_fail_closed() {
        let a = encode(&marked("chain-a"));
        let b = encode(&marked("chain-b"));
        let err = resolve_documents(
            ResolutionTier::Cached,
            &[fetched("a", &a, false), fetched("b", &b, false)],
        )
        .unwrap_err();
        assert_eq!(err, ResolveError::Duplicity);
    }

    #[test]
    fn unparseable_source_is_not_a_vote() {
        let good = encode(&marked("only"));
        let got = resolve_documents(
            ResolutionTier::Cached,
            &[
                fetched("good", &good, false),
                fetched("junk", b"not-cbor", false),
            ],
        )
        .unwrap();
        assert_eq!(got.bytes, good);
    }

    #[test]
    fn consequential_rejects_cache_only() {
        let good = encode(&marked("cached"));
        let err = resolve_documents(
            ResolutionTier::Consequential,
            &[fetched("cache", &good, true)],
        )
        .unwrap_err();
        assert_eq!(err, ResolveError::CachedOnly);
    }

    #[test]
    fn cached_tier_accepts_one_document() {
        let good = encode(&marked("one"));
        let got =
            resolve_documents(ResolutionTier::Cached, &[fetched("cache", &good, true)]).unwrap();
        assert_eq!(got.bytes, good);
    }

    #[test]
    fn unmarked_identical_copies_succeed() {
        let bytes = encode(&unmarked());
        let got = resolve_documents(
            ResolutionTier::Cached,
            &[fetched("a", &bytes, false), fetched("b", &bytes, false)],
        )
        .unwrap();
        assert_eq!(got.bytes, bytes);
    }

    #[test]
    fn unmarked_different_documents_are_duplicity() {
        let a = encode(&unmarked());
        let b = encode(&unmarked());
        let err = resolve_documents(
            ResolutionTier::Cached,
            &[fetched("a", &a, false), fetched("b", &b, false)],
        )
        .unwrap_err();
        assert_eq!(err, ResolveError::Duplicity);
    }
}
