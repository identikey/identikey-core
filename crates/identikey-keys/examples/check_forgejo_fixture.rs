//! Inspect a fixture against a separate authority file and an explicit Forgejo target.
//! This offline example has no checkpoint store, durable nonce store, or production keys.
use identikey_keys::forgejo_binding::{CurrentAuthority, Proof, verify};
use std::{env, error::Error, fs::File, io::Read};

fn load(path: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    File::open(path)?.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err("fixture input exceeds 64 KiB".into());
    }
    Ok(bytes)
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = env::args().skip(1).collect();
    let [context, proof, instance, org] = args.as_slice() else {
        return Err("usage: check_forgejo_fixture CONTEXT.json PROOF.json INSTANCE ORG_ID".into());
    };
    let authority: CurrentAuthority = serde_json::from_slice(&load(context)?)?;
    let proof: Proof = serde_json::from_slice(&load(proof)?)?;
    if authority.binding.instance != *instance || authority.binding.org_id != org.parse::<u64>()? {
        return Err("fixture authority does not match the requested Forgejo target".into());
    }
    verify(&authority, &proof)?;
    println!(
        "Verified fixture for {instance} organization {org}, guild {}",
        bs58::encode(authority.binding.guild_xid).into_string()
    );
    Ok(())
}
