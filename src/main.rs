use anyhow::{bail, Context, Result};
use rand::Rng;
use sha2::{Sha256, Digest};
use cryptoki::{
    session::{
        Session,
        UserType
    },
    context::{
        CInitializeArgs,
        Pkcs11,
    },
    mechanism::Mechanism,
    object::{
        Attribute,
        AttributeType,
        ObjectHandle, ObjectClass,
    },
    slot::Slot,
};
use rsa::{BigUint, PaddingScheme, PublicKey};
use std::{
    convert::TryFrom,
    path::PathBuf,
    thread,
};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "cryptoki-example", about = "An example cryptoki CLI")]
struct CliOpt {
    /// PKCS11 Module path
    #[structopt(long, parse(from_os_str))]
    module: PathBuf,

    /// User PIN
    #[structopt(long)]
    pin: String,

    /// Slot ID
    #[structopt(long)]
    slot: u64,

    /// Key ID
    #[structopt(long)]
    id: String,
}

fn extract_modulus(session: &Session, object: ObjectHandle) -> Result<BigUint> {
    let attributes = session.get_attributes(object, &[AttributeType::Modulus])?;

    if let Some(Attribute::Modulus(vec)) = attributes.get(0) {
        Ok(BigUint::from_bytes_be(&vec))
    } else {
        bail!("Modulus Attribute is not available");
    }
}

fn extract_public_exponent(session: &Session, object: ObjectHandle) -> Result<BigUint> {
    let attributes = session.get_attributes(object, &[AttributeType::PublicExponent])?;

    if let Some(Attribute::PublicExponent(vec)) = attributes.get(0) {
        Ok(BigUint::from_bytes_be(&vec))
    } else {
        bail!("Public Exponent Attribute is not available");
    }
}

fn main() -> Result<()> {
    let opt = CliOpt::from_args();

    // Extra parsing out of command line arguments
    let keyid = hex::decode(&opt.id)
        .with_context(|| format!("Failed to parse input Key ID ('{}') as hex", &opt.id))?;
    let slot = Slot::try_from(opt.slot)
        .with_context(|| format!("Failed to parse slot ('{}') as Slot", opt.slot))?;

    // Create and initialize the PKCS11 client object
    let mut pkcs11client = Pkcs11::new(opt.module)?;
    pkcs11client.initialize(CInitializeArgs::OsThreads)?;

    // Open a session and login with as a User type
    let session = pkcs11client.open_ro_session(slot)?;
    session.login(UserType::User, Some(&opt.pin.as_str()))?;

    // Find the objects corresponding to the provided key ID for signing and signature verification
    let verify_objects = session.find_objects(&[
        Attribute::Verify(true.into()),
        Attribute::Id(keyid.clone()),
    ])?;
    let sign_objects = session.find_objects(&[
        Attribute::Sign(true.into()),
        Attribute::Local(true.into()),
        Attribute::Id(keyid.clone()),
    ])?;

    if verify_objects.len() != 1 && sign_objects.len() != 1 {
        bail!("Can't uniquely determine encryption and decryption objects for key id: {}", opt.id);
    }
    let private_key = sign_objects[0];

    // The NitrokeyHSM doesn't support encrypting using asymmetric RSA keys on the device, you're
    // meant to extract the public key attributes and use them locally to encrypt any data.
    let modulus = extract_modulus(&session, verify_objects[0])?;
    let pubexp = extract_public_exponent(&session, verify_objects[0])?;

    // Use the RustCrypto RSA crate to establish the public key locally
    let pubkey = rsa::RSAPublicKey::new(modulus, pubexp)?;
    let mut message = [0u8; 256];

    loop {
        rand::thread_rng().fill(&mut message);
        let signature = session.sign(&Mechanism::Sha256RsaPkcs, private_key, &message).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&message);
        let hash = hasher.finalize();
        pubkey.verify(PaddingScheme::PKCS1v15Sign { hash: Some(rsa::Hash::SHA2_256)}, &hash, &signature)?;
        println!("signature valid");

        thread::sleep(std::time::Duration::from_secs(10));
    }
}
