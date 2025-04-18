/*++

Licensed under the Apache-2.0 license.

File Name:

    csr_rustcrypto.rs

Abstract:

    File contains generation of X509 Certificate Signing Request (CSR) To Be Signed (TBS)
    template using RustCrypto that can be substituted at firmware runtime.

--*/
use std::str::FromStr;

use crate::tbs::{get_tbs, init_param, sanitize, TbsParam, TbsTemplate};
use const_oid::{AssociatedOid, ObjectIdentifier};
use core::marker::PhantomData;
use der::Decode;
use der::Sequence;
use ml_dsa::{KeyGen, MlDsa87};
use sha2::{Digest, Sha256};
use signature::Keypair;
use spki::EncodePublicKey;
use x509_cert::builder::{Builder, RequestBuilder};
use x509_cert::der::Encode;
use x509_cert::ext::{
    pkix::{BasicConstraints, KeyUsage},
    AsExtension, Extension,
};
use x509_cert::name::Name;

/// CSR Template Param
struct CsrTemplateParam {
    tbs_param: TbsParam,
    needle: Vec<u8>,
}

#[derive(Sequence, Default, Debug)]
struct TcgUeid<'a> {
    #[asn1(type = "OCTET STRING")]
    ueid: &'a [u8],
}

impl<'a> AssociatedOid for TcgUeid<'a> {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.5.4.4");
}

impl<'a> AsExtension for TcgUeid<'a> {
    fn critical(&self, _subject: &Name, _extensions: &[Extension]) -> bool {
        true
    }
}

/// CSR Tempate Builder
pub struct CsrTemplateBuilder<'a, Key> {
    basic_constraints: Option<BasicConstraints>,
    key_usage: Option<KeyUsage>,
    tcg_ueid: Option<TcgUeid<'a>>,
    params: Vec<CsrTemplateParam>,
    _phantom: PhantomData<Key>,
}

pub trait BuilderKeys: Sized {
    type Signature: spki::SignatureBitStringEncoding;
    fn key_gen() -> Self;
}

impl BuilderKeys for ml_dsa::KeyPair<MlDsa87> {
    type Signature = ml_dsa::Signature<MlDsa87>;
    fn key_gen() -> Self {
        let mut rng = rand::thread_rng();
        <MlDsa87 as KeyGen>::key_gen(&mut rng)
    }
}

impl<'a, Key> CsrTemplateBuilder<'a, Key>
where
    Key: BuilderKeys
        + spki::SignatureAlgorithmIdentifier
        + Keypair
        + signature::Signer<<Key as BuilderKeys>::Signature>,
    Key::VerifyingKey: EncodePublicKey,
{
    pub fn new() -> Self {
        Self {
            params: Vec::new(),
            _phantom: PhantomData,
            basic_constraints: None,
            key_usage: None,
            tcg_ueid: None,
        }
    }

    pub fn add_basic_constraints_ext(mut self, ca: bool, path_len: u32) -> Self {
        self.basic_constraints = Some(BasicConstraints {
            ca,
            path_len_constraint: Some(path_len as u8),
        });
        self
    }

    pub fn add_key_usage_ext(mut self, usage: KeyUsage) -> Self {
        self.key_usage = Some(usage);
        self
    }

    pub fn add_ueid_ext(mut self, ueid: &'a [u8]) -> Self {
        self.tcg_ueid = Some(TcgUeid { ueid });
        let param = CsrTemplateParam {
            tbs_param: TbsParam::new("UEID", 0, ueid.len()),
            needle: ueid.to_vec(),
        };
        self.params.push(param);

        self
    }

    pub fn tbs_template(mut self, subject_cn: &str) -> TbsTemplate {
        let key = Key::key_gen();

        // Get the public key and encode it
        let pk_der = key.verifying_key().to_public_key_der().unwrap();
        // Parse DER to obtain SubjectPublicKeyInfo and extract public key bytes
        let spki: spki::SubjectPublicKeyInfo<der::asn1::Any, der::asn1::BitString> =
            spki::SubjectPublicKeyInfo::from_der(pk_der.as_bytes()).unwrap();
        let pk_bytes = spki.subject_public_key.as_bytes().unwrap().to_vec();
        let param = CsrTemplateParam {
            tbs_param: TbsParam::new("PUBLIC_KEY", 0, pk_bytes.len()),
            needle: pk_bytes.clone(),
        };
        self.params.push(param);

        // Format the subject name with CN and serialNumber
        let key_hash = hex::encode(Sha256::digest(&pk_bytes)).to_uppercase();
        let subject = format!("CN={},serialNumber={}", subject_cn, key_hash);
        let name = Name::from_str(&subject).unwrap();
        let param = CsrTemplateParam {
            tbs_param: TbsParam::new("SUBJECT_SN", 0, key_hash.len()),
            needle: key_hash.into_bytes(),
        };
        self.params.push(param);

        let mut builder = RequestBuilder::new(name).unwrap();

        if let Some(basic_constraints) = self.basic_constraints {
            builder.add_extension(&basic_constraints).unwrap();
        }
        if let Some(ueid) = self.tcg_ueid {
            builder.add_extension(&ueid).unwrap();
        }
        let req = builder.build(&key).unwrap();
        let der = req.to_der().unwrap();

        // Decode the DER data back into a CertReq to verify it worked
        let decoded = x509_cert::request::CertReq::from_der(&der).unwrap();

        // Print subject names
        println!("\nSubject names:");
        for name in decoded.info.subject.iter_rdn() {
            let attr = name.iter().next().unwrap();
            println!("  {}: {:?}", attr.oid, attr.value);
        }

        // Print public key info
        println!("\nPublic key:");
        println!("  Algorithm: {}", decoded.info.public_key.algorithm.oid);
        println!(
            "  Parameters: {:?}",
            decoded.info.public_key.algorithm.parameters
        );
        println!("  Key: {:?}", decoded.info.public_key.subject_public_key);

        // Print attributes and extensions
        println!("\nAttributes:");
        for attr in decoded.info.attributes.iter() {
            println!("  OID: {}", attr.oid);
            for value in attr.values.iter() {
                if attr.oid.to_string() == "1.2.840.113549.1.9.14" {
                    // This is extensionRequest
                    if let Ok(extensions) = value.decode_as::<x509_cert::ext::Extensions>() {
                        println!("  Extensions:");
                        for ext in extensions.iter() {
                            println!("    ID: {}", ext.extn_id);
                            println!("    Critical: {}", ext.critical);
                            println!("    Value: {:?}", ext.extn_value);
                        }
                    }
                } else {
                    println!("    Value: {:?}", value);
                }
            }
        }

        // Write both DER and PEM formats
        std::fs::write("cert.der", &der).unwrap();

        // TODO move get_tbs from x509_openssl
        // Retrieve the To be signed portion from the CSR
        let mut tbs = get_tbs(der);

        // Calculate the offset of parameters and sanitize the TBS section
        let params = self
            .params
            .iter()
            .map(|p| sanitize(init_param(&p.needle, &tbs, p.tbs_param), &mut tbs))
            .collect();
        // Create the template
        TbsTemplate::new(tbs, params)
    }
}
