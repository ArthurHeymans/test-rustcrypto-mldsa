use ml_dsa::{KeyGen, MlDsa87};
use std::str::FromStr;
use x509_cert::builder::{Builder, RequestBuilder};
use x509_cert::der::{Decode, Encode, EncodePem};
use x509_cert::name::Name;

mod code_gen;
mod csr_rustcrypto;
mod tbs;

fn main() {}

#[test]
fn test_gen_mldsa87_csr_template() {
    use crate::code_gen::CodeGen;
    use crate::csr_rustcrypto::CsrTemplateBuilder;
    use ml_dsa::MlDsa87;
    use x509_cert::ext::pkix::{KeyUsage, KeyUsages};

    // Create a temporary directory for output
    let temp_dir = std::env::temp_dir();
    let out_dir = temp_dir.to_str().unwrap();

    // Set up key usage for certificate signing
    let key_usage = KeyUsage(KeyUsages::KeyCertSign.into());

    // Create the CSR template builder with ML-DSA-87
    let bldr = CsrTemplateBuilder::<ml_dsa::KeyPair<MlDsa87>>::new()
        .add_ueid_ext(&[0xFF; 17])
        .add_basic_constraints_ext(true, 5)
        .add_key_usage_ext(key_usage);

    // Generate the template with a subject name
    let template = bldr.tbs_template("ML-DSA-87 Test Certificate");

    // Generate code from the template
    CodeGen::gen_code("MlDsa87CsrTbs", template, out_dir);

    println!("Generated ML-DSA-87 CSR template code in: {}", out_dir);
}

#[test]
fn test() {
    let name = Name::from_str("CN=test").unwrap();

    let mut rng = rand::thread_rng();
    let kp = MlDsa87::key_gen(&mut rng);

    let builder = RequestBuilder::new(name).unwrap();

    let res = builder.build(&kp).unwrap();

    let der = res.to_der().unwrap();

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
    std::fs::write(
        "cert.pem",
        res.to_pem(x509_cert::der::pem::LineEnding::LF).unwrap(),
    )
    .unwrap();

    assert_eq!(decoded.to_der().unwrap(), der);
}
