use std::str::FromStr;
use ml_dsa::{MlDsa87, KeyGen};
use x509_cert::builder::{Builder, RequestBuilder};
use x509_cert::name::Name;
use x509_cert::der::{Encode, Decode, EncodePem};

fn main() {}

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
    println!("  Parameters: {:?}", decoded.info.public_key.algorithm.parameters);
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
    std::fs::write("cert.pem", res.to_pem(x509_cert::der::pem::LineEnding::LF).unwrap()).unwrap();

    assert_eq!(decoded.to_der().unwrap(), der);
}
