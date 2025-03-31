
mod code_gen;
mod cert_rustcrypto;
mod csr_rustcrypto;
mod tbs; 

fn main() {
    // Call the test function directly
//    test_gen_mldsa87_cert_template();
//    test_gen_fmc_alias_cert_template();
}

// Make the test function public so it can be called from main
// #[test]
// pub fn test_gen_mldsa87_cert_template() {
//     use crate::code_gen::CodeGen;
//     use crate::cert_rustcrypto::CertTemplateBuilder;
//     use ml_dsa::MlDsa87;
//     use x509_cert::ext::pkix::{KeyUsage, KeyUsages};

//     // Create a temporary directory for output
//     let temp_dir = std::env::temp_dir();
//     let out_dir = temp_dir.to_str().unwrap();

//     // Set up key usage for certificate signing
//     let key_usage = KeyUsage(KeyUsages::KeyCertSign.into());

//     // Create the Certificate template builder with ML-DSA-87
//     let bldr = CertTemplateBuilder::<ml_dsa::KeyPair<MlDsa87>>::new()
//         .add_ueid_ext(&[0xFF; 17])
//         .add_basic_constraints_ext(true, 5)
//         .add_key_usage_ext(key_usage);

//     // Generate the template with subject and issuer names
//     let template = bldr.tbs_template("ML-DSA-87 Test Subject", "ML-DSA-87 Test Issuer");

//     // Generate code from the template
//     CodeGen::gen_code("MlDsa87CertTbs", template, out_dir);

//     println!("Generated ML-DSA-87 Certificate template code in: {}", out_dir);
// }

#[test]
fn test_gen_fmc_alias_cert_template() {
    use crate::cert_rustcrypto::CertTemplateBuilder;
    use crate::code_gen::CodeGen;
    use ml_dsa::MlDsa87;
    use x509_cert::ext::pkix::{KeyUsage, KeyUsages};

    // Create a temporary directory for output
    let temp_dir = std::env::temp_dir();
    let out_dir = temp_dir.to_str().unwrap();

    // Create KeyUsage with key_cert_sign set to true
    let key_usage = KeyUsage(KeyUsages::KeyCertSign.into());

    // Build the FMC Alias certificate template
    let bldr = CertTemplateBuilder::<ml_dsa::KeyPair<MlDsa87>>::new()
        .add_basic_constraints_ext(true, 3)
        .add_key_usage_ext(key_usage)
        .add_ueid_ext(&[0xFF; 17]);

    // Generate the template with subject and issuer CN
    let template = bldr.tbs_template("Caliptra 1.0 FMC Alias", "Caliptra 1.0 LDevID");
    
    // Generate the code
    CodeGen::gen_code("FmcAliasCertTbsMlDsa87", template, out_dir);
    
    println!("Generated FMC Alias certificate template at: {}", out_dir);
}

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
