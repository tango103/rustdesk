//! tech-keygen: genera y prueba la llave del técnico.
//!
//!   tech-keygen gen  <archivo_salida>   crea llave nueva (pide contraseña 2 veces)
//!   tech-keygen test <archivo_clave>    prueba que el archivo y la contraseña sirven
//!
//! Para automatizar pruebas se puede usar la variable TECH_KEY_PASS en vez de escribir
//! la contraseña. En uso real, escribila a mano.

#[path = "../../../src/tech_auth.rs"]
#[allow(dead_code)]
mod tech_auth;

use std::process::exit;

fn ask(prompt: &str) -> String {
    if let Ok(p) = std::env::var("TECH_KEY_PASS") {
        return p;
    }
    rpassword::prompt_password(prompt).unwrap_or_default()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("uso: tech-keygen gen <archivo_salida> | test <archivo_clave>");
        exit(2);
    }
    match args[1].as_str() {
        "gen" => {
            let out = &args[2];
            if std::path::Path::new(out).exists() {
                eprintln!("ERROR: {out} ya existe, no lo piso. Borralo a mano si querés reemplazarlo.");
                exit(1);
            }
            let p1 = ask("Contraseña de la llave (mínimo 10 caracteres): ");
            let p2 = ask("Repetila: ");
            if p1 != p2 {
                eprintln!("ERROR: las contraseñas no coinciden.");
                exit(1);
            }
            let (pk, sk) = tech_auth::generate_keypair();
            let Some(blob) = tech_auth::encrypt_secret(&sk, &p1) else {
                eprintln!("ERROR: contraseña demasiado corta (mínimo 10).");
                exit(1);
            };
            std::fs::write(out, blob).expect("no pude escribir el archivo");
            println!("Llave privada cifrada guardada en: {out}");
            println!("Guardala SOLO en el pendrive y hacé una copia de respaldo.");
            println!();
            println!("CLAVE PÚBLICA (esta va en la compilación como TECH_PUBKEY):");
            println!("{}", tech_auth::pubkey_to_b64(&pk));
        }
        "test" => {
            let pass = ask("Contraseña: ");
            let Some(sk) = tech_auth::load_key_file(&args[2], &pass) else {
                eprintln!("ERROR: archivo ilegible o contraseña incorrecta.");
                exit(1);
            };
            let pk = sk.public_key();
            let sig = tech_auth::sign_login(&sk, "desafio-de-prueba-0123456789abcdef", "sal", "111", "222");
            let ok = tech_auth::verify_login(&pk, "desafio-de-prueba-0123456789abcdef", "sal", "111", "222", &sig);
            println!("Firma de prueba: {}", if ok { "OK" } else { "FALLÓ" });
            println!("Clave pública: {}", tech_auth::pubkey_to_b64(&pk));
            if !ok { exit(1); }
        }
        _ => { eprintln!("comando desconocido"); exit(2); }
    }
}
