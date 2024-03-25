use openssl::{base64, hash::MessageDigest, sign::Signer};
use sfv::{Dictionary, Item, ListEntry, Parameters, ParseValue, Parser, SerializeValue};

const PRIVATE_KEY:&[u8] = b"-----BEGIN RSA PRIVATE KEY-----\r\nMIIEowIBAAKCAQEA3DGzdfA8onY6PtCJVsALzuGWkpEqAgonuG/AFu6Uec0D5OO0\r\ng2g9s+v2P0yb0KhsC/qzDKNDjXUo1/HuLOw55H0uXvfqpCH/QGDHFVsbUTb6kyhx\r\n8FPyxBVEnT5C2Iuo6pOOAczWL9L16N7fBQtndGBkPQykVOVO8PjawtdsNgU4LU+p\r\n0g8YNLDTcz7M42fdR1f6WflkNJfFphDneqCqTzCm+mayYtgAHK5fOJv4Gt+Hu9Y/\r\nh6D60SnXk0GMH1I0HQ+JSfCFrWaIX2ff+4ZNR792OvCWyAp62arNv1aXE5zuvdha\r\nWSdJsKLr/L+BZOtVZYVfxgw8uAUexv8RU9J8dwIDAQABAoIBAFf81EVwdgpFTAkF\r\ns5uiqhVFN7Hhp/OgszaUESIYu+Pf9IpmIx/Pa7iVtZSdvDWo12QCDcIjCz9fba68\r\n0fvJeWjATONOFcj4fNLw2RzDhyrw2TgslTr/kKaiCQT8eCGnzRvPUpONkpkRp4oi\r\nZOPTJsfuLJ/oiVITP3QzPNdW1brPpPFYiF0NhKVl8qtyK2DrJUSxwt6kqtZ50B6A\r\nm1tXc4POpEulzTMCNmrgIwhOYwS1D0JgORjG9gPi9G72d6ZzPYzWqUR7R8XN2s9/\r\nDuJh8XiKQcvorQmvygvNuh1wz2t6xZu5b0xYOabAezhGXEb6ZgixNZNp1Y+Fa0UN\r\nQVnxJ0ECgYEA3fEMzKj/pwlWPbCAkj+URp82WY1Oa+3NV7ME5TIbVzvlTGLX37YU\r\nIFJGC1Ucps7DCmzmTFVJnNG2JZB9FFHQnRuOWYRB5uXFDnQAS2VVAjHrbf0P2TBy\r\n1HMK/sLSVnoe+2rOyOPmzrSLuy17z6mcZEpTOhnHJVpFnzNBwIH/t4kCgYEA/fwA\r\nm84/U0Rai5SiPl0RCQgExnNdGn/BfSgt5F7wFXVDODz6Oj9xKOaJMZeMME3ev3lo\r\nMYPoQF6x0zqJmBeJcwgIV1oHfw69vat+bobHQBzKgfHW9LPk4Pq+kB5jrAx4HRmR\r\nJNrN2nFCEO8n9zPfVc1t/W5WmXHlPlS9wu0/k/8CgYA64LnOiX7Y50czsmFJawiA\r\n+7fFZhFJ3Jo/C8TesL5EFCWucAJo3LrWID1owDmLnwpq95zY3z9aFOBHct9bxqCb\r\nLTZEVSvOf2IZhXiWh9lXbbrRQPM1YP71kVd3YmO+gUM624jkDmGqsIbpLxXLb2mH\r\nyZfur+v+4sXZiBWHZnVaUQKBgQDLHI54CxZFRrKKUVD2QoLvEASRl4xrNqPLrSgW\r\nK34gCui4vrr1ferG5KXujN1Fe+CYi0Sx5GUFpTTcUUHb6Wa4IUJaaNr51xYR6mVv\r\nikUplly0UmyuwHZXHO7sXgEjg81CqEGUkY5yFITa+gaiAE+oVGKTe3uxto23rRkc\r\nG5LujQKBgF9FuZkBK2gnOfaVnjKoXQKU8S+iaWuGRYuYYVYkHAY/zihLUgOVicQ4\r\nK+ItUKlVYuNb+xFkiwiTZFPs64xncL40B5kG5j2nsmk2qteGV0e2wQc3DLlBXHnf\r\nziujI3jSSeKbtzdS6HKy5zxXTH2IWkP/th0WrEJvuD9N0xlXJlX/\r\n-----END RSA PRIVATE KEY-----\r\n";

fn main() {
    use openssl::rsa::{Padding, Rsa};
    use openssl::pkey::PKey;

    let base = "hello";

    let keypair = PKey::from_rsa(Rsa::private_key_from_pem(PRIVATE_KEY).unwrap()).unwrap();

    let mut signer = Signer::new(MessageDigest::sha256(), &keypair).unwrap();
    signer.set_rsa_padding(Padding::PKCS1).unwrap();
    let tag = signer
        .sign_oneshot_to_vec(&base.as_bytes())
        .expect("Signing to be infallible");

        let dict = Dictionary::from([(
            "pyhms".to_owned(),
            ListEntry::Item(Item {
                bare_item: sfv::BareItem::ByteSeq(tag),
                params: Parameters::new(),
            }),
        )]);

    println!("{}",dict.serialize_value().unwrap());
}
