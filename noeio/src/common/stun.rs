use rand::Rng;
use stun_codec::TransactionId;

pub fn generate_tid() -> TransactionId {
    let mut tid = [0u8; 12];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut tid);
    TransactionId::new(tid)
}

#[cfg(test)]
mod test {

    use super::*;
    #[test]
    fn test_generate_tid() {
        let tid = generate_tid();

        println!("{:?}", tid)
    }
}
