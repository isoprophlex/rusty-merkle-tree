extern crate crypto;
pub mod merkle_tree;
fn main() {
    let leaves = vec!["franco".to_string()];
    let mk = merkle_tree::MerkleTree::new(leaves);
    println!(
        "root for the vec given: {:?}",
        mk.unwrap().calculate_merkle_root()
    );
}
