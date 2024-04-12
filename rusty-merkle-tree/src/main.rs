pub mod merkle_tree;
fn main() {
    let leafs = vec!["franco".to_string()];

    match merkle_tree::MerkleTree::new(leafs) {
        Ok(tree) => {
            let root = tree.calculate_merkle_root();
            println!("root for the vec given: {:?}", root);
        }
        Err(err) => {
            eprintln!("Error: Failed to create Merkle tree: {:?}", err);
        }
    }
}
