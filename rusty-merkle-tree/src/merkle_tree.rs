extern crate crypto;
use::crypto::sha3::Sha3;
use crypto::digest::Digest;
#[derive(Debug, PartialEq)]
pub enum ArrayError{
    Empty,
    NotPowerOfTwo
}
#[derive(Debug, PartialEq)]
pub struct MerkleTree {
    input:Vec<String>,
    leaves: Vec<String>
}
impl MerkleTree {
    //  This function creates the MerkleTree struct
    // verying the input array
    fn new(leaves_array: Vec<String>) -> Result<MerkleTree, ArrayError> {
        if let Err(error) = MerkleTree::verify_input(&leaves_array) {
            return Err(error);
        }
        Ok( Self { input: leaves_array.clone(),
            leaves: MerkleTree::hash_leaves(leaves_array.clone()) })
    }
    // Hash the members of the array
    fn hash_leaves(leaves_array: Vec<String>) -> Vec<String> {
        let mut sha3_hasher = Sha3::keccak256();
        let hash_vector : Vec<String> = leaves_array.iter().
            map(|elem| {
                sha3_hasher.input(elem.as_ref());
                sha3_hasher.result_str().to_string()
                }).
            collect();
        hash_vector
    }
    // Check the array provided
    fn verify_input(array: &Vec<String>) -> Result<(), ArrayError> {
        if array.is_empty() {
            return Err(ArrayError::Empty);
        }
        if !is_power_of_two(array.len()) {
            return Err(ArrayError::NotPowerOfTwo);
        }
        Ok(())
    }
    fn get_root(&self) {
        /* ... */
    }
}


fn is_power_of_two(len: usize) -> bool {
    len > 0 && (len & (len - 1)) == 0
}

#[cfg(test)]
mod tests {
    use crate::merkle_tree;
    use super::*;
    #[test]
    fn empty_array() {
        let empty_vec = Vec::new();
        let mk = MerkleTree::new(empty_vec);
        assert_eq!(mk, Err(ArrayError::Empty));
    }
    /*
    #[test]
    fn build_from_two_elements_is_ok() {
        let tree = MerkleTree::build_from(vec!["foo".into(), "bar".into()]);
        assert!(tree.is_ok());
    }
    #[test]
    fn build_from_two_elements_root_is_ok() {
        let tree = MerkleTree::build_from(vec!["foo".into(), "bar".into()]);
        let mut hasher = Sha3::keccak256();
        hasher.input("foo".to_string().as_bytes());
        let hash1 = hasher.result_str();
        let mut hasher = Sha3::keccak256();
        hasher.input("bar".to_string().as_bytes());
        let hash2 = hasher.result_str();
        let mut hasher = Sha3::keccak256();
        hasher.input((hash1 + hash2.as_str()).as_bytes());
        let root = hasher.result_str();

        assert_eq![tree.unwrap().get_root(), root];
    }

    #[test]
    fn build_from_four_elements_root_is_ok() {
        let tree = MerkleTree::build_from(vec!["foo".into(), "bar".into(), "hello".into(), "world!".into()]);

        //manually get the hashes of all inputs
        let mut hasher = Sha3::keccak256();
        hasher.input("foo".to_string().as_bytes());
        let hash1 = hasher.result_str();

        let mut hasher = Sha3::keccak256();
        hasher.input("bar".to_string().as_bytes());
        let hash2 = hasher.result_str();

        let mut hasher = Sha3::keccak256();
        hasher.input("hello".to_string().as_bytes());
        let hash3 = hasher.result_str();

        let mut hasher = Sha3::keccak256();
        hasher.input("world!".to_string().as_bytes());
        let hash4 = hasher.result_str();

        //manually get the hashes of the parents
        let mut hasher = Sha3::keccak256();
        hasher.input((hash1 + hash2.as_str()).as_bytes());
        let root1 = hasher.result_str();

        let mut hasher = Sha3::keccak256();
        hasher.input((hash3 + hash4.as_str()).as_bytes());
        let root2 = hasher.result_str();

        //manually get the root
        let mut hasher = Sha3::keccak256();
        hasher.input((root1 + root2.as_str()).as_bytes());
        let root = hasher.result_str();

        println!("{root}");
        assert!(tree.is_ok());

        assert_eq![tree.unwrap().get_root(), root];

    }

     */
}