extern crate crypto;
use::crypto::sha3::Sha3;
use crypto::digest::Digest;
use crate::array_error::ArrayError;

pub struct MerkleTree {
    leaves: Vec<String>
}
impl MerkleTree {
    //  This function creates the MerkleTree struct
    // verying the input array
    fn new(&self ,leaves_array: Vec<String>) -> Result<MerkleTree, ArrayError> {
        if let Err(error) = MerkleTree::verify_input(&leaves_array) {
            return Err(error);
        }
        let mk = MerkleTree::hash_leaves(leaves_array);
        Ok( Self { leaves: mk })
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