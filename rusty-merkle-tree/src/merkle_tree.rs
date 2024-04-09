extern crate crypto;
use ::crypto::sha3::Sha3;
use crypto::digest::Digest;
#[derive(Debug, PartialEq, Clone)]
pub enum ArrayError {
    Empty,
    NotPowerOfTwo,
}
#[derive(Debug, PartialEq, Clone)]
pub struct MerkleTree {
    input: Vec<String>,
    leaves: Vec<String>,
}
const SMALL_ARRAY: usize = 1;
impl MerkleTree {
    //  This function creates the MerkleTree struct
    // verying the input array
    fn new(leaves_array: Vec<String>) -> Result<MerkleTree, ArrayError> {
        if let Err(error) = MerkleTree::verify_input(&leaves_array) {
            return Err(error);
        }
        Ok(Self {
            input: leaves_array.clone(),
            leaves: MerkleTree::hash_leaves(leaves_array),
        })
    }
    // Hash the members of the array
    fn hash_leaves(leaves_array: Vec<String>) -> Vec<String> {
        let mut sha3_hasher = Sha3::keccak256();
        let hash_vector: Vec<String> = leaves_array
            .iter()
            .map(|elem| {
                sha3_hasher.input(elem.as_ref());
                let str = sha3_hasher.result_str().to_string();
                sha3_hasher.reset();
                str
            })
            .collect();
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
    fn calculate_merkle_root(&self) -> String {
        if self.leaves.is_empty() {
            return String::new(); // Devolver una cadena vacía si no hay hojas
        }
        let mut current_level: Vec<String> = self.leaves.clone();
        while current_level.len() > 1 {
            let mut next_level: Vec<String> = Vec::new();
            for i in (0..current_level.len()).step_by(2) {
                let left_hash = &current_level[i];
                let right_hash = if i + 1 < current_level.len() {
                    &current_level[i + 1]
                } else {
                    left_hash
                };
                let combined_hash = self.hash_nodes(left_hash, right_hash);
                next_level.push(combined_hash);
            }
            current_level = next_level;
        }
        current_level[0].clone()
    }
    fn hash_nodes(&self, left: &str, right: &str) -> String {
        let mut hasher = Sha3::keccak256();

        // Concatenar los hashes de los nodos hijos
        hasher.input(left.as_bytes());
        hasher.input(right.as_bytes());

        // Calcular el hash combinado
        let result = hasher.result_str();

        result
    }
}

fn is_power_of_two(len: usize) -> bool {
    len > 0 && (len & (len - 1)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_array() {
        let empty_vec = Vec::new();
        let mk = MerkleTree::new(empty_vec);
        assert_eq!(mk, Err(ArrayError::Empty));
    }
    #[test]
    fn array_with_three_elements_fails() {
        let mut three_elements_vec = Vec::new();
        three_elements_vec.push("franco".to_string());
        three_elements_vec.push("cuppari".to_string());
        three_elements_vec.push("lambda".to_string());
        let mk = MerkleTree::new(three_elements_vec);
        assert_eq!(mk, Err(ArrayError::NotPowerOfTwo));
    }
    #[test]
    fn calculate_root_for_a_single_node() {
        let mut vec = Vec::new();
        vec.push("franco".to_string());
        let mk = MerkleTree::new(vec);
        let mut sha_3_hasher = Sha3::keccak256();
        sha_3_hasher.input("franco".to_string().as_ref());
        let manual_hash_root = sha_3_hasher.result_str();
        //  Manual hash equals the one that the struct returns
        assert_eq!(manual_hash_root, mk.unwrap().calculate_merkle_root())
    }
    #[test]
    fn root_for_four_element_vec() {
        let leaf_hashes = vec![
            "hash1".to_string(),
            "hash2".to_string(),
            "hash3".to_string(),
            "hash4".to_string(),
        ];
        let mk = MerkleTree::new(leaf_hashes);
        let merkle_root_calculated = mk.unwrap().calculate_merkle_root();
        let vec2 = vec!["hash1", "hash2", "hash3", "hash4"];
        let mut vec_leafs = Vec::new();
        let mut hasher1 = Sha3::keccak256();
        hasher1.input(vec2[0].as_bytes());
        vec_leafs.push(hasher1.result_str());
        let mut hasher2 = Sha3::keccak256();
        hasher2.input(vec2[1].as_bytes());
        vec_leafs.push(hasher2.result_str());
        let mut hasher3 = Sha3::keccak256();
        hasher3.input(vec2[2].as_bytes());
        vec_leafs.push(hasher3.result_str());
        let mut hasher4 = Sha3::keccak256();
        hasher4.input(vec2[3].as_bytes());
        vec_leafs.push(hasher4.result_str());

        let mut hasher_parent_1 = Sha3::keccak256();
        hasher_parent_1.input(vec_leafs[0].as_bytes());
        hasher_parent_1.input(vec_leafs[1].as_bytes());
        let hash_p1 = hasher_parent_1.result_str();

        let mut hasher_parent_2 = Sha3::keccak256();
        hasher_parent_2.input(vec_leafs[2].as_bytes());
        hasher_parent_2.input(vec_leafs[3].as_bytes());
        let hash_p2 = hasher_parent_2.result_str();

        let mut hasher_root = Sha3::keccak256();
        hasher_root.input(hash_p1.as_bytes());
        hasher_root.input(hash_p2.as_bytes());
        let hash_root = hasher_root.result_str();

        // Check if results are equal
        assert_eq!(merkle_root_calculated, hash_root);
    }
}
