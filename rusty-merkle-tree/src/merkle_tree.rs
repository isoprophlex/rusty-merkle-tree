extern crate crypto;
use ::crypto::sha3::Sha3;
use crypto::digest::Digest;
#[derive(Debug, PartialEq, Clone)]
pub enum ArrayError {
    Empty,
}
#[derive(Debug, PartialEq, Clone)]
pub struct MerkleTree {
    pub(crate) input: Vec<String>,
    leaves: Vec<String>,
}
const _SMALL_ARRAY: usize = 1;
impl MerkleTree {
    //  This function creates the MerkleTree struct
    // verying the input array
    pub(crate) fn new(leaves_array: Vec<String>) -> Result<MerkleTree, ArrayError> {
        MerkleTree::verify_input(&leaves_array)?;
        Ok(Self {
            input: leaves_array.clone(),
            leaves: MerkleTree::hash_leaves(leaves_array),
        })
    }
    // Hash the members of the array
    fn hash_leaves(leaves_array: Vec<String>) -> Vec<String> {
        let mut hashes: Vec<String> = leaves_array
            .iter()
            .map(|e| {
                let mut sha3 = Sha3::keccak256();
                sha3.input(e.as_bytes());
                sha3.result_str().to_string()
            })
            .collect();

        let mut len = hashes.len();
        while (len & (len - 1)) != 0 {
            hashes.push(hashes.last().unwrap().clone());
            len = hashes.len();
        }

        hashes
    }
    // Check the array provided
    fn verify_input(array: &Vec<String>) -> Result<(), ArrayError> {
        if array.is_empty() {
            return Err(ArrayError::Empty);
        }
        Ok(())
    }
    pub(crate) fn calculate_merkle_root(&self) -> String {
        // Return empty string if no roots
        if self.leaves.is_empty() {
            return String::new();
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

        // Input both nodes
        hasher.input(left.as_bytes());
        hasher.input(right.as_bytes());

        // Get nodes
        let result = hasher.result_str();

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::sha3::Sha3Mode::Sha3_256;

    #[test]
    fn empty_array() {
        let empty_vec = Vec::new();
        let mk = MerkleTree::new(empty_vec);
        assert_eq!(mk, Err(ArrayError::Empty));
    }
    #[test]
    fn array_with_three_elements() {
        let mut three_elements_vec = Vec::new();
        three_elements_vec.push("franco".to_string());
        three_elements_vec.push("cuppari".to_string());
        three_elements_vec.push("lambda".to_string());
        let mk = MerkleTree::new(three_elements_vec.clone());
        assert_eq!(mk.unwrap().input, three_elements_vec)
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
    #[test]
    fn ten_elements_array_turns_to_sixteen() {
        let mk = MerkleTree::new(vec![
            "f".into(),
            "r".into(),
            "o".into(),
            "m".into(),
            "t".into(),
            "e".into(),
            "n".into(),
            "t".into(),
            "o".into(),
            "s".into(),
        ]);

        assert!(mk.is_ok());
        assert_eq!(mk.unwrap().leaves.len(), 16);
    }
    #[test]
    fn root_for_three_elements() {
        let input = vec![
            "hash1".to_string(),
            "hash2".to_string(),
            "hash3".to_string(),
        ];
        let mut mk = MerkleTree::new(input.clone());
        let mut sha3_1 = Sha3::keccak256();
        let mut sha3_2 = Sha3::keccak256();
        let mut sha3_3 = Sha3::keccak256();
        sha3_1.input(&input[0].as_bytes());
        sha3_2.input(&input[1].as_bytes());
        sha3_3.input(&input[2].as_bytes());
        let leaves_hashes = vec![
            sha3_1.result_str(),
            sha3_2.result_str(),
            sha3_3.result_str(),
        ];

        let mut sha_parent_1 = Sha3::keccak256();
        let mut sha_parent_2 = Sha3::keccak256();

        //  parent one
        sha_parent_1.input(&leaves_hashes[0].as_bytes());
        sha_parent_1.input(&leaves_hashes[1].as_bytes());

        //  parent two
        sha_parent_2.input(&leaves_hashes[2].as_bytes());
        sha_parent_2.input(&leaves_hashes[2].as_bytes());

        let parents_hashes = vec![sha_parent_1.result_str(), sha_parent_2.result_str()];

        let mut sha_root = Sha3::keccak256();
        sha_root.input(&parents_hashes[0].as_bytes());
        sha_root.input(&parents_hashes[1].as_bytes());

        let root = sha_root.result_str();

        assert!(mk.is_ok());
        assert_eq!(mk.unwrap().calculate_merkle_root(), root);
    }
}
