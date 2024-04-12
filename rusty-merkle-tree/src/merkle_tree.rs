extern crate crypto;
use ::crypto::sha3::Sha3;
use crypto::digest::Digest;

#[derive(Debug, PartialEq, Clone)]
pub enum InputError {
    Empty,
    LeafNotFound,
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
    #[allow(unused)]
    pub(crate) fn new(leaves_array: Vec<String>) -> Result<MerkleTree, InputError> {
        MerkleTree::verify_input(&leaves_array)?;
        Ok(Self {
            input: leaves_array.clone(),
            leaves: MerkleTree::hash_leaves(leaves_array),
        })
    }
    // Hash the members of the array
    #[allow(unused)]
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
    #[allow(unused)]
    fn verify_input(array: &Vec<String>) -> Result<(), InputError> {
        if array.is_empty() {
            return Err(InputError::Empty);
        }
        Ok(())
    }
    #[allow(unused)]
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
    fn proof(&self, index: usize, new_leaves: &[String], mut proof: Vec<String>) -> Vec<String> {
        if new_leaves.len() == _SMALL_ARRAY {
            return proof;
        }
        let mut parents = vec![];
        // Get the hash for the upper nodes
        for chunk in new_leaves.chunks_exact(2) {
            let mut sha3 = Sha3::keccak256();
            sha3.input(&chunk[0].as_ref());
            sha3.input(&chunk[1].as_ref());
            parents.push(sha3.result_str());
        }
        //  If index % 2 == 0 I'm the left child
        // So, my sibling is on my right (+1)
        let sibling_index: usize = if index % 2 == 0 {
            index + 1
            //  If index % 2 != 0 I'm the right child
            // So, my sibling is on my left (-1)
        } else {
            index - 1
        };
        //  Add the node I need to my proof vector
        proof.push(new_leaves[sibling_index].clone());
        let updated_index = index / 2;
        self.proof(updated_index, &parents, proof)
    }
    pub fn leaf_exists(&mut self, node_to_check: String) -> Result<Vec<String>, InputError> {
        let mut sha3 = Sha3::keccak256();
        sha3.input(node_to_check.as_ref());
        let hash = sha3.result_str();
        for (index, &ref hash_leaf) in self.leaves.iter().enumerate() {
            if hash_leaf.to_string() == hash {
                let proof = vec![hash];
                return Ok(self.proof(index, &self.leaves, proof));
            }
        }
        Err(InputError::LeafNotFound)
    }
}
#[allow(unused)]
pub fn verify_proof(mut proof: Vec<String>, root: &str, index: usize) -> bool {
    let mut element = proof.remove(0);
    let mut current_index = index;

    for sibling in proof {
        let mut sha3 = Sha3::keccak256();
        //  Im on the left
        if current_index % 2 == 0 {
            sha3.input(element.as_ref());
            sha3.input(sibling.as_ref());
            element = sha3.result_str();
        //  Im on the right
        } else {
            sha3.input(sibling.as_ref());
            sha3.input(element.as_ref());
            element = sha3.result_str();
        }
        current_index /= 2;
    }
    element == root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_array() {
        let empty_vec = Vec::new();
        let mk = MerkleTree::new(empty_vec);
        assert_eq!(mk, Err(InputError::Empty));
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
        let mk = MerkleTree::new(input.clone());
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
    #[test]
    fn member_not_in_array_is_err() {
        let input = vec![
            String::from("hash1"),
            String::from("hash2"),
            String::from("hash3"),
            String::from("hash4"),
        ];
        let mk = MerkleTree::new(input.clone());
        assert!(mk.is_ok());
        assert!(mk.unwrap().leaf_exists("foo".to_string()).is_err())
    }
    #[test]
    fn member_in_array() {
        let input = vec![
            String::from("hash1"),
            String::from("hash2"),
            String::from("hash3"),
            String::from("hash4"),
        ];
        let mk = MerkleTree::new(input.clone());
        assert!(mk.clone().is_ok());
        // let mut apparent_proof = vec![];
        let mut hasher1 = Sha3::keccak256();
        hasher1.input(String::from("hash1").as_ref());
        let mut hasher2 = Sha3::keccak256();
        hasher2.input(String::from("hash2").as_ref());

        let mut parent_left_hasher = Sha3::keccak256();
        parent_left_hasher.input(hasher1.result_str().as_ref());
        parent_left_hasher.input(hasher2.result_str().as_ref());
        let parent_left = parent_left_hasher.result_str();

        let mut hasher3 = Sha3::keccak256();
        hasher3.input(String::from("hash3").as_ref());
        let mut hasher4 = Sha3::keccak256();
        hasher4.input(String::from("hash4").as_ref());

        let mut parent_right_hasher = Sha3::keccak256();
        parent_right_hasher.input(hasher3.result_str().as_ref());
        let hash4 = hasher4.result_str();
        parent_right_hasher.input(hash4.as_ref());
        let parent_right = parent_right_hasher.result_str();

        let mut hasher_root = Sha3::keccak256();
        hasher_root.input(parent_left.as_ref());
        hasher_root.input(parent_right.as_ref());
        let root = hasher_root.result_str();
        //  Check if I got root right
        assert_eq!(mk.clone().unwrap().calculate_merkle_root(), root);
        let proof = mk.unwrap().leaf_exists(String::from("hash3"));
        //  Check if I got the proof right in MT struct and in and aux function I made
        assert!(verify_proof(proof.unwrap(), &root, 2));
    }
}
