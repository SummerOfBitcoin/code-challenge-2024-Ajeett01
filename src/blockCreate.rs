use std::{ fs, io::{Read, Write}, time::{SystemTime, UNIX_EPOCH}, vec};
use serde_json::Value;
use sha2::{Digest, Sha256};


extern crate hex;
extern crate serde_json;

use serde_json::{json};
use std::{slice::Windows};





use secp256k1::{
    ecdsa::Signature,
    Message, PublicKey, Secp256k1,
};



pub fn checkp2pkh(txn: &serde_json::Value) -> bool {
    txn["vin"]
        .as_array()
        .unwrap()
        .iter()
        .all(|input| input["prevout"]["scriptpubkey_type"].as_str().unwrap() == "p2pkh")
}



fn createBlockHeader(merkle_root: String) -> String {
 // Initialize version, previous block hash, target, and bits
 let version = "04000000";
 let previous_block_hash = "0000000000000000000000000000000000000000000000000000000000000000"; //32 bytes of zeroes
 let time = GetTime();
 let target = "0000ffff00000000000000000000000000000000000000000000000000000000";
 let bits = "ffff001f";

 // Concatenate the header components
 let header = format!(
     "{}{}{}{}{}",
     version, previous_block_hash, merkle_root, time, bits
 );

 // Mine the header
 let mined_header = mineHeader(&target, header);
 mined_header
}






fn GetTime() -> String {
    let now = SystemTime::now();
    let current = now.duration_since(UNIX_EPOCH).expect("Backward time running").as_secs() as u32;
    hex::encode(current.to_le_bytes())
}






pub(crate) fn hash256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize_reset();
    hasher.update(&result);
    let data = hasher.finalize_reset();
    data.to_vec()
}















fn mineHeader(target: &str, header: String) -> String {
     // Initialize nonce
     let mut nonce: u32 = 0;

     // Decode target and header bytes
     let target_bytes = hex::decode(target).unwrap();
     let header_bytes = hex::decode(header).unwrap();
 
     // Loop until a valid block is found
     loop {
         // Clone the header bytes and append nonce
         let mut header_clone = header_bytes.clone();
         header_clone.extend(nonce.to_le_bytes());
 
         // Calculate double SHA256 hash
         let mut hash_bytes = hash256(&header_clone);
         hash_bytes.reverse();
         
         // Check if the hash meets the target
         if hash_bytes < target_bytes {
             // Print the nonce and return the mined block header
             println!("Found a block");
             println!("Nonce = {}", nonce);
             return hex::encode(&header_clone);
         }
         nonce += 1;
     }
 
}












fn createTXIDWTXID(transactions: &[String], witnessTransactions: &[String]) -> (Vec<String>, Vec<String>) {
   // Initialize vectors to store transaction IDs
   let mut txids: Vec<String> = vec![];
   let mut wtxids: Vec<String> = vec![];

   // Initialize SHA256 hasher
   let mut hasher = Sha256::new();
   
   // Calculate transaction IDs for normal transactions
   for txn in transactions {
       let txn_bytes = hex::decode(txn).unwrap();
       hasher.update(&txn_bytes);
       let result = hasher.finalize_reset();
       hasher.update(&result);
       let result = hasher.finalize_reset();
       let txid = hex::encode(result);
       txids.push(txid);
   }

   // Calculate transaction IDs for witness transactions
   for wtxn in witnessTransactions {
       let txn_seg_bytes = hex::decode(wtxn).unwrap();
       hasher.update(&txn_seg_bytes);
       let result = hasher.finalize_reset();
       hasher.update(&result);
       let result = hasher.finalize_reset();
       let wtxid = hex::encode(result);
       wtxids.push(wtxid);
   }

   // Return transaction IDs
   (txids, wtxids)
}











pub fn checkp2wpkh(txn: &serde_json::Value) -> bool {
    txn["vin"]
        .as_array()
        .unwrap()
        .iter()
        .all(|input| input["prevout"]["scriptpubkey_type"].as_str().unwrap() == "v0_p2wpkh")
}















fn calculateFees(transaction: &serde_json::Value) -> usize {
 // Calculate total input amount
 let inputs: usize = transaction["vin"]
 .as_array()
 .unwrap()
 .iter()
 .map(|input| input["prevout"]["value"].as_u64().unwrap() as usize)
 .sum();

// Calculate total output amount
let outputs: usize = transaction["vout"]
 .as_array()
 .unwrap()
 .iter()
 .map(|output| output["value"].as_u64().unwrap() as usize)
 .sum();

// Calculate transaction fees
inputs - outputs
}

fn calculateWeight(transaction_data: &String, wit_witness_datadata: &String) -> usize {
        // Calculate transaction weight
        let txn_weight = transaction_data.len() / 2 * 4;

        // Calculate witness data weight
        let wit_weight = wit_witness_datadata.len() / 2;
    
        // Calculate total weight
        txn_weight + wit_weight
}












fn createCoinBase(merkle_root: &String, transaction_fees: &usize) -> (String, String) {
    // Clone transaction fees
    let new_satoshis = transaction_fees.clone();

    // Create coinbase transaction
    let mut coinbase = returnCoinbaseTransaction();
    coinbase["vout"][0]["value"] = serde_json::Value::from(new_satoshis);

    // Calculate witness commitment
    let witness_commitment = calculateWitnessCommitment(merkle_root);

    // Update coinbase transaction with witness commitment
    coinbase["vout"][1]["scriptpubkey"] =
        serde_json::Value::from(format!("{}{}", "6a24aa21a9ed", witness_commitment));
    coinbase["vout"][1]["scriptpubket_asm"] = serde_json::Value::from(format!(
        "{}{}",
        "OP_0 OP_PUSHBYTES_36 aa21a9ed", witness_commitment
    ));

    // Serialize coinbase transaction
    let coinbase_bytes = serializeTransaction(&coinbase);
    let coinbase_hex = hex::encode(coinbase_bytes.0); // Complete coinbase
    let coinbase_wit_hex = hex::encode(coinbase_bytes.1); // Without witness data
    
    // Return serialized coinbase transactions
    return (coinbase_hex, coinbase_wit_hex);
}
















fn calculateWitnessCommitment(witness_root: &String) -> String {
        // Initialize witness reserved value
        let witness_reserved_value = "0000000000000000000000000000000000000000000000000000000000000000";

        // Decode witness reserved value and witness root
        let wrv_bytes = hex::decode(witness_reserved_value).unwrap();
        let wr_bytes = hex::decode(witness_root).unwrap();
    
        // Concatenate witness root and witness reserved value
        let mut wc: Vec<u8> = vec![];
        wc.extend(wr_bytes);
        wc.extend(wrv_bytes);
    
        // Calculate double SHA256 hash
        let hash = hash256(&wc);
    
        // Return witness commitment
        hex::encode(hash)
}









fn createMarkleRoot(transactions: &Vec<String>) -> String {
    // Check if there's only one transaction
    if transactions.len() == 1 {
        return transactions.first().unwrap().clone();
    }

    // Initialize results vector
    let mut results: Vec<String> = vec![];

    // Iterate through transactions and calculate their hashes
    for i in (0..transactions.len()).step_by(2) {
        let txn1 = &transactions[i];
        let txn2: &String;

        // Handle odd number of transactions
        if i < transactions.len() - 1 {
            txn2 = &transactions[i + 1];
        } else {
            txn2 = txn1;
        }

        // Concatenate transactions and calculate hash
        let mut txn = hex::decode(txn1).unwrap();
        txn.extend(hex::decode(txn2).unwrap());

        // Calculate double SHA256 hash
        let mut hasher = Sha256::new();
        hasher.update(&txn);
        let hashed = hasher.finalize_reset();
        hasher.update(&hashed);
        let hashed = hasher.finalize_reset();

        // Store hash in results
        results.push(hex::encode(hashed));
    }

    // Recursively calculate merk
    createMarkleRoot(&results)
}







pub(crate) fn blockCreate() {
    // Start timing block creation process
    use std::time::Instant;
    let start_time = Instant::now();

    // Read transactions from mempool
    let transactions_json = readTrasactions();
    
    // Select transactions and calculate transaction and witness transaction IDs
    let mut selected_transactions = transactionSelector(transactions_json);
    let (mut txids, mut wtxids) = createTXIDWTXID(&selected_transactions.0, &selected_transactions.1);
    
    // Insert placeholder for coinbase witness transaction ID
    wtxids.insert(0, "0000000000000000000000000000000000000000000000000000000000000000".to_string());
    
    // Calculate merkle root of witness transaction IDs
    let merkle_wtxid = createMarkleRoot(&wtxids);
    
    // Create coinbase transaction
    let coinbase_txn = createCoinBase(&merkle_wtxid, &selected_transactions.2);
    
    // Insert coinbase transaction ID into list of transaction IDs
    selected_transactions.0.insert(0, coinbase_txn.clone().0);
    txids.insert(0, transactionIDMaker(coinbase_txn.clone().0));
    
    // Calculate merkle root of transaction IDs
    let merkle_txid = createMarkleRoot(&txids);
    
    // Create block header
    let block_header = createBlockHeader(merkle_txid);
    
    // Write block header and transactions to output file
    let mut file = fs::File::create("./output.txt").unwrap();
    file.write_all(block_header.as_bytes()).unwrap();
    file.write_all("\n".as_bytes()).unwrap();
    file.write_all(coinbase_txn.0.as_bytes()).unwrap();
    file.write_all("\n".as_bytes()).unwrap();
    for txn in txids {
        let mut bytes = hex::decode(txn).unwrap();
        bytes.reverse();
        file.write_all(hex::encode(bytes).as_bytes()).unwrap();
        file.write_all("\n".as_bytes()).unwrap();
    }
    file.write_all("\n".as_bytes()).unwrap();

    // Print total block creation time
    println!("Total block creation time: {:?}", start_time.elapsed());
}







fn readTrasactions() -> Vec<String> {
 // Read transactions from mempool directory
 let path = "./mempool";
 let directory = fs::read_dir(path).unwrap();

 // Initialize vector to store transactions
 let mut transactions: Vec<String> = vec![];

 // Iterate through files in directory and read transaction data
 for transaction in directory {
     let transaction = transaction.unwrap();
     if transaction.path().is_file() {
         let path = transaction.path();
         let mut file = fs::File::open(path).unwrap();
         let mut tx_data = String::new();
         file.read_to_string(&mut tx_data).unwrap();
         transactions.push(tx_data);
     }
 }
 return transactions;
}














fn returnCoinbaseTransaction() -> serde_json::Value {
    // Define the coinbase transaction JSON string
    let txn = r#"
    {
    "version": 1,
    "locktime": 0,
    "vin": [
        {
            "txid": "0000000000000000000000000000000000000000000000000000000000000000",
            "vout": 4294967295,
            "scriptsig": "03233708184d696e656420627920416e74506f6f6c373946205b8160a4256c0000946e0100",
            "scriptsig_asm": "OP_PUSHBYTES_3 233708 OP_PUSHBYTES_24 4d696e656420627920416e74506f6f6c373946205b8160a4 OP_PUSHBYTES_37 6c0000946e0100",
            "witness": [
                "0000000000000000000000000000000000000000000000000000000000000000"
            ],
            "is_coinbase": true,
            "sequence": 4294967295
        }
    ],
    "vout": [
        {
            "scriptpubkey": "00143b821fecac837bd5e3773a6568eb301ccfafe3e1",
            "scriptpubkey_asm": "OP_0 OP_PUSHBYTES_20 3b821fecac837bd5e3773a6568eb301ccfafe3e1",
            "scriptpubkey_type": "v0_p2wpkh",
            "scriptpubkey_address": "bc1q8wpplm9vsdaatcmh8fjk36esrn86lclp60dlnx",
            "value": 0
        },
        {
            "scriptpubkey": "",
            "scriptpubkey_asm": "OP_0 OP_PUSHBYTES_32 aa21a9ed+merkleroot",
            "scriptpubkey_type": "v0_p2wsh",
            "scriptpubkey_address": "bc1qej6dxtvr48ke9d724pg80522f6d5e0dk5z7a6mzmfl5acaxn6tnsgpfr4k",
            "value": 0
        }
    ]
}"#;

    // Parse the JSON string into a serde_json::Value
    serde_json::from_str(&txn).unwrap()
}


















fn transactionSelector(transactions: Vec<String>) -> (Vec<String>, Vec<String>, usize) {
     // Initialize vectors to store selected transactions and variables to track weight and fees
     let mut txvec: Vec<String> = vec![];
     let mut wtxvec: Vec<String> = vec![];
     let mut weight: usize = 0;
     let mut bytes: usize = 0;
     let mut total_fees: usize = 0;
     let mut skipped_transactions = 0;
 
     // Iterate through transactions
     for transaction in transactions {
         // Parse transaction JSON
         let tx: Value = serde_json::from_str(&transaction).unwrap();
 
         // Check if transaction is P2WPKH and SegWit valid
         if !checkp2wpkh(&tx) || !Segwittvalidate(&tx) {
             skipped_transactions += 1;
             continue;
         }
 
         // Serialize transaction and calculate fees and weight
         let serialized_tx = serializer(&tx);
         let fees = calculateFees(&tx);
         let txwt = calculateWeight(&serialized_tx.1, &serialized_tx.2);
 
         // Check if adding transaction exceeds block weight limit
         if (weight + txwt) < (4000000 - 1000) {
             // Add transaction to selected transactions list
             wtxvec.push(serialized_tx.0.clone()); 
             txvec.push(serialized_tx.1.clone()); 
             weight += txwt;
             bytes += serialized_tx.1.len() / 2 + serialized_tx.2.len() / 8;
             total_fees += fees;
         }
     }
 
     // Print total fees generated and number of transactions selected
     println!("Total fees generated = {}", total_fees);
     println!("Number of transactions selected = {}", txvec.len());
 
     // Return selected transactions and total fees
     (txvec, wtxvec, total_fees)
}













pub fn checkp2wpkhpkh(txn: &serde_json::Value) -> bool {
    txn["vin"]
        .as_array()
        .unwrap()
        .iter()
        .all(|input| {
            let scriptpubkey_type = input["prevout"]["scriptpubkey_type"].as_str().unwrap();
            scriptpubkey_type == "v0_p2wpkh" || scriptpubkey_type == "p2pkh"
        })
}
























pub(crate) fn encodeVariant(num: u64) -> Vec<u8> {
    match num {
        0..=0xfc => vec![num as u8],
        0xfd..=0xffff => {
            let mut varint_bytes = vec![0xfd];
            varint_bytes.extend_from_slice(&(num as u16).to_le_bytes());
            varint_bytes
        }
        0x10000..=0xffffffff => {
            let mut varint_bytes = vec![0xfe];
            varint_bytes.extend_from_slice(&(num as u32).to_le_bytes());
            varint_bytes
        }
        _ => {
            let mut varint_bytes = vec![0xff];
            varint_bytes.extend_from_slice(&num.to_le_bytes());
            varint_bytes
        }
    }

}



















fn encodeVariableString(s: Vec<u8>) -> Vec<u8> {
    let mut varstr = encodeVariant(s.len() as u64);
    varstr.extend(s);
    varstr
}















pub fn serializeInputData(tx_input: &Value) -> Vec<u8> {
    let mut serialized_data = vec![];

    // Extract transaction ID bytes
    let txid_bytes: Vec<u8> = hex::decode(tx_input["txid"].as_str().unwrap()).unwrap();
    serialized_data.extend(txid_bytes.iter().rev());

    // Extract and append vout bytes
    serialized_data.extend(&(tx_input["vout"].as_u64().unwrap() as u32).to_le_bytes());

    // Extract script sig hex and convert to bytes
    let binding = json!("");
    let script_sig_hex = tx_input
        .get("scriptsig")
        .unwrap_or(&binding)
        .as_str()
        .unwrap();
    let script_sig_bytes: Vec<u8> = hex::decode(script_sig_hex).unwrap();

    // Encode script sig bytes
    let encoded_script_sig = encodeVariableString(script_sig_bytes);
    serialized_data.extend(encoded_script_sig);

    // Extract and append sequence bytes
    serialized_data.extend(&(tx_input["sequence"].as_u64().unwrap() as u32).to_le_bytes());

    serialized_data
}














pub fn serializeOutputDATA(tx_output: &Value) -> Vec<u8> {
    // Initialize a vector to hold the serialized output data
    let mut serialized_output = vec![];

    // Extract the value of the transaction output and append its bytes
    let value_bytes = &(tx_output["value"].as_u64().unwrap()).to_le_bytes();
    serialized_output.extend(value_bytes);

    // Extract script pubkey hex and convert it to bytes
    let script_pubkey_hex = tx_output["scriptpubkey"].as_str().unwrap();
    let script_pubkey_bytes: Vec<u8> = hex::decode(script_pubkey_hex).unwrap();

    // Encode script pubkey bytes
    let encoded_script_pubkey = encodeVariableString(script_pubkey_bytes);
    serialized_output.extend(encoded_script_pubkey);

    // Return the serialized output data
    serialized_output
}










pub fn serializeWitttness(witness: &serde_json::Value) -> Vec<u8> {
    // Initialize a new vector to store the serialized witness data
    let mut serialized_data = Vec::new();

    // Extract the length of the witness array and convert it to u64
    let witness_len = witness.as_array().unwrap().len() as u64;

    // Encode the witness length and append it to the serialized data
    serialized_data.extend(encodeVariant(witness_len));

    // Iterate through each item in the witness array
    for item in witness.as_array().unwrap() {
        // Decode the item from hex string to bytes
        let item_bytes: Vec<u8> = hex::decode(item.as_str().unwrap()).unwrap();

        // Encode the variable-length string and append it to the serialized data
        let item_encoded = encodeVariableString(item_bytes);
        serialized_data.extend(item_encoded);
    }

    // Return the serialized witness data
    serialized_data
}
















pub fn serializeTransaction(tx_data: &Value) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
 
    // Initialize vectors to store serialized data
    let mut serialized_complete = vec![];
    let mut serialized_without_witness = vec![];
    let mut serialized_witness_only = vec![];

    // Serialize transaction version and append to both complete and without-witness data
    serialized_complete.extend(&(tx_data["version"].as_u64().unwrap() as u32).to_le_bytes());
    serialized_without_witness.extend(&(tx_data["version"].as_u64().unwrap() as u32).to_le_bytes());

    // Check if SegWit is used
    let mut segwit_used = false;
    for input in tx_data["vin"].as_array().unwrap() {
        if input["witness"].is_array() {
            serialized_complete.extend(&[0x00, 0x01]); // witness flag
            serialized_witness_only.extend(&[0x00, 0x01]); // witness flag
            segwit_used = true;
            break;
        }
    }

    // Encode the number of inputs and append to both complete and without-witness data
    serialized_complete.extend(encodeVariant(tx_data["vin"].as_array().unwrap().len() as u64));
    serialized_without_witness.extend(encodeVariant(tx_data["vin"].as_array().unwrap().len() as u64));

    // Serialize each input and append to both complete and without-witness data
    for input_data in tx_data["vin"].as_array().unwrap() {
        serialized_complete.extend(serializeInputData(&input_data));
        serialized_without_witness.extend(serializeInputData(&input_data));
    }

    // Encode the number of outputs and append to both complete and without-witness data
    serialized_complete.extend(encodeVariant(tx_data["vout"].as_array().unwrap().len() as u64));
    serialized_without_witness.extend(encodeVariant(tx_data["vout"].as_array().unwrap().len() as u64));

    // Serialize each output and append to both complete and without-witness data
    for output_data in tx_data["vout"].as_array().unwrap() {
        serialized_complete.extend(serializeOutputDATA(&output_data));
        serialized_without_witness.extend(serializeOutputDATA(&output_data));
    }

    // If SegWit is used, serialize witness data and append to both complete and witness-only data
    if segwit_used {
        for input_data in tx_data["vin"].as_array().unwrap() {
            if input_data["witness"].is_array() {
                serialized_complete.extend(serializeWitttness(&input_data["witness"]));
                serialized_witness_only.extend(serializeWitttness(&input_data["witness"]));
            }
        }
    }

    // Serialize locktime and append to both complete and without-witness data
    serialized_complete.extend(&(tx_data["locktime"].as_u64().unwrap() as u32).to_le_bytes());
    serialized_without_witness.extend(&(tx_data["locktime"].as_u64().unwrap() as u32).to_le_bytes());

    // Explanation of vectors:
    // serialized_complete -> Complete serialization including witness data
    // serialized_without_witness -> Serialization without witness data
    // serialized_witness_only -> Witness data only (if SegWit used)
    // (serialized_without_witness + serialized_witness_only) != serialized_complete
    // serialized_complete -> Used for WTXIDs

    // Return the serialized data
    (serialized_complete, serialized_without_witness, serialized_witness_only)
}

























pub fn serializer(tx: &serde_json::Value) -> (String, String, String) {
    let serialized_tx = serializeTransaction(tx);
    let hex_serialized_tx = (
        hex::encode(&serialized_tx.0),
        hex::encode(&serialized_tx.1),
        hex::encode(&serialized_tx.2),
    );
    hex_serialized_tx
}











pub fn transactionIDMaker(transaction_hex: String) -> String {
    let bytes = hex::decode(&transaction_hex).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let first_hash = hasher.finalize_reset();
    hasher.update(&first_hash);
    let second_hash = hasher.finalize_reset();
    hex::encode(second_hash)
}

















pub(crate) fn generateLegacySigHash(tx: Value, index: usize, sighash_flag: u8) -> Vec<u8> {

    let mut sighash_txn = tx.clone();
    for input in sighash_txn["vin"].as_array_mut().unwrap() {
        input["scriptsig"] = "".into();
    }
    let script_pubkey = tx["vin"][index as usize]["prevout"]["scriptpubkey"].as_str().unwrap();
    sighash_txn["vin"][index as usize]["scriptsig"] = script_pubkey.into();
    let mut serialized_txn_in_bytes = serializeTransaction(&sighash_txn).1;
    let sighash_flag_bytes = [sighash_flag, 0, 0, 0];
    serialized_txn_in_bytes.extend_from_slice(&sighash_flag_bytes);

    let mut hasher = Sha256::new();
    hasher.update(&serialized_txn_in_bytes);
    let mut result = hasher.finalize_reset();
    hasher.update(&result);
    result = hasher.finalize_reset();
    result.to_vec()
}







pub(crate) struct Reusese {
    version: [u8; 4],
    input_txn_vout_hash: Vec<u8>,
    sequence_hash: Vec<u8>,
    output_hash: Vec<u8>,
    locktime: [u8; 4],
}












pub(crate) fn generateSegWittPreIImage(tx: &Value, index: usize, sighash_flag: u8, reuse: &Reusese) -> Vec<u8> {
    let mut input: Vec<u8> = vec![];
    let txid_bytes = hex::decode(tx["vin"][index]["txid"].as_str().unwrap()).unwrap();
    let vout = (tx["vin"][index]["vout"].as_u64().unwrap() as u32).to_le_bytes();
    input.extend(txid_bytes.iter().rev());
    input.extend(vout);
    let scriptpubkey_asm = tx["vin"][index]["prevout"]["scriptpubkey_asm"].as_str().unwrap();
    let publickey_hash = scriptpubkey_asm.split_ascii_whitespace().nth(2).unwrap();
    let scriptcode = hex::decode(format!("{}{}{}", "1976a914", publickey_hash, "88ac")).unwrap();
    let amount = (tx["vin"][index]["prevout"]["value"].as_u64().unwrap()).to_le_bytes();
    let sequence = (tx["vin"][index]["sequence"].as_u64().unwrap() as u32).to_le_bytes();
    let sighash_flag = [sighash_flag, 0, 0, 0];
    let mut preimage_bytes: Vec<u8> = vec![];
    preimage_bytes.extend(reuse.version.iter());
    preimage_bytes.extend(reuse.input_txn_vout_hash.iter());
    preimage_bytes.extend(reuse.sequence_hash.iter());
    preimage_bytes.extend(input.iter());
    preimage_bytes.extend(scriptcode);
    preimage_bytes.extend(amount.iter());
    preimage_bytes.extend(sequence.iter());
    preimage_bytes.extend(reuse.output_hash.iter());
    preimage_bytes.extend(reuse.locktime.iter());
    preimage_bytes.extend(sighash_flag.iter());
    let mut hasher = Sha256::new();
    hasher.update(&preimage_bytes);
    let result = hasher.finalize_reset();
    hasher.update(&result);
    let result = hasher.finalize_reset();
    result.to_vec()
}


pub(crate) fn MakeREusese(tx: &Value) -> Reusese {
    let version_ln_bytes = (tx["version"].as_u64().unwrap() as u32).to_le_bytes();
    let mut input_txn_vout_hash: Vec<u8> = vec![];
    for (_index, input) in tx["vin"].as_array().unwrap().iter().enumerate() {
        let txid = hex::decode(input["txid"].as_str().unwrap()).unwrap();
        input_txn_vout_hash.extend(txid.iter().rev());
        let vout = (input["vout"].as_u64().unwrap() as u32).to_le_bytes();
        input_txn_vout_hash.extend(vout);
    }
    let mut hasher = Sha256::new();
    hasher.update(&input_txn_vout_hash);
    let input_txn_vout_hash = hasher.finalize_reset();
    hasher.update(&input_txn_vout_hash);
    let input_txn_vout_hash = hasher.finalize_reset().to_vec();
    let mut sequence_serialized: Vec<u8> = vec![];
    for (_index, input) in tx["vin"].as_array().unwrap().iter().enumerate() {
        let sequence_bytes = (input["sequence"].as_u64().unwrap() as u32).to_le_bytes();
        sequence_serialized.extend(sequence_bytes);
    }
    hasher.update(sequence_serialized);
    let sequence_hash = hasher.finalize_reset().to_vec();
    hasher.update(sequence_hash);
    let sequence_hash = hasher.finalize_reset().to_vec();
    let mut txn_outputs_serialized: Vec<u8> = vec![];
    for output in tx["vout"].as_array().unwrap() {
        txn_outputs_serialized.extend(serializeOutputDATA(output));
    }
    hasher.update(&txn_outputs_serialized);
    let output_hash = hasher.finalize_reset().to_vec();
    hasher.update(output_hash);
    let output_hash = hasher.finalize_reset().to_vec();
    let locktime = (tx["locktime"].as_u64().unwrap() as u32).to_le_bytes();
    Reusese {
        version: version_ln_bytes,
        input_txn_vout_hash: input_txn_vout_hash,
        sequence_hash: sequence_hash,
        output_hash: output_hash,
        locktime: locktime,
    }
}
















pub fn LegacyTransactionValidate(transaction_data: &str) -> bool {
    // Deserialize the transaction data into a JSON value
    let transaction_json: serde_json::Value = serde_json::from_str(transaction_data).unwrap();

    // Initialize a boolean variable to track validation result
    let mut is_valid = true;

    // Iterate through each input, generate the signature hash, and validate the signature
    for (index, input) in transaction_json["vin"].as_array().unwrap().iter().enumerate() {
        // Clone the transaction JSON for temporary use
        let transaction_temp = transaction_json.clone();

        // Extract scriptsig assembly from the input
        let scriptsig_asm = transaction_json["vin"][index]["scriptsig_asm"].as_str().unwrap();

        // Extract public key and signature from scriptsig assembly
        let public_key = hex::decode(scriptsig_asm.split_ascii_whitespace().nth(3).unwrap()).unwrap();
        let signature = hex::decode(scriptsig_asm.split_ascii_whitespace().nth(1).unwrap()).unwrap();

        // Extract sighash flag from the signature
        let sighash_flag = *signature.last().unwrap();

        // Generate signature hash
        let sighash = generateLegacySigHash(transaction_temp, index, sighash_flag);

        // Remove the sighash flag from the signature
        let signature = signature[..signature.len() - 1].to_vec();

        // Validate the signature
        is_valid = SignatureVarifyHelper(sighash, public_key, signature);
    }

    // Return the validation result
    is_valid
}







pub fn Segwittvalidate(transaction_data: &serde_json::Value) -> bool {
      // Initialize a boolean variable to track validation result
      let mut is_valid = true;

      // Generate reusable data for the transaction
      let reusables = MakeREusese(&transaction_data.clone());
  
      // Iterate through each input in the transaction
      for (index, input) in transaction_data["vin"].as_array().unwrap().iter().enumerate() {
          // Clone the transaction JSON for temporary use
          let transaction_temp = transaction_data.clone();
  
          // Check if the input is SegWit
          if input["prevout"]["scriptpubkey_type"] == "v0_p2wpkh" {
              // Extract public key and signature from witness data
              let public_key =
                  hex::decode(transaction_data["vin"][index]["witness"][1].as_str().unwrap()).unwrap();
              let signature =
                  hex::decode(transaction_data["vin"][index]["witness"][0].as_str().unwrap()).unwrap();
  
              // Extract sighash flag from the signature
              let sighash_flag = *signature.last().unwrap();
  
              // Generate SegWit preimage hash
              let preimage_hash =
                  generateSegWittPreIImage(&transaction_temp, index, sighash_flag, &reusables);
  
              // Remove the sighash flag from the signature
              let signature = signature[..signature.len() - 1].to_vec();
  
              // Validate the signature
              is_valid = SignatureVarifyHelper(preimage_hash, public_key, signature);
          } else {
              // Extract public key and signature from scriptsig assembly
              let scriptsig_asm = transaction_data["vin"][index]["scriptsig_asm"].as_str().unwrap();
              let public_key =
                  hex::decode(scriptsig_asm.split_ascii_whitespace().nth(3).unwrap()).unwrap();
              let signature =
                  hex::decode(scriptsig_asm.split_ascii_whitespace().nth(1).unwrap()).unwrap();
  
              // Extract sighash flag from the signature
              let sighash_flag = *signature.last().unwrap();
  
              // Generate legacy signature hash
              let sighash = generateLegacySigHash(transaction_temp, index, sighash_flag);
  
              // Remove the sighash flag from the signature
              let signature = signature[..signature.len() - 1].to_vec();
  
              // Validate the signature
              is_valid = SignatureVarifyHelper(sighash, public_key, signature);
          }
      }
  
      // Return the validation result
      is_valid
}











pub fn SignatureVarifyHelper(msg_hash: Vec<u8>, pub_key: Vec<u8>, sig: Vec<u8>) -> bool {
     // Initialize a Secp256k1 context for verification only
     let secp = Secp256k1::verification_only();

     // Create message from hash
     let message = Message::from_digest_slice(&msg_hash).unwrap();
 
     // Create public key from bytes
     let pubkey = PublicKey::from_slice(&pub_key).unwrap();
 
     // Create signature from bytes
     let signature = Signature::from_der(&sig).unwrap();
 
     // Verify the ECDSA signature
     secp.verify_ecdsa(&message, &signature, &pubkey).is_ok()
}





























