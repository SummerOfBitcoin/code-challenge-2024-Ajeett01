#![ allow(warnings)]

use std::{ fs, io::{Read, Write}, time::{SystemTime, UNIX_EPOCH}, vec};
use serde_json::Value;
use sha2::{Digest, Sha256};

extern crate hex;
extern crate serde_json;

use serde_json::{json};

use secp256k1::{
    ecdsa::Signature,
    Message, PublicKey, Secp256k1,
};


fn main() {
    block_create()
}



pub(crate) fn hash256(data: &[u8]) -> Vec<u8> {
    let mut hash_it = Sha256::new();
    hash_it.update(data);
    let result = hash_it.finalize_reset();
    hash_it.update(&result);
    let data = hash_it.finalize_reset();
    data.to_vec()
}

fn mineHeader(target: &str, header: String) -> String {
    let mut nonce: u32 = 0;
    let tgt_bytes = hex::decode(target).expect("Target is not valid");
    let header_bytes_ = hex::decode(header).expect("Counld not decode the hex");

    loop {
        let mut header_bytes = header_bytes_.clone();
        header_bytes.extend(nonce.to_le_bytes());

        let mut hash_bytes = hash256(&header_bytes);
        hash_bytes.reverse();
        
        if hash_bytes < tgt_bytes {
            println!("A block was found");
            println!("Nonce = {}", nonce);
            return hex::encode(&header_bytes);
        }
        nonce += 1;
    }
}

fn createTXIDWTXID(txns: &[String], wtxns: &[String]) -> (Vec<String>, Vec<String>) {
    let mut transaction_ids: Vec<String> = vec![];
    let mut witness_transaction_ids: Vec<String> = vec![];
    let mut hash_it = Sha256::new();
    
    for txn in txns {
        let txn_bytes = hex::decode(txn).expect("Couldnt parse hex");
        hash_it.update(&txn_bytes);
        let result = hash_it.finalize_reset();
        hash_it.update(&result);
        let result = hash_it.finalize_reset();
        let txid = hex::encode(result);
        transaction_ids.push(txid);
    }

    for wtxn in wtxns {
        let txn_seg_bytes = hex::decode(wtxn).expect("Couldnt parse hex");
        hash_it.update(&txn_seg_bytes);
        let result = hash_it.finalize_reset();
        hash_it.update(&result);
        let result = hash_it.finalize_reset();
        let wtxid = hex::encode(result);
        witness_transaction_ids.push(wtxid);
    }

    (transaction_ids, witness_transaction_ids)
}


fn transactionSelector(txns: Vec<String>) -> (Vec<String>, Vec<String>, usize) {
    let mut selected_transactions: Vec<String> = vec![];
    let mut selected_witness_transactions: Vec<String> = vec![];
    let mut total_weight: usize = 0;
    let mut bytes: usize = 0;
    let mut total_fees: usize = 0;

    for transaction in txns {
        let tx: Value = serde_json::from_str(&transaction).expect("Error parsing JSON");

        if !checkp2wpkh(&tx) || Segwittnessvalidate(&tx) {
            continue;
        }

        let serialized_tx = serializer(&tx);
        let fees = calculateFees(&tx);
        let txwt = calculatetotal_weight(&serialized_tx.1, &serialized_tx.2);

        if (total_weight + txwt) < (4000000 - 1000) {
            selected_witness_transactions.push(serialized_tx.0.clone()); 
            selected_transactions.push(serialized_tx.1.clone()); 
            total_weight += txwt;
            bytes += serialized_tx.1.len() / 2 + serialized_tx.2.len() / 8;
            total_fees += fees;
        }
    }

    println!("fees generated = {}", total_fees);
    println!("transaction selected");

    (selected_transactions, selected_witness_transactions, total_fees)
}

pub fn checkp2wpkh(txn: &serde_json::Value) -> bool {
    txn["vin"]
        .as_array()
        .unwrap()
        .iter()
        .all(|input| input["prevout"]["scriptpubkey_type"].as_str().unwrap() == "v0_p2wpkh")
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

pub fn checkp2pkh(txn: &serde_json::Value) -> bool {
    txn["vin"]
        .as_array()
        .unwrap()
        .iter()
        .all(|input| input["prevout"]["scriptpubkey_type"].as_str().unwrap() == "p2pkh")
}

fn calculateFees(tx: &serde_json::Value) -> usize {
    let inputs: usize = tx["vin"].as_array().unwrap().iter()
        .map(|input| input["prevout"]["value"].as_u64().unwrap() as usize)
        .sum();
    let outputs: usize = tx["vout"].as_array().unwrap().iter()
        .map(|output| output["value"].as_u64().unwrap() as usize)
        .sum();
    inputs - outputs
}

fn calculatetotal_weight(transaction_data: &String, witness_data: &String) -> usize {
    let transaction_total_weight = transaction_data.len() / 2 * 4;
    let witness_total_weight = witness_data.len() / 2;

    transaction_total_weight + witness_total_weight
}

fn createCoinBase(merkle_root: &String, txn_fees: &usize) -> (String, String) {
    let new_satoshis = txn_fees.clone();
    let mut coinbase = rt_Coinbase_Trans();
    coinbase["vout"][0]["value"] = serde_json::Value::from(new_satoshis);
    let wit_total_weight = calculateWitnessCommitment(merkle_root);

    coinbase["vout"][1]["scriptpubkey"] =
        serde_json::Value::from(format!("{}{}", "6a24aa21a9ed", wit_total_weight));
    coinbase["vout"][1]["scriptpubket_asm"] = serde_json::Value::from(format!(
        "{}{}",
        "OP_0 OP_PUSHBYTES_36 aa21a9ed", wit_total_weight
    ));
    
    let coinbase_bytes = serializeTransaction(&coinbase);
    let coinbase_hex = hex::encode(coinbase_bytes.0); 
    let coinbase_wit_hex = hex::encode(coinbase_bytes.1);
    return (coinbase_hex, coinbase_wit_hex);
}

fn calculateWitnessCommitment(witness_root: &String) -> String {
    let wit_reserved_value = "0000000000000000000000000000000000000000000000000000000000000000";
    let reserved_bytes = hex::decode(wit_reserved_value).unwrap();
    let witness_root_bytes = hex::decode(witness_root).unwrap();
    let mut wc: Vec<u8> = vec![];
    wc.extend(witness_root_bytes);
    wc.extend(reserved_bytes);

    let hash = hash256(&wc);
    hex::encode(hash)
}

fn createMarkleRoot(transactions: &Vec<String>) -> String {
    if transactions.len() == 1 {
        return transactions.first().unwrap().clone();
    }

    let mut results: Vec<String> = vec![];
    
    
    for i in (0..transactions.len()).step_by(2) {
        let txn1 = &transactions[i];
        let txn2: &String;

        if i < transactions.len() - 1 {
            txn2 = &transactions[i + 1];
        } else {
            txn2 = txn1;
        }

        let mut txn = hex::decode(txn1).unwrap();
        txn.extend(hex::decode(txn2).unwrap());

       
        let mut hash_it = Sha256::new();
        hash_it.update(txn);
        let hashed = hash_it.finalize_reset();
        hash_it.update(hashed);
        let hashed = hash_it.finalize_reset();
        results.push(hex::encode(hashed));
    }

    createMarkleRoot(&results)
}

fn read_trans() -> Vec<String> {
    let path = "./mempool";
    let directory = fs::read_dir(path).unwrap();

    let mut transactions: Vec<String> = vec![];

    for transaction in directory {
        let transaction = transaction.expect("Unable to read directory transaction");
        if transaction.path().is_file() {
            let path = transaction.path();
            let mut file = fs::File::open(path).expect("File not found");
            let mut transaction_data = String::new();
            
            file.read_to_string(&mut transaction_data).expect("Error reading file");
            transactions.push(transaction_data);
        }
    }
    return transactions;
}

fn rt_Coinbase_Trans() -> serde_json::Value {
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

    serde_json::from_str(&txn).unwrap()
}



pub(crate) fn encodeVariant(num: u64) -> Vec<u8> {
    match num {
        0..=0xfc => vec![num as u8],
        0xfd..=0xffff => {
            let mut bytes = vec![0xfd];
            bytes.extend_from_slice(&(num as u16).to_le_bytes());
            bytes
        }
        0x10000..=0xffffffff => {
            let mut bytes = vec![0xfe];
            bytes.extend_from_slice(&(num as u32).to_le_bytes());
            bytes
        }
        _ => {
            let mut bytes = vec![0xff];
            bytes.extend_from_slice(&num.to_le_bytes());
            bytes
        }
    }
}


fn encodeVariableString(s: Vec<u8>) -> Vec<u8> {
    let mut variablestring = encodeVariant(s.len() as u64);
    variablestring.extend(s);
    variablestring
}

pub fn serializeInputData(tx_input: &Value) -> Vec<u8> {
    let mut out = vec![];
    let txid_bytes: Vec<u8> = hex::decode(tx_input["txid"].as_str().unwrap()).expect("Invalid hex in txid");
    out.extend(txid_bytes.iter().rev());
    out.extend(&(tx_input["vout"].as_u64().unwrap() as u32).to_le_bytes());
    let bind = json!("");
    let script_sig_hex = tx_input
        .get("scriptsig")
        .unwrap_or(&bind)
        .as_str()
        .unwrap();
    let scr_sig_bytes: Vec<u8> = hex::decode(script_sig_hex).expect("Invalid hex in scriptsig");
    let script_sig_encoded = encodeVariableString(scr_sig_bytes);
    out.extend(script_sig_encoded);
    out.extend(&(tx_input["sequence"].as_u64().unwrap() as u32).to_le_bytes());
    out
}

pub fn serialize_output_data(tx_output: &Value) -> Vec<u8> {
    let mut out = vec![];
    out.extend(&(tx_output["value"].as_u64().unwrap()).to_le_bytes());
    let script_pubkey_hex = tx_output["scriptpubkey"].as_str().unwrap();
    let script_pubkey_bytes: Vec<u8> =
        hex::decode(script_pubkey_hex).expect("Invalid hex in scriptpubkey");
    let script_pubkey_encoded = encodeVariableString(script_pubkey_bytes);
    out.extend(script_pubkey_encoded);
    out
}

pub fn serialize_witttness_data(witness: &serde_json::Value) -> Vec<u8> {
    let mut result = Vec::new();
    let witness_len = witness.as_array().unwrap().len() as u64;
    result.extend(encodeVariant(witness_len));
    for item in witness.as_array().unwrap() {
        let item_bytes: Vec<u8> =
            hex::decode(item.as_str().unwrap()).expect("Invalid hex in witness item");
        let item_encoded = encodeVariableString(item_bytes);
        result.extend(item_encoded);
    }
    result
}


pub(crate) fn block_create() {
    use std::time::Instant;
    let now = Instant::now();
    let transactions_json = read_trans();
    let now = Instant::now();
    let mut transactions = transactionSelector(transactions_json);
    let (mut transaction_ids, mut witness_transaction_ids) = createTXIDWTXID(&transactions.0, &transactions.1);
    witness_transaction_ids.insert(0, "0000000000000000000000000000000000000000000000000000000000000000".to_string());
    let merkle_wtxid = createMarkleRoot(&witness_transaction_ids);
    let coinbase_txn = createCoinBase(&merkle_wtxid, &transactions.2);
    transactions.0.insert(0, coinbase_txn.clone().0);
    transaction_ids.insert(0, transactionIDMaker(coinbase_txn.clone().0));
    let merkle_txid = createMarkleRoot(&transaction_ids);
    let block_header = create_block_header(merkle_txid);
    let mut file = fs::File::create("./output.txt").expect("Unable to create file");
    file.write_all(block_header.as_bytes()).expect("Unable to write to file");
    file.write_all("\n".as_bytes()).expect("Unable to write to file");
    file.write_all(coinbase_txn.0.as_bytes()).expect("Unable to write to file");
    file.write_all("\n".as_bytes()).expect("Unable to write to file");
    for txn in transaction_ids {
        let mut bytes = hex::decode(txn).unwrap();
        bytes.reverse();
        file.write_all(hex::encode(bytes).as_bytes()).expect("Unable to write to file");
        file.write_all("\n".as_bytes()).expect("Unable to write to file");
    }
    file.write_all("\n".as_bytes()).expect("Unable to write to file");
}


fn create_block_header(merkle_root: String) -> String {
    let version = "04000000";
    let prevous_block_hash = "0000000000000000000000000000000000000000000000000000000000000000"; 
    let time = GetTime();
    let target = "0000ffff00000000000000000000000000000000000000000000000000000000";
    let bits = "ffff001f";
    let header = format!(
        "{}{}{}{}{}",
        version, prevous_block_hash, merkle_root, time, bits
    );
    let header = mineHeader(&target, header);
    header
}

fn GetTime() -> String {
    let now = SystemTime::now();
    let current = now.duration_since(UNIX_EPOCH).expect("Time went backwards").as_secs() as u32;
    hex::encode(current.to_le_bytes())
}

pub fn serializeTransaction(tx: &serde_json::Value) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut out = Vec::new();
    let mut alt_out = Vec::new();
    let mut wit_out = Vec::new();

    out.extend(&(tx["version"].as_u64().unwrap() as u32).to_le_bytes());
    alt_out.extend(&out);

    let segwit = tx["vin"].as_array().unwrap().iter().any(|vin| vin["witness"].is_array());
    if segwit {
        out.extend(&[0x00, 0x01]); // witness flag
        wit_out.extend(&[0x00, 0x01]);
    }

    out.extend(encodeVariant(tx["vin"].as_array().unwrap().len() as u64));
    alt_out.extend(encodeVariant(tx["vin"].as_array().unwrap().len() as u64));

    for tx_input in tx["vin"].as_array().unwrap() {
        out.extend(serializeInputData(&tx_input));
        alt_out.extend(serializeInputData(&tx_input));
        if segwit && tx_input["witness"].is_array() {
            wit_out.extend(serialize_witttness_data(&tx_input["witness"]));
        }
    }

    out.extend(encodeVariant(tx["vout"].as_array().unwrap().len() as u64));
    alt_out.extend(encodeVariant(tx["vout"].as_array().unwrap().len() as u64));
    for tx_output in tx["vout"].as_array().unwrap() {
        out.extend(serialize_output_data(&tx_output));
        alt_out.extend(serialize_output_data(&tx_output));
    }

    out.extend(&(tx["locktime"].as_u64().unwrap() as u32).to_le_bytes());
    alt_out.extend(&(tx["locktime"].as_u64().unwrap() as u32).to_le_bytes());

    (out, alt_out, wit_out)
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
    let bytes = hex::decode(&transaction_hex).expect("Invalid hexadecimal string");
    let mut hash_it = Sha256::new();
    hash_it.update(&bytes);
    let first_hash = hash_it.finalize_reset();
    hash_it.update(&first_hash);
    let second_hash = hash_it.finalize_reset();
    hex::encode(second_hash)
}


pub(crate) fn genLegacySigHash(tx: Value, index: usize, sighash_flag: u8) -> Vec<u8> {

    let mut sighash_txn = tx.clone();
    for input in sighash_txn["vin"].as_array_mut().unwrap() {
        input["scriptsig"] = "".into();
    }
    let script_pubkey = tx["vin"][index as usize]["prevout"]["scriptpubkey"].as_str().unwrap();
    sighash_txn["vin"][index as usize]["scriptsig"] = script_pubkey.into();
    let mut serialized_txn_in_bytes = serializeTransaction(&sighash_txn).1;
    let sighash_flag_bytes = [sighash_flag, 0, 0, 0];
    serialized_txn_in_bytes.extend_from_slice(&sighash_flag_bytes);

    let mut hash_it = Sha256::new();
    hash_it.update(&serialized_txn_in_bytes);
    let mut result = hash_it.finalize_reset();
    hash_it.update(&result);
    result = hash_it.finalize_reset();
    result.to_vec()
}

pub fn Segwittnessvalidate(txn: &serde_json::Value) -> bool {
    let mut is_valid = true;
    let reusables = make_reusese(&txn.clone());

    for (index, input) in txn["vin"].as_array().unwrap().iter().enumerate() {
        let txn_temp = txn.clone();
        if input["prevout"]["scriptpubkey_type"] == "v0_p2wpkh" {
            let public_key = hex::decode(txn["vin"][index]["witness"][1].as_str().unwrap()).unwrap();
            let signature = hex::decode(txn["vin"][index]["witness"][0].as_str().unwrap()).unwrap();
            let sighash_flag = *signature.last().unwrap();
            let preimage_hash = generate_segwit_preimage(&txn_temp, index, sighash_flag, &reusables);
            let signature = signature[..signature.len() - 1].to_vec();
            is_valid = signature_verify_helper(preimage_hash, public_key, signature);
        }

        else {
            let scriptsig_asm = txn["vin"][index]["scriptsig_asm"].as_str().unwrap();
            let public_key = hex::decode(scriptsig_asm.split_ascii_whitespace().nth(3).unwrap()).unwrap();
            let signature = hex::decode(scriptsig_asm.split_ascii_whitespace().nth(1).unwrap()).unwrap();
            let sighash_flag = *signature.last().unwrap();
            let sighash = genLegacySigHash(txn_temp, index, sighash_flag);
            let signature = signature[..signature.len() - 1].to_vec();
            is_valid = signature_verify_helper(sighash, public_key, signature);
        }
    }

    return is_valid;
}
pub(crate) struct Reusese {
    version: [u8; 4],
    input_txn_vout_hash: Vec<u8>,
    sequence_hash: Vec<u8>,
    output_hash: Vec<u8>,
    locktime: [u8; 4],
}

pub(crate) fn generate_segwit_preimage(tx: &Value, index: usize, sighash_flag: u8, reuse: &Reusese) -> Vec<u8> {
    let mut input: Vec<u8> = vec![];
    let txid_bytes = hex::decode(tx["vin"][index]["txid"].as_str().unwrap()).expect("Invalid hex in txid");
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
    let mut hash_it = Sha256::new();
    hash_it.update(&preimage_bytes);
    let result = hash_it.finalize_reset();
    hash_it.update(&result);
    let result = hash_it.finalize_reset();
    result.to_vec()
}


pub(crate) fn make_reusese(tx: &Value) -> Reusese {
    let version_ln_bytes = (tx["version"].as_u64().unwrap() as u32).to_le_bytes();
    let mut input_txn_vout_hash: Vec<u8> = vec![];
    for (_index, input) in tx["vin"].as_array().unwrap().iter().enumerate() {
        let txid = hex::decode(input["txid"].as_str().unwrap()).expect("Invalid hex in txid");
        input_txn_vout_hash.extend(txid.iter().rev());
        let vout = (input["vout"].as_u64().unwrap() as u32).to_le_bytes();
        input_txn_vout_hash.extend(vout);
    }
    let mut hash_it = Sha256::new();
    hash_it.update(&input_txn_vout_hash);
    let input_txn_vout_hash = hash_it.finalize_reset();
    hash_it.update(&input_txn_vout_hash);
    let input_txn_vout_hash = hash_it.finalize_reset().to_vec();
    let mut sequence_serialized: Vec<u8> = vec![];
    for (_index, input) in tx["vin"].as_array().unwrap().iter().enumerate() {
        let sequence_bytes = (input["sequence"].as_u64().unwrap() as u32).to_le_bytes();
        sequence_serialized.extend(sequence_bytes);
    }
    hash_it.update(sequence_serialized);
    let sequence_hash = hash_it.finalize_reset().to_vec();
    hash_it.update(sequence_hash);
    let sequence_hash = hash_it.finalize_reset().to_vec();
    let mut txn_outputs_serialized: Vec<u8> = vec![];
    for output in tx["vout"].as_array().unwrap() {
        txn_outputs_serialized.extend(serialize_output_data(output));
    }
    hash_it.update(&txn_outputs_serialized);
    let output_hash = hash_it.finalize_reset().to_vec();
    hash_it.update(output_hash);
    let output_hash = hash_it.finalize_reset().to_vec();
    let locktime = (tx["locktime"].as_u64().unwrap() as u32).to_le_bytes();
    Reusese {
        version: version_ln_bytes,
        input_txn_vout_hash: input_txn_vout_hash,
        sequence_hash: sequence_hash,
        output_hash: output_hash,
        locktime: locktime,
    }
}



fn read_transactions() -> Vec<String> {
    let path = "./mempool";
    let directory = fs::read_dir(path).unwrap();

    let mut transactions: Vec<String> = vec![];

    for transaction in directory {
        let transaction = transaction.expect("Unable to read directory transaction");
        if transaction.path().is_file() {
            let path = transaction.path();
            let mut file = fs::File::open(path).expect("File not found");
            let mut transaction_data = String::new();
            
            file.read_to_string(&mut transaction_data).expect("Error reading file");
            transactions.push(transaction_data);
        }
    }
    return transactions;
}

fn return_Coinbase_Trans() -> serde_json::Value {
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

    serde_json::from_str(&txn).unwrap()
}



pub fn LegTransValidate(txn: &str) -> bool {
    let txn: serde_json::Value = serde_json::from_str(txn).unwrap();
    let mut is_valid = true;

    
    for (index, input) in txn["vin"].as_array().unwrap().iter().enumerate() {
        let txn_temp = txn.clone();
        let scriptsig_asm = txn["vin"][index]["scriptsig_asm"].as_str().unwrap();
        let publickey = hex::decode(scriptsig_asm.split_ascii_whitespace().nth(3).unwrap()).unwrap();
        let signature = hex::decode(scriptsig_asm.split_ascii_whitespace().nth(1).unwrap()).unwrap();
        let sighash_flag = *signature.last().unwrap();
        let sighash = genLegacySigHash(txn_temp, index, sighash_flag);
        let signature = signature[..signature.len() - 1].to_vec();
        is_valid = signature_verify_helper(sighash, publickey, signature);
    }
    is_valid
}

pub fn Segwitvalidate(txn: &serde_json::Value) -> bool {
    let mut is_valid = true;
    let reusables = make_reusese(&txn.clone());

    for (index, input) in txn["vin"].as_array().unwrap().iter().enumerate() {
        let txn_temp = txn.clone();
        if input["prevout"]["scriptpubkey_type"] == "v0_p2wpkh" {
            let public_key = hex::decode(txn["vin"][index]["witness"][1].as_str().unwrap()).unwrap();
            let signature = hex::decode(txn["vin"][index]["witness"][0].as_str().unwrap()).unwrap();
            let sighash_flag = *signature.last().unwrap();
            let preimage_hash = generate_segwit_preimage(&txn_temp, index, sighash_flag, &reusables);
            let signature = signature[..signature.len() - 1].to_vec();
            is_valid = signature_verify_helper(preimage_hash, public_key, signature);
        }

        else {
            let scriptsig_asm = txn["vin"][index]["scriptsig_asm"].as_str().unwrap();
            let public_key = hex::decode(scriptsig_asm.split_ascii_whitespace().nth(3).unwrap()).unwrap();
            let signature = hex::decode(scriptsig_asm.split_ascii_whitespace().nth(1).unwrap()).unwrap();
            let sighash_flag = *signature.last().unwrap();
            let sighash = genLegacySigHash(txn_temp, index, sighash_flag);
            let signature = signature[..signature.len() - 1].to_vec();
            is_valid = signature_verify_helper(sighash, public_key, signature);
        }
    }

    return is_valid;
}

pub fn signature_verify_helper(msg_hash: Vec<u8>, pub_key: Vec<u8>, sig: Vec<u8>) -> bool {
    let secp = Secp256k1::verification_only();
    let message = Message::from_digest_slice(&msg_hash).unwrap();
    let pubkey = PublicKey::from_slice(&pub_key).unwrap();
    let signature = Signature::from_der(&sig).unwrap();
    secp.verify_ecdsa(&message, &signature, &pubkey).is_ok()
}