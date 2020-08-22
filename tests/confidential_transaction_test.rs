extern crate cfd_rust;

#[cfg(test)]
mod tests {
  use cfd_rust::{
    get_default_blinding_key, get_issuance_blinding_key, Address, Amount, BlindFactor,
    ConfidentialAddress, ConfidentialAsset, ConfidentialNonce, ConfidentialTransaction,
    ConfidentialTxOutData, ConfidentialValue, Descriptor, ExtPrivkey, ExtPubkey, FeeOption,
    FundTargetOption, FundTransactionData, HashType, Network, OutPoint, Privkey, Pubkey, Script,
    SigHashType, SignParameter, Transaction, TxInData, TxOutData, UtxoData,
  };
  use std::str::FromStr;

  const ASSET_A: &str = "aa00000000000000000000000000000000000000000000000000000000000000";
  const ASSET_B: &str = "bb00000000000000000000000000000000000000000000000000000000000000";
  // const ASSET_C: &str = "cc00000000000000000000000000000000000000000000000000000000000000";

  #[test]
  fn confidential_tx_test() {
    let tx_hex = "0200000000020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000";
    let tx = ConfidentialTransaction::from_str(tx_hex).expect("Fail");

    assert_eq!(tx_hex, tx.to_str());
    assert_eq!(
      "cf7783b2b1de646e35186df988a219a17f0317b5c3f3c47fa4ab2d7463ea3992",
      tx.as_txid().to_hex()
    );
    let tx_data = tx.get_info();
    assert_eq!(
      "cf7783b2b1de646e35186df988a219a17f0317b5c3f3c47fa4ab2d7463ea3992",
      tx_data.tx_data.wtxid.to_hex()
    );
    assert_eq!(
      "938e3a9b5bac410e812d08db74c4ef2bc58d1ed99d94b637cab0ac2e9eb59df8",
      tx_data.wit_hash.to_hex()
    );
    assert_eq!(2, tx_data.tx_data.version);
    assert_eq!(0, tx_data.tx_data.locktime);
    assert_eq!(512, tx_data.tx_data.size);
    assert_eq!(512, tx_data.tx_data.vsize);
    assert_eq!(2048, tx_data.tx_data.weight);
  }

  #[test]
  fn create_raw_transaction_test() {
    // based: cfd-csharp
    let network_type = Network::LiquidV1;
    let xpriv: &str = "xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV";
    let privkey = ExtPrivkey::new(xpriv).expect("Fail");
    let child_xpriv_1 = privkey.derive_from_number(11, false).expect("Fail");
    let child_xpriv_2 = privkey.derive_from_number(12, false).expect("Fail");
    let child_xpriv_3 = privkey.derive_from_number(13, false).expect("Fail");
    let blind_extkey_3 = privkey.derive_from_number(103, false).expect("Fail");
    let blind_key_3 = blind_extkey_3.get_privkey();

    let child_pubkey_1 = child_xpriv_1.get_privkey().get_pubkey().expect("Fail");
    let child_pubkey_2 = child_xpriv_2.get_privkey().get_pubkey().expect("Fail");
    let child_pubkey_3 = child_xpriv_3.get_privkey().get_pubkey().expect("Fail");
    let ct_key_3 = blind_key_3.get_pubkey().expect("Fail");
    assert_eq!(
      "03e95214596e9291c6e596c324f62d84cfa5e48fb3383841c1dd7fefaa17ad640d",
      ct_key_3.to_hex()
    );

    let addr1 = Address::p2wpkh(&child_pubkey_1, &network_type).expect("Fail");
    let addr2 = Address::p2wpkh(&child_pubkey_2, &network_type).expect("Fail");
    let addr3 = Address::p2wpkh(&child_pubkey_3, &network_type).expect("Fail");
    assert_eq!("ex1qjex3wgf33j9u0vqk6r4exa9xyr5t3z5c7saq0d", addr3.to_str());
    let ct_addr3 = ConfidentialAddress::new(&addr3, &ct_key_3).expect("Fail");

    let outpoint1 = OutPoint::from_str(
      "7ca81dd22c934747f4f5ab7844178445fe931fb248e0704c062b8f4fbd3d500a",
      0,
    )
    .expect("Fail");
    let outpoint2 = OutPoint::from_str(
      "30f71f39d210f7ee291b0969c6935debf11395b0935dca84d30c810a75339a0a",
      0,
    )
    .expect("Fail");

    let asset_a = ConfidentialAsset::from_str(ASSET_A).expect("Fail");
    let asset_b = ConfidentialAsset::from_str(ASSET_B).expect("Fail");
    let txin_list = vec![TxInData::new(&outpoint1), TxInData::new(&outpoint2)];
    let txout_list = vec![
      ConfidentialTxOutData::from_fee(1000, &asset_a),
      ConfidentialTxOutData::from_address(10000000, &asset_a, &addr1),
      ConfidentialTxOutData::from_address(5000000, &asset_b, &addr2),
    ];
    let mut tx = ConfidentialTransaction::create_tx(2, 0, &txin_list, &txout_list).expect("Fail");

    let txout_append_data = vec![ConfidentialTxOutData::from_confidential_address(
      3000000, &asset_b, &ct_addr3,
    )];
    tx = tx.append_data(&[], &txout_append_data).expect("Fail");
    tx = tx.update_fee_amount(2000).expect("Fail");
    let tx1 = tx.clone();

    assert_eq!("0200000000020a503dbd4f8f2b064c70e048b21f93fe4584174478abf5f44747932cd21da87c0000000000ffffffff0a9a33750a810cd384ca5d93b09513f1eb5d93c669091b29eef710d2391ff7300000000000ffffffff040100000000000000000000000000000000000000000000000000000000000000aa0100000000000007d000000100000000000000000000000000000000000000000000000000000000000000aa010000000000989680001600142c9337c6875705dc8ead1d42b961ffeb2e9ac1790100000000000000000000000000000000000000000000000000000000000000bb0100000000004c4b4000160014265cb61e5c017c02270d7fe385ba08836616c1180100000000000000000000000000000000000000000000000000000000000000bb0100000000002dc6c003e95214596e9291c6e596c324f62d84cfa5e48fb3383841c1dd7fefaa17ad640d160014964d1721318c8bc7b016d0eb9374a620e8b88a9800000000",
    tx1.to_str());

    let ext_privkey1 = privkey.derive_from_number(1, false).expect("Fail");
    let privkey1 = ext_privkey1.get_privkey();
    let pubkey1 = privkey1.get_pubkey().expect("Fail");
    let desc = format!("wsh(pkh({}))", pubkey1.to_hex());
    let descriptor = Descriptor::new(&desc, &network_type).expect("Fail");
    let value1 = ConfidentialValue::from_amount(10000000).expect("Fail");
    let sighash_type = SigHashType::All;
    let script1 = descriptor.get_redeem_script().expect("Fail");
    let sighash = tx
      .create_sighash_by_script(
        &outpoint1,
        descriptor.get_hash_type(),
        script1,
        &sighash_type,
        &value1,
      )
      .expect("Fail");
    let sign_param = privkey1
      .calculate_ec_signature(&sighash, true)
      .expect("Fail");
    tx = tx
      .add_script_hash_sign(
        &outpoint1,
        descriptor.get_hash_type(),
        &[sign_param],
        script1,
        true,
      )
      .expect("Fail");
    let tx2 = tx.clone();
    assert_eq!("0200000001020a503dbd4f8f2b064c70e048b21f93fe4584174478abf5f44747932cd21da87c0000000000ffffffff0a9a33750a810cd384ca5d93b09513f1eb5d93c669091b29eef710d2391ff7300000000000ffffffff040100000000000000000000000000000000000000000000000000000000000000aa0100000000000007d000000100000000000000000000000000000000000000000000000000000000000000aa010000000000989680001600142c9337c6875705dc8ead1d42b961ffeb2e9ac1790100000000000000000000000000000000000000000000000000000000000000bb0100000000004c4b4000160014265cb61e5c017c02270d7fe385ba08836616c1180100000000000000000000000000000000000000000000000000000000000000bb0100000000002dc6c003e95214596e9291c6e596c324f62d84cfa5e48fb3383841c1dd7fefaa17ad640d160014964d1721318c8bc7b016d0eb9374a620e8b88a9800000000000002473044022048c9f2a869d5878dcb84c72bfa7037e845e35d07dd6a84e6d9ccda33ad31572e02200be3f6e9ff5ee56bbc99916004a073d21745de2eaf1f4b3f493b93b154676535011976a9148b756cbd98f4f55e985f80437a619d47f0732a9488ac00000000000000000000000000",
      tx2.to_str());

    tx = tx
      .sign_with_privkey(
        &outpoint2,
        &HashType::P2wpkh,
        &privkey1,
        &sighash_type,
        &value1,
      )
      .expect("Fail");

    let out_index1 = tx.get_txout_fee_index().expect("Fail");
    assert_eq!(0, out_index1);
    let out_index2 = tx.get_txout_index_by_address(&addr1).expect("Fail");
    assert_eq!(1, out_index2);
    let out_index3 = tx
      .get_txout_index_by_script(addr2.get_locking_script())
      .expect("Fail");
    assert_eq!(2, out_index3);
    let out_index4 = tx.get_txout_index_by_address(&addr3).expect("Fail");
    assert_eq!(3, out_index4);

    assert_eq!(
      descriptor.get_redeem_script().expect("Fail").to_hex(),
      tx.get_txin_list()[0].script_witness.witness_stack[1].to_hex()
    );
    let txin_index = tx.get_txin_index(&outpoint2).expect("Fail") as usize;
    assert_eq!(
      pubkey1.to_hex(),
      tx.get_txin_list()[txin_index].script_witness.witness_stack[1].to_hex()
    );
    assert_eq!(
      addr1.get_locking_script().to_hex(),
      tx.get_txout_list()[1].locking_script.to_hex()
    );
  }

  /*
  [Fact]
  public void CreateRawTransactionTest2()
  {
    ExtPrivkey privkey = new ExtPrivkey("xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV");
    ExtPubkey key = privkey.GetExtPubkey();
    Address setAddr1 = new Address(key.DerivePubkey(11).GetPubkey(), CfdAddressType.P2wpkh, CfdNetworkType.Liquidv1);
    Address setAddr2 = new Address(key.DerivePubkey(12).GetPubkey(), CfdAddressType.P2wpkh, CfdNetworkType.Liquidv1);
    Address setAddr3 = new Address(key.DerivePubkey(13).GetPubkey(), CfdAddressType.P2wpkh, CfdNetworkType.Liquidv1);
    Pubkey confidentialKey3 = key.DerivePubkey(103).GetPubkey();
    ConfidentialAddress ctAddr3 = new ConfidentialAddress(setAddr3, confidentialKey3);

    ConfidentialTransaction tx = new ConfidentialTransaction(2, 0);
    tx.AddTxIn(new OutPoint("7ca81dd22c934747f4f5ab7844178445fe931fb248e0704c062b8f4fbd3d500a", 0));
    tx.AddTxIn(new OutPoint("30f71f39d210f7ee291b0969c6935debf11395b0935dca84d30c810a75339a0a", 0));
    tx.AddTxIn(new OutPoint("30f71f39d210f7ee291b0969c6935debf11395b0935dca84d30c810a75339a0a", 0));
    tx.AddFeeTxOut(assetA, 1000);
    tx.AddTxOut(new ConfidentialAsset(assetA), new ConfidentialValue(10000000), setAddr1);
    tx.AddTxOut(new ConfidentialAsset(assetB), new ConfidentialValue(5000000), setAddr2);
    tx.AddTxOut(new ConfidentialAsset(assetB), new ConfidentialValue(3000000), ctAddr3);
    tx.AddDestroyAmountTxOut(assetB, 10000);
    tx.UpdateFee(2000, new ConfidentialAsset(assetA));

    output.WriteLine("tx: " + tx.ToHexString());
    assert_eq!("0200000000030a503dbd4f8f2b064c70e048b21f93fe4584174478abf5f44747932cd21da87c0000000000ffffffff0a9a33750a810cd384ca5d93b09513f1eb5d93c669091b29eef710d2391ff7300000000000ffffffff0a9a33750a810cd384ca5d93b09513f1eb5d93c669091b29eef710d2391ff7300000000000ffffffff050100000000000000000000000000000000000000000000000000000000000000aa0100000000000007d000000100000000000000000000000000000000000000000000000000000000000000aa010000000000989680001600142c9337c6875705dc8ead1d42b961ffeb2e9ac1790100000000000000000000000000000000000000000000000000000000000000bb0100000000004c4b4000160014265cb61e5c017c02270d7fe385ba08836616c1180100000000000000000000000000000000000000000000000000000000000000bb0100000000002dc6c000160014964d1721318c8bc7b016d0eb9374a620e8b88a980100000000000000000000000000000000000000000000000000000000000000bb01000000000000271000016a00000000",
      tx.ToHexString());

    tx.UpdateTxOutAmount(0, 2000);
    output.WriteLine("tx2: " + tx.ToHexString());
    assert_eq!("0200000000030a503dbd4f8f2b064c70e048b21f93fe4584174478abf5f44747932cd21da87c0000000000ffffffff0a9a33750a810cd384ca5d93b09513f1eb5d93c669091b29eef710d2391ff7300000000000ffffffff0a9a33750a810cd384ca5d93b09513f1eb5d93c669091b29eef710d2391ff7300000000000ffffffff050100000000000000000000000000000000000000000000000000000000000000aa0100000000000007d000000100000000000000000000000000000000000000000000000000000000000000aa010000000000989680001600142c9337c6875705dc8ead1d42b961ffeb2e9ac1790100000000000000000000000000000000000000000000000000000000000000bb0100000000004c4b4000160014265cb61e5c017c02270d7fe385ba08836616c1180100000000000000000000000000000000000000000000000000000000000000bb0100000000002dc6c000160014964d1721318c8bc7b016d0eb9374a620e8b88a980100000000000000000000000000000000000000000000000000000000000000bb01000000000000271000016a00000000",
      tx.ToHexString());
  }

  [Fact]
  public void AddSignTest()
  {
    ExtPrivkey privkey = new ExtPrivkey("xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV");
    ExtPubkey key = privkey.GetExtPubkey();

    ConfidentialTransaction tx = new ConfidentialTransaction("0200000000020a503dbd4f8f2b064c70e048b21f93fe4584174478abf5f44747932cd21da87c0000000000ffffffff0a9a33750a810cd384ca5d93b09513f1eb5d93c669091b29eef710d2391ff7300000000000ffffffff040100000000000000000000000000000000000000000000000000000000000000aa0100000000000007d000000100000000000000000000000000000000000000000000000000000000000000aa010000000000989680001600142c9337c6875705dc8ead1d42b961ffeb2e9ac1790100000000000000000000000000000000000000000000000000000000000000bb0100000000004c4b4000160014265cb61e5c017c02270d7fe385ba08836616c1180100000000000000000000000000000000000000000000000000000000000000bb0100000000002dc6c000160014964d1721318c8bc7b016d0eb9374a620e8b88a9800000000");

    // AddScriptSign
    Pubkey pubkey1 = key.DerivePubkey(1).GetPubkey();
    Privkey privkey1 = privkey.DerivePrivkey(1).GetPrivkey();
    string desc = string.Format("wsh(pkh({0}))", pubkey1.ToHexString());
    Descriptor descriptor = new Descriptor(desc, CfdNetworkType.Liquidv1);
    OutPoint outpoint1 = new OutPoint("7ca81dd22c934747f4f5ab7844178445fe931fb248e0704c062b8f4fbd3d500a", 0);
    ConfidentialValue value1 = new ConfidentialValue(10000000);
    SignatureHashType sighashType = new SignatureHashType(CfdSighashType.All, false);
    ByteData sighash = tx.GetSignatureHash(outpoint1, descriptor.GetHashType(), descriptor.GetRedeemScript(), value1,
      sighashType);
    SignParameter signParam = privkey1.CalculateEcSignature(sighash);

    tx.AddSign(outpoint1.GetTxid(), outpoint1.GetVout(), descriptor.GetHashType(), signParam, true);
    SignParameter script = new SignParameter(descriptor.GetRedeemScript().ToHexString());
    tx.AddSign(outpoint1.GetTxid(), outpoint1.GetVout(), descriptor.GetHashType(), script, false);

    output.WriteLine("tx: " + tx.ToHexString());
    assert_eq!("0200000001020a503dbd4f8f2b064c70e048b21f93fe4584174478abf5f44747932cd21da87c0000000000ffffffff0a9a33750a810cd384ca5d93b09513f1eb5d93c669091b29eef710d2391ff7300000000000ffffffff040100000000000000000000000000000000000000000000000000000000000000aa0100000000000007d000000100000000000000000000000000000000000000000000000000000000000000aa010000000000989680001600142c9337c6875705dc8ead1d42b961ffeb2e9ac1790100000000000000000000000000000000000000000000000000000000000000bb0100000000004c4b4000160014265cb61e5c017c02270d7fe385ba08836616c1180100000000000000000000000000000000000000000000000000000000000000bb0100000000002dc6c000160014964d1721318c8bc7b016d0eb9374a620e8b88a98000000000000024730440220205c9d0314ddd2a60e63e525e2452d360d9a485325a76ce359ab015bfbffa63102201da43d23a1cb397252d354cd07f0954ed5406b1cef74b5f2dc06c20897c8046a011976a9148b756cbd98f4f55e985f80437a619d47f0732a9488ac00000000000000000000000000",
      tx.ToHexString());
  }
  */

  #[test]
  fn get_issuance_blinding_key_test() {
    let master_blinding_key =
      Privkey::from_str("a0cd219833629db30c5210716c7b2e22fb8dd10aa231692f1f53acd8e662de01")
        .expect("Fail");
    let outpoint = OutPoint::from_str(
      "21fe3fc8e38256ec747fa8d8ea96319fd00cbcf318c2586b9b8e9e27a5afe9aa",
      0,
    )
    .expect("Fail");
    let blinding_key = get_issuance_blinding_key(&master_blinding_key, &outpoint).expect("Fail");
    assert_eq!(
      "24c10c3b128f220e3b4253cec39ea3b75d2f6000033508c8deeadc1b6eefc4a1",
      blinding_key.to_hex()
    );
  }

  #[test]
  fn get_default_blinding_key_test() {
    let master_blinding_key =
      Privkey::from_str("881a1ab07e99ab0626b4d93b3dddfd16cbc04342ee71aab4da7093e7b853fd80")
        .expect("Fail");
    let locking_script =
      Script::from_hex("001478bf37fbe762374026b2b884f7eb47fa61e3420d").expect("Fail");
    let address =
      Address::from_string("ert1q0zln07l8vgm5qf4jhzz00668lfs7xssdlxlysh").expect("Fail");

    let blinding_key1 =
      get_default_blinding_key(&master_blinding_key, &locking_script).expect("Fail");
    assert_eq!(
      "95af1be4f929e182442c9f3aa55a3cacde69d1182677f3afd618cdfb4a588742",
      blinding_key1.to_hex()
    );

    let blinding_key2 =
      get_default_blinding_key(&master_blinding_key, address.get_locking_script()).expect("Fail");
    assert_eq!(
      "95af1be4f929e182442c9f3aa55a3cacde69d1182677f3afd618cdfb4a588742",
      blinding_key2.to_hex()
    );
  }

  #[test]
  fn get_commitment_test() {
    let asset = ConfidentialAsset::from_str(
      "6f1a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3",
    )
    .expect("Fail");
    let abf =
      BlindFactor::from_str("346dbdba35c19f6e3958a2c00881024503f6611d23d98d270b98ef9de3edc7a3")
        .expect("Fail");
    let vbf =
      BlindFactor::from_str("fe3357df1f35df75412d9ad86ebd99e622e26019722f316027787a685e2cd71a")
        .expect("Fail");
    let amount: i64 = 13000000000000;
    let asset_commitment = asset.get_commitment(&abf).expect("Fail");
    assert_eq!(
      "0a533b742a568c0b5285bf5bdfe9623a78082d19fac9be1678f7c3adbb48b34d29",
      asset_commitment.as_str()
    );
    let value_commitment =
      ConfidentialValue::get_commitment(amount, &asset_commitment, &vbf).expect("Fail");
    assert_eq!(
      "08672d4e2e60f2e8d742552a8bc4ca6335ed214982c7728b4483284169aaae7f49",
      value_commitment.as_str()
    );
  }
}
