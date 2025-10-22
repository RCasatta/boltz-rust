use bitcoin::{
    hashes::{hash160, Hash},
    hex::DisplayHex,
    key::rand::{rngs::OsRng, RngCore},
    secp256k1::Keypair,
    Amount, Witness, XOnlyPublicKey,
};
use elements::{
    confidential::{Asset, AssetBlindingFactor, ValueBlindingFactor},
    hex::FromHex,
    secp256k1_zkp::{Secp256k1, SecretKey},
    sighash::{Prevouts, SighashCache},
    taproot::{LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo},
    Address, AssetIssuance, BlockHash, LockTime, OutPoint, SchnorrSig, SchnorrSighashType, Script,
    Sequence, Transaction, TxIn, TxInWitness, TxOut, TxOutWitness,
};
use secp256k1_musig::{musig, rand, Scalar};
use std::str::FromStr;

use elements::encode::serialize;
use elements::secp256k1_zkp::Message;

use crate::util::secrets::Preimage;

use crate::error::Error;

use super::{
    boltz::{
        BoltzApiClientV2, ChainSwapDetails, Cooperative, CreateReverseResponse,
        CreateSubmarineResponse, Side, SwapTxKind, SwapType, ToSign,
    },
    wrappers::SwapScriptCommon,
};
use crate::fees::{create_tx_with_fee, Fee};
use crate::network::{LiquidChain, LiquidClient};
use elements::bitcoin::PublicKey;
use elements::secp256k1_zkp::Keypair as ZKKeyPair;
use elements::{
    address::Address as EAddress,
    opcodes::all::*,
    script::{Builder as EBuilder, Instruction},
};

/// Liquid v2 swap script helper.
#[derive(Debug, Clone, PartialEq)]
pub struct LBtcSwapScript {
    pub swap_type: SwapType,
    pub side: Option<Side>,
    pub funding_addrs: Option<Address>,
    pub hashlock: hash160::Hash,
    pub receiver_pubkey: PublicKey,
    pub locktime: LockTime,
    pub sender_pubkey: PublicKey,
    pub blinding_key: ZKKeyPair,
}

impl LBtcSwapScript {
    /// Create the struct for a submarine swap from boltz create response.
    pub fn submarine_from_swap_resp(
        create_swap_response: &CreateSubmarineResponse,
        our_pubkey: PublicKey,
    ) -> Result<Self, Error> {
        let claim_script = Script::from_hex(&create_swap_response.swap_tree.claim_leaf.output)?;
        let refund_script = Script::from_hex(&create_swap_response.swap_tree.refund_leaf.output)?;

        let claim_instructions = claim_script.instructions();
        let refund_instructions = refund_script.instructions();

        let mut last_op = OP_0NOTEQUAL;
        let mut hashlock = None;
        let mut locktime = None;

        for instruction in claim_instructions {
            match instruction {
                Ok(Instruction::PushBytes(bytes)) => {
                    if bytes.len() == 20 {
                        hashlock = Some(hash160::Hash::from_slice(bytes)?);
                    } else {
                        continue;
                    }
                }
                _ => continue,
            }
        }

        for instruction in refund_instructions {
            match instruction {
                Ok(Instruction::Op(opcode)) => last_op = opcode,
                Ok(Instruction::PushBytes(bytes)) => {
                    if last_op == OP_CHECKSIGVERIFY {
                        locktime =
                            Some(LockTime::from_consensus(bytes_to_u32_little_endian(bytes)));
                    } else {
                        continue;
                    }
                }
                _ => continue,
            }
        }

        let hashlock =
            hashlock.ok_or_else(|| Error::Protocol("No hashlock provided".to_string()))?;

        let locktime =
            locktime.ok_or_else(|| Error::Protocol("No timelock provided".to_string()))?;

        let funding_addrs = Address::from_str(&create_swap_response.address)?;

        let blinding_str = create_swap_response
            .blinding_key
            .as_ref()
            .ok_or(Error::Protocol(
                "No blinding key provided in Create Swap Response".to_string(),
            ))?;
        let blinding_key = ZKKeyPair::from_seckey_str(&Secp256k1::new(), blinding_str)?;

        Ok(Self {
            swap_type: SwapType::Submarine,
            side: None,
            funding_addrs: Some(funding_addrs),
            hashlock,
            receiver_pubkey: create_swap_response.claim_public_key,
            locktime,
            sender_pubkey: our_pubkey,
            blinding_key,
        })
    }

    /// Create the struct for a reverse swap from boltz create response.
    pub fn reverse_from_swap_resp(
        reverse_response: &CreateReverseResponse,
        our_pubkey: PublicKey,
    ) -> Result<Self, Error> {
        let claim_script = Script::from_hex(&reverse_response.swap_tree.claim_leaf.output)?;
        let refund_script = Script::from_hex(&reverse_response.swap_tree.refund_leaf.output)?;

        let claim_instructions = claim_script.instructions();
        let refund_instructions = refund_script.instructions();

        let mut last_op = OP_0NOTEQUAL;
        let mut hashlock = None;
        let mut locktime = None;

        for instruction in claim_instructions {
            match instruction {
                Ok(Instruction::PushBytes(bytes)) => {
                    if bytes.len() == 20 {
                        hashlock = Some(hash160::Hash::from_slice(bytes)?);
                    } else {
                        continue;
                    }
                }
                _ => continue,
            }
        }

        for instruction in refund_instructions {
            match instruction {
                Ok(Instruction::Op(opcode)) => last_op = opcode,
                Ok(Instruction::PushBytes(bytes)) => {
                    if last_op == OP_CHECKSIGVERIFY {
                        locktime =
                            Some(LockTime::from_consensus(bytes_to_u32_little_endian(bytes)));
                    } else {
                        continue;
                    }
                }
                _ => continue,
            }
        }

        let hashlock =
            hashlock.ok_or_else(|| Error::Protocol("No hashlock provided".to_string()))?;

        let locktime =
            locktime.ok_or_else(|| Error::Protocol("No timelock provided".to_string()))?;

        let funding_addrs = Address::from_str(&reverse_response.lockup_address)?;

        let blinding_str = reverse_response
            .blinding_key
            .as_ref()
            .ok_or(Error::Protocol(
                "No blinding key provided in Create Swap Response".to_string(),
            ))?;
        let blinding_key = ZKKeyPair::from_seckey_str(&Secp256k1::new(), blinding_str)?;

        Ok(Self {
            swap_type: SwapType::ReverseSubmarine,
            side: None,
            funding_addrs: Some(funding_addrs),
            hashlock,
            receiver_pubkey: our_pubkey,
            locktime,
            sender_pubkey: reverse_response.refund_public_key,
            blinding_key,
        })
    }

    /// Create the struct for a chain swap from boltz create response.
    pub fn chain_from_swap_resp(
        side: Side,
        chain_swap_details: ChainSwapDetails,
        our_pubkey: PublicKey,
    ) -> Result<Self, Error> {
        let claim_script = Script::from_hex(&chain_swap_details.swap_tree.claim_leaf.output)?;
        let refund_script = Script::from_hex(&chain_swap_details.swap_tree.refund_leaf.output)?;

        let claim_instructions = claim_script.instructions();
        let refund_instructions = refund_script.instructions();

        let mut last_op = OP_0NOTEQUAL;
        let mut hashlock = None;
        let mut locktime = None;

        for instruction in claim_instructions {
            match instruction {
                Ok(Instruction::PushBytes(bytes)) => {
                    if bytes.len() == 20 {
                        hashlock = Some(hash160::Hash::from_slice(bytes)?);
                    } else {
                        continue;
                    }
                }
                _ => continue,
            }
        }

        for instruction in refund_instructions {
            match instruction {
                Ok(Instruction::Op(opcode)) => last_op = opcode,
                Ok(Instruction::PushBytes(bytes)) => {
                    if last_op == OP_CHECKSIGVERIFY {
                        locktime =
                            Some(LockTime::from_consensus(bytes_to_u32_little_endian(bytes)));
                    } else {
                        continue;
                    }
                }
                _ => continue,
            }
        }

        let hashlock =
            hashlock.ok_or_else(|| Error::Protocol("No hashlock provided".to_string()))?;

        let locktime =
            locktime.ok_or_else(|| Error::Protocol("No timelock provided".to_string()))?;

        let funding_addrs = Address::from_str(&chain_swap_details.lockup_address)?;

        let (sender_pubkey, receiver_pubkey) = match side {
            Side::Lockup => (our_pubkey, chain_swap_details.server_public_key),
            Side::Claim => (chain_swap_details.server_public_key, our_pubkey),
        };

        let blinding_str = chain_swap_details
            .blinding_key
            .as_ref()
            .ok_or(Error::Protocol(
                "No blinding key provided in ChainSwapDetails".to_string(),
            ))?;
        let blinding_key = ZKKeyPair::from_seckey_str(&Secp256k1::new(), blinding_str)?;

        Ok(Self {
            swap_type: SwapType::Chain,
            side: Some(side),
            funding_addrs: Some(funding_addrs),
            hashlock,
            receiver_pubkey,
            locktime,
            sender_pubkey,
            blinding_key,
        })
    }

    fn claim_script(&self) -> Script {
        match self.swap_type {
            SwapType::Submarine => EBuilder::new()
                .push_opcode(OP_HASH160)
                .push_slice(self.hashlock.as_byte_array())
                .push_opcode(OP_EQUALVERIFY)
                .push_slice(&self.receiver_pubkey.inner.x_only_public_key().0.serialize())
                .push_opcode(OP_CHECKSIG)
                .into_script(),

            SwapType::ReverseSubmarine | SwapType::Chain => EBuilder::new()
                .push_opcode(OP_SIZE)
                .push_int(32)
                .push_opcode(OP_EQUALVERIFY)
                .push_opcode(OP_HASH160)
                .push_slice(self.hashlock.as_byte_array())
                .push_opcode(OP_EQUALVERIFY)
                .push_slice(&self.receiver_pubkey.inner.x_only_public_key().0.serialize())
                .push_opcode(OP_CHECKSIG)
                .into_script(),
        }
    }

    fn refund_script(&self) -> Script {
        // Refund scripts are same for all swap types
        EBuilder::new()
            .push_slice(&self.sender_pubkey.inner.x_only_public_key().0.serialize())
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_int(self.locktime.to_consensus_u32().into())
            .push_opcode(OP_CLTV)
            .into_script()
    }

    pub fn musig_keyagg_cache(&self) -> musig::KeyAggCache {
        match (self.swap_type, self.side.clone()) {
            (SwapType::ReverseSubmarine, _) | (SwapType::Chain, Some(Side::Claim)) => {
                let pubkeys = [self.sender_pubkey.inner, self.receiver_pubkey.inner];
                let converted = convert_pubkeys_for_musig(&pubkeys);
                musig::KeyAggCache::new(&converted)
            }

            (SwapType::Submarine, _) | (SwapType::Chain, _) => {
                let pubkeys = [self.receiver_pubkey.inner, self.sender_pubkey.inner];
                let converted = convert_pubkeys_for_musig(&pubkeys);
                musig::KeyAggCache::new(&converted)
            }
        }
    }

    /// Internally used to convert struct into a bitcoin::Script type
    fn taproot_spendinfo(&self) -> Result<TaprootSpendInfo, Error> {
        let secp = Secp256k1::new();

        // Setup Key Aggregation cache
        let key_agg_cache = self.musig_keyagg_cache();

        // Construct the Taproot
        let internal_key = key_agg_cache.agg_pk();

        let taproot_builder = TaprootBuilder::new();

        let taproot_builder =
            taproot_builder.add_leaf_with_ver(1, self.claim_script(), LeafVersion::default())?;
        let taproot_builder =
            taproot_builder.add_leaf_with_ver(1, self.refund_script(), LeafVersion::default())?;

        let taproot_spend_info =
            taproot_builder.finalize(&secp, convert_xonly_key(internal_key))?;

        // Verify taproot construction
        if let Some(funding_addrs) = &self.funding_addrs {
            let claim_key = taproot_spend_info.output_key();

            let lockup_spk = funding_addrs.script_pubkey();

            let pubkey_instruction = lockup_spk
                .instructions()
                .last()
                .ok_or(Error::Protocol(
                    "Script should contain at least one instruction".to_string(),
                ))?
                .map_err(|_| Error::Protocol("Failed to parse script instruction".to_string()))?;

            let lockup_xonly_pubkey_bytes = pubkey_instruction.push_bytes().ok_or(
                Error::Protocol("Expected push bytes instruction for pubkey".to_string()),
            )?;

            let lockup_xonly_pubkey = XOnlyPublicKey::from_slice(lockup_xonly_pubkey_bytes)?;

            if lockup_xonly_pubkey != claim_key.into_inner() {
                return Err(Error::Protocol(format!(
                    "Taproot construction Failed. Lockup Pubkey: {lockup_xonly_pubkey}, Claim Pubkey {claim_key:?}"
                )));
            }

            log::info!("Taproot creation and verification success!");
        }

        Ok(taproot_spend_info)
    }

    /// Get taproot address for the swap script.
    /// Always returns a confidential address
    pub fn to_address(&self, network: LiquidChain) -> Result<EAddress, Error> {
        let taproot_spend_info = self.taproot_spendinfo()?;

        Ok(EAddress::p2tr(
            &Secp256k1::new(),
            taproot_spend_info.internal_key(),
            taproot_spend_info.merkle_root(),
            Some(self.blinding_key.public_key()),
            network.into(),
        ))
    }

    pub fn validate_address(&self, chain: LiquidChain, address: String) -> Result<(), Error> {
        let to_address = self.to_address(chain)?;
        if to_address.to_string() == address {
            Ok(())
        } else {
            Err(Error::Protocol("Script/LockupAddress Mismatch".to_string()))
        }
    }

    /// Fetch utxo for script from Electrum
    pub async fn fetch_utxo<LC: LiquidClient + ?Sized>(
        &self,
        liquid_client: &LC,
    ) -> Result<Option<(OutPoint, TxOut)>, Error> {
        let address = self.to_address(liquid_client.network())?;
        liquid_client.get_address_utxo(&address).await
    }

    /// Fetch utxo for script from BoltzApi
    pub async fn fetch_lockup_utxo_boltz(
        &self,
        network: LiquidChain,
        boltz_client: &BoltzApiClientV2,
        swap_id: &str,
        tx_kind: SwapTxKind,
    ) -> Result<(OutPoint, TxOut), Error> {
        let hex = match self.swap_type {
            SwapType::Chain => match tx_kind {
                SwapTxKind::Claim => {
                    boltz_client
                        .get_chain_txs(swap_id)
                        .await?
                        .server_lock
                        .ok_or(Error::Protocol(
                            "No server_lock transaction for Chain Swap available".to_string(),
                        ))?
                        .transaction
                        .hex
                }
                SwapTxKind::Refund => {
                    boltz_client
                        .get_chain_txs(swap_id)
                        .await?
                        .user_lock
                        .ok_or(Error::Protocol(
                            "No user_lock transaction for Chain Swap available".to_string(),
                        ))?
                        .transaction
                        .hex
                }
            },
            SwapType::ReverseSubmarine => boltz_client.get_reverse_tx(swap_id).await?.hex,
            SwapType::Submarine => boltz_client.get_submarine_tx(swap_id).await?.hex,
        };
        if hex.is_none() {
            return Err(Error::Hex(
                "No transaction hex found in boltz response".to_string(),
            ));
        }
        let address = self.to_address(network)?;
        let tx: Transaction = elements::encode::deserialize(&hex::decode(hex.unwrap())?)?;
        for (vout, output) in tx.clone().output.into_iter().enumerate() {
            if output.script_pubkey == address.script_pubkey() {
                let outpoint_0 = OutPoint::new(tx.txid(), vout as u32);

                return Ok((outpoint_0, output));
            }
        }
        Err(Error::Protocol(
            "Boltz could not find a Liquid UTXO for script".to_string(),
        ))
    }

    // Get the chain genesis hash. Requires for sighash calculation
    pub async fn genesis_hash<LC: LiquidClient>(
        &self,
        liquid_client: &LC,
    ) -> Result<BlockHash, Error> {
        liquid_client.get_genesis_hash().await
    }
}

fn bytes_to_u32_little_endian(bytes: &[u8]) -> u32 {
    let mut result = 0u32;
    for (i, &byte) in bytes.iter().enumerate() {
        result |= (byte as u32) << (8 * i);
    }
    result
}

/// Liquid swap transaction helper.
#[derive(Debug, Clone)]
pub struct LBtcSwapTx {
    pub kind: SwapTxKind,
    pub swap_script: LBtcSwapScript,
    pub output_address: Address,
    pub funding_outpoint: OutPoint,
    pub funding_utxo: TxOut, // there should only ever be one outpoint in a swap
    pub genesis_hash: BlockHash, // Required to calculate sighash
}

impl LBtcSwapTx {
    /// Craft a new ClaimTx. Only works for Reverse and Chain Swaps.
    pub async fn new_claim<LC: LiquidClient + ?Sized>(
        swap_script: LBtcSwapScript,
        output_address: String,
        liquid_client: &LC,
        boltz_client: &BoltzApiClientV2,
        swap_id: String,
    ) -> Result<LBtcSwapTx, Error> {
        if swap_script.swap_type == SwapType::Submarine {
            return Err(Error::Protocol(
                "Claim transactions cannot be constructed for Submarine swaps.".to_string(),
            ));
        }

        let (funding_outpoint, funding_utxo) = match swap_script.fetch_utxo(liquid_client).await {
            Ok(Some(r)) => r,
            Ok(None) | Err(_) => {
                swap_script
                    .fetch_lockup_utxo_boltz(
                        liquid_client.network(),
                        boltz_client,
                        &swap_id,
                        SwapTxKind::Claim,
                    )
                    .await?
            }
        };

        let genesis_hash = liquid_client.get_genesis_hash().await?;

        Ok(LBtcSwapTx {
            kind: SwapTxKind::Claim,
            swap_script,
            output_address: Address::from_str(&output_address)?,
            funding_outpoint,
            funding_utxo,
            genesis_hash,
        })
    }

    /// Construct a RefundTX corresponding to the swap_script. Only works for Submarine and Chain Swaps.
    pub async fn new_refund<LC: LiquidClient + ?Sized>(
        swap_script: LBtcSwapScript,
        output_address: &str,
        liquid_client: &LC,
        boltz_client: &BoltzApiClientV2,
        swap_id: String,
    ) -> Result<LBtcSwapTx, Error> {
        if swap_script.swap_type == SwapType::ReverseSubmarine {
            return Err(Error::Protocol(
                "Refund Txs cannot be constructed for Reverse Submarine Swaps.".to_string(),
            ));
        }

        let address = Address::from_str(output_address)?;
        let (funding_outpoint, funding_utxo) = match swap_script.fetch_utxo(liquid_client).await {
            Ok(Some(r)) => r,
            Ok(None) | Err(_) => {
                swap_script
                    .fetch_lockup_utxo_boltz(
                        liquid_client.network(),
                        boltz_client,
                        &swap_id,
                        SwapTxKind::Refund,
                    )
                    .await?
            }
        };

        let genesis_hash = liquid_client.get_genesis_hash().await?;

        Ok(LBtcSwapTx {
            kind: SwapTxKind::Refund,
            swap_script,
            output_address: address,
            funding_outpoint,
            funding_utxo,
            genesis_hash,
        })
    }

    /// Compute the Musig partial signature.
    /// This is used to cooperatively close a Submarine or Chain Swap.
    pub fn partial_sign(
        &self,
        keys: &Keypair,
        pub_nonce: &str,
        transaction_hash: &str,
    ) -> Result<(musig::PartialSignature, musig::PublicNonce), Error> {
        self.swap_script
            .partial_sign(keys, pub_nonce, transaction_hash)
    }

    /// Sign a claim transaction.
    /// Panics if called on a Submarine Swap or Refund Tx.
    /// If the claim is cooperative, provide the other party's partial sigs.
    /// If this is None, transaction will be claimed via taproot script path.
    pub async fn sign_claim(
        &self,
        keys: &Keypair,
        preimage: &Preimage,
        fee: Fee,
        is_cooperative: Option<Cooperative<'_>>,
        is_discount_ct: bool,
    ) -> Result<Transaction, Error> {
        if self.swap_script.swap_type == SwapType::Submarine {
            return Err(Error::Protocol(
                "Claim Tx signing is not applicable for Submarine Swaps".to_string(),
            ));
        }

        if self.kind == SwapTxKind::Refund {
            return Err(Error::Protocol(
                "Cannot sign claim with refund-type LBtcSwapTx".to_string(),
            ));
        }

        let mut claim_tx = create_tx_with_fee(
            fee,
            |fee| self.create_claim(keys, preimage, fee, is_cooperative.is_some()),
            |tx| tx_size(&tx, is_discount_ct),
        )?;

        // If its a cooperative claim, compute the Musig2 Aggregate Signature and use Keypath spending
        if let Some(Cooperative {
            boltz_api,
            swap_id,
            signature,
        }) = is_cooperative
        {
            let claim_tx_taproot_hash = SighashCache::new(&claim_tx)
                .taproot_key_spend_signature_hash(
                    0,
                    &Prevouts::All(&[&self.funding_utxo]),
                    SchnorrSighashType::Default,
                    self.genesis_hash,
                )?;

            let msg = claim_tx_taproot_hash.as_byte_array().clone();

            let mut key_agg_cache = self.swap_script.musig_keyagg_cache();

            let tweak = Scalar::from_be_bytes(
                self.swap_script
                    .taproot_spendinfo()?
                    .tap_tweak()
                    .as_byte_array()
                    .clone(),
            )
            .expect("TODO");

            let _ = key_agg_cache.pubkey_xonly_tweak_add(&tweak).expect("TODO");

            let session_id = musig::SessionSecretRand::from_rng(&mut rand::rng());

            let mut extra_rand = [0u8; 32];
            OsRng.fill_bytes(&mut extra_rand);

            let (claim_sec_nonce, claim_pub_nonce) = key_agg_cache.nonce_gen(
                session_id,
                convert_public_key(keys.public_key()),
                &msg,
                Some(extra_rand),
            );

            // Step 7: Get boltz's partial sig
            let claim_tx_hex = serialize(&claim_tx).to_lower_hex_string();
            let partial_sig_resp = match self.swap_script.swap_type {
                SwapType::Chain => {
                    boltz_api
                        .post_chain_claim_tx_details(
                            &swap_id,
                            preimage,
                            signature,
                            ToSign {
                                pub_nonce: claim_pub_nonce.serialize().to_lower_hex_string(),
                                transaction: claim_tx_hex,
                                index: 0,
                            },
                        )
                        .await
                }
                SwapType::ReverseSubmarine => {
                    boltz_api
                        .get_reverse_partial_sig(
                            &swap_id,
                            preimage,
                            &claim_pub_nonce,
                            &claim_tx_hex,
                        )
                        .await
                }
                _ => Err(Error::Protocol(format!(
                    "Cannot get partial sig for {:?} Swap",
                    self.swap_script.swap_type
                ))),
            }?;

            let boltz_public_nonce =
                musig::PublicNonce::from_byte_array(&hex_to_bytes66(&partial_sig_resp.pub_nonce)?)
                    .expect("TODO");

            let boltz_partial_sig = musig::PartialSignature::from_byte_array(&hex_to_bytes32(
                &partial_sig_resp.partial_signature,
            )?)
            .expect("TODO");

            let agg_nonce = musig::AggregatedNonce::new(&[&boltz_public_nonce, &claim_pub_nonce]);

            let musig_session = musig::Session::new(&key_agg_cache, agg_nonce, &msg);

            // Verify the sigs.
            let boltz_partial_sig_verify = musig_session.partial_verify(
                &key_agg_cache,
                &boltz_partial_sig,
                &boltz_public_nonce,
                convert_public_key(self.swap_script.sender_pubkey.inner), //boltz key
            );

            if !boltz_partial_sig_verify {
                return Err(Error::Taproot(
                    "Unable to verify Partial Signature".to_string(),
                ));
            }

            let our_partial_sig =
                musig_session.partial_sign(claim_sec_nonce, convert_keypair(keys), &key_agg_cache);

            let schnorr_sig = musig_session
                .partial_sig_agg(&[&boltz_partial_sig, &our_partial_sig])
                .assume_valid();

            let final_schnorr_sig = SchnorrSig {
                sig: convert_schnorr_signature(schnorr_sig),
                hash_ty: SchnorrSighashType::Default,
            };

            let output_key = self.swap_script.taproot_spendinfo()?.output_key();

            let secp = Secp256k1::new();
            let msg = Message::from_digest_slice(&msg)?;
            secp.verify_schnorr(&final_schnorr_sig.sig, &msg, &output_key.into_inner())?;

            let mut script_witness = Witness::new();
            script_witness.push(final_schnorr_sig.to_vec());

            let witness = TxInWitness {
                amount_rangeproof: None,
                inflation_keys_rangeproof: None,
                script_witness: script_witness.to_vec(),
                pegin_witness: vec![],
            };

            claim_tx.input[0].witness = witness;
        }

        Ok(claim_tx)
    }

    fn create_claim(
        &self,
        keys: &Keypair,
        preimage: &Preimage,
        absolute_fees: u64,
        is_cooperative: bool,
    ) -> Result<Transaction, Error> {
        if preimage.bytes.is_none() {
            return Err(Error::Protocol("No preimage provided".to_string()));
        }

        let claim_txin = TxIn {
            sequence: Sequence::MAX,
            previous_output: self.funding_outpoint,
            script_sig: Script::new(),
            witness: TxInWitness::default(),
            is_pegin: false,
            asset_issuance: AssetIssuance::default(),
        };

        let secp = Secp256k1::new();
        let mut rng = OsRng;

        let unblined_utxo = self
            .funding_utxo
            .unblind(&secp, self.swap_script.blinding_key.secret_key())?;
        let asset_id = unblined_utxo.asset;
        let out_abf = AssetBlindingFactor::new(&mut rng);
        let exp_asset = Asset::Explicit(asset_id);

        let (blinded_asset, asset_surjection_proof) =
            exp_asset.blind(&mut rng, &secp, out_abf, &[unblined_utxo])?;

        let output_value = Amount::from_sat(unblined_utxo.value) - Amount::from_sat(absolute_fees);

        let final_vbf = ValueBlindingFactor::last(
            &secp,
            output_value.to_sat(),
            out_abf,
            &[(
                unblined_utxo.value,
                unblined_utxo.asset_bf,
                unblined_utxo.value_bf,
            )],
            &[(
                absolute_fees,
                AssetBlindingFactor::zero(),
                ValueBlindingFactor::zero(),
            )],
        );
        let explicit_value = elements::confidential::Value::Explicit(output_value.to_sat());
        let msg = elements::RangeProofMessage {
            asset: asset_id,
            bf: out_abf,
        };
        let ephemeral_sk = SecretKey::new(&mut rng);

        // assuming we always use a blinded address that has an extractable blinding pub
        let blinding_key = self
            .output_address
            .blinding_pubkey
            .ok_or(Error::Protocol("No blinding key in tx.".to_string()))?;
        let (blinded_value, nonce, rangeproof) = explicit_value.blind(
            &secp,
            final_vbf,
            blinding_key,
            ephemeral_sk,
            &self.output_address.script_pubkey(),
            &msg,
        )?;

        let tx_out_witness = TxOutWitness {
            surjection_proof: Some(Box::new(asset_surjection_proof)), // from asset blinding
            rangeproof: Some(Box::new(rangeproof)),                   // from value blinding
        };
        let payment_output: TxOut = TxOut {
            script_pubkey: self.output_address.script_pubkey(),
            value: blinded_value,
            asset: blinded_asset,
            nonce,
            witness: tx_out_witness,
        };
        let fee_output: TxOut = TxOut::new_fee(absolute_fees, asset_id);

        let mut claim_tx = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![claim_txin],
            output: vec![payment_output, fee_output],
        };

        if is_cooperative {
            claim_tx.input[0].witness = Self::stubbed_cooperative_witness();
        } else {
            // If Non-Cooperative claim use the Script Path spending
            claim_tx.input[0].sequence = Sequence::ZERO;
            let claim_script = self.swap_script.claim_script();
            let leaf_hash = TapLeafHash::from_script(&claim_script, LeafVersion::default());

            let sighash = SighashCache::new(&claim_tx).taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&[&self.funding_utxo]),
                leaf_hash,
                SchnorrSighashType::Default,
                self.genesis_hash,
            )?;

            let msg = Message::from_digest_slice(sighash.as_byte_array())?;

            let sig = secp.sign_schnorr(&msg, keys);

            let final_sig = SchnorrSig {
                sig,
                hash_ty: SchnorrSighashType::Default,
            };

            let control_block = match self
                .swap_script
                .taproot_spendinfo()?
                .control_block(&(claim_script.clone(), LeafVersion::default()))
            {
                Some(r) => r,
                None => return Err(Error::Taproot("Could not create control block".to_string())),
            };

            let mut script_witness = Witness::new();
            script_witness.push(final_sig.to_vec());
            script_witness.push(preimage.bytes.ok_or(Error::Protocol(
                "Preimage bytes not available - cannot claim without actual preimage".to_string(),
            ))?);
            script_witness.push(claim_script.as_bytes());
            script_witness.push(control_block.serialize());

            let witness = TxInWitness {
                amount_rangeproof: None,
                inflation_keys_rangeproof: None,
                script_witness: script_witness.to_vec(),
                pegin_witness: vec![],
            };

            claim_tx.input[0].witness = witness;
        }

        Ok(claim_tx)
    }

    /// Sign a refund transaction.
    /// Panics if called on a Reverse Swap or Claim Tx.
    pub async fn sign_refund(
        &self,
        keys: &Keypair,
        fee: Fee,
        is_cooperative: Option<Cooperative<'_>>,
        is_discount_ct: bool,
    ) -> Result<Transaction, Error> {
        if self.swap_script.swap_type == SwapType::ReverseSubmarine {
            return Err(Error::Protocol(
                "Refund Tx signing is not applicable for Reverse Submarine Swaps".to_string(),
            ));
        }

        if self.kind == SwapTxKind::Claim {
            return Err(Error::Protocol(
                "Cannot sign refund with a claim-type LBtcSwapTx".to_string(),
            ));
        }

        let mut refund_tx = create_tx_with_fee(
            fee,
            |fee| self.create_refund(keys, fee, is_cooperative.is_some()),
            |tx| tx_size(&tx, is_discount_ct),
        )?;

        if let Some(Cooperative {
            boltz_api, swap_id, ..
        }) = is_cooperative
        {
            let secp = Secp256k1::new();

            refund_tx.lock_time = LockTime::ZERO;

            let claim_tx_taproot_hash = SighashCache::new(&refund_tx)
                .taproot_key_spend_signature_hash(
                    0,
                    &Prevouts::All(&[&self.funding_utxo]),
                    SchnorrSighashType::Default,
                    self.genesis_hash,
                )?;

            let msg = claim_tx_taproot_hash.as_byte_array().clone();

            let mut key_agg_cache = self.swap_script.musig_keyagg_cache();

            let tweak = Scalar::from_be_bytes(
                self.swap_script
                    .taproot_spendinfo()?
                    .tap_tweak()
                    .as_byte_array()
                    .clone(),
            )
            .expect("TODO");

            let _ = key_agg_cache.pubkey_xonly_tweak_add(&tweak).expect("TODO");

            let session_id = musig::SessionSecretRand::from_rng(&mut rand::rng());

            let mut extra_rand = [0u8; 32];
            OsRng.fill_bytes(&mut extra_rand);

            let (sec_nonce, pub_nonce) = key_agg_cache.nonce_gen(
                session_id,
                convert_public_key(keys.public_key()),
                &msg,
                Some(extra_rand),
            );

            // Step 7: Get boltz's partial sig
            let refund_tx_hex = serialize(&refund_tx).to_lower_hex_string();
            let partial_sig_resp = match self.swap_script.swap_type {
                SwapType::Chain => {
                    boltz_api
                        .get_chain_partial_sig(&swap_id, 0, &pub_nonce, &refund_tx_hex)
                        .await
                }
                SwapType::Submarine => {
                    boltz_api
                        .get_submarine_partial_sig(&swap_id, 0, &pub_nonce, &refund_tx_hex)
                        .await
                }
                _ => Err(Error::Protocol(format!(
                    "Cannot get partial sig for {:?} Swap",
                    self.swap_script.swap_type
                ))),
            }?;

            let boltz_public_nonce =
                musig::PublicNonce::from_byte_array(&hex_to_bytes66(&partial_sig_resp.pub_nonce)?)
                    .expect("TODO");

            let boltz_partial_sig = musig::PartialSignature::from_byte_array(&hex_to_bytes32(
                &partial_sig_resp.partial_signature,
            )?)
            .expect("TODO");

            let agg_nonce = musig::AggregatedNonce::new(&[&boltz_public_nonce, &pub_nonce]);

            let musig_session = musig::Session::new(&key_agg_cache, agg_nonce, &msg);

            // Verify the sigs.
            let boltz_partial_sig_verify = musig_session.partial_verify(
                &key_agg_cache,
                &boltz_partial_sig,
                &boltz_public_nonce,
                convert_public_key(self.swap_script.receiver_pubkey.inner), //boltz key
            );

            if !boltz_partial_sig_verify {
                return Err(Error::Taproot(
                    "Unable to verify Partial Signature".to_string(),
                ));
            }

            let our_partial_sig =
                musig_session.partial_sign(sec_nonce, convert_keypair(keys), &key_agg_cache);

            let schnorr_sig = musig_session
                .partial_sig_agg(&[&boltz_partial_sig, &our_partial_sig])
                .assume_valid();

            let final_schnorr_sig = SchnorrSig {
                sig: convert_schnorr_signature(schnorr_sig),
                hash_ty: SchnorrSighashType::Default,
            };

            let output_key = self.swap_script.taproot_spendinfo()?.output_key();

            let msg = Message::from_digest_slice(&msg)?;
            secp.verify_schnorr(&final_schnorr_sig.sig, &msg, &output_key.into_inner())?;

            let mut script_witness = Witness::new();
            script_witness.push(final_schnorr_sig.to_vec());

            let witness = TxInWitness {
                amount_rangeproof: None,
                inflation_keys_rangeproof: None,
                script_witness: script_witness.to_vec(),
                pegin_witness: vec![],
            };

            refund_tx.input[0].witness = witness;
        }

        Ok(refund_tx)
    }

    fn create_refund(
        &self,
        keys: &Keypair,
        absolute_fees: u64,
        is_cooperative: bool,
    ) -> Result<Transaction, Error> {
        // Create unsigned refund transaction
        let refund_txin = TxIn {
            sequence: Sequence::MAX,
            previous_output: self.funding_outpoint,
            script_sig: Script::new(),
            witness: TxInWitness::default(),
            is_pegin: false,
            asset_issuance: AssetIssuance::default(),
        };

        let secp = Secp256k1::new();
        let mut rng = OsRng;

        let unblined_utxo = self
            .funding_utxo
            .unblind(&secp, self.swap_script.blinding_key.secret_key())?;
        let asset_id = unblined_utxo.asset;
        let out_abf = AssetBlindingFactor::new(&mut rng);
        let exp_asset = Asset::Explicit(asset_id);

        let (blinded_asset, asset_surjection_proof) =
            exp_asset.blind(&mut rng, &secp, out_abf, &[unblined_utxo])?;

        let output_value = Amount::from_sat(unblined_utxo.value) - Amount::from_sat(absolute_fees);

        let final_vbf = ValueBlindingFactor::last(
            &secp,
            output_value.to_sat(),
            out_abf,
            &[(
                unblined_utxo.value,
                unblined_utxo.asset_bf,
                unblined_utxo.value_bf,
            )],
            &[(
                absolute_fees,
                AssetBlindingFactor::zero(),
                ValueBlindingFactor::zero(),
            )],
        );
        let explicit_value = elements::confidential::Value::Explicit(output_value.to_sat());
        let msg = elements::RangeProofMessage {
            asset: asset_id,
            bf: out_abf,
        };
        let ephemeral_sk = SecretKey::new(&mut rng);

        // assuming we always use a blinded address that has an extractable blinding pub
        let blinding_key = self
            .output_address
            .blinding_pubkey
            .ok_or(Error::Protocol("No blinding key in tx.".to_string()))?;
        let (blinded_value, nonce, rangeproof) = explicit_value.blind(
            &secp,
            final_vbf,
            blinding_key,
            ephemeral_sk,
            &self.output_address.script_pubkey(),
            &msg,
        )?;

        let tx_out_witness = TxOutWitness {
            surjection_proof: Some(Box::new(asset_surjection_proof)), // from asset blinding
            rangeproof: Some(Box::new(rangeproof)),                   // from value blinding
        };
        let payment_output: TxOut = TxOut {
            script_pubkey: self.output_address.script_pubkey(),
            value: blinded_value,
            asset: blinded_asset,
            nonce,
            witness: tx_out_witness,
        };
        let fee_output: TxOut = TxOut::new_fee(absolute_fees, asset_id);

        let refund_script = self.swap_script.refund_script();

        let lock_time = match refund_script
            .instructions()
            .filter_map(|i| {
                let ins = i.ok()?;
                if let Instruction::PushBytes(bytes) = ins {
                    if bytes.len() < 5_usize {
                        Some(LockTime::from_consensus(bytes_to_u32_little_endian(bytes)))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .next()
        {
            Some(r) => r,
            None => {
                return Err(Error::Protocol(
                    "Error getting timelock from refund script".to_string(),
                ))
            }
        };

        let mut refund_tx = Transaction {
            version: 2,
            lock_time,
            input: vec![refund_txin],
            output: vec![fee_output, payment_output],
        };

        if is_cooperative {
            refund_tx.input[0].witness = Self::stubbed_cooperative_witness();
        } else {
            refund_tx.input[0].sequence = Sequence::ZERO;

            let leaf_hash = TapLeafHash::from_script(&refund_script, LeafVersion::default());

            let sighash = SighashCache::new(&refund_tx).taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&[&self.funding_utxo]),
                leaf_hash,
                SchnorrSighashType::Default,
                self.genesis_hash,
            )?;

            let msg = Message::from_digest_slice(sighash.as_byte_array())?;

            let sig = secp.sign_schnorr(&msg, keys);

            let final_sig = SchnorrSig {
                sig,
                hash_ty: SchnorrSighashType::Default,
            };

            let control_block = match self
                .swap_script
                .taproot_spendinfo()?
                .control_block(&(refund_script.clone(), LeafVersion::default()))
            {
                Some(r) => r,
                None => return Err(Error::Taproot("Could not create control block".to_string())),
            };

            let mut script_witness = Witness::new();
            script_witness.push(final_sig.to_vec());
            script_witness.push(refund_script.as_bytes());
            script_witness.push(control_block.serialize());

            let witness = TxInWitness {
                amount_rangeproof: None,
                inflation_keys_rangeproof: None,
                script_witness: script_witness.to_vec(),
                pegin_witness: vec![],
            };

            refund_tx.input[0].witness = witness;
        }

        Ok(refund_tx)
    }

    fn stubbed_cooperative_witness() -> TxInWitness {
        let mut witness = Witness::new();
        // Stub because we don't want to create cooperative signatures here
        // but still be able to have an accurate size estimation
        witness.push([0; 64]);

        TxInWitness {
            amount_rangeproof: None,
            inflation_keys_rangeproof: None,
            script_witness: witness.to_vec(),
            pegin_witness: vec![],
        }
    }

    /// Calculate the size of a transaction.
    /// Use this before calling drain to help calculate the absolute fees.
    /// Multiply the size by the fee_rate to get the absolute fees.
    pub fn size(
        &self,
        keys: &Keypair,
        is_cooperative: bool,
        is_discount_ct: bool,
    ) -> Result<usize, Error> {
        let dummy_abs_fee = 1;
        let tx = match self.kind {
            SwapTxKind::Claim => {
                let preimage = Preimage::from_vec([0; 32].to_vec())?;
                self.create_claim(keys, &preimage, dummy_abs_fee, is_cooperative)?
            }
            SwapTxKind::Refund => self.create_refund(keys, dummy_abs_fee, is_cooperative)?,
        };
        Ok(tx_size(&tx, is_discount_ct))
    }

    /// Broadcast transaction to the network
    pub async fn broadcast<LC: LiquidClient + ?Sized>(
        &self,
        signed_tx: &Transaction,
        liquid_client: &LC,
    ) -> Result<String, Error> {
        liquid_client.broadcast_tx(signed_tx).await
    }
}

fn convert_schnorr_signature(
    _schnorr_sig: secp256k1_musig::schnorr::Signature,
) -> bitcoin::secp256k1::schnorr::Signature {
    todo!()
}

fn convert_pubkeys_for_musig<'a>(
    _pubkeys: &'a [elements::secp256k1_zkp::PublicKey; 2],
) -> [&'a secp256k1_musig::PublicKey; 2] {
    todo!()
}

fn convert_xonly_key(_key: secp256k1_musig::XOnlyPublicKey) -> bitcoin::XOnlyPublicKey {
    todo!()
}

fn convert_public_key(_key: elements::secp256k1_zkp::PublicKey) -> secp256k1_musig::PublicKey {
    todo!()
}

fn hex_to_bytes32(hex: &str) -> Result<[u8; 32], Error> {
    let bytes = Vec::from_hex(hex)?;
    if bytes.len() != 32 {
        return Err(Error::Protocol(format!(
            "Expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes);
    Ok(result)
}

fn hex_to_bytes66(hex: &str) -> Result<[u8; 66], Error> {
    let bytes = Vec::from_hex(hex)?;
    if bytes.len() != 66 {
        return Err(Error::Protocol(format!(
            "Expected 66 bytes, got {}",
            bytes.len()
        )));
    }
    let mut result = [0u8; 66];
    result.copy_from_slice(&bytes);
    Ok(result)
}

impl SwapScriptCommon for LBtcSwapScript {
    fn swap_type(&self) -> SwapType {
        self.swap_type
    }

    /// Compute the Musig partial signature.
    /// This is used to cooperatively close a Submarine or Chain Swap.
    fn partial_sign(
        &self,
        keys: &Keypair,
        pub_nonce: &str,
        transaction_hash: &str,
    ) -> Result<(musig::PartialSignature, musig::PublicNonce), Error> {
        // Step 1: Start with a Musig KeyAgg Cache
        let pubkeys = [self.receiver_pubkey.inner, self.sender_pubkey.inner];
        let converted = convert_pubkeys_for_musig(&pubkeys);

        let mut key_agg_cache = musig::KeyAggCache::new(&converted);

        let tweak = Scalar::from_be_bytes(
            self.taproot_spendinfo()?
                .tap_tweak()
                .as_byte_array()
                .clone(),
        )
        .expect("TODO");

        let _ = key_agg_cache.pubkey_xonly_tweak_add(&tweak).expect("TODO");

        let session_id = musig::SessionSecretRand::from_rng(&mut rand::rng());

        let msg = hex_to_bytes32(transaction_hash)?;

        // Step 4: Start the Musig2 Signing session
        let mut extra_rand = [0u8; 32];
        OsRng.fill_bytes(&mut extra_rand);

        let (gen_sec_nonce, gen_pub_nonce) = key_agg_cache.nonce_gen(
            session_id,
            convert_public_key(keys.public_key()),
            &msg,
            Some(extra_rand),
        );

        let boltz_nonce =
            musig::PublicNonce::from_byte_array(&hex_to_bytes66(pub_nonce)?).expect("TODO");

        let agg_nonce = musig::AggregatedNonce::new(&[&boltz_nonce, &gen_pub_nonce]);

        let musig_session = musig::Session::new(&key_agg_cache, agg_nonce, &msg);

        let partial_sig =
            musig_session.partial_sign(gen_sec_nonce, convert_keypair(keys), &key_agg_cache);

        Ok((partial_sig, gen_pub_nonce))
    }
}

fn convert_keypair(_keys: &Keypair) -> &secp256k1_musig::Keypair {
    todo!()
}

fn tx_size(tx: &Transaction, is_discount_ct: bool) -> usize {
    match is_discount_ct {
        true => tx.discount_vsize(),
        false => tx.vsize(),
    }
}
