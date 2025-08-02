var electrum_username = 'user';
var electrum_password = '';
var electrum_alt_password = '';
var electrum_endpoint = 'http://127.0.0.1:7777';
var nostr_relays = [ "wss://nostrue.com" ];
var minimum_channel_capacity = 80_000;
var inbound_capacity_fee = 20; //if you set a fee of 1 and set 'absolute' below, you will charge 1 sat per channel regardless of its size; if you set a fee of 1 and set 'percent' below, you will charge 1% of the channel capacity instead
var inbound_capacity_fee_type = 'absolute'; //can be 'absolute' or change to 'percent'

// DO NOT MODIFY STUFF BELOW THIS LINE

//npm i noble-secp256k1 @cmdcode/tapscript ws base58check crypto bech32 bolt11

var crypto = require( 'crypto' );
globalThis.crypto = crypto;
var nobleSecp256k1 = require( 'noble-secp256k1' );
var tapscript = require( '@cmdcode/tapscript' );
var WebSocket = require( 'ws' ).WebSocket;
var base58 = require( 'base58check' );
var bech32 = require( 'bech32' );
var bolt11 = require( 'bolt11' );
var fs = require( 'fs' );

if ( fs.existsSync( "db.txt" ) ) {
    var dbtext = fs.readFileSync( "db.txt" ).toString();
    var db = JSON.parse( dbtext );
} else {
    var db = {
        nostr_privkey: null,
    };
    var texttowrite = JSON.stringify( db );
    fs.writeFileSync( "db.txt", texttowrite, function() {return;});
    var dbtext = fs.readFileSync( "db.txt" ).toString();
    var db = JSON.parse( dbtext );
}

var hedgehog = {
    state: {},
    keypairs: {},
    network: "regtest",
    backup_pubkey: "a".repeat( 64 ),
    hexToBytes: hex => Uint8Array.from( hex.match( /.{1,2}/g ).map( byte => parseInt( byte, 16 ) ) ),
    bytesToHex: bytes => bytes.reduce( ( str, byte ) => str + byte.toString( 16 ).padStart( 2, "0" ), "" ),
    getPrivkey: () => hedgehog.bytesToHex( nobleSecp256k1.utils.randomPrivateKey() ),
    getPubkey: privkey => nobleSecp256k1.getPublicKey( privkey, true ).substring( 2 ),
    getAddressData: ( scripts, index ) => {
        var tree = scripts.map( s => tapscript.Tap.encodeScript( s ) );
        var [ tpubkey, cblock ] = tapscript.Tap.getPubKey( hedgehog.backup_pubkey, { tree, target: tree[ index ] });
        var address = tapscript.Address.p2tr.fromPubKey( tpubkey, hedgehog.network );
        return [ address, tree, cblock ];
    },
    getChannelScripts: chan_id => {
        var state = hedgehog.state[ chan_id ];
        return [ [ state.alices_pub, "OP_CHECKSIGVERIFY", state.bobs_pub, "OP_CHECKSIG" ] ];
    },
    sha256: async s => {
        if ( typeof s == "string" ) s = new TextEncoder().encode( s );
        var arr = await crypto.subtle.digest( 'SHA-256', s );
        return hedgehog.bytesToHex( new Uint8Array( arr ) );
    },
    isValidAddress: address => {
        try {
            return !!tapscript.Address.decode( address ).script;
        } catch( e ) {return;}
        return;
    },
    getVin: ( txid, vout, amnt, addy, sequence = 0xffffffff - 2 ) => ({
        txid,
        vout,
        sequence,
        prevout: {
            value: amnt,
            scriptPubKey: hedgehog.isValidAddress( addy ) ? tapscript.Address.toScriptPubKey( addy ) : addy,
        },
    }),
    getVout: ( amnt, addy ) => ({
        value: amnt,
        scriptPubKey: hedgehog.isValidAddress( addy ) ? tapscript.Address.toScriptPubKey( addy ) : addy,
    }),
    getMidstateScripts: ( chan_id, am_sender, revocation_hash, uses_htlc, sender_is_funding_htlc, creating_counterparties_version ) => {
        var state = hedgehog.state[ chan_id ];
        var am_alice = !!state.alices_priv;

        //the midstate can be revoked by the recipient, so we need to find out
        //which user can do that and which revocation hash is required -- namely,
        //the one for which the recipient alone knows the preimage (until they
        //revoke it)
        if ( am_sender && am_alice ) {
            var senders_pub = state.alices_pub;
            var revhash = state.bobs_revocation_hashes[ state.bobs_revocation_hashes.length - 1 ];
        }
        if ( am_sender && !am_alice ) {
            var senders_pub = state.bobs_pub;
            var revhash = state.alices_revocation_hashes[ state.alices_revocation_hashes.length - 1 ];
        }
        if ( !am_sender && am_alice ) {
            var senders_pub = state.bobs_pub;
            var revhash = state.alices_revocation_hashes[ state.alices_revocation_hashes.length - 1 ];
        }
        if ( !am_sender && !am_alice ) {
            var senders_pub = state.alices_pub;
            var revhash = state.bobs_revocation_hashes[ state.bobs_revocation_hashes.length - 1 ];
        }

        //in some cases, the revocation hash is not *the latest* one, but is supplied by
        //the person spending the money, because they are spending a midstate that does
        //not represent the latest state -- e.g. this happens in a justice transaction
        if ( revocation_hash ) revhash = revocation_hash;

        //prepare and return the midstate scripts
        var midstate_scripts = [
            //the first branch allows for both parties to finalize the state
            //it also allows the recipient to conditionally revoke this state later
            [ state.alices_pub, "OP_CHECKSIGVERIFY", state.bobs_pub, "OP_CHECKSIG" ],
            //the second branch allows the sender to recover the funds if the recipient disappears after initiating a force closure -- this is called a disappearance transaction
            //TODO: change the 6 to 2026
            [ senders_pub, "OP_CHECKSIGVERIFY", 6, "OP_CHECKSEQUENCEVERIFY" ],
            //the third branch allows the recipient to absolutely revoke this state
            [ "OP_SIZE", 32, "OP_EQUALVERIFY", "OP_SHA256", revhash, "OP_EQUALVERIFY", senders_pub, "OP_CHECKSIG" ],
        ];

        //in some cases, tx1 and tx2 must be different for Alice and Bob, otherwise one
        //can broadcast a transaction that puts the money into a state the other one has
        //revoked. Thus we need to know who is broadcasting the tx that funds the midstate
        //and use that to modify it so that neither party has the sigs necessary for
        //forcing the other one's money into a state they revoked
        if ( uses_htlc ) {
            /*
                When Bob sends an htlc to Alice, he creates two txs:
                - one where he creates his own version and writes "bob_is_funding_this"
                - one where he creates alice's version and writes "alice_is_funding_this"
                
                When Alice receives an htlc from Bob, she creates two txs:
                - one where she creates her own version and writes "alice_is_funding_this"
                - one where she creates bob's version and writes "bob_is_funding_this"

                When Alice sends an htlc to Bob, she creates two txs:
                - one where she creates her own version and writes "alice_is_funding_this"
                - one where she creates bob's version and writes "bob_is_funding_this"

                When Bob receives an htlc from Alice, he creates two txs:
                - one where he creates his own version and writes "bob_is_funding_this"
                - one where he creates alice's version and writes "alice_is_funding_this"
            */
            if ( am_alice === creating_counterparties_version ) var extra_branch = [ "OP_RETURN", "bob_is_funding_this" ];
            else var extra_branch = [ "OP_RETURN", "alice_is_funding_this" ];
            midstate_scripts.push( extra_branch );
        }

        return midstate_scripts;
    },
    getInitialHTLCScripts: ( chan_id, sender_is_funder, am_sender, pmthash, htlc_locktime ) => {
        var state = hedgehog.state[ chan_id ];
        var am_alice = !!state.alices_priv;

        //the initial HTLC address can be swept by whichever party did *not* fund it after a long delay, so we need to find out which user can do that
        if ( sender_is_funder && am_sender && am_alice ) var sweepers_pub = state.bobs_pub;
        if ( sender_is_funder && !am_sender && am_alice ) var sweepers_pub = state.alices_pub;
        if ( sender_is_funder && am_sender && !am_alice ) var sweepers_pub = state.alices_pub;
        if ( sender_is_funder && !am_sender && !am_alice ) var sweepers_pub = state.bobs_pub;
        if ( !sender_is_funder && am_sender && am_alice ) var sweepers_pub = state.alices_pub;
        if ( !sender_is_funder && !am_sender && am_alice ) var sweepers_pub = state.bobs_pub;
        if ( !sender_is_funder && am_sender && !am_alice ) var sweepers_pub = state.bobs_pub;
        if ( !sender_is_funder && !am_sender && !am_alice ) var sweepers_pub = state.alices_pub;
        var counterpartys_pub = state.alices_pub;
        if ( sweepers_pub === state.alices_pub ) var counterpartys_pub = state.bobs_pub;

        //in the initial htlc, both paths require both parties to cosign, and one path – the “reveal path,” as opposed to the “recovery path” – also requires the recipient to reveal a preimage
        return [
            //the first branch is the "reveal path" and it allows both parties to
            //spend the money if they cosign and reveal a preimage
            [ "OP_SIZE", 32, "OP_EQUALVERIFY", "OP_SHA256", pmthash, "OP_EQUALVERIFY", state.alices_pub, "OP_CHECKSIGVERIFY", state.bobs_pub, "OP_CHECKSIG" ],
            //the second branch is the "recovery path" and it does not require a preimage
            //but is otherwise the same
            [ state.alices_pub, "OP_CHECKSIGVERIFY", state.bobs_pub, "OP_CHECKSIG" ],
            //the third branch allows whichever party did *not* fund the address to sweep it
            //after a long delay
            [ sweepers_pub, "OP_CHECKSIGVERIFY", htlc_locktime, "OP_CHECKSEQUENCEVERIFY" ],
        ];
    },
    getRevocableScripts: ( chan_id, sender_is_revoker, am_sender, revhash ) => {
        var state = hedgehog.state[ chan_id ];
        var am_alice = !!state.alices_priv;

        //the revocation address can be revoked by one party, so we need to find out
        //which user can do that
        if ( sender_is_revoker && am_sender && am_alice ) var revokers_pub = state.alices_pub;
        if ( sender_is_revoker && !am_sender && am_alice ) var revokers_pub = state.bobs_pub;
        if ( sender_is_revoker && am_sender && !am_alice ) var revokers_pub = state.bobs_pub;
        if ( sender_is_revoker && !am_sender && !am_alice ) var revokers_pub = state.alices_pub;
        if ( !sender_is_revoker && am_sender && am_alice ) var revokers_pub = state.bobs_pub;
        if ( !sender_is_revoker && !am_sender && am_alice ) var revokers_pub = state.alices_pub;
        if ( !sender_is_revoker && am_sender && !am_alice ) var revokers_pub = state.alices_pub;
        if ( !sender_is_revoker && !am_sender && !am_alice ) var revokers_pub = state.bobs_pub;
        var counterpartys_pub = state.alices_pub;
        if ( revokers_pub === state.alices_pub ) counterpartys_pub = state.bobs_pub;

        //in a revocable script, the soon-to-be revoker can recover the money after
        //a delay, or their counterparty can sweep the money if they learn the
        //revocation secret
        return [
            //the first branch allows the revoker to spend the money after a delay
            //TODO: change the 6 to 2016
            [ revokers_pub, "OP_CHECKSIGVERIFY", 6, "OP_CHECKSEQUENCEVERIFY" ],
            //the second branch allows the counterparty to sweep the money if they
            //learn the revocation secret
            [ "OP_SHA256", revhash, "OP_EQUALVERIFY", counterpartys_pub, "OP_CHECKSIGVERIFY" ],
        ];
    },
    getTx1: ( chan_id, am_sender, htlc_addy_and_amnt, midstate_scripts_override ) => {
        //tx1 is used during a force closure
        //it takes money from the channel and puts it in the midstate
        //prepare variables necessary for creating tx1
        var state = hedgehog.state[ chan_id ];
        var channel_scripts = hedgehog.getChannelScripts( chan_id );
        var channel = hedgehog.getAddressData( channel_scripts, 0 )[ 0 ];
        var uses_htlc = !!htlc_addy_and_amnt;
        var sender_is_funding_htlc = htlc_addy_and_amnt ? htlc_addy_and_amnt[ 2 ] : null;
        var revhash = htlc_addy_and_amnt ? htlc_addy_and_amnt[ 3 ] : null;
        var creating_counterparties_version = false;
        if ( htlc_addy_and_amnt && htlc_addy_and_amnt.length > 4 && htlc_addy_and_amnt[ 4 ] ) {
            creating_counterparties_version = htlc_addy_and_amnt[ 4 ];
        }
        var midstate_scripts = hedgehog.getMidstateScripts( chan_id, am_sender, revhash, uses_htlc, sender_is_funding_htlc, creating_counterparties_version );
        if ( midstate_scripts_override ) midstate_scripts = midstate_scripts_override;
        var midstate = hedgehog.getAddressData( midstate_scripts, 0 )[ 0 ];

        //prepare the vouts
        var vout = [
            hedgehog.getVout( state.funding_txinfo[ 2 ] - 240, midstate ),
            hedgehog.getVout( 240, "51024e73" ),
        ];

        //if the payment involves an htlc, modify the vouts
        if ( htlc_addy_and_amnt ) {
            var [ htlc_address, htlc_amnt ] = htlc_addy_and_amnt;
            vout.push( hedgehog.getVout( htlc_amnt, htlc_address ) );
            vout[ 0 ] = hedgehog.getVout( state.funding_txinfo[ 2 ] - 240 - htlc_amnt, midstate );
        }

        //prepare and return tx1
        return tapscript.Tx.create({
            version: 3,
            vin: [
                hedgehog.getVin( state.funding_txinfo[ 0 ], state.funding_txinfo[ 1 ], state.funding_txinfo[ 2 ], channel ),
            ],
            vout,
        });
    },
    getTx2: ( chan_id, am_sender, tx1_txid, midstate, recipients_new_balance, sum_of_senders_htlcs = 0, am_alice_for_tx2 ) => {
        //tx2 is used during a force closure
        //it takes money from the midstate and creates the latest state
        //prepare variables necessary for creating tx2
        var state = hedgehog.state[ chan_id ];
        var am_alice = am_alice_for_tx2;
        if ( am_sender && am_alice ) var recipients_pub = state.bobs_pub;
        if ( am_sender && !am_alice ) var recipients_pub = state.alices_pub;
        if ( !am_sender && am_alice ) var recipients_pub = state.alices_pub;
        if ( !am_sender && !am_alice ) var recipients_pub = state.bobs_pub;
        if ( recipients_pub === state.alices_pub ) var senders_pub = state.bobs_pub;
        else var senders_pub = state.alices_pub;
        var sender_is_alice = ( am_sender && am_alice ) || ( !am_sender && !am_alice );

        //figure out what amount each user should get in this transaction
        if ( !state.channel_states.length ) var total_in_channel = recipients_new_balance;
        else var total_in_channel = state.channel_states[ 0 ].amnt;
        var alices_amnt = total_in_channel - recipients_new_balance;
        var bobs_amnt = recipients_new_balance;
        if ( recipients_pub === state.alices_pub ) {
            var alices_amnt = recipients_new_balance;
            var bobs_amnt = total_in_channel - recipients_new_balance;
        }

        //account for the loss of 480 sats due to anchor outputs
        //note that 240 is the dust limit for v3 "anchor outputs"
        if ( sender_is_alice ) alices_amnt = alices_amnt - 240 - 240 - sum_of_senders_htlcs;
        else bobs_amnt = bobs_amnt - 240 - 240 - sum_of_senders_htlcs;

        //prepare and return tx2
        var tx = tapscript.Tx.create({
            version: 3,
            vin: [
                hedgehog.getVin( tx1_txid, 0, state.funding_txinfo[ 2 ] - 240 - sum_of_senders_htlcs, midstate, 3 ),
            ],
            vout: [
                hedgehog.getVout( 240, "51024e73" ),
            ],
        });
        //note that 330 sats is the dust limit for taproot addresses other than anchor outputs
        if ( alices_amnt > 330 ) tx.vout.push( hedgehog.getVout( alices_amnt, [ 1, state.alices_pub ] ) );
        if ( bobs_amnt > 330 ) tx.vout.push( hedgehog.getVout( bobs_amnt, [ 1, state.bobs_pub ] ) );
        return tx;
    },
    getConditionalRevocationTx: ( prev_tx1_txid, prev_tx1, tx2 ) => {
        return tapscript.Tx.create({
            version: 3,
            vin: [{
                txid: prev_tx1_txid,
                vout: 0,
                prevout: prev_tx1.vout[ 0 ],
            }],
            vout: tx2.vout,
        });
    },
    getTxData: ( chan_id, am_alice, am_sender, amnt, sender, htlc_addy_and_amnt, use_custom_midstate_revhash, midstate_scripts_override, pending_htlcs = [], do_not_delete ) => {
        //prepare variables necessary for returning the required txdata
        var state = hedgehog.state[ chan_id ];
        var uses_htlc = !!htlc_addy_and_amnt;
        var sender_is_funding_htlc;
        var midstate_revhash = null;
        var sender_of_htlc = null;
        if ( htlc_addy_and_amnt ) {
            sender_is_funding_htlc = htlc_addy_and_amnt[ 2 ];
            if ( use_custom_midstate_revhash ) midstate_revhash = htlc_addy_and_amnt[ 3 ];
            if ( htlc_addy_and_amnt.length > 5 && htlc_addy_and_amnt[ 5 ] ) sender_of_htlc = htlc_addy_and_amnt[ 5 ];
        }

        //find out if the sender of *this* tx also sent the *previous* tx
        var sender_previously_sent = false;
        if ( state.channel_states.length ) sender_previously_sent = state.channel_states[ state.channel_states.length - 1 ].from === sender;

        //if the sender *did* send the previous tx you must remove whatever revocation
        //preimage and hash they created after sending that tx, because you are replacing
        //that state with a new one that sends the recipient more money, and that new
        //state will use a different revocation preimage and hash
        if ( sender_previously_sent && !do_not_delete ) {
            if ( am_sender ) {
                if ( am_alice ) {
                    state.alices_revocation_preimages.pop();
                    state.alices_revocation_hashes.pop();
                } else {
                    state.bobs_revocation_preimages.pop();
                    state.bobs_revocation_hashes.pop();
                }
            } else {
                if ( am_alice ) {
                    state.bobs_revocation_preimages.pop();
                    state.bobs_revocation_hashes.pop();
                } else {
                    state.alices_revocation_preimages.pop();
                    state.alices_revocation_hashes.pop();
                }
            }
        }

        //prepare tx1 and the variables needed for broadcasting it
        var tx1 = hedgehog.getTx1( chan_id, am_sender, htlc_addy_and_amnt, midstate_scripts_override );
        var tx1_txid = tapscript.Tx.util.getTxid( tx1 );
        var channel_scripts = hedgehog.getChannelScripts( chan_id );
        var [ _, channel_tree, channel_cblock ] = hedgehog.getAddressData( channel_scripts, 0 );

        //prepare the variables needed for creating and broadcasting tx2
        var midstate_scripts = hedgehog.getMidstateScripts( chan_id, am_sender, midstate_revhash, uses_htlc, sender_is_funding_htlc );
        if ( midstate_scripts_override ) midstate_scripts = midstate_scripts_override;
        var absolute_revocation_hash = midstate_scripts[ 2 ][ 4 ];
        var [ midstate, midstate_tree, midstate_cblock ] = hedgehog.getAddressData( midstate_scripts, 0 );

        //find out how much money the sender and recipient are supposed to get via tx2
        if ( !state.channel_states.length ) var balances = [ 0, 0 ];
        else var balances = hedgehog.getBalances( chan_id );
        if ( am_sender ) {
            var recipients_old_balance = am_alice ? balances[ 1 ] : balances[ 0 ];
        } else {
            var recipients_old_balance = am_alice ? balances[ 0 ] : balances[ 1 ];
        }
        var recipients_new_balance = recipients_old_balance + amnt;
        if ( !state.channel_states.length ) recipients_new_balance = recipients_new_balance - 240 - 240;

        //if the user was the last to send, modify recipients_new_balance so that it is
        //the previous amount sent plus the new amount -- unless the last transaction
        //sent money via an htlc, because then the previous amount sent was really 0
        if ( sender_previously_sent ) {
            var prev_state = state.channel_states[ state.channel_states.length - 1 ];
            var prev_update_added_htlc = prev_state.added_htlc;
            if ( !prev_update_added_htlc ) {
                var amnt_recipient_had = prev_state.amnt + 240 + 240 - prev_state.amnt_sent;
                var amnt_sent_previously = prev_state.amnt_sent;
                if ( am_sender ) amnt = amnt_sent_previously + amnt;
                var recipients_new_balance = amnt_recipient_had + amnt - 240 - 240;
            }
        }

        //in an htlc is used, the recipient's balance should not change
        if ( uses_htlc ) recipients_new_balance = recipients_old_balance;

        //prepare tx2
        var sum_of_senders_htlcs = 0;
        var latest_state = state.channel_states[ state.channel_states.length - 1 ];
        //TODO: instead of getting *all* pending htlcs, just get the ones relevant
        //to the current transaction -- e.g. if you are creating a justice tx for
        //a state many states ago, some pending htlcs may have been created *after*
        //that state and thus should be ignored when creating the justice transaction
        //perhaps I should pass the relevant htlcs to this function as a parameter
        pending_htlcs.forEach( htlc => {
            if ( ( am_alice && htlc.sender === "alice" ) || ( !am_alice && htlc.sender === "bob" ) ) sum_of_senders_htlcs = sum_of_senders_htlcs + htlc.amnt;
        });
        if ( htlc_addy_and_amnt ) {
            if ( ( am_alice && sender_of_htlc === "alice" ) || ( !am_alice && sender_of_htlc === "bob" ) ) sum_of_senders_htlcs = htlc_addy_and_amnt[ 1 ];
        }
        var tx2 = hedgehog.getTx2( chan_id, am_sender, tx1_txid, midstate, recipients_new_balance, sum_of_senders_htlcs, am_alice );

        //if the sender received money at any point, they must revoke the most recent tx by
        //which they received money, so we prepare that tx if necessary so they can sign it
        var conditional_revocation_needed = hedgehog.conditionalRevocationNeeded( chan_id, am_sender );
        if ( conditional_revocation_needed ) {
            var prev_tx1 = tapscript.Tx.decode( conditional_revocation_needed );
            var prev_tx1_txid = tapscript.Tx.util.getTxid( prev_tx1 );
            var conditional_revocation_tx = hedgehog.getConditionalRevocationTx( prev_tx1_txid, prev_tx1, tx2 );
        }

        //return all the variables and txs needed for creating the new state
        var txs = [ recipients_new_balance, channel_tree, channel_cblock, midstate_tree, midstate_cblock, amnt, conditional_revocation_needed, absolute_revocation_hash, tx1, tx2 ];
        if ( conditional_revocation_needed ) txs.push( conditional_revocation_tx, prev_tx1 );
        return txs;
    },
    getBalances: chan_id => {
        var state = hedgehog.state[ chan_id ];
        var total_in_channel = state.channel_states[ 0 ].amnt;
        //find the last state that didn't send an htlc -- note that
        //when htlcs are sent, neither party's balance should change
        //because the payment is pending until the htlc resolves, at
        //which point, *that* is when their balances should change
        var findPrevState = ( possible_last_state ) => {
            var prev_state = state.channel_states[ state.channel_states.length - possible_last_state ];
            var htlc_was_added = prev_state.added_htlc;
            if ( !htlc_was_added ) return prev_state;
            possible_last_state = possible_last_state + 1;
            return findPrevState( possible_last_state );
        }
        var prev_state = findPrevState( 1 );
        var last_sender = prev_state.from;
        var last_senders_amount = total_in_channel - prev_state.amnt;
        var htlc_was_added = prev_state.added_htlc;
        var balances = [ last_senders_amount, prev_state.amnt + 240 + 240 ];
        if ( last_sender !== "alice" ) balances = [ prev_state.amnt + 240 + 240, last_senders_amount ];
        return balances;
    },
    conditionalRevocationNeeded: ( chan_id, am_sender ) => {
        //prepare variables necessary for finding out if a conditional revocation is necessary
        var tx_to_be_revoked = null;
        var state = hedgehog.state[ chan_id ];
        var am_alice = !!state.alices_priv;

        //we start by assuming we are the sender, though we will change that assumption momentarily if needed. if we are the sender, we must revoke the last state where we received money. the creator of that state was our counterparty, who sent us money in that state. so if we are alice, we must seek the last state created by bob, i.e. where bob was the sender. if, however, we are not the sender, then we seek to ensure the sender revoked the last state where *they* received money, which is a state where *we* were the sender; so, if we are alice and we are *not* the sender of *this* transaction, we seek the last state where the sender was *alice,* i.e. ourselves, because that is the state where we last sent money, and that is the state we must ensure our counterparty revoked.
        if ( am_alice && am_sender ) var sender = "bob";
        if ( !am_alice && am_sender ) var sender = "alice";
        if ( am_alice && !am_sender ) var sender = "alice";
        if ( !am_alice && !am_sender ) var sender = "bob";

        //return the most recent state where the recipient received money, if any
        //I parse a strinigified version of the object to create a deep clone
        //so that the original is unmodified by my reversing of it
        var reversed = JSON.parse( JSON.stringify( state.channel_states ) );
        reversed = reversed.reverse();
        reversed.every( ( item, index ) => {
            if ( item.from === sender ) {
                tx_to_be_revoked = item[ "tx1" ];
                return;
            }
            return true;
        });
        return tx_to_be_revoked;
    },
    absoluteRevocationNeeded: ( chan_id, am_sender ) => {
        var state = hedgehog.state[ chan_id ];
        var am_alice = !!state.alices_priv;
        //this function is used twice: when sending and when receiving i.e. validating
        //when sending, you revoke the state two transactions ago, because the most *recent*
        //state is one you're *allowed to* broadcast per the hedgehog protocol, and the
        //*current* state is also allowed. But you're not allowed to broadcast and states
        //before then. So, every time you make a new transaction, you get the revocation preimage
        //from two transactions ago and reveal it to your recipient so that you can no longer
        //broadcast that old state.
        //As the recipient, you check the validity of the revocation preimage by grabing your
        //counterparty's revocation hash from two transactions ago and ensuring that the
        //preimage they revealed to you hashes to that hash. Which is why this function
        //returns the revoation hash from two transactions ago if you are the recipient.
        if ( am_alice && am_sender ) return state.alices_revocation_preimages[ state.alices_revocation_preimages.length - 2 ];
        if ( !am_alice && am_sender ) return state.bobs_revocation_preimages[ state.bobs_revocation_preimages.length - 2 ];
        if ( am_alice && !am_sender ) return state.bobs_revocation_hashes[ state.bobs_revocation_hashes.length - 2 ];
        if ( !am_alice && !am_sender ) return state.alices_revocation_hashes[ state.alices_revocation_hashes.length - 2 ];
    },
    conditionallyRevokeChannelStates: async ( chan_id, prev_tx1, sig, vout ) => {
        var state = hedgehog.state[ chan_id ];
        var real_txid = tapscript.Tx.util.getTxid( prev_tx1 );
        state.channel_states.forEach( item => {
            var expected_txid = tapscript.Tx.util.getTxid( item.tx1 );
            if ( expected_txid !== real_txid ) return;
            item[ "conditional_revocation_sig" ] = sig;
            item[ "conditional_revocation_vout" ] = vout;
        });
    },
    fullyRevokeChannelStates: async ( chan_id, preimage ) => {
        var state = hedgehog.state[ chan_id ];
        var real_hash = await hedgehog.sha256( hedgehog.hexToBytes( preimage ) );
        state.channel_states.forEach( item => {
            var expected_hash = item.absolute_revocation_hash;
            if ( expected_hash !== real_hash ) return;
            item[ "absolute_revocation_preimage" ] = preimage;
        });
    },
    prepChannel: bobs_pubkey_and_hash => {
        //make a channel id
        var chan_id = "a_" + hedgehog.getPrivkey().substring( 0, 32 );

        //initialize the channel state
        hedgehog.state[ chan_id ] = {
            alices_priv: null,
            bobs_priv: null,
            alices_pub: null,
            bobs_pub: null,
            alices_revocation_preimages: [],
            alices_revocation_hashes: [],
            bobs_revocation_preimages: [],
            bobs_revocation_hashes: [],
            funding_txinfo: [],
            channel_states: [],
            data_for_preparing_htlcs: {},
        }
        var state = hedgehog.state[ chan_id ];

        //prepare alice's privkey and pubkey
        if ( !state.alices_priv ) state.alices_priv = hedgehog.getPrivkey();
        state.alices_pub = hedgehog.getPubkey( state.alices_priv );

        //store bob's pubkey and hash
        state.bobs_pub = bobs_pubkey_and_hash[ 0 ];
        state.bobs_revocation_hashes.push( bobs_pubkey_and_hash[ 1 ] );
        return chan_id;
    },
    openChannel: async ( bobs_pubkey_and_hash, txdata, data_from_alice, chan_id ) => {
        //if we pass in an existing chan_id then we skip the first few steps
        //because only alice does that and she only does it if she already
        //did the first few steps using the prepChannel() method
        if ( !chan_id ) {
            //alice always opens a channel to bob and pushes all funds to his side
            //bob always opens a channel by receiving data from alice and validating it
            //consequently the first thing bob must do is change the chan_id to a version
            //he can use, distinguished by having the first character be a_ if the channel
            //data is stored by alice and b_ if the channel data is stored by bob
            //and therefore the first thing we do is detect whether we are alice or bob
            //by checking if the object data_from_alice exists -- if so, we must be bob
            //so we change the chan_id so that it doesn't start with a_ but b_
            if ( data_from_alice ) var chan_id = "b_" + data_from_alice.chan_id.substring( 2 );
            else var chan_id = "a_" + hedgehog.getPrivkey().substring( 0, 32 );

            //initialize the channel state
            hedgehog.state[ chan_id ] = {
                alices_priv: null,
                bobs_priv: null,
                alices_pub: null,
                bobs_pub: null,
                alices_revocation_preimages: [],
                alices_revocation_hashes: [],
                bobs_revocation_preimages: [],
                bobs_revocation_hashes: [],
                funding_txinfo: [],
                channel_states: [],
                data_for_preparing_htlcs: {},
            }
            var state = hedgehog.state[ chan_id ];
        } else {
            var state = hedgehog.state[ chan_id ];
            if ( !bobs_pubkey_and_hash ) bobs_pubkey_and_hash = [ state.bobs_pub, state.bobs_revocation_hashes[ 0 ] ];
            state.bobs_revocation_hashes.pop();
        }

        //if we are alice, the array bobs_pubkey_and_hash will exist, because alice
        //needs that info in order to open a channel to bob
        if ( bobs_pubkey_and_hash ) {
            //prepare alice's privkey and pubkey
            if ( !state.alices_priv ) state.alices_priv = hedgehog.getPrivkey();
            state.alices_pub = hedgehog.getPubkey( state.alices_priv );

            //store bob's pubkey and hash
            state.bobs_pub = bobs_pubkey_and_hash[ 0 ];
            state.bobs_revocation_hashes.push( bobs_pubkey_and_hash[ 1 ] );

            //prepare the channel address
            var channel_scripts = hedgehog.getChannelScripts( chan_id );
            var channel = hedgehog.getAddressData( channel_scripts, 0 )[ 0 ];

            //fund the channel
            console.log( 'send money to this address:' );
            console.log( channel );
            if ( txdata ) var [ txid, vout, amnt ] = txdata;
            else {
                var txid = prompt( `send money into the address in your console and enter the txid` );
                var vout = Number( prompt( `and the vout` ) );
                var amnt = Number( prompt( `and the amount` ) );
            }
            state.funding_txinfo = [ txid, vout, amnt ];

            //send bob the data he needs to validate this channel
            var data_for_bob = await hedgehog.send( chan_id, amnt );
            data_for_bob[ "funding_txinfo" ] = state.funding_txinfo;
            data_for_bob[ "alices_pub" ] = state.alices_pub;
            data_for_bob[ "bobs_pub" ] = state.bobs_pub;
            return data_for_bob;
        }

        //if we are bob, the data_from_alice object will exist
        if ( data_from_alice ) {
            //bob's private key was generated previously and stored in an object called keypairs
            //so we get the private key and Bob's preimage from there and store them in state,
            //ready for future use
            var my_pub = data_from_alice.bobs_pub;
            state.bobs_priv = hedgehog.keypairs[ my_pub ][ "privkey" ];
            state.bobs_pub = my_pub;
            state.bobs_revocation_preimages.push( hedgehog.keypairs[ my_pub ][ "preimage" ] );
            var hash = await hedgehog.sha256( hedgehog.hexToBytes( state.bobs_revocation_preimages[ 0 ] ) );
            state.bobs_revocation_hashes.push( hash );
            delete hedgehog.keypairs[ my_pub ];

            //we also store alice's pubkey and the funding info
            state.alices_pub = data_from_alice.alices_pub;
            state.funding_txinfo = data_from_alice.funding_txinfo;

            //validate the channel opening data
            var initial_state_is_valid = await hedgehog.receive( data_from_alice );
            return initial_state_is_valid;
        }
    },
    send: async ( chan_id, amnt, overwrite_pending_htlcs ) => {
        //prepare the variables you need to send money
        var state = hedgehog.state[ chan_id ];
        var am_sender = true;
        var am_alice = !!state.alices_priv;
        var privkey = am_alice ? state.alices_priv : state.bobs_priv;
        var sender = am_alice ? "alice" : "bob";

        //get the transaction data
        var pending_htlcs = [];
        var latest_state = state.channel_states[ state.channel_states.length - 1 ];
        if ( latest_state && latest_state.hasOwnProperty( "pending_htlcs" ) ) pending_htlcs = latest_state.pending_htlcs;
        if ( overwrite_pending_htlcs ) pending_htlcs = overwrite_pending_htlcs;
        var txs = hedgehog.getTxData( chan_id, am_alice, am_sender, amnt, sender, null, null, null, pending_htlcs );
        var [ recipients_new_balance, channel_tree, channel_cblock, midstate_tree, midstate_cblock, amnt, conditional_revocation_needed, absolute_revocation_hash, tx1, tx2 ] = txs;
        //getTxData always returns 10 items. It also returns two additional items if a conditional revocation was needed on a prior state, so in that cirucmstance we also grab those two additional items so that we can sign them
        if ( txs.length > 10 ) {
            var conditional_revocation_tx = txs[ 10 ];
            var prev_tx1 = txs[ 11 ];
        }

        //sign everything and, if necessary, prepare to revoke previous states
        var to_midstate_sig = tapscript.Signer.taproot.sign( privkey, tx1, 0, {extension: channel_tree[ 0 ] }).hex;
        var finalizer_sig = tapscript.Signer.taproot.sign( privkey, tx2, 0, {extension: midstate_tree[ 0 ] }).hex;
        if ( conditional_revocation_needed ) var conditional_revocation_sig = tapscript.Signer.taproot.sign( privkey, conditional_revocation_tx, 0, {extension: channel_tree[ 0 ] }).hex;
        var absolute_revocation_needed = hedgehog.absoluteRevocationNeeded( chan_id, am_sender );

        //update your state
        var ch_state = {
            from: sender,
            amnt: recipients_new_balance,
            amnt_sent: amnt,
            tx1: tapscript.Tx.encode( tx1 ).hex,
            absolute_revocation_hash,
            added_htlc: false,
            pending_htlcs,
            absolute_revocation_preimage: null,
            conditional_revocation_sig: null,
            conditional_revocation_vout: null,
        }
        state.channel_states.push( ch_state );

        //generate the hash you want your counterparty to use when they next send you money
        var revocation_preimage = hedgehog.getPrivkey();
        var revocation_hash = await hedgehog.sha256( hedgehog.hexToBytes( revocation_preimage ) );
        if ( am_alice ) {
            state.alices_revocation_preimages.push( revocation_preimage );
            state.alices_revocation_hashes.push( revocation_hash );
        } else {
            state.bobs_revocation_preimages.push( revocation_preimage );
            state.bobs_revocation_hashes.push( revocation_hash );
        }
        // console.log( 'tx1:' );
        // console.log( tx1 );
        // console.log( tapscript.Tx.util.getTxid( tx1 ) );
        // console.log( 'tx2:' );
        // console.log( tx2 );
        // console.log( tapscript.Tx.util.getTxid( tx2 ) );

        //send your counterparty the data they need to validate the new state
        var obj = {
            to_midstate_sig,
            finalizer_sig,
            amnt,
            chan_id,
            revocation_hash,
        }
        if ( conditional_revocation_needed ) obj[ "conditional_revocation_sig" ] = conditional_revocation_sig;
        if ( absolute_revocation_needed ) obj[ "absolute_revocation_preimage" ] = absolute_revocation_needed;
        return obj;
    },
    receive: async ( data_from_sender, overwrite_pending_htlcs ) => {
        //prepare the variables necessary for validating the new state
        var chan_id = data_from_sender.chan_id;
        if ( chan_id.startsWith( "a_" ) ) chan_id = "b_" + chan_id.substring( 2 );
        else chan_id = "a_" + chan_id.substring( 2 );
        var state = hedgehog.state[ chan_id ];
        var am_alice = !!state.alices_priv;
        var am_sender = false;
        var sender = am_alice ? "bob" : "alice";
        var amnt = data_from_sender.amnt;

        //do not allow the sender to reuse a revocation hash
        var revocation_hash = data_from_sender.revocation_hash;
        var counterpartys_revhashes = state.alices_revocation_hashes;
        if ( am_alice ) counterpartys_revhashes = state.bobs_revocation_hashes;
        if ( counterpartys_revhashes.includes( revocation_hash ) ) return;

        //get the transaction data
        var pending_htlcs = [];
        var latest_state = state.channel_states[ state.channel_states.length - 1 ];
        if ( latest_state && latest_state.hasOwnProperty( "pending_htlcs" ) ) pending_htlcs = latest_state.pending_htlcs;
        if ( overwrite_pending_htlcs ) pending_htlcs = overwrite_pending_htlcs;
        var txs = hedgehog.getTxData( chan_id, am_alice, am_sender, amnt, sender, null, null, null, pending_htlcs );
        var [ recipients_new_balance, channel_tree, channel_cblock, midstate_tree, midstate_cblock, amnt, conditional_revocation_needed, absolute_revocation_hash, tx1, tx2 ] = txs;
        //getTxData always returns 10 items. It also returns two additional items if a conditional revocation was needed on a prior state, so in that cirucmstance we also grab those two additional items so that we can validate the signatures involving them
        if ( txs.length > 10 ) {
            var conditional_revocation_tx = txs[ 10 ];
            var prev_tx1 = txs[ 11 ];
        }

        //validate the signatures
        var to_midstate_sig = data_from_sender.to_midstate_sig;
        var to_midstate_sighash = tapscript.Signer.taproot.hash( tx1, 0, {extension: channel_tree[ 0 ] }).hex;
        if ( am_alice ) var senders_pub = state.bobs_pub;
        else var senders_pub = state.alices_pub;
        var to_midstate_sig_is_valid = await nobleSecp256k1.schnorr.verify( to_midstate_sig, to_midstate_sighash, senders_pub );
        var finalizer_sig = data_from_sender.finalizer_sig;
        var finalizer_sighash = tapscript.Signer.taproot.hash( tx2, 0, {extension: midstate_tree[ 0 ] }).hex;
        var finalizer_sig_is_valid = await nobleSecp256k1.schnorr.verify( finalizer_sig, finalizer_sighash, senders_pub );

        //if necessary, validate the revocation data for prior states
        if ( conditional_revocation_needed ) {
            var conditional_revocation_sig = data_from_sender.conditional_revocation_sig;
            var conditional_revocation_sighash = tapscript.Signer.taproot.hash( conditional_revocation_tx, 0, {extension: channel_tree[ 0 ] }).hex;
            var conditional_revocation_sig_is_valid = await nobleSecp256k1.schnorr.verify( conditional_revocation_sig, conditional_revocation_sighash, senders_pub );
        }
        var absolute_revocation_needed = hedgehog.absoluteRevocationNeeded( chan_id, am_sender );
        if ( absolute_revocation_needed ) {
            var absolute_revocation_preimage = data_from_sender.absolute_revocation_preimage;
            var hash = await hedgehog.sha256( hedgehog.hexToBytes( absolute_revocation_preimage ) );
            if ( hash !== absolute_revocation_needed ) return;
        }
        // console.log( 'tx1:' );
        // console.log( tx1 );
        // console.log( tapscript.Tx.util.getTxid( tx1 ) );
        // console.log( 'tx2:' );
        // console.log( tx2 );
        // console.log( tapscript.Tx.util.getTxid( tx2 ) );
        // console.log( 'to_midstate_sig_is_valid, right?', to_midstate_sig_is_valid );
        // console.log( 'finalizer_sig_is_valid, right?', finalizer_sig_is_valid );
        if ( !to_midstate_sig_is_valid || !finalizer_sig_is_valid ) return;
        if ( conditional_revocation_needed && !conditional_revocation_sig_is_valid ) return;

        //store the revocation data given by your counterparty for future use
        if ( am_alice ) state.bobs_revocation_hashes.push( revocation_hash );
        else state.alices_revocation_hashes.push( revocation_hash );
        if ( conditional_revocation_needed ) await hedgehog.conditionallyRevokeChannelStates( chan_id, prev_tx1, conditional_revocation_sig, conditional_revocation_tx.vout );
        if ( absolute_revocation_needed ) await hedgehog.fullyRevokeChannelStates( chan_id, absolute_revocation_preimage );

        //update your state
        var ch_state = {
            from: sender,
            amnt: recipients_new_balance,
            amnt_sent: amnt,
            to_midstate_sig,
            finalizer_sig,
            tx1: tapscript.Tx.encode( tx1 ).hex,
            absolute_revocation_hash,
            added_htlc: false,
            pending_htlcs,
            //it seems unnecessary for the recipient to reserve a
            //place for tracking whether or not they themselves
            //revoked a state because they will simply never
            //broadcast an old state, so they have no use for the
            //proof-of-revocation
            // absolute_revocation_preimage: null,
            // conditional_revocation_sig: null,
            // conditional_revocation_vout: null,
        }
        state.channel_states.push( ch_state );
        return true;
    },
    prepareHtlcPartOne: async ( chan_id, amnt, pmthash, am_sender, recipients_revhashes, s_recovery_p2_revhash, s_midstate_revhash, htlc_locktime ) => {
        //the minimum htlc amount is 330, because that is the
        //dust limit for taproot addresses, but in our case
        //it is even lower: 330 + 240 -- because we use anchor
        //outputs and thus we always need at least 570 sats as
        //a minimum for each htlc
        if ( amnt < 570 ) return console.log( "error: htlc limit too low" );

        //get requisite data from the recipient
        if ( !recipients_revhashes ) recipients_revhashes = prompt( 'enter two revhashes created by the recipient' );
        var data_for_doing_part_three = await hedgehog.prepareHtlcPartTwo( chan_id, amnt, pmthash, am_sender, recipients_revhashes, s_recovery_p2_revhash, s_midstate_revhash, htlc_locktime );
        return data_for_doing_part_three;
    },
    prepareHtlcPartTwo: async ( chan_id, amnt, pmthash, am_sender, recipients_revhashes, s_recovery_p2_revhash, s_midstate_revhash, htlc_locktime ) => {
        //prepare the variables you need to send money via an HTLC
        var state = hedgehog.state[ chan_id ];
        var am_alice = !!state.alices_priv;
        console.log( 'i am alice, right?', am_alice );
        var privkey = am_alice ? state.alices_priv : state.bobs_priv;
        var pmt_preimage = null;
        if ( !pmthash ) pmt_preimage = hedgehog.getPrivkey();
        if ( pmt_preimage ) pmthash = await hedgehog.sha256( hedgehog.hexToBytes( pmt_preimage ) );
        //TODO: ensure the following hashes are valid
        var r_midstate_revhash = recipients_revhashes[ 0 ];
        var r_reveal_p2_revhash = recipients_revhashes[ 1 ];

        //get the two versions of the initial HTLC
        var sender_is_funder = true;
        var senders_inital_htlc_scripts = hedgehog.getInitialHTLCScripts( chan_id, sender_is_funder, am_sender, pmthash, htlc_locktime );
        var [ senders_initial_htlc_addy, senders_initial_htlc_tree, senders_initial_htlc_cblock ] = hedgehog.getAddressData( senders_inital_htlc_scripts, 1 );
        sender_is_funder = false;
        var recipients_inital_htlc_scripts = hedgehog.getInitialHTLCScripts( chan_id, sender_is_funder, !am_sender, pmthash, htlc_locktime );
        var [ recipients_initial_htlc_addy, recipients_initial_htlc_tree, recipients_initial_htlc_cblock ] = hedgehog.getAddressData( recipients_inital_htlc_scripts, 1 );
        console.log( 'senders_initial_htlc_addy:', senders_initial_htlc_addy );
        console.log( 'recipients_initial_htlc_addy:', recipients_initial_htlc_addy );

        var sender_is_revoker = true;
        var recovery_htlc_scripts = hedgehog.getRevocableScripts( chan_id, sender_is_revoker, am_sender, s_recovery_p2_revhash );
        var [ recovery_htlc_addy ] = hedgehog.getAddressData( recovery_htlc_scripts, 0 );
        console.log( 'recovery_htlc_scripts:', recovery_htlc_scripts );
        console.log( 'recovery_htlc_addy:', recovery_htlc_addy );

        //he also creates a "reveal-part-two htlc"
        var sender_is_revoker = false;
        var reveal_htlc_scripts = hedgehog.getRevocableScripts( chan_id, sender_is_revoker, !am_sender, r_reveal_p2_revhash );
        var [ reveal_htlc_addy ] = hedgehog.getAddressData( reveal_htlc_scripts, 0 );
        console.log( 'reveal_htlc_addy:', reveal_htlc_addy );

        //the sender is about to create a recovery-part-one tx, but first he needs to know the txid of the tx that funds the initial htlc
        if ( am_sender ) var creating_counterparties_version = false;
        else var creating_counterparties_version = true;
        sender_is_funder = true;
        var sender_of_htlc = ( am_sender === am_alice ) ? "alice" : "bob";
        var htlc_addy_and_amnt = [ senders_initial_htlc_addy, amnt, sender_is_funder, s_midstate_revhash, creating_counterparties_version, sender_of_htlc ];
        if ( am_sender ) var am_sender_for_senders_version = false;
        else var am_sender_for_senders_version = true;
        var senders_version_of_tx1 = hedgehog.getTx1( chan_id, am_sender_for_senders_version, htlc_addy_and_amnt );
        if ( am_sender ) var creating_counterparties_version = true;
        else var creating_counterparties_version = false;
        sender_is_funder = false;
        htlc_addy_and_amnt = [ recipients_initial_htlc_addy, amnt, sender_is_funder, r_midstate_revhash, creating_counterparties_version, sender_of_htlc ];
        if ( am_sender ) var am_sender_for_recipients_version = true;
        else var am_sender_for_recipients_version = false;
        var recipients_version_of_tx1 = hedgehog.getTx1( chan_id, am_sender_for_recipients_version, htlc_addy_and_amnt );
        var sender = am_sender === am_alice ? "alice" : "bob";
        var use_custom_midstate_revhash = true;
        var pending_htlcs = [];
        var latest_state = state.channel_states[ state.channel_states.length - 1 ];
        if ( latest_state && latest_state.hasOwnProperty( "pending_htlcs" ) ) pending_htlcs = latest_state.pending_htlcs;
        var do_not_delete = true;
        var txs = hedgehog.getTxData( chan_id, am_alice, am_sender, amnt, sender, htlc_addy_and_amnt, use_custom_midstate_revhash, null, pending_htlcs, do_not_delete );
        var [ _, _, _, _, _, _, _, _, _, recipients_tx2 ] = txs;
        var senders_version_of_tx1_txid = tapscript.Tx.util.getTxid( senders_version_of_tx1 );
        var recipients_version_of_tx1_txid = tapscript.Tx.util.getTxid( recipients_version_of_tx1 );
        // console.log( 'senders_version_of_tx1_txid:', senders_version_of_tx1_txid );
        // console.log( 'recipients_version_of_tx1_txid:', recipients_version_of_tx1_txid );
        // console.log( 'senders_version_of_tx1:', JSON.stringify( senders_version_of_tx1 ) );
        // console.log( 'recipients_version_of_tx1:', JSON.stringify( recipients_version_of_tx1 ) );

        //the sender creates the recovery-part-one txs which use the recovery path to send the money from the initial htlc to the recovery-part-two htlc
        var senders_recovery_part_one_tx = tapscript.Tx.create({
            version: 3,
            vin: [
                hedgehog.getVin( senders_version_of_tx1_txid, 2, amnt, senders_initial_htlc_addy ),
            ],
            vout: [
                hedgehog.getVout( amnt - 240, recovery_htlc_addy ),
                hedgehog.getVout( 240, "51024e73" ),
            ],
        });
        var recipients_recovery_part_one_tx = tapscript.Tx.create({
            version: 3,
            vin: [
                hedgehog.getVin( recipients_version_of_tx1_txid, 2, amnt, recipients_initial_htlc_addy ),
            ],
            vout: [
                hedgehog.getVout( amnt - 240, recovery_htlc_addy ),
                hedgehog.getVout( 240, "51024e73" ),
            ],
        });
        var senders_recovery_part_one_txid = tapscript.Tx.util.getTxid( senders_recovery_part_one_tx );
        var recipients_recovery_part_one_txid = tapscript.Tx.util.getTxid( recipients_recovery_part_one_tx );
        console.log( 'recipients_recovery_part_one_txid:', senders_recovery_part_one_txid );
        console.log( 'recipients_recovery_part_one_txid:', recipients_recovery_part_one_txid );

        //the sender creates the recovery-part-three txs which take his money back out of the recovery-part-two htlc after a relative timelock of 2 weeks expires
        if ( am_sender ) var senders_address = am_alice ? tapscript.Address.fromScriptPubKey( [ 1, state.alices_pub ] ) : tapscript.Address.fromScriptPubKey( [ 1, state.bobs_pub ] );
        else var senders_address = am_alice ? tapscript.Address.fromScriptPubKey( [ 1, state.bobs_pub ] ) : tapscript.Address.fromScriptPubKey( [ 1, state.alices_pub ] );
        var senders_recovery_part_one_txid = tapscript.Tx.util.getTxid( senders_recovery_part_one_tx );
        var recipients_recovery_part_one_txid = tapscript.Tx.util.getTxid( recipients_recovery_part_one_tx );
        var senders_recovery_part_three_tx = tapscript.Tx.create({
            version: 3,
            vin: [
                //TODO: change the relative timelock from 3 to 2016
                hedgehog.getVin( senders_recovery_part_one_txid, 0, amnt - 240, recovery_htlc_addy, 3 ),
            ],
            vout: [
                hedgehog.getVout( amnt - 240, senders_address ),
                hedgehog.getVout( 240, "51024e73" ),
            ],
        });
        var recipients_recovery_part_three_tx = tapscript.Tx.create({
            version: 3,
            vin: [
                //TODO: change the relative timelock from 3 to 2016
                hedgehog.getVin( recipients_recovery_part_one_txid, 0, amnt - 240, recovery_htlc_addy, 3 ),
            ],
            vout: [
                hedgehog.getVout( amnt - 240, senders_address ),
                hedgehog.getVout( 240, "51024e73" ),
            ],
        });
        var senders_recovery_part_three_txid = tapscript.Tx.util.getTxid( senders_recovery_part_three_tx );
        var recipients_recovery_part_three_txid = tapscript.Tx.util.getTxid( recipients_recovery_part_three_tx );
        console.log( 'senders_recovery_part_three_txid:', senders_recovery_part_three_txid );
        console.log( 'recipients_recovery_part_three_txid:', recipients_recovery_part_three_txid );

        //the sender also creates the reveal-part-one txs which use the reveal path to send the money from the initial htlc to the reveal-part-two htlc
        var senders_reveal_part_one_tx = tapscript.Tx.create({
            version: 3,
            vin: [
                hedgehog.getVin( senders_version_of_tx1_txid, 2, amnt, senders_initial_htlc_addy ),
            ],
            vout: [
                hedgehog.getVout( amnt - 240, reveal_htlc_addy ),
                hedgehog.getVout( 240, "51024e73" ),
            ],
        });
        var recipients_reveal_part_one_tx = tapscript.Tx.create({
            version: 3,
            vin: [
                hedgehog.getVin( recipients_version_of_tx1_txid, 2, amnt, recipients_initial_htlc_addy ),
            ],
            vout: [
                hedgehog.getVout( amnt - 240, reveal_htlc_addy ),
                hedgehog.getVout( 240, "51024e73" ),
            ],
        });
        var senders_reveal_part_one_txid = tapscript.Tx.util.getTxid( senders_reveal_part_one_tx );
        var recipients_reveal_part_one_txid = tapscript.Tx.util.getTxid( recipients_reveal_part_one_tx );
        console.log( 'senders_reveal_part_one_txid:', senders_reveal_part_one_txid );
        console.log( 'recipients_reveal_part_one_txid:', recipients_reveal_part_one_txid );

        return {
            pmt_preimage,
            pmthash,
            r_midstate_revhash,
            r_reveal_p2_revhash,
            s_recovery_p2_revhash,
            senders_version_of_tx1,
            recipients_version_of_tx1,
            senders_recovery_part_one_tx,
            recipients_recovery_part_one_tx,
            senders_recovery_part_three_tx,
            recipients_recovery_part_three_tx,
            senders_reveal_part_one_tx,
            recipients_reveal_part_one_tx,
            recipients_tx2,
        }
    },
    sendHtlc: async ( chan_id, amnt, htlc_locktime, pmthash, block_when_i_must_force_close ) => {
        //prepare variables for sending htlc
        var state = hedgehog.state[ chan_id ];
        if ( !state ) return console.log( 'error, there is no channel with this chan_id:', chan_id, 'available channels:', Object.keys( hedgehog.state ) );
        var am_alice = !!state.alices_priv;
        var privkey = am_alice ? state.alices_priv : state.bobs_priv;
        var pmt_preimage = null;
        if ( !pmthash ) pmt_preimage = hedgehog.getPrivkey();
        if ( pmt_preimage ) pmthash = await hedgehog.sha256( hedgehog.hexToBytes( pmt_preimage ) );
        var s_midstate_rev_preimage = hedgehog.getPrivkey();
        var s_midstate_revhash = await hedgehog.sha256( hedgehog.hexToBytes( s_midstate_rev_preimage ) );
        var s_recovery_p2_rev_preimage = hedgehog.getPrivkey();
        var s_recovery_p2_revhash = await hedgehog.sha256( hedgehog.hexToBytes( s_recovery_p2_rev_preimage ) );
        var am_sender = true;
        var sender_is_funder = true;
        var sender_is_revoker = true;
        var data_for_recipient = { chan_id, pmthash, s_midstate_revhash };
        var recipients_revhashes = await hedgehog.communicateWithUser( data_for_recipient );
        // var recipients_revhashes = await hedgehog.receiveHtlcPartOne( data_for_recipient );
        var data_for_doing_part_three = await hedgehog.prepareHtlcPartOne( chan_id, amnt, pmthash, am_sender, recipients_revhashes, s_recovery_p2_revhash, s_midstate_revhash, htlc_locktime );

        //save the data you need for doing part three
        state.data_for_preparing_htlcs[ pmthash ] = [ "sender_part_two", data_for_doing_part_three ];

        var {
            pmthash,
            r_midstate_revhash,
            r_reveal_p2_revhash,
            senders_version_of_tx1,
            recipients_version_of_tx1,
            senders_recovery_part_one_tx,
            recipients_recovery_part_one_tx,
            senders_recovery_part_three_tx,
            recipients_recovery_part_three_tx,
            senders_reveal_part_one_tx,
            recipients_reveal_part_one_tx,
        } = data_for_doing_part_three;

        //prepare a data object to send to the counterparty
        var data_for_counterparty = {
            chan_id,
            amnt,
            htlc_locktime,
        }

        //sign the transactions needed by the counterparty
        var recipients_inital_htlc_scripts = hedgehog.getInitialHTLCScripts( chan_id, !sender_is_funder, !am_sender, pmthash, htlc_locktime );
        var [ recipients_initial_htlc_addy, recipients_initial_htlc_tree, recipients_initial_htlc_cblock ] = hedgehog.getAddressData( recipients_inital_htlc_scripts, 1 );
        var sig_on_recipients_reveal_p1_tx = tapscript.Signer.taproot.sign( privkey, recipients_reveal_part_one_tx, 0, {extension: recipients_initial_htlc_tree[ 0 ]} ).hex;
        var senders_inital_htlc_scripts = hedgehog.getInitialHTLCScripts( chan_id, sender_is_funder, am_sender, pmthash, htlc_locktime );
        var [ senders_initial_htlc_addy, senders_initial_htlc_tree, senders_initial_htlc_cblock ] = hedgehog.getAddressData( senders_inital_htlc_scripts, 1 );
        var sig_on_senders_reveal_p1_tx = tapscript.Signer.taproot.sign( privkey, senders_reveal_part_one_tx, 0, {extension: senders_initial_htlc_tree[ 0 ]} ).hex;

        //add the signatures to the data object
        data_for_counterparty[ "sig_on_recipients_reveal_p1_tx" ] = sig_on_recipients_reveal_p1_tx;
        data_for_counterparty[ "sig_on_senders_reveal_p1_tx" ] = sig_on_senders_reveal_p1_tx;

        //send the data object to your counterparty
        data_for_counterparty[ "pmthash" ] = pmthash;
        data_for_counterparty[ "s_recovery_p2_revhash" ] = s_recovery_p2_revhash;
        var reply_from_counterparty = await hedgehog.communicateWithUser( data_for_counterparty );
        // var reply_from_counterparty = await hedgehog.receiveHtlcPartTwo( data_for_counterparty );

        //TODO: force close if the following error is thrown
        if ( !reply_from_counterparty ) return console.log( 'error, your counterparty rejected your htlc' );

        //prepare variables for validating the counterparty's signatures
        var { sig_on_senders_recovery_p1_tx, sig_on_recipients_recovery_p1_tx, sig_on_senders_deposit_tx, sig_on_senders_tx2 } = reply_from_counterparty;
        var recipients_pub = am_alice ? state.bobs_pub : state.alices_pub;

        //validate the counterparty's recovery signatures
        var senders_recovery_part_one_sighash = tapscript.Signer.taproot.hash( senders_recovery_part_one_tx, 0, {extension: senders_initial_htlc_tree[ 1 ] }).hex;
        var sig_on_senders_recovery_p1_tx_is_valid = await nobleSecp256k1.schnorr.verify( sig_on_senders_recovery_p1_tx, senders_recovery_part_one_sighash, recipients_pub );
        var recipients_recovery_part_one_sighash = tapscript.Signer.taproot.hash( recipients_recovery_part_one_tx, 0, {extension: recipients_initial_htlc_tree[ 1 ] }).hex;
        var sig_on_recipients_recovery_p1_tx_is_valid = await nobleSecp256k1.schnorr.verify( sig_on_recipients_recovery_p1_tx, recipients_recovery_part_one_sighash, recipients_pub );

        //validate the counterparty's sigs on tx1 and tx2
        var channel_scripts = hedgehog.getChannelScripts( chan_id );
        var [ _, channel_tree, channel_cblock ] = hedgehog.getAddressData( channel_scripts, 0 );
        var deposit_sighash = tapscript.Signer.taproot.hash( senders_version_of_tx1, 0, {extension: channel_tree[ 0 ] }).hex;
        var sig_on_deposit_is_valid = await nobleSecp256k1.schnorr.verify( sig_on_senders_deposit_tx, deposit_sighash, recipients_pub );
        var creating_counterparties_version = true;
        var sender_of_htlc = ( am_sender === am_alice ) ? "alice" : "bob";
        var htlc_addy_and_amnt = [ senders_initial_htlc_addy, amnt, sender_is_funder, s_midstate_revhash, creating_counterparties_version, sender_of_htlc ];
        var sender_for_tx1 = am_alice ? "bob" : "alice";
        var am_alice_for_tx1 = am_alice ? false : true;
        var use_custom_midstate_revhash = true;
        var am_sender_for_script_override = false;
        var uses_htlc_for_script_override = true;
        var sender_is_funder_for_script_override = true;
        var creating_counterparties_version_for_script_override = false;
        var midstate_scripts_override = hedgehog.getMidstateScripts( chan_id, am_sender_for_script_override, s_midstate_revhash, uses_htlc_for_script_override, sender_is_funder_for_script_override, creating_counterparties_version_for_script_override );
        var midstate_tree_override = hedgehog.getAddressData( midstate_scripts_override, 0 )[ 1 ];
        var use_custom_midstate_revhash = null;
        var pending_htlcs = [];
        var latest_state = state.channel_states[ state.channel_states.length - 1 ];
        if ( latest_state && latest_state.hasOwnProperty( "pending_htlcs" ) ) pending_htlcs = latest_state.pending_htlcs;
        var do_not_delete = true;
        var txs = hedgehog.getTxData( chan_id, am_alice_for_tx1, am_sender, amnt, sender_for_tx1, htlc_addy_and_amnt, use_custom_midstate_revhash, midstate_scripts_override, pending_htlcs, do_not_delete );
        var [ _, _, _, _, _, _, _, _, senders_tx1, senders_tx2 ] = txs;
        var senders_pub = state.alices_pub;
        if ( !am_alice ) var senders_pub = state.bobs_pub;
        if ( senders_tx2.vout.length < 3 ) {
            senders_tx2.vout[ 1 ].scriptPubKey = [ 1, senders_pub ];
        } else {
            senders_tx2.vout[ 1 ].scriptPubKey = [ 1, state.alices_pub ];
            senders_tx2.vout[ 2 ].scriptPubKey = [ 1, state.bobs_pub ];
        }
        var senders_tx2_sighash = tapscript.Signer.taproot.hash( senders_tx2, 0, {extension: midstate_tree_override[ 0 ] }).hex;
        var sig_on_senders_tx2_is_valid = await nobleSecp256k1.schnorr.verify( sig_on_senders_tx2, senders_tx2_sighash, recipients_pub );

        //TODO: force close if the following error is thrown
        if ( !sig_on_senders_recovery_p1_tx_is_valid || !sig_on_recipients_recovery_p1_tx_is_valid || !sig_on_deposit_is_valid || !sig_on_senders_tx2_is_valid ) return console.log( 'error, your counterparty sent you invalid signatures' );

        //save the data provided by the counterparty
        state.data_for_preparing_htlcs[ pmthash ] = [ "sender_part_three", {
            ...data_for_doing_part_three,
            sig_on_senders_recovery_p1_tx,
            sig_on_recipients_recovery_p1_tx,
        }];

        //sign the recipients version of tx2
        var recipients_inital_htlc_scripts = hedgehog.getInitialHTLCScripts( chan_id, !sender_is_funder, !am_sender, pmthash, htlc_locktime );
        var [ recipients_initial_htlc_addy, recipients_initial_htlc_tree, recipients_initial_htlc_cblock ] = hedgehog.getAddressData( recipients_inital_htlc_scripts, 1 );
        var creating_counterparties_version = true;
        var sender_of_htlc = ( am_sender === am_alice ) ? "alice" : "bob";
        var htlc_addy_and_amnt = [ recipients_initial_htlc_addy, amnt, !sender_is_funder, r_midstate_revhash, creating_counterparties_version, sender_of_htlc ];
        var sender = "bob";
        var use_custom_midstate_revhash = true;
        var pending_htlcs = [];
        var latest_state = state.channel_states[ state.channel_states.length - 1 ];
        if ( latest_state && latest_state.hasOwnProperty( "pending_htlcs" ) ) pending_htlcs = latest_state.pending_htlcs;
        var do_not_delete = true;
        var txs = hedgehog.getTxData( chan_id, am_alice, am_sender, amnt, sender, htlc_addy_and_amnt, use_custom_midstate_revhash, null, pending_htlcs, do_not_delete );
        var [ recipients_new_balance, channel_tree, channel_cblock, midstate_tree, midstate_cblock, amnt, conditional_revocation_needed, absolute_revocation_hash, tx1, tx2 ] = txs;
        //getTxData always returns 10 items. It also returns two additional items if a conditional revocation was needed on a prior state, so in that cirucmstance we also grab those two additional items so that we can sign them
        if ( txs.length > 10 ) {
            var conditional_revocation_tx = txs[ 10 ];
            var prev_tx1 = txs[ 11 ];
        }

        //ensure tx1 is the same now as it was before
        var tx1_txid = tapscript.Tx.util.getTxid( tx1 );
        var prev_tx1_txid = tapscript.Tx.util.getTxid( recipients_version_of_tx1 );
        console.log( 'tx1_txid:', tx1_txid );
        console.log( 'prev_tx1_txid:', prev_tx1_txid );

        //sign everything
        var to_midstate_sig = tapscript.Signer.taproot.sign( privkey, tx1, 0, {extension: channel_tree[ 0 ] }).hex;
        var finalizer_sig = tapscript.Signer.taproot.sign( privkey, tx2, 0, {extension: midstate_tree[ 0 ] }).hex;

        //update your state
        var sender = am_alice ? "alice" : "bob";
        var latest_state = state.channel_states[ state.channel_states.length - 1 ];
        var pending_htlcs = [];
        if ( latest_state && latest_state.hasOwnProperty( "pending_htlcs" ) ) pending_htlcs = latest_state.pending_htlcs;
        pending_htlcs.push({
            pmt_preimage,
            pmthash,
            s_midstate_rev_preimage,
            s_midstate_revhash,
            s_recovery_p2_rev_preimage,
            s_recovery_p2_revhash,
            recipients_rev_preimages: null,
            recipients_revhashes,
            htlc_locktime,
            amnt,
            sender: am_alice ? "alice" : "bob",
            txid_to_check: tapscript.Tx.util.getTxid( senders_version_of_tx1 ),
            block_when_i_must_force_close,
        });
        var ch_state = {
            from: sender,
            amnt: recipients_new_balance,
            amnt_sent: 0,
            tx1: tapscript.Tx.encode( tx1 ).hex,
            absolute_revocation_hash,
            absolute_revocation_preimage: null,
            conditional_revocation_sig: null,
            conditional_revocation_vout: null,
            added_htlc: true,
            pending_htlcs,
        }
        state.channel_states.push( ch_state );

        //generate the hash you want your counterparty to use when they next send you money
        var revocation_preimage = hedgehog.getPrivkey();
        var revocation_hash = await hedgehog.sha256( hedgehog.hexToBytes( revocation_preimage ) );
        if ( am_alice ) {
            state.alices_revocation_preimages.push( revocation_preimage );
            state.alices_revocation_hashes.push( revocation_hash );
        } else {
            state.bobs_revocation_preimages.push( revocation_preimage );
            state.bobs_revocation_hashes.push( revocation_hash );
        }

        //send your counterparty the data they need to validate the new state
        var my_revocation_preimages = state[ "alices_revocation_preimages" ];
        if ( !am_alice ) my_revocation_preimages = state[ "bobs_revocation_preimages" ];
        var obj = {
            to_midstate_sig,
            finalizer_sig,
            chan_id,
            revocation_hash,
            pmthash,
            revocation_of_previous_state: my_revocation_preimages[ my_revocation_preimages.length - 2 ],
        }

        //send the data to your counterparty and get their revocation preimage
        var data_from_recipient = await hedgehog.communicateWithUser( obj );
        // var data_from_recipient = await hedgehog.receiveHtlcPartThree( obj );

        //validate and store it
        var counterpartys_revhashes = state.alices_revocation_hashes;
        var counterpartys_rev_preimages = state.alices_revocation_preimages;
        if ( am_alice ) {
            counterpartys_revhashes = state.bobs_revocation_hashes;
            counterpartys_rev_preimages = state.bobs_revocation_preimages;
        }
        //TODO: force close if the following errors are thrown
        if ( counterpartys_revhashes.length && !data_from_recipient.hasOwnProperty( "revocation_of_previous_state" ) ) return console.log( 'your counterparty tried to cheat you by not sending requisite data' );
        if ( counterpartys_revhashes.length ) {
            var revocation_of_previous_state = data_from_recipient.revocation_of_previous_state;
            //if your counterparty was the last person to send money, and he did so in a state update that did *not* include an htlc, then he will have a revocation hash that he should *not* revoke here; you will use it next time you send him money, and if he revokes it here, he won't be able to safely receive that money; this also applies if 
            var num_of_hashes_behind = 2;
            var latest_state = state.channel_states[ state.channel_states.length - 1 ];
            if ( ( ( latest_state.from === "bob" && am_alice ) || ( latest_state.from === "alice" && !am_alice ) ) && !latest_state.uses_htlc ) num_of_hashes_behind = 2;
            var expected_revhash = counterpartys_revhashes[ counterpartys_revhashes.length - num_of_hashes_behind ];
            if ( typeof revocation_of_previous_state !== "string" ) return console.log( 'error, your counterparty tried to cheat you by sending invalid data' );
            var actual_revhash = await hedgehog.sha256( hedgehog.hexToBytes( revocation_of_previous_state ) );
            if ( actual_revhash !== expected_revhash ) return console.log( `error, your counterparty tried to cheat you by refusing to revoke the previous state; the rev_preimage they sent you: ${revocation_of_previous_state} | its actual hash: ${actual_revhash} | the revhash you wanted: ${expected_revhash} | all your counterpartys revhashes: ${counterpartys_revhashes}` );

            //add your counterparty's revocation preimage to your state unless you already
            //have it
            if ( !counterpartys_rev_preimages.includes( revocation_of_previous_state ) ) counterpartys_rev_preimages.push( revocation_of_previous_state );
        }
        return pmthash;
    },
    receiveHtlcPartOne: async data_from_sender => {
        //prepare revocation hashes for use in the upcoming state update
        var { chan_id, pmthash, s_midstate_revhash } = data_from_sender;
        if ( chan_id.startsWith( "a_" ) ) chan_id = "b_" + chan_id.substring( 2 );
        else chan_id = "a_" + chan_id.substring( 2 );
        var midstate_rev_preimage = hedgehog.getPrivkey();
        var midstate_revhash = await hedgehog.sha256( hedgehog.hexToBytes( midstate_rev_preimage ) );
        var reveal_p2_rev_preimage = hedgehog.getPrivkey();
        var reveal_p2_revhash = await hedgehog.sha256( hedgehog.hexToBytes( reveal_p2_rev_preimage ) );
        var recipients_preimages = [ midstate_rev_preimage, reveal_p2_rev_preimage ];
        var recipients_revhashes = [ midstate_revhash, reveal_p2_revhash ];
        hedgehog.state[ chan_id ].data_for_preparing_htlcs[ pmthash ] = [ "recipient_part_one", recipients_revhashes, recipients_preimages, s_midstate_revhash ];
        return recipients_revhashes;
    },
    receiveHtlcPartTwo: async data_from_sender => {
        //process the data from the sender
        var { chan_id, amnt, sig_on_recipients_reveal_p1_tx, sig_on_senders_reveal_p1_tx, pmthash, s_recovery_p2_revhash, htlc_locktime } = data_from_sender;
        if ( chan_id.startsWith( "a_" ) ) chan_id = "b_" + chan_id.substring( 2 );
        else chan_id = "a_" + chan_id.substring( 2 );
        //TODO: force close if the following errors are thrown
        if ( !hedgehog.state.hasOwnProperty( chan_id ) ) return console.log( 'error, counterparty tried to cheat you by providing wrong chan id' );
        if ( hedgehog.state[ chan_id ].data_for_preparing_htlcs[ pmthash ][ 0 ] !== "recipient_part_one" ) return console.log( 'error, counterparty tried to cheat you by providing wrong data for the current part of an htlc transfer' );

        //prepare the variables needed for this state update
        var state = hedgehog.state[ chan_id ];
        var am_sender = false;
        var am_alice = !!state.alices_priv;
        var privkey = am_alice ? state.alices_priv : state.bobs_priv;
        var senders_pub = am_alice ? state.bobs_pub : state.alices_pub;
        var sender_is_funder = true;
        var sender_is_revoker = true;

        //prepare the htlc
        var recipients_revhashes = hedgehog.state[ chan_id ].data_for_preparing_htlcs[ pmthash ][ 1 ];
        var recipients_rev_preimages = hedgehog.state[ chan_id ].data_for_preparing_htlcs[ pmthash ][ 2 ];
        var s_midstate_revhash = hedgehog.state[ chan_id ].data_for_preparing_htlcs[ pmthash ][ 3 ];
        var data_for_doing_part_three = await hedgehog.prepareHtlcPartTwo( chan_id, amnt, pmthash, am_sender, recipients_revhashes, s_recovery_p2_revhash, s_midstate_revhash, htlc_locktime );
        var { recipients_version_of_tx1, recipients_reveal_part_one_tx, senders_version_of_tx1, senders_recovery_part_one_tx, senders_recovery_part_three_tx, senders_reveal_part_one_tx, recipients_recovery_part_one_tx } = data_for_doing_part_three;

        //ensure you can move the money from the initial htlc if you learn the preimage
        var recipients_inital_htlc_scripts = hedgehog.getInitialHTLCScripts( chan_id, !sender_is_funder, am_sender, pmthash, htlc_locktime );
        var [ recipients_initial_htlc_addy, recipients_initial_htlc_tree, recipients_initial_htlc_cblock ] = hedgehog.getAddressData( recipients_inital_htlc_scripts, 1 );
        var recipients_reveal_part_one_sighash = tapscript.Signer.taproot.hash( recipients_reveal_part_one_tx, 0, {extension: recipients_initial_htlc_tree[ 0 ] }).hex;
        var sig_on_recipients_reveal_p1_is_valid = await nobleSecp256k1.schnorr.verify( sig_on_recipients_reveal_p1_tx, recipients_reveal_part_one_sighash, senders_pub );

        //ensure the same is true even if the sender is the one who puts the money into the inital htlc
        var senders_inital_htlc_scripts = hedgehog.getInitialHTLCScripts( chan_id, sender_is_funder, am_sender, pmthash, htlc_locktime );
        var [ senders_initial_htlc_addy, senders_initial_htlc_tree, senders_initial_htlc_cblock ] = hedgehog.getAddressData( senders_inital_htlc_scripts, 1 );
        var senders_reveal_part_one_sighash = tapscript.Signer.taproot.hash( senders_reveal_part_one_tx, 0, {extension: senders_initial_htlc_tree[ 0 ] }).hex;
        var sig_on_senders_reveal_p1_is_valid = await nobleSecp256k1.schnorr.verify( sig_on_senders_reveal_p1_tx, senders_reveal_part_one_sighash, senders_pub );

        //TODO: force close if the following error is thrown
        if ( !sig_on_recipients_reveal_p1_is_valid || !sig_on_senders_reveal_p1_is_valid )  return console.log( 'error, counterparty tried to cheat you by providing invalid signatures' );

        //sign the transactions that let the sender recover his money if you never learn the preimage
        var sig_on_senders_recovery_p1_tx = tapscript.Signer.taproot.sign( privkey, senders_recovery_part_one_tx, 0, {extension: senders_initial_htlc_tree[ 1 ]} ).hex;
        var sig_on_recipients_recovery_p1_tx = tapscript.Signer.taproot.sign( privkey, recipients_recovery_part_one_tx, 0, {extension: recipients_initial_htlc_tree[ 1 ]} ).hex;
        var channel_scripts = hedgehog.getChannelScripts( chan_id );
        var [ channel, channel_tree, channel_cblock ] = hedgehog.getAddressData( channel_scripts, 0 );
        var sig_on_senders_deposit_tx = tapscript.Signer.taproot.sign( privkey, senders_version_of_tx1, 0, {extension: channel_tree[ 0 ]} ).hex;

        //sign the sender's version of tx2 as well
        var creating_counterparties_version = true;
        var sender_of_htlc = ( am_sender === am_alice ) ? "alice" : "bob";
        var htlc_addy_and_amnt = [ senders_initial_htlc_addy, amnt, sender_is_funder, s_midstate_revhash, creating_counterparties_version, sender_of_htlc ];
        var sender = am_alice ? "alice" : "bob";
        var am_sender_for_tx1 = true;
        var pending_htlcs = [];
        var latest_state = state.channel_states[ state.channel_states.length - 1 ];
        if ( latest_state && latest_state.hasOwnProperty( "pending_htlcs" ) ) pending_htlcs = latest_state.pending_htlcs;
        var do_not_delete = true;
        var txs = hedgehog.getTxData( chan_id, am_alice, am_sender_for_tx1, amnt, sender, htlc_addy_and_amnt, null, null, pending_htlcs, do_not_delete );
        var [ recipients_new_balance, channel_tree, channel_cblock, midstate_tree, midstate_cblock, amnt, conditional_revocation_needed, absolute_revocation_hash, tx1, tx2 ] = txs;
        tx2.vin[ 0 ].prevout.scriptPubKey = tx1.vout[ 0 ].scriptPubKey;
        var senders_tx2_sighash = tapscript.Signer.taproot.hash( tx2, 0, {extension: midstate_tree[ 0 ] }).hex;
        var sig_on_senders_tx2 = tapscript.Signer.taproot.sign( privkey, tx2, 0, {extension: midstate_tree[ 0 ]} ).hex;

        hedgehog.state[ chan_id ].data_for_preparing_htlcs[ pmthash ] = [ "recipient_part_two", {recipients_rev_preimages, recipients_revhashes, s_midstate_revhash, data_for_doing_part_three, part_twos_data_from_sender: data_from_sender, recipients_inital_htlc_scripts, recipients_new_balance} ];

        //return the signatures so you can provide them to the sender
        return {
            sig_on_senders_recovery_p1_tx,
            sig_on_recipients_recovery_p1_tx,
            sig_on_senders_deposit_tx,
            sig_on_senders_tx2,
        }
    },
    receiveHtlcPartThree: async data_from_sender => {
        //process the data from the sender
        var { to_midstate_sig, finalizer_sig, chan_id, revocation_hash, pmthash, revocation_of_previous_state } = data_from_sender;
        var absolute_revocation_hash = revocation_hash;
        var chan_id = data_from_sender.chan_id;
        if ( chan_id.startsWith( "a_" ) ) chan_id = "b_" + chan_id.substring( 2 );
        else chan_id = "a_" + chan_id.substring( 2 );
        var state = hedgehog.state[ chan_id ];
        var am_alice = !!state.alices_priv;
        var counterpartys_revhashes = state.alices_revocation_hashes;
        var counterpartys_rev_preimages = state.alices_revocation_preimages;
        if ( am_alice ) {
            counterpartys_revhashes = state.bobs_revocation_hashes;
            counterpartys_rev_preimages = state.bobs_revocation_preimages;
        }
        var expected_revhash = counterpartys_revhashes[ counterpartys_revhashes.length - 1 ];
        //TODO: force close if the following errors are thrown
        if ( typeof revocation_of_previous_state !== "string" ) return console.log( 'error, your counterparty tried to cheat you by sending invalid data' );
        var actual_revhash = await hedgehog.sha256( hedgehog.hexToBytes( revocation_of_previous_state ) );
        if ( actual_revhash !== expected_revhash ) return console.log( 'error, your counterparty tried to cheat you by refusing to revoke the previous state' );
        if ( !hedgehog.state.hasOwnProperty( chan_id ) ) return console.log( 'error, counterparty tried to cheat you by providing wrong chan id' );
        if ( hedgehog.state[ chan_id ].data_for_preparing_htlcs[ pmthash ][ 0 ] !== "recipient_part_two" ) return console.log( 'error, counterparty tried to cheat you by providing wrong data for the current part of an htlc transfer' );

        //add your counterparty's revocation preimage to your state unless you already
        //have it
        if ( !counterpartys_rev_preimages.includes( revocation_of_previous_state ) ) counterpartys_rev_preimages.push( revocation_of_previous_state );

        //do not allow the sender to reuse a revocation hash
        var revocation_hash = data_from_sender.revocation_hash;
        if ( counterpartys_revhashes.includes( revocation_hash ) ) return;

        //prepare the variables necessary for validating the new state
        var am_sender = false;
        var sender = am_alice ? "bob" : "alice";
        var senders_pub = am_alice ? state.bobs_pub : state.alices_pub;
        var pmthash = data_from_sender.pmthash;

        //get data from previous part of process
        var data_from_part_two = state.data_for_preparing_htlcs[ pmthash ];
        var amnt = data_from_part_two[ 1 ].part_twos_data_from_sender.amnt;
        var htlc_locktime = data_from_part_two[ 1 ].part_twos_data_from_sender.htlc_locktime;
        var recipients_new_balance = data_from_part_two[ 1 ].recipients_new_balance;
        var recipients_inital_htlc_scripts = data_from_part_two[ 1 ].recipients_inital_htlc_scripts;
        var recipients_rev_preimages = data_from_part_two[ 1 ].recipients_rev_preimages;
        var recipients_revhashes = data_from_part_two[ 1 ].recipients_revhashes;
        var s_midstate_revhash = data_from_part_two[ 1 ].s_midstate_revhash;
        var data_for_doing_part_three = data_from_part_two[ 1 ].data_for_doing_part_three;
        var { recipients_version_of_tx1, recipients_reveal_part_one_tx, senders_version_of_tx1, senders_recovery_part_one_tx, senders_recovery_part_three_tx, senders_reveal_part_one_tx, recipients_recovery_part_one_tx, r_midstate_revhash, recipients_tx2, s_recovery_p2_revhash } = data_for_doing_part_three;

        //ensure you can broadcast tx1
        var channel_scripts = hedgehog.getChannelScripts( chan_id );
        var [ channel, channel_tree, channel_cblock ] = hedgehog.getAddressData( channel_scripts, 0 );
        var deposit_sighash = tapscript.Signer.taproot.hash( recipients_version_of_tx1, 0, {extension: channel_tree[ 0 ] }).hex;
        var sig_on_deposit_is_valid = await nobleSecp256k1.schnorr.verify( to_midstate_sig, deposit_sighash, senders_pub );
        //TODO: force close if the following error is thrown
        if ( !sig_on_deposit_is_valid )  return console.log( 'error, counterparty tried to cheat you by providing invalid signatures' );

        //ensure you can broadcast tx2
        var uses_htlc = true;
        var sender_is_funding_htlc = false;
        var recipients_midstate_scripts = hedgehog.getMidstateScripts( chan_id, am_sender, r_midstate_revhash, uses_htlc, sender_is_funding_htlc );
        var recipients_midstate_tree = hedgehog.getAddressData( recipients_midstate_scripts, 0 )[ 1 ];
        var tx2_sighash = tapscript.Signer.taproot.hash( recipients_tx2, 0, {extension: recipients_midstate_tree[ 0 ] }).hex;
        var sig_on_tx2_is_valid = await nobleSecp256k1.schnorr.verify( finalizer_sig, tx2_sighash, senders_pub );
        //TODO: force close if the following error is thrown
        if ( !sig_on_deposit_is_valid )  return console.log( 'error, counterparty tried to cheat you by providing invalid signatures' );

        //store the revocation data given by your counterparty for future use
        if ( am_alice ) state.bobs_revocation_hashes.push( revocation_hash );
        else state.alices_revocation_hashes.push( revocation_hash );

        //update your state
        var latest_state = state.channel_states[ state.channel_states.length - 1 ];
        var pending_htlcs = [];
        if ( latest_state && latest_state.hasOwnProperty( "pending_htlcs" ) ) pending_htlcs = latest_state.pending_htlcs;
        pending_htlcs.push({
            pmt_preimage: null,
            pmthash,
            s_midstate_rev_preimage: null,
            s_midstate_revhash,
            s_recovery_p2_rev_preimage: null,
            s_recovery_p2_revhash,
            recipients_rev_preimages,
            recipients_revhashes,
            htlc_locktime,
            amnt,
            sender: am_alice ? "bob" : "alice",
            txid_to_check: tapscript.Tx.util.getTxid( senders_version_of_tx1 ),
        });
        var ch_state = {
            from: sender,
            amnt: recipients_new_balance,
            amnt_sent: 0,
            to_midstate_sig,
            finalizer_sig,
            tx1: tapscript.Tx.encode( recipients_version_of_tx1 ).hex,
            absolute_revocation_hash: s_midstate_revhash,
            added_htlc: true,
            pending_htlcs,
        }
        state.channel_states.push( ch_state );

        //revoke all old states
        var my_revocation_preimages = state.alices_revocation_preimages;
        var my_revocation_hashes = state.alices_revocation_hashes;
        if ( !am_alice ) {
            my_revocation_preimages = state.bobs_revocation_preimages;
            my_revocation_hashes = state.bobs_revocation_hashes;
        }
        var data_for_sender = {}
        if ( my_revocation_preimages.length > 1 ) data_for_sender[ "revocation_of_previous_state" ] = my_revocation_preimages[ my_revocation_preimages.length - 2 ];
        return data_for_sender;
    },
    findPreimage: async ( chan_id, pmthash ) => {
        return new Promise( resolve => {
            var channel_states = hedgehog.state[ chan_id ].channel_states;
            channel_states.every( state => {
                if ( state.pending_htlcs ) {
                    state.pending_htlcs.every( htlc => {
                        if ( htlc.pmthash === pmthash && htlc.pmt_preimage ) resolve( htlc.pmt_preimage );
                        return true;
                    });
                }
                return true;
            });
        });
    },
    resolveHtlcAsSender: async ( chan_id, preimage ) => {
        console.log( chan_id, preimage );
    },
    resolveHtlcAsRecipient: async ( chan_id, pmthash ) => {

    },
    forceClose: async ( chan_id, txid, txdata, try_to_cheat ) => {
        //prepare variables needed for force closing the channel
        var state = hedgehog.state[ chan_id ];
        var am_alice = !!state.alices_priv;
        var privkey = am_alice ? state.alices_priv : state.bobs_priv;
        var pubkey = hedgehog.getPubkey( privkey );
        var reversed = JSON.parse( JSON.stringify( state.channel_states ) );
        reversed = reversed.reverse();

        //if you detected that your counterparty force closed and broadcasted
        //tx1, check if you have a later state or the ability to broadcast a
        //justice transaction or a disappearance transaction, and if you can
        //do so, do it
        if ( txid ) {
            var senders_pub = am_alice ? state.bobs_pub : state.alices_pub;

            //look for a revoked state state with that txid
            var revoked_state = null;
            var tx1 = null;
            var revhash = null;
            reversed.every( ( item, index ) => {
                var txid_to_check = tapscript.Tx.util.getTxid( item.tx1 );
                if ( txid_to_check === txid ) {
                    var this_state_is_revoked = item.absolute_revocation_preimage || item.conditional_revocation_sig;
                    if ( this_state_is_revoked ) revoked_state = item;
                    else {
                        tx1 = item.tx1;
                        revhash = item.absolute_revocation_hash;
                    }
                    return;
                }
                return true;
            });

            //if you could not find a revoked state with that txid, that means your counterparty
            //is trying to broadcast the latest state, which is good. But if they disappear
            //you should be ready to broadcast the disappearance tx, so prepare to do that
            if ( !revoked_state ) {
                //prepare a tx that sweeps the funds if your counterparty disappeared
                var txfee = 500;
                var disappearance_tx = tapscript.Tx.create({
                    version: 2,
                    vin: [{
                        txid,
                        vout: 0,
                        prevout: tapscript.Tx.decode( tx1 ).vout[ 0 ],
                        //TODO: change the 6 to 2026
                        sequence: 6,
                    }],
                    vout: [{
                        value: Number( tapscript.Tx.decode( tx1 ).vout[ 0 ].value ) - txfee,
                        scriptPubKey: [ 1, pubkey ],
                    }],
                });

                //sign the disappearance tx
                var am_sender = true;
                var midstate_scripts = hedgehog.getMidstateScripts( chan_id, am_sender, revhash );
                var [ midstate, midstate_tree, midstate_cblock ] = hedgehog.getAddressData( midstate_scripts, 1 );
                var mysig = tapscript.Signer.taproot.sign( privkey, disappearance_tx, 0, {extension: midstate_tree[ 1 ]} ).hex;
                disappearance_tx.vin[ 0 ].witness = [ mysig, midstate_scripts[ 1 ], midstate_cblock ];

                //broadcast the disappearance tx
                return { disappearance_tx }
            }

            //if you found a revoked state and it was *fully* revoked, broadcast a justice transaction
            var am_sender = true;
            var revhash = revoked_state.absolute_revocation_hash;
            var midstate_scripts = hedgehog.getMidstateScripts( chan_id, am_sender, revhash );
            var [ midstate, midstate_tree, midstate_cblock ] = hedgehog.getAddressData( midstate_scripts, 0 );
            if ( revoked_state.absolute_revocation_preimage ) {
                //prepare variables needed in the justice tx
                var preimage = revoked_state.absolute_revocation_preimage;
                var txfee = 500;

                //prepare the justice tx
                var justice_tx = tapscript.Tx.create({
                    version: 2,
                    vin: [{
                        txid: tapscript.Tx.util.getTxid( revoked_state[ "tx1" ] ),
                        vout: 0,
                        prevout: tapscript.Tx.decode( revoked_state[ "tx1" ] ).vout[ 0 ],
                    }],
                    vout: [{
                        value: tapscript.Tx.decode( revoked_state[ "tx1" ] ).vout[ 0 ].value - txfee,
                        scriptPubKey: [ 1, pubkey ],
                    }],
                });

                //sign the justice tx
                var midstate_cblock = hedgehog.getAddressData( midstate_scripts, 2 );
                var mysig = tapscript.Signer.taproot.sign( privkey, justice_tx, 0, {extension: midstate_tree[ 2 ]} ).hex;
                justice_tx.vin[ 0 ].witness = [ mysig, preimage, midstate_scripts[ 2 ], midstate_cblock ];

                //broadcast the justice tx
                console.log( 'broadcast this justice transaction:' );
                console.log( tapscript.Tx.encode( justice_tx ).hex );
                return { justice_tx }
            }

            //if you have a revoked transaction that was *not* absolutely revoked but only conditionally revoked, prepare a transaction updating the state to the latest state
            var alt_tx2 = tapscript.Tx.create({
                version: 3,
                vin: [{
                    txid: tapscript.Tx.util.getTxid( revoked_state[ "tx1" ] ),
                    vout: 0,
                    prevout: tapscript.Tx.decode( revoked_state[ "tx1" ] ).vout[ 0 ],
                }],
                vout: revoked_state[ "conditional_revocation_vout" ],
            });

            //get all sigs required to broadcast it
            var revsig = revoked_state[ "conditional_revocation_sig" ];
            var mysig = tapscript.Signer.taproot.sign( privkey, alt_tx2, 0, {extension: midstate_tree[ 0 ]} ).hex;
            alt_tx2.vin[ 0 ].witness = [ mysig, revsig, midstate_scripts[ 0 ], midstate_cblock ];
            if ( am_alice ) alt_tx2.vin[ 0 ].witness = [ revsig, mysig, midstate_scripts[ 0 ], midstate_cblock ];

            //get utxos to cover the fees
            var addy = tapscript.Address.fromScriptPubKey( [ 1, pubkey ], hedgehog.network );
            if ( !txdata ) {
                console.log( 'send 500 sats into this address:' );
                console.log( addy );
                var txid2 = prompt( `send 500 sats into the address in your console and enter the txid` );
                if ( !txid2 ) return;
                var vout2 = Number( prompt( `and the vout` ) );
                var amnt2 = Number( prompt( `and the amount` ) );
            } else {
                var [ txid2, vout2, amnt2 ] = txdata;
            }

            //prepare a fee-paying tx
            var tx2_txid = tapscript.Tx.util.getTxid( alt_tx2 );
            var tx2_fee = tapscript.Tx.create({
                version: 3,
                vin: [
                    hedgehog.getVin( tx2_txid, 0, 240, "51024e73" ),
                    hedgehog.getVin( txid2, vout2, amnt2, addy ),
                ],
                vout: [{
                    value: 0,
                    scriptPubKey: [ "OP_RETURN", "" ],
                }],
            });
            var fee2_sig = tapscript.Signer.taproot.sign( privkey, tx2_fee, 1 ).hex;
            tx2_fee.vin[ 1 ].witness = [ fee2_sig ];

            //broadcast the transactions
            return { alt_tx2, tx2_fee }
        }

        //all the code after this point is for preparing and broadcasting the latest state
        //m_r_s = most recent state where I received money
        var m_r_s = null;
        var counterparty = am_alice ? "bob" : "alice";
        reversed.every( ( item, index ) => {
            if ( item.from === counterparty ) {
                m_r_s = item;
                return;
            }
            return true;
        });

        //if try_to_cheat is enabled, then instead of broadcasting
        //the latest state, we broadcast the one where we first received
        //money
        if ( try_to_cheat ) {
            state.channel_states.every( ( item, index ) => {
                if ( item.from === counterparty ) {
                    m_r_s = item;
                    return;
                }
                return true;
            });
        }

        //prepare tx1
        var channel_scripts = hedgehog.getChannelScripts( chan_id );
        var [ channel, channel_tree, channel_cblock ] = hedgehog.getAddressData( channel_scripts, 0 );
        var total_in_channel = hedgehog.getBalances( chan_id ).reduce( ( accumulator, currentValue ) => accumulator + currentValue, 0 );
        var tx1 = tapscript.Tx.decode( m_r_s.tx1 );
        //in order to save space in the database, I don't store the prevout of tx1, so here I add it back in
        tx1.vin[ 0 ].prevout = {
            value: total_in_channel,
            scriptPubKey: tapscript.Address.toScriptPubKey( channel ),
        }

        //sign tx1
        var recipients_to_midstate_sig = tapscript.Signer.taproot.sign( privkey, tx1, 0, { extension: channel_tree[ 0 ] }).hex;
        var senders_to_midstate_sig = m_r_s.to_midstate_sig;
        if ( am_alice ) tx1.vin[ 0 ].witness = [ senders_to_midstate_sig, recipients_to_midstate_sig, channel_scripts[ 0 ], channel_cblock ];
        else tx1.vin[ 0 ].witness = [ recipients_to_midstate_sig, senders_to_midstate_sig, channel_scripts[ 0 ], channel_cblock ];

        //prepare tx2
        var am_sender = false;
        var tx1_txid = tapscript.Tx.util.getTxid( m_r_s.tx1 );
        var revhash = m_r_s.absolute_revocation_hash;
        var midstate_scripts = hedgehog.getMidstateScripts( chan_id, am_sender, revhash );
        var [ midstate, midstate_tree, midstate_cblock ] = hedgehog.getAddressData( midstate_scripts, 0 );
        var amnt = m_r_s.amnt;
        var tx2 = hedgehog.getTx2( chan_id, am_sender, tx1_txid, midstate, amnt );

        //sign tx2
        var recipients_finalizer_sig = tapscript.Signer.taproot.sign( privkey, tx2, 0, { extension: midstate_tree[ 0 ] }).hex;
        var senders_finalizer_sig = m_r_s.finalizer_sig;
        if ( am_alice ) tx2.vin[ 0 ].witness = [ senders_finalizer_sig, recipients_finalizer_sig, midstate_scripts[ 0 ], midstate_cblock ];
        else tx2.vin[ 0 ].witness = [ recipients_finalizer_sig, senders_finalizer_sig, midstate_scripts[ 0 ], midstate_cblock ];

        //prepare a tx that pays the fee for tx1
        var addy = tapscript.Address.fromScriptPubKey( [ 1, pubkey ], hedgehog.network );
        if ( !txdata ) {
            console.log( 'send 1000 sats into this address:' );
            console.log( addy );
            var txid2 = prompt( `send 1000 sats into the address in your console and enter the txid` );
            if ( !txid2 ) return;
            var vout2 = Number( prompt( `and the vout` ) );
            var amnt2 = Number( prompt( `and the amount` ) );
        } else {
            var [ txid2, vout2, amnt2 ] = txdata;
        }
        var tx1_txid = tapscript.Tx.util.getTxid( tx1 );
        var tx1_fee = tapscript.Tx.create({
            version: 3,
            vin: [
                hedgehog.getVin( tx1_txid, 1, 240, "51024e73" ),
                hedgehog.getVin( txid2, vout2, amnt2, addy ),
            ],
            vout: [
                hedgehog.getVout( amnt2 - 250, addy ),
            ],
        });
        var fee_sig = tapscript.Signer.taproot.sign( privkey, tx1_fee, 1 ).hex;
        tx1_fee.vin[ 1 ].witness = [ fee_sig ];

        //prepare a tx that pays the fee for tx2
        var tx1_fee_txid = tapscript.Tx.util.getTxid( tx1_fee );
        var tx2_txid = tapscript.Tx.util.getTxid( tx2 );
        var tx2_fee = tapscript.Tx.create({
            version: 3,
            vin: [
                hedgehog.getVin( tx2_txid, 0, 240, "51024e73" ),
                hedgehog.getVin( tx1_fee_txid, 0, amnt2 - 250, addy ),
            ],
            vout: [{
                value: 0,
                scriptPubKey: [ "OP_RETURN", "" ],
            }],
        });
        var fee2_sig = tapscript.Signer.taproot.sign( privkey, tx2_fee, 1 ).hex;
        tx2_fee.vin[ 1 ].witness = [ fee2_sig ];

        //broadcast everything
        return { tx1, tx1_fee, tx2, tx2_fee }
    },
    runBasicTests: async ( test_on_regtest, b_force, disappearance, a_force, justice ) => {
        //prepare a keypair
        var privkey = hedgehog.getPrivkey();
        var pubkey = hedgehog.getPubkey( privkey );
        var preimage = hedgehog.getPrivkey();
        var hash = await hedgehog.sha256( hedgehog.hexToBytes( preimage ) );
        hedgehog.keypairs[ pubkey ] = {privkey, preimage}

        //test opening a channel
        console.log( 'testing opening a channel...' );
        var bobs_pubkey = Object.keys( hedgehog.keypairs )[ 0 ];
        var bobs_hash = await hedgehog.sha256( hedgehog.hexToBytes( hedgehog.keypairs[ bobs_pubkey ].preimage ) );
        var bobs_pubkey_and_hash = [ bobs_pubkey, bobs_hash ];
        var txdata = null;
        var txdata2 = null;
        //txdata2 is used later when testing force closures later. You can test them on regtest or testnet by commenting out the two lines below. If you do, then the openChannel command will prompt you to manually enter a txid, vout, and amount for your funding transaction, and the forceClose command will promt you to manually enter similar data for a transaction that pays the fee for your force closures.
        if ( !test_on_regtest ) {
            txdata = [ "a".repeat( 64 ), 0, 10_000 ];
            txdata2 = [ "a".repeat( 64 ), 0, 1_000 ];
        }
        var show_logs = !txdata2;
        var data_for_bob = await hedgehog.openChannel( bobs_pubkey_and_hash, txdata );
        var channel_is_valid = await hedgehog.openChannel( null, null, data_for_bob );
        console.log( 'channel_is_valid, right?', channel_is_valid );
        console.log( `alice's balance: ${hedgehog.getBalances( data_for_bob.chan_id )[ 0 ]} | bob's balance: ${hedgehog.getBalances( data_for_bob.chan_id )[ 1 ]}` );
        var test0 = "failed";
        if ( channel_is_valid ) test0 = "passed";

        //test sending from bob to alice
        console.log( 'testing a payment of 8000 sats from bob to alice...' );
        var a_chan_id = data_for_bob.chan_id;
        var b_chan_id = "b_" + data_for_bob.chan_id.substring( 2 );
        var data_for_recipient = await hedgehog.send( b_chan_id, 8_000 );
        await hedgehog.receive( data_for_recipient );
        var what_alice_thinks_the_balances_are = hedgehog.getBalances( a_chan_id );
        var what_bob_thinks_the_balances_are = hedgehog.getBalances( b_chan_id );
        var they_agree = ( JSON.stringify( what_alice_thinks_the_balances_are ) === JSON.stringify( what_bob_thinks_the_balances_are ) );
        console.log( `bob's payment to alice worked, right?`, they_agree );
        console.log( `alice's balance: ${hedgehog.getBalances( a_chan_id )[ 0 ]} | bob's balance: ${hedgehog.getBalances( a_chan_id )[ 1 ]}` );
        var test1 = "failed";
        if ( they_agree ) test1 = "passed";

        //test sending from alice to bob
        console.log( 'testing a payment of 2000 sats from alice to bob...' );
        var a_chan_id = data_for_bob.chan_id;
        var b_chan_id = "b_" + data_for_bob.chan_id.substring( 2 );
        var data_for_recipient = await hedgehog.send( a_chan_id, 2_000 );
        await hedgehog.receive( data_for_recipient );
        var what_alice_thinks_the_balances_are = hedgehog.getBalances( a_chan_id );
        var what_bob_thinks_the_balances_are = hedgehog.getBalances( b_chan_id );
        var they_agree = ( JSON.stringify( what_alice_thinks_the_balances_are ) === JSON.stringify( what_bob_thinks_the_balances_are ) );
        console.log( `alice's payment to bob worked, right?`, they_agree );
        console.log( `alice's balance: ${hedgehog.getBalances( a_chan_id )[ 0 ]} | bob's balance: ${hedgehog.getBalances( a_chan_id )[ 1 ]}` );
        var test2 = "failed";
        if ( they_agree ) test2 = "passed";

        //test a second consecutive payment from alice to bob
        console.log( 'testing a second payment from alice to bob of 3_000 sats...' );
        var a_chan_id = data_for_bob.chan_id;
        var b_chan_id = "b_" + data_for_bob.chan_id.substring( 2 );
        var data_for_recipient = await hedgehog.send( a_chan_id, 3_000 );
        await hedgehog.receive( data_for_recipient );
        var what_alice_thinks_the_balances_are = hedgehog.getBalances( a_chan_id );
        var what_bob_thinks_the_balances_are = hedgehog.getBalances( b_chan_id );
        var they_agree = ( JSON.stringify( what_alice_thinks_the_balances_are ) === JSON.stringify( what_bob_thinks_the_balances_are ) );
        console.log( `alice's second payment to bob worked, right?`, they_agree );
        console.log( `alice's balance: ${hedgehog.getBalances( a_chan_id )[ 0 ]} | bob's balance: ${hedgehog.getBalances( a_chan_id )[ 1 ]}` );
        var test3 = "failed";
        if ( they_agree ) test3 = "passed";

        //test two payments from bob to alice, where alice does not notice the first
        console.log( 'testing two payments from bob to alice of 2_000 sats apiece...' );
        console.log( 'note that alice will not notice the first one...' );
        var a_chan_id = data_for_bob.chan_id;
        var b_chan_id = "b_" + data_for_bob.chan_id.substring( 2 );
        var data_for_recipient = await hedgehog.send( b_chan_id, 2_000 );
        // await hedgehog.receive( data_for_recipient );
        var data_for_recipient = await hedgehog.send( b_chan_id, 2_000 );
        await hedgehog.receive( data_for_recipient );
        var what_alice_thinks_the_balances_are = hedgehog.getBalances( a_chan_id );
        var what_bob_thinks_the_balances_are = hedgehog.getBalances( b_chan_id );
        var they_agree = ( JSON.stringify( what_alice_thinks_the_balances_are ) === JSON.stringify( what_bob_thinks_the_balances_are ) );
        console.log( `bob's two payments to alice worked, right?`, they_agree );
        console.log( `alice's balance: ${hedgehog.getBalances( a_chan_id )[ 0 ]} | bob's balance: ${hedgehog.getBalances( a_chan_id )[ 1 ]}` );
        var test4 = "failed";
        if ( they_agree ) test4 = "passed";

        //test two payments from alice to bob, where bob does not notice the first
        console.log( 'testing two payments from alice to bob of 2_000 sats apiece...' );
        console.log( 'note that bob will not notice the first one...' );
        var a_chan_id = data_for_bob.chan_id;
        var b_chan_id = "b_" + data_for_bob.chan_id.substring( 2 );
        var data_for_recipient = await hedgehog.send( a_chan_id, 2_000 );
        // await hedgehog.receive( data_for_recipient );
        var data_for_recipient = await hedgehog.send( a_chan_id, 2_000 );
        await hedgehog.receive( data_for_recipient );
        var what_alice_thinks_the_balances_are = hedgehog.getBalances( a_chan_id );
        var what_bob_thinks_the_balances_are = hedgehog.getBalances( b_chan_id );
        var they_agree = ( JSON.stringify( what_alice_thinks_the_balances_are ) === JSON.stringify( what_bob_thinks_the_balances_are ) );
        console.log( `alice's two payments to bob worked, right?`, they_agree );
        console.log( `alice's balance: ${hedgehog.getBalances( a_chan_id )[ 0 ]} | bob's balance: ${hedgehog.getBalances( a_chan_id )[ 1 ]}` );
        var test5 = "failed";
        if ( they_agree ) test5 = "passed";

        //test two payments from bob to alice, where alice notices both
        console.log( 'testing two payments from bob to alice of 2_000 sats apiece...' );
        console.log( 'note that alice will notice both...' );
        var a_chan_id = data_for_bob.chan_id;
        var b_chan_id = "b_" + data_for_bob.chan_id.substring( 2 );
        var data_for_recipient = await hedgehog.send( b_chan_id, 2_000 );
        await hedgehog.receive( data_for_recipient );
        var data_for_recipient = await hedgehog.send( b_chan_id, 2_000 );
        await hedgehog.receive( data_for_recipient );
        var what_alice_thinks_the_balances_are = hedgehog.getBalances( a_chan_id );
        var what_bob_thinks_the_balances_are = hedgehog.getBalances( b_chan_id );
        var they_agree = ( JSON.stringify( what_alice_thinks_the_balances_are ) === JSON.stringify( what_bob_thinks_the_balances_are ) );
        console.log( `bob's two payments to alice worked, right?`, they_agree );
        console.log( `alice's balance: ${hedgehog.getBalances( a_chan_id )[ 0 ]} | bob's balance: ${hedgehog.getBalances( a_chan_id )[ 1 ]}` );
        var test6 = "failed";
        if ( they_agree ) test6 = "passed";

        //test three payments from alice to bob, where bob notices all of them
        console.log( 'testing three payments from alice to bob of 2_000 sats apiece...' );
        console.log( 'note that bob will notice all of them...' );
        var a_chan_id = data_for_bob.chan_id;
        var b_chan_id = "b_" + data_for_bob.chan_id.substring( 2 );
        var data_for_recipient = await hedgehog.send( a_chan_id, 2_000 );
        await hedgehog.receive( data_for_recipient );
        var data_for_recipient = await hedgehog.send( a_chan_id, 2_000 );
        await hedgehog.receive( data_for_recipient );
        var data_for_recipient = await hedgehog.send( a_chan_id, 2_000 );
        await hedgehog.receive( data_for_recipient );
        var what_alice_thinks_the_balances_are = hedgehog.getBalances( a_chan_id );
        var what_bob_thinks_the_balances_are = hedgehog.getBalances( b_chan_id );
        var they_agree = ( JSON.stringify( what_alice_thinks_the_balances_are ) === JSON.stringify( what_bob_thinks_the_balances_are ) );
        console.log( `alice's three payments to bob worked, right?`, they_agree );
        console.log( `alice's balance: ${hedgehog.getBalances( a_chan_id )[ 0 ]} | bob's balance: ${hedgehog.getBalances( a_chan_id )[ 1 ]}` );
        var test7 = "failed";
        if ( they_agree ) test7 = "passed";

        //test a force closure by bob when he has the latest state
        console.log( 'testing a force closure by bob when he has the latest state...' );
        var b_chan_id = "b_" + data_for_bob.chan_id.substring( 2 );
        //the txid variable is used for checking if your counterparty broadcasted the latest state.
        //if you detect that your counterparty broadcasted tx1 of the force closure transactions,
        //you can get its txid and pass it to the forceClose command, and if your counterparty did
        //*not* broadcast the latest state, it will do one of two things: if they broadcasted a
        //state that they *fully* revoked, it will return a justice transaction that takes their
        //money; if they broadcasted a state that they *conditionally* revoked, it will return a
        //transaction that updates the state to the latest one
        var txid = null;
        var test8;
        console.log( 0 );
        if ( b_force || disappearance ) {
            console.log( 1 );
            if ( test_on_regtest && ( b_force || disappearance ) ) alert( `we are about to test a force closure by bob, so you will be prompted to send additional money in so that he may cover the fees associated with his force closure` );
            var force_closure_txs = await hedgehog.forceClose( b_chan_id, txid, txdata2 );
            var { tx1, tx1_fee, tx2, tx2_fee } = force_closure_txs;
            if ( b_force && show_logs ) {
                console.log( 'broadcast this to create the midstate:' );
                console.log( tapscript.Tx.encode( tx1 ).hex );
                console.log( 'broadcast this to pay the fee:' );
                console.log( tapscript.Tx.encode( tx1_fee ).hex );
                console.log( 'then wait 2 weeks' );
                console.log( 'then broadcast this to finalize your state:' );
                console.log( tapscript.Tx.encode( tx2 ).hex );
                console.log( 'broadcast this to pay the fee:' );
                console.log( tapscript.Tx.encode( tx2_fee ).hex );
            }
            console.log( `alice got the amount she should, right?`, tx2.vout[ 1 ][ "value" ] === hedgehog.getBalances( a_chan_id )[ 0 ] );
            console.log( `bob got the amount he should, right?`, tx2.vout[ 2 ][ "value" ] === hedgehog.getBalances( a_chan_id )[ 1 ] - 480 );
            test8 = "failed";
            if ( tx2.vout[ 1 ][ "value" ] === hedgehog.getBalances( a_chan_id )[ 0 ] && hedgehog.getBalances( a_chan_id )[ 1 ] - 480 ) test8 = "passed";
        }
        if ( b_force ) return { test0, test1, test2, test3, test4, test5, test6, test7, test8 };

        //test that alice can recover the money bob abandoned if bob disappears before broadcasting tx2
        var test9;
        if ( disappearance ) {
            console.log( 'testing that alice can recover the money bob abandoned if bob disappears before broadcasting tx2...' );
            var a_chan_id = data_for_bob.chan_id;
            var tx1_txid = tapscript.Tx.util.getTxid( tx1 );
            var { disappearance_tx } = await hedgehog.forceClose( a_chan_id, tx1_txid );
            var total_in_channel = hedgehog.getBalances( a_chan_id ).reduce( ( accumulator, currentValue ) => accumulator + currentValue, 0 );
            if ( show_logs ) {
                console.log( 'broadcast this to create the midstate:' );
                console.log( tapscript.Tx.encode( tx1 ).hex );
                console.log( 'wait 2026 blocks' );
                console.log( 'broadcast this disappearance_tx transaction because Bob never broadcasted tx2:' );
                console.log( tapscript.Tx.encode( disappearance_tx ).hex );
            }
            console.log( 'alice can sweep everything after 2026 blocks, right?', disappearance_tx.vout[ 0 ].value === total_in_channel - 240 - 500 );
            test9 = "failed";
            if ( disappearance_tx.vout[ 0 ].value === total_in_channel - 240 - 500 ) test9 = "passed";
            if ( disappearance ) return { test0, test1, test2, test3, test4, test5, test6, test7, test8, test9 };
        }

        //test a force closure by alice when she does *not* have the latest state
        console.log( 'testing a force closure by alice when she does *not* have the latest state...' );
        var a_chan_id = data_for_bob.chan_id;
        var b_chan_id = "b_" + data_for_bob.chan_id.substring( 2 );
        var txid = null;
        if ( test_on_regtest ) alert( `we are about to test a force closure by alice in a situation where she does not have the latest state. Consequently, you will be prompted to send additional money in so that she may cover the fees associated with her force closure` );
        var alices_force_closure_txs = await hedgehog.forceClose( a_chan_id, txid, txdata2 );
        var { tx1, tx1_fee } = alices_force_closure_txs;
        var tx1_txid = tapscript.Tx.util.getTxid( tx1 );
        if ( test_on_regtest && a_force ) alert( `since Alice did not have the latest state, she broadcasted the previous state, and bob will have to finalize it in the latest state so that he does not lose any money; consequently, bob will need to broadcast a transaction, and therefore you will be prompted *again* to send in *even more* additional money in so that he may cover the fees required to finalize the state` );
        var test10;
        if ( a_force ) {
            var bobs_force_closure_txs = await hedgehog.forceClose( b_chan_id, tx1_txid, txdata2 );
            var { alt_tx2: tx2, tx2_fee } = bobs_force_closure_txs;
            if ( show_logs ) {
                console.log( 'broadcast this to create the midstate:' );
                console.log( tapscript.Tx.encode( tx1 ).hex );
                console.log( 'broadcast this to pay the fee:' );
                console.log( tapscript.Tx.encode( tx1_fee ).hex );
                console.log( 'broadcast this to finalize in the latest state:' );
                console.log( tapscript.Tx.encode( tx2 ).hex );
                console.log( 'broadcast this to pay the fee:' );
                console.log( tapscript.Tx.encode( tx2_fee ).hex );
            }
            console.log( `alice got the amount she should, right?`, tx2.vout[ 1 ][ "value" ] === hedgehog.getBalances( b_chan_id )[ 0 ], tx2.vout[ 1 ][ "value" ], hedgehog.getBalances( b_chan_id )[ 0 ] );
            console.log( `bob got the amount he should, right?`, tx2.vout[ 2 ][ "value" ] === hedgehog.getBalances( b_chan_id )[ 1 ] - 480, tx2.vout[ 2 ][ "value" ], hedgehog.getBalances( b_chan_id )[ 1 ] );
            test10 = "failed";
            if ( tx2.vout[ 1 ][ "value" ] === hedgehog.getBalances( b_chan_id )[ 0 ] && hedgehog.getBalances( b_chan_id )[ 1 ] - 480 ) test10 = "passed";
            return { test0, test1, test2, test3, test4, test5, test6, test7, test8, test9, test10 }
        }

        //test a force closure by bob when she does *not* have the latest state
        console.log( 'testing a force closure by alice when she does *not* have the latest state...' );
        var a_chan_id = data_for_bob.chan_id;
        var b_chan_id = "b_" + data_for_bob.chan_id.substring( 2 );
        var txid = null;
    },
    runHTLCTests: async test_on_regtest => {
        //prepare a keypair
        var privkey = hedgehog.getPrivkey();
        var pubkey = hedgehog.getPubkey( privkey );
        var preimage = hedgehog.getPrivkey();
        var hash = await hedgehog.sha256( hedgehog.hexToBytes( preimage ) );
        hedgehog.keypairs[ pubkey ] = {privkey, preimage}

        //test opening a channel
        console.log( 'testing opening a channel...' );
        var bobs_pubkey = Object.keys( hedgehog.keypairs )[ 0 ];
        var bobs_hash = await hedgehog.sha256( hedgehog.hexToBytes( hedgehog.keypairs[ bobs_pubkey ].preimage ) );
        var bobs_pubkey_and_hash = [ bobs_pubkey, bobs_hash ];
        var txdata = null;
        var txdata2 = null;
        //txdata2 is used later when testing force closures later. You can test them on regtest or testnet by commenting out the two lines below. If you do, then the openChannel command will prompt you to manually enter a txid, vout, and amount for your funding transaction, and the forceClose command will promt you to manually enter similar data for a transaction that pays the fee for your force closures.
        if ( !test_on_regtest ) {
            txdata = [ "a".repeat( 64 ), 0, 10_000 ];
            txdata2 = [ "a".repeat( 64 ), 0, 1_000 ];
        }
        var show_logs = !txdata2;
        var data_for_bob = await hedgehog.openChannel( bobs_pubkey_and_hash, txdata );
        var channel_is_valid = await hedgehog.openChannel( null, null, data_for_bob );
        console.log( 'channel_is_valid, right?', channel_is_valid );
        console.log( `alice's balance: ${hedgehog.getBalances( data_for_bob.chan_id )[ 0 ]} | bob's balance: ${hedgehog.getBalances( data_for_bob.chan_id )[ 1 ]}` );
        var test0 = "failed";
        if ( channel_is_valid ) test0 = "passed";

        //test sending an HTLC from bob to alice
        console.log( 'testing an HTLC payment of 8000 sats from bob to alice...' );
        var a_chan_id = data_for_bob.chan_id;
        var b_chan_id = "b_" + data_for_bob.chan_id.substring( 2 );
        var chan_id = b_chan_id;
        var amnt = 8_000;
        var htlc_locktime = 20;
        var pmthash = await hedgehog.sendHtlc( chan_id, amnt, htlc_locktime );
        var preimage = await hedgehog.findPreimage( chan_id, pmthash );
        await hedgehog.resolveHtlcAsSender( chan_id, preimage );
        console.log( 'yay' );
    },
    runAllTests: async () => {
        var test_on_regtest = confirm( `click ok if you want to test on regtest, which requires manually entering transaction data. Otherwise click cancel and we will just assume the signatures generated by these tests are valid` );
        var b_force = await hedgehog.runBasicTests( test_on_regtest, true );
        var disappearance = await hedgehog.runBasicTests( test_on_regtest, false, true );
        var a_force = await hedgehog.runBasicTests( test_on_regtest, false, false, true );
        console.log( 'in these tests, Bob force closes the channel in the latest state:' );
        console.log( b_force );
        console.log( 'in these tests, Bob initiates a force closure but then disappears before finalizing, so Alice sweeps the funds:' );
        console.log( disappearance );
        console.log( 'in these tests, Alice force closes the channel in the previous state, and Bob corrects it:' );
        console.log( a_force );
        console.log( 'note that in the above example, it is okay for test8 and test9 to be undefined because we did not run test8 or test9, which are only relevant when Bob initiates a force closure' );
    },
    communicateWithUser: async data_for_user => {
        throw( 'batteries not included -- you are supposed to overwrite this function with something that *actually* communicates with the user' );
    }
}

var super_nostr = {
    sockets: {},
    hexToBytes: hex => Uint8Array.from( hex.match( /.{1,2}/g ).map( byte => parseInt( byte, 16 ) ) ),
    bytesToHex: bytes => bytes.reduce( ( str, byte ) => str + byte.toString( 16 ).padStart( 2, "0" ), "" ),
    hexToBase64: hex => btoa( hex.match( /\w{2}/g ).map( a => String.fromCharCode( parseInt( a, 16 ) ) ).join( "" ) ),
    base64ToHex: str => {
        var raw = atob( str );
        var result = '';
        var i; for ( i=0; i<raw.length; i++ ) {
            var hex = raw.charCodeAt( i ).toString( 16 );
            result += hex.length % 2 ? '0' + hex : hex;
        }
        return result.toLowerCase();
    },
    base64ToBytes: str => {
        var raw = atob( str );
        var result = [];
        var i; for ( i=0; i<raw.length; i++ ) result.push( raw.charCodeAt( i ) );
        return new Uint8Array( result );
    },
    getPrivkey: () => super_nostr.bytesToHex( nobleSecp256k1.utils.randomPrivateKey() ),
    getPubkey: privkey => nobleSecp256k1.getPublicKey( privkey, true ).substring( 2 ),
    sha256: async text_or_bytes => {if ( typeof text_or_bytes === "string" ) text_or_bytes = ( new TextEncoder().encode( text_or_bytes ) );return super_nostr.bytesToHex( await nobleSecp256k1.utils.sha256( text_or_bytes ) )},
    waitSomeSeconds: num => {
        var num = num.toString() + "000";
        num = Number( num );
        return new Promise( resolve => setTimeout( resolve, num ) );
    },
    getEvents: async ( relay_or_socket, ids, authors, kinds, until, since, limit, etags, ptags ) => {
        var socket_is_permanent = false;
        if ( typeof relay_or_socket !== "string" ) socket_is_permanent = true;
        if ( typeof relay_or_socket === "string" ) var socket = new WebSocket( relay_or_socket );
        else var socket = relay_or_socket;
        var events = [];
        var opened = false;
        if ( socket_is_permanent ) {
            var subId = super_nostr.bytesToHex( nobleSecp256k1.utils.randomPrivateKey() ).substring( 0, 16 );
            var filter  = {}
            if ( ids ) filter.ids = ids;
            if ( authors ) filter.authors = authors;
            if ( kinds ) filter.kinds = kinds;
            if ( until ) filter.until = until;
            if ( since ) filter.since = since;
            if ( limit ) filter.limit = limit;
            if ( etags ) filter[ "#e" ] = etags;
            if ( ptags ) filter[ "#p" ] = ptags;
            var subscription = [ "REQ", subId, filter ];
            socket.send( JSON.stringify( subscription ) );
            return;
        }
        socket.addEventListener( 'message', async function( message ) {
            var [ type, subId, event ] = JSON.parse( message.data );
            var { kind, content } = event || {}
            if ( !event || event === true ) return;
            events.push( event );
        });
        socket.addEventListener( 'open', async function( e ) {
            opened = true;
            var subId = super_nostr.bytesToHex( nobleSecp256k1.utils.randomPrivateKey() ).substring( 0, 16 );
            var filter  = {}
            if ( ids ) filter.ids = ids;
            if ( authors ) filter.authors = authors;
            if ( kinds ) filter.kinds = kinds;
            if ( until ) filter.until = until;
            if ( since ) filter.since = since;
            if ( limit ) filter.limit = limit;
            if ( etags ) filter[ "#e" ] = etags;
            if ( ptags ) filter[ "#p" ] = ptags;
            var subscription = [ "REQ", subId, filter ];
            socket.send( JSON.stringify( subscription ) );
        });
        var loop = async () => {
            if ( !opened ) {
                await super_nostr.waitSomeSeconds( 1 );
                return await loop();
            }
            var len = events.length;
            await super_nostr.waitSomeSeconds( 1 );
            if ( len !== events.length ) return await loop();
            socket.close();
            return events;
        }
        return await loop();
    },
    prepEvent: async ( privkey, msg, kind, tags ) => {
        pubkey = super_nostr.getPubkey( privkey );
        if ( !tags ) tags = [];
        var event = {
            "content": msg,
            "created_at": Math.floor( Date.now() / 1000 ),
            "kind": kind,
            "tags": tags,
            "pubkey": pubkey,
        }
        var signedEvent = await super_nostr.getSignedEvent( event, privkey );
        return signedEvent;
    },
    sendEvent: ( event, relay_or_socket ) => {
        var socket_is_permanent = false;
        if ( typeof relay_or_socket !== "string" ) socket_is_permanent = true;
        if ( typeof relay_or_socket === "string" ) var socket = new WebSocket( relay_or_socket );
        else var socket = relay_or_socket;
        if ( !socket_is_permanent ) {
            socket.addEventListener( 'open', async () => {
                socket.send( JSON.stringify( [ "EVENT", event ] ) );
                setTimeout( () => {socket.close();}, 1000 );
            });
        } else {
            socket.send( JSON.stringify( [ "EVENT", event ] ) );
        }
        return event.id;
    },
    getSignedEvent: async ( event, privkey ) => {
        var eventData = JSON.stringify([
            0,
            event['pubkey'],
            event['created_at'],
            event['kind'],
            event['tags'],
            event['content'],
        ]);
        event.id = await super_nostr.sha256( eventData );
        event.sig = await nobleSecp256k1.schnorr.sign( event.id, privkey );
        return event;
    },
    //the "alt_encrypt" and "alt_decrypt" functions are
    //alternatives to the defaults; I think they are
    //better because they eliminate the dependency
    //on browserify-cipher, but they are asynchronous
    //and I already made so much stuff with this library
    //that assumes synchronicity, I don't want to change
    //it all
    alt_encrypt: async ( privkey, pubkey, text ) => {
        var msg = ( new TextEncoder() ).encode( text );
        var iv = crypto.getRandomValues( new Uint8Array( 16 ) );
        var key_raw = super_nostr.hexToBytes( nobleSecp256k1.getSharedSecret( privkey, '02' + pubkey, true ).substring( 2 ) );
        var key = await crypto.subtle.importKey(
            "raw",
            key_raw,
            "AES-CBC",
            false,
            [ "encrypt", "decrypt" ],
        );
        var emsg = await crypto.subtle.encrypt(
            {
                name: "AES-CBC",
                iv,
            },
            key,
            msg,
        )
        emsg = new Uint8Array( emsg );
        var arr = emsg;
        emsg = super_nostr.hexToBase64( super_nostr.bytesToHex( emsg ) ) + "?iv=" + btoa( String.fromCharCode.apply( null, iv ) );
        return emsg;
    },
    alt_decrypt: async ( privkey, pubkey, ciphertext ) => {
        var [ emsg, iv ] = ciphertext.split( "?iv=" );
        var key_raw = super_nostr.hexToBytes( nobleSecp256k1.getSharedSecret( privkey, '02' + pubkey, true ).substring( 2 ) );
        var key = await crypto.subtle.importKey(
            "raw",
            key_raw,
            "AES-CBC",
            false,
            [ "encrypt", "decrypt" ],
        );
        var decrypted = await crypto.subtle.decrypt(
            {
                name: "AES-CBC",
                iv: super_nostr.base64ToBytes( iv ),
            },
            key,
            super_nostr.base64ToBytes( emsg ),
        );
        var msg = ( new TextDecoder() ).decode( decrypted );
        return msg;
    },
    encrypt: ( privkey, pubkey, text ) => {
        var key = nobleSecp256k1.getSharedSecret( privkey, '02' + pubkey, true ).substring( 2 );
        var iv = crypto.getRandomValues( new Uint8Array( 16 ) );
        var cipher = browserifyCipher.createCipheriv( 'aes-256-cbc', super_nostr.hexToBytes( key ), iv );
        var encryptedMessage = cipher.update(text,"utf8","base64");
        emsg = encryptedMessage + cipher.final( "base64" );
        var uint8View = new Uint8Array( iv.buffer );
        var decoder = new TextDecoder();
        return emsg + "?iv=" + btoa( String.fromCharCode.apply( null, uint8View ) );
    },
    decrypt: ( privkey, pubkey, ciphertext ) => {
        var [ emsg, iv ] = ciphertext.split( "?iv=" );
        var key = nobleSecp256k1.getSharedSecret( privkey, '02' + pubkey, true ).substring( 2 );
        var decipher = browserifyCipher.createDecipheriv(
            'aes-256-cbc',
            super_nostr.hexToBytes( key ),
            super_nostr.hexToBytes( super_nostr.base64ToHex( iv ) )
        );
        var decryptedMessage = decipher.update( emsg, "base64" );
        dmsg = decryptedMessage + decipher.final( "utf8" );
        return dmsg;
    },
    //var listenFunction = async socket => {
    //    var subId = super_nostr.bytesToHex( crypto.getRandomValues( new Uint8Array( 8 ) ) );
    //    var filter  = {}
    //    filter.kinds = [ 1 ];
    //    filter.limit = 1;
    //    filter.since = Math.floor( Date.now() / 1000 ) - 86400;
    //    var subscription = [ "REQ", subId, filter ];
    //    socket.send( JSON.stringify( subscription ) );
    //}
    //var handleFunction = async message => {
    //    var [ type, subId, event ] = JSON.parse( message.data );
    //    if ( !event || event === true ) return;
    //    console.log( event );
    //}
    newPermanentConnection: ( relay, listenFunction, handleFunction ) => {
        var socket_id = super_nostr.bytesToHex( nobleSecp256k1.utils.randomPrivateKey() ).substring( 0, 16 );
        super_nostr.sockets[ socket_id ] = {socket: null, connection_failure: false}
        super_nostr.connectionLoop( 0, relay, socket_id, listenFunction, handleFunction );
        return socket_id;
    },
    connectionLoop: async ( tries = 0, relay, socket_id, listenFunction, handleFunction ) => {
        var socketRetrieverFunction = socket_id => {
            return super_nostr.sockets[ socket_id ][ "socket" ];
        }
        var socketReplacerFunction = ( socket_id, socket ) => {
            super_nostr.sockets[ socket_id ][ "socket" ] = socket;
            super_nostr.sockets[ socket_id ][ "connection_failure" ] = false;
        }
        var socketFailureCheckerFunction = socket_id => {
            return super_nostr.sockets[ socket_id ][ "connection_failure" ];
        }
        var socketFailureSetterFunction = socket_id => {
            return super_nostr.sockets[ socket_id ][ "connection_failure" ] = true;
        }
        if ( socketFailureCheckerFunction( socket_id ) ) return console.log( `your connection to nostr failed and could not be restarted, please restart the app` );
        var socket = socketRetrieverFunction( socket_id );
        if ( !socket ) {
            var socket = new WebSocket( relay );
            socket.addEventListener( 'message', handleFunction );
            socket.addEventListener( 'open', ()=>{listenFunction( socket );} );
            socketReplacerFunction( socket_id, socket );
        }
        if ( socket.readyState === 1 ) {
            await super_nostr.waitSomeSeconds( 1 );
            return super_nostr.connectionLoop( 0, relay, socket_id, listenFunction, handleFunction );
        }
        // if there is no connection, check if we are still connecting
        // give it two chances to connect if so
        if ( socket.readyState === 0 && !tries ) {
            await super_nostr.waitSomeSeconds( 1 );
            return super_nostr.connectionLoop( 1, relay, socket_id, listenFunction, handleFunction );
        }
        if ( socket.readyState === 0 && tries ) {
            socketFailureSetterFunction( socket_id );
            return;
        }
        // otherwise, it is either closing or closed
        // ensure it is closed, then make a new connection
        socket.close();
        await super_nostr.waitSomeSeconds( 1 );
        socket = new WebSocket( relay );
        socket.addEventListener( 'message', handleFunction );
        socket.addEventListener( 'open', ()=>{listenFunction( socket );} );
        socketReplacerFunction( socket_id, socket );
        await super_nostr.connectionLoop( 0, relay, socket_id, listenFunction, handleFunction );
    },
}

var queryElectrum = async ( username, password, endpoint, method, params = {}, debug )=>{
    var headers = new Headers();
    headers.append( 'Content-Type', 'application/json' ); 
    headers.append( 'Authorization', 'Basic ' + btoa( `${username}:${password}` ) );
    var body = {
        jsonrpc: '2.0',
        id: 'curltext',
        method,
        params,
    };
    var request = await fetch( endpoint, {
        method: 'POST',
        headers: headers,
        body: JSON.stringify( body ), 
    });
    if ( debug ) console.log( request );
    var json = await request.json();
    return json;
}

var hedgehog_server = {
    network: "testnet4/",
    explorer: "mempool.space",
    data_for_channel_opens: {},
    two_way_comms: {},
    comms_keys: {},
    isValidHex: hex => {
        if ( !hex ) return;
        var length = hex.length;
        if ( length % 2 ) return;
        try {
            var bigint = BigInt( "0x" + hex, "hex" );
        } catch( e ) {
            return;
        }
        var prepad = bigint.toString( 16 );
        var i; for ( i=0; i<length; i++ ) prepad = "0" + prepad;
        var padding = prepad.slice( -Math.abs( length ) );
        return ( padding === hex );
    },
    listenOnNostr: async nostr_pubkey => {
        var listenFunction = async socket => {
            var subId = super_nostr.bytesToHex( crypto.getRandomValues( new Uint8Array( 8 ) ) );
            var filter  = {}
            filter.kinds = [ 4 ];
            filter[ "#p" ] = [ nostr_pubkey ];
            filter.since = Math.floor( Date.now() / 1000 );
            var subscription = [ "REQ", subId, filter ];
            socket.send( JSON.stringify( subscription ) );
        }
        var handleFunction = async message => {
            var [ type, subId, event ] = JSON.parse( message.data );
            if ( !event || event === true ) return;
            try {
                event.content = await super_nostr.alt_decrypt( nostr_privkey, event.pubkey, event.content );
                var json = JSON.parse( event.content );
                console.log( json );
                if ( json.msg_type === "two_way_comms" ) {
                    var msg_id = json.msg_value.message_identifier;
                    var privkey = nostr_privkey;
                    var counterparty_pubkey = event.pubkey;
                    if ( json.msg_value.hasOwnProperty( "more_message_info" ) && json.msg_value.more_message_info === "htlc_to_server_part_one" ) {

                        //parse the message from the user
                        var data_for_htlc_p1 = json.msg_value;
                        delete data_for_htlc_p1[ "message_identifier" ];
                        delete data_for_htlc_p1[ "more_message_info" ];
                        var my_revhashes = await hedgehog.receiveHtlcPartOne( data_for_htlc_p1 );

                        //send channel data to user
                        var msg_for_counterparty = JSON.stringify({
                            msg_type: "two_way_comms",
                            msg_value: {message_identifier: msg_id, data_for_counterparty: my_revhashes, more_message_info: "htlc_to_server_part_two"},
                        });
                        var emsg = await super_nostr.alt_encrypt( privkey, counterparty_pubkey, msg_for_counterparty );
                        var event = await super_nostr.prepEvent( privkey, emsg, 4, [ [ "p", counterparty_pubkey ] ] );
                        super_nostr.sendEvent( event, nostr_relays[ 0 ] );

                        return;
                    }
                    if ( json.msg_value.hasOwnProperty( "more_message_info" ) && json.msg_value.more_message_info === "htlc_to_server_part_three" ) {

                        //parse the message from the server
                        var data_for_htlc_p2 = json.msg_value;
                        delete data_for_htlc_p2[ "message_identifier" ];
                        delete data_for_htlc_p2[ "more_message_info" ];
                        var data_for_counterparty = await hedgehog.receiveHtlcPartTwo( data_for_htlc_p2 );

                        //send channel data to user
                        var msg_for_counterparty = JSON.stringify({
                            msg_type: "two_way_comms",
                            msg_value: {message_identifier: msg_id, data_for_counterparty, more_message_info: "htlc_to_server_part_four"},
                        });
                        var emsg = await super_nostr.alt_encrypt( privkey, counterparty_pubkey, msg_for_counterparty );
                        var event = await super_nostr.prepEvent( privkey, emsg, 4, [ [ "p", counterparty_pubkey ] ] );
                        super_nostr.sendEvent( event, nostr_relays[ 0 ] );
                    }

                    if ( json.msg_value.hasOwnProperty( "more_message_info" ) && json.msg_value.more_message_info === "htlc_to_server_part_five" ) {

                        var data_for_htlc_p3 = json.msg_value;
                        delete data_for_htlc_p3[ "message_identifier" ];
                        delete data_for_htlc_p3[ "more_message_info" ];
                        var data_for_counterparty = await hedgehog.receiveHtlcPartThree( data_for_htlc_p3 );

                        //send channel data to server
                        var msg_for_counterparty = JSON.stringify({
                            msg_type: "two_way_comms",
                            msg_value: {message_identifier: msg_id, data_for_counterparty, more_message_info: "htlc_to_server_part_six"},
                        });
                        var emsg = await super_nostr.alt_encrypt( privkey, counterparty_pubkey, msg_for_counterparty );
                        var event = await super_nostr.prepEvent( privkey, emsg, 4, [ [ "p", counterparty_pubkey ] ] );
                        super_nostr.sendEvent( event, nostr_relays[ 0 ] );
                    }

                    hedgehog_server.two_way_comms[ msg_id ] = json.msg_value.data_for_server;
                    return;
                }
                if ( json.msg_type === "get_check_status" ) {
                    //prepare requisite variables
                    var { encrypted_chan_id, check_pmthash, check_amnt, encryption_pubkey, check_absolute_timelock } = json.msg_value;
                    var privkey = nostr_privkey;
                    var counterparty_pubkey = event.pubkey;
                    var chan_id = await super_nostr.alt_decrypt( privkey, encryption_pubkey, encrypted_chan_id );
                    chan_id = "b_" + chan_id.substring( 2 );
                    var error = null;
                    if ( !hedgehog.state.hasOwnProperty( chan_id ) ) {
                        error = 'irredeemable';
                    } else {
                        var state = hedgehog.state[ chan_id ];
                        var am_alice = !!state.alices_priv;

                        //find relevant pending htlc
                        var pmthash = check_pmthash;
                        var index_of_pending_htlc = -1;
                        var amnt_of_pending_htlc = null;
                        var pending_htlcs = [];
                        var latest_state = state.channel_states[ state.channel_states.length - 1 ];
                        if ( latest_state && latest_state.hasOwnProperty( "pending_htlcs" ) ) pending_htlcs = latest_state.pending_htlcs;
                        if ( !pending_htlcs.length ) error = "irredeemable";
                        pending_htlcs.every( ( htlc, index ) => {
                            if ( htlc.pmthash !== pmthash ) return true;
                            if ( htlc.sender !== "alice" ) return true;
                            index_of_pending_htlc = index;
                            amnt_of_pending_htlc = htlc.amnt;
                        });
                        if ( index_of_pending_htlc < 0 ) error = "irredeemable";

                        //check timelock info
                        //TODO: allow absolute timelocks other than 0
                        //TODO: also compare it with the one in the actual htlc
                        if ( check_absolute_timelock !== 0 ) error = "irredeemable";

                        //ensure amount matches
                        var pending_htlc = pending_htlcs[ index_of_pending_htlc ];
                        if ( pending_htlc.amnt !== check_amnt ) error = "irredeemable";
                    }

                    var msg_for_counterparty = JSON.stringify({
                        msg_type: "get_check_status_reply",
                        msg_value: error || "redeemable",
                    });
                    var emsg = await super_nostr.alt_encrypt( privkey, counterparty_pubkey, msg_for_counterparty );
                    var event = await super_nostr.prepEvent( privkey, emsg, 4, [ [ "p", counterparty_pubkey ] ] );
                    super_nostr.sendEvent( event, nostr_relays[ 0 ] );
                }
                if ( json.msg_type === "pay_ln_invoice_for_user" ) {
                    //prepare requisite variables
                    var { encrypted_chan_id, invoice, encryption_pubkey } = json.msg_value;
                    var privkey = nostr_privkey;
                    var user_pubkey = event.pubkey;
                    var chan_id = await super_nostr.alt_decrypt( privkey, encryption_pubkey, encrypted_chan_id );
                    chan_id = "b_" + chan_id.substring( 2 );
                    var state = hedgehog.state[ chan_id ];
                    var am_alice = !!state.alices_priv;

                    //find the pending htlc
                    var pmthash = hedgehog_server.getInvoicePmthash( invoice );
                    var index_of_pending_htlc = -1;
                    var amnt_of_pending_htlc = null;
                    var pending_htlcs = [];
                    var latest_state = state.channel_states[ state.channel_states.length - 1 ];
                    if ( latest_state && latest_state.hasOwnProperty( "pending_htlcs" ) ) pending_htlcs = latest_state.pending_htlcs;
                    //TODO: send back an error message
                    if ( !pending_htlcs.length ) return console.log( 'aborting because an unknown person wants to resolve an htlc that does not exist' );
                    pending_htlcs.every( ( htlc, index ) => {
                        if ( htlc.pmthash !== pmthash ) return true;
                        if ( am_alice && htlc.sender === "alice" ) return true;
                        if ( !am_alice && htlc.sender === "bob" ) return true;
                        index_of_pending_htlc = index;
                        amnt_of_pending_htlc = htlc.amnt;
                    });
                    //TODO: send back an error message
                    if ( index_of_pending_htlc < 0 ) return console.log( 'aborting because an unknown person wants to resolve an htlc that does not exist' );
                    var pending_htlc = pending_htlcs[ index_of_pending_htlc ];
                    //TODO: send back an error message
                    if ( pending_htlc.sender === "bob" && !am_alice || pending_htlc.sender === "alice" && am_alice ) return console.log( 'aborting because an unknown person wants to resolve an htlc that does not pay you' );

                    //ensure the invoice is worth a value equal to or less than the htlc
                    var invoice_amnt = hedgehog_server.getInvoiceAmount( invoice );
                    //TODO: send back an error message
                    if ( invoice_amnt > pending_htlc.amnt ) return console.log( 'aborting because an unknown person wants to resolve an htlc that does not pay you' );

                    //pay the invoice
                    //TODO: set a max outgoing fee and ensure you recoup it when settling the pending htlc
                    var error = null;
                    var method = "lnpay";
                    var params = {
                        invoice,
                        password: electrum_alt_password,
                    }
                    queryElectrum( electrum_username, electrum_password, electrum_endpoint, method, params );

                    //check its status on loop
                    var loop = async () => {
                        await super_nostr.waitSomeSeconds( 1 );
                        var error = null;
                        var method = "get_invoice";
                        var params = {
                            invoice_id: pmthash,
                        }
                        var status = null;
                        var status_data = await queryElectrum( electrum_username, electrum_password, electrum_endpoint, method, params );
                        if ( status_data.error && status_data.error.message ) error = status_data.error.message;
                        else status = status_data.result;
                        if ( status && status.status_str === "Paid" ) return status.preimage;
                        if ( error ) return `error: ${error}`;
                        return loop();
                    }
                    var status = await loop();
                    if ( status.startsWith( "error" ) ) {
                        console.log( 'error:', error );
                        return;
                    }

                    var preimage = status;
                    pending_htlcs[ index_of_pending_htlc ].pmt_preimage = preimage;
                    //TODO: return success message to whoever requested that this invoice be paid
                    //TODO: do not ask your counterparty to resolve the htlc unless they are online
                    //and recall that they might not be the person who asked you to pay this --
                    //the person desiring payment may be a third party using a hedgehog-to-LN bridge

                    hedgehog_server.askCounterpartyToResolveHtlc( chan_id, preimage );

                    return;
                }
                if ( json.msg_type === "channel_request" ) {
                    //find out how much money to put in this channel
                    //i.e. double the amount requested, or a minimum
                    var channel_capacity = json.msg_value.amount * 2;
                    if ( channel_capacity < minimum_channel_capacity ) channel_capacity = minimum_channel_capacity;

                    //find a utxo capable of funding that channel
                    var error = null;
                    var method = "listunspent";
                    var utxos_available = null;
                    var utxos_available_data = await queryElectrum( electrum_username, electrum_password, electrum_endpoint, method );
                    if ( utxos_available_data.error && utxos_available_data.error.message ) error = utxos_available_data.error.message;
                    else utxos_available = utxos_available_data.result;

                    //TODO: if there is an error, return it

                    //sort your utxos
                    var utxos_ill_use = [];
                    //TODO: actually calculate the txfee properly
                    var txfee = 300;
                    utxos_available.every( utxo => {
                        var amnt = hedgehog_server.bitcoinToSats( Number( utxo.value ) );
                        //TODO: allow funding the channel with multiple utxos
                        //the problem currently is that I don't see how to
                        //identify what coins to spend via electrum's payto
                        //command, except with this caveat: there are two
                        //flags I can pass, from_addr and from_coins, and
                        //the former looks intuitive; as long as I only have
                        //one utxo per address, I should be able to fund my
                        //channels by just finding one utxo that is capable
                        //of funding it and passing the from_addr flag when
                        //calling the payto command. The alternative is to
                        //learn how to use the from_coins flag so that I can
                        //pass multiple utxos; hence this todo
                        if ( amnt <= channel_capacity + txfee ) return true;
                        //ensure no other utxo uses this address
                        var num_of_utxos_that_use_this_address = 0;
                        utxos_available.forEach( item => {
                            if ( item.address === utxo.address ) num_of_utxos_that_use_this_address = num_of_utxos_that_use_this_address + 1;
                        });
                        if ( num_of_utxos_that_use_this_address > 1 ) return true;
                        utxos_ill_use.push({
                            txid: utxo.prevout_hash,
                            vout: utxo.prevout_n,
                            addy: utxo.address,
                            amnt,
                        });
                    });
                    if ( !utxos_ill_use.length ) error = "not enough money to fund this channel";

                    //TODO: if there is an error, return it

                    //get the private key for your utxo
                    //TODO: ensure this works with multiple utxos
                    var error = null;
                    var method = "getprivatekeys";
                    var params = {
                        address: utxos_ill_use[ 0 ].addy,
                        password: electrum_alt_password,
                    }
                    var priv_str = null;
                    var privkey_data = await queryElectrum( electrum_username, electrum_password, electrum_endpoint, method, params );
                    if ( privkey_data.error && privkey_data.error.message ) error = privkey_data.error.message;
                    else priv_str = privkey_data.result;

                    //TODO: if there is an error, return it

                    var wif = priv_str.split( ":" )[ 1 ];
                    var hex_priv = hedgehog_server.getHexFromWif( wif );
                    var encrypted_hex_priv = await super_nostr.alt_encrypt( nostr_privkey, nostr_pubkey, hex_priv );

                    //check if we need a fee invoice
                    var need_fee_invoice = true;
                    if ( json.msg_value.hasOwnProperty( "fee_payment" ) ) {
                        //extract fee payment info
                        var fee_payment_info = json.msg_value.fee_payment;
                        var encrypted_chan_id = fee_payment_info.encrypted_chan_id;
                        var encryption_pubkey = fee_payment_info.encryption_pubkey;
                        var fee_chan_id = await super_nostr.alt_decrypt( nostr_privkey, encryption_pubkey, encrypted_chan_id );
                        var encrypted_channel_fee_data = fee_payment_info.encrypted_channel_fee_data;
                        var decrypted_channel_fee_data = await super_nostr.alt_decrypt( nostr_privkey, encryption_pubkey, encrypted_channel_fee_data );
                        var fee_payment_json = JSON.parse( decrypted_channel_fee_data );
                        var { fee_amount, fee_preimage, fee_absolute_timelock } = fee_payment_json;

                        //check if the fee-paying htlc exists
                        var chan_id = "b_" + fee_chan_id.substring( 2 );
                        if ( hedgehog.state.hasOwnProperty( chan_id ) ) {
                            var state = hedgehog.state[ chan_id ];
                            var am_alice = !!state.alices_priv;

                            //find the to-be-resolved htlc
                            var pmthash = await hedgehog.sha256( hedgehog.hexToBytes( fee_preimage ) );
                            var index_of_pending_htlc = -1;
                            var amnt_of_pending_htlc = null;
                            var pending_htlcs = [];
                            var latest_state = state.channel_states[ state.channel_states.length - 1 ];
                            if ( latest_state && latest_state.hasOwnProperty( "pending_htlcs" ) ) pending_htlcs = latest_state.pending_htlcs;
                            //TODO: force close if the error below is thrown
                            if ( !pending_htlcs.length ) return console.log( 'error, your counterparty sent you a preimage when you have no pending htlcs' );
                            pending_htlcs.every( ( htlc, index ) => {
                                if ( htlc.pmthash !== pmthash ) return true;
                                if ( am_alice && htlc.sender === "alice" ) return true;
                                if ( !am_alice && htlc.sender === "bob" ) return true;
                                index_of_pending_htlc = index;
                                amnt_of_pending_htlc = htlc.amnt;
                            });
                            if ( index_of_pending_htlc >= 0 ) {
                                //TODO: mark the fee payment as ready for settlement next time the sender gets online
                                pending_htlcs[ index_of_pending_htlc ].pmt_preimage = fee_preimage;
                                need_fee_invoice = false;
                                //TODO: do not ask that counterparty to resolve the htlc unless they are online
                                hedgehog_server.askCounterpartyToResolveHtlc( fee_chan_id, fee_preimage );
                            }
                        }
                    }

                    var fee_invoice = null;
                    if ( need_fee_invoice ) {
                        //prepare to make a "fee invoice" for the cost of the channel
                        var cost_of_channel = inbound_capacity_fee_type === "absolute" ? Number( inbound_capacity_fee ) : Number( ( Number( channel_capacity ) * Number( ( Number( inbound_capacity_fee ) / 100 ).toFixed( 2 ) ) ).toFixed( 2 ) );
                        var cost_of_fee_invoice = hedgehog_server.satsToBitcoin( cost_of_channel );
                        cost_of_fee_invoice = Number( cost_of_fee_invoice );
                        var fee_invoice_preimage = super_nostr.getPrivkey();
                        var fee_invoice_pmthash = await super_nostr.sha256( super_nostr.hexToBytes( fee_invoice_preimage ) );
                        var encrypted_fee_preimage = await super_nostr.alt_encrypt( nostr_privkey, nostr_pubkey, fee_invoice_preimage );

                        //make the fee invoice
                        var method = 'add_hold_invoice';
                        var params = {payment_hash: fee_invoice_pmthash, amount: cost_of_fee_invoice, memo: ""};
                        var fee_invoice_data = await queryElectrum( electrum_username, electrum_password, electrum_endpoint, method, params );
                        if ( fee_invoice_data.error && fee_invoice_data.error.message ) error = fee_invoice_data.error.message;
                        else fee_invoice = fee_invoice_data.result.invoice;

                        //TODO: if there is an error, return it                        
                    }

                    //prepare a channel keypair
                    var channel_privkey = hedgehog.getPrivkey();
                    var channel_pubkey = hedgehog.getPubkey( channel_privkey );
                    var channel_preimage = hedgehog.getPrivkey();
                    var channel_hash = await hedgehog.sha256( hedgehog.hexToBytes( channel_preimage ) );
                    hedgehog.keypairs[ channel_pubkey ] = {privkey: channel_privkey, preimage: channel_preimage}

                    //get a change address from electrum
                    var method = "getunusedaddress";
                    var change_address = null;
                    var change_address_data = await queryElectrum( electrum_username, electrum_password, electrum_endpoint, method );
                    if ( change_address_data.error && change_address_data.error.message ) error = change_address_data.error.message;
                    else change_address = change_address_data.result;

                    //TODO: if there is an error, return it

                    //save the data for later use
                    var data_to_save = {
                        utxos: utxos_ill_use || error,
                        channel_pubkey_and_hash: {pubkey: channel_pubkey, hash: channel_hash},
                        fee: txfee,
                        change_address: change_address || error,
                        channel_capacity,
                        encrypted_hex_priv,
                        need_fee_invoice,
                    }
                    if ( need_fee_invoice ) {
                        data_to_save.fee_invoice = fee_invoice;
                        data_to_save.fee_invoice_pmthash = fee_invoice_pmthash;
                        data_to_save.encrypted_fee_preimage = encrypted_fee_preimage;
                    }
                    hedgehog_server.data_for_channel_opens[ event.pubkey ] = data_to_save;

                    //send the data to the user
                    var message_for_user = JSON.stringify({
                        msg_type: "channel_request_reply",
                        msg_value: hedgehog_server.data_for_channel_opens[ event.pubkey ],
                    });
                    console.log( 'replying:', message_for_user );
                    var privkey = nostr_privkey;
                    var pubkey = nostr_pubkey;
                    var emsg = await super_nostr.alt_encrypt( privkey, event.pubkey, message_for_user );
                    var event = await super_nostr.prepEvent( privkey, emsg, 4, [ [ "p", event.pubkey ] ] );
                    super_nostr.sendEvent( event, nostr_relays[ 0 ] );
                    return;
                }
                if ( json.msg_type === "channel_init" ) {
                    //validate the channel
                    var channel_is_valid = await hedgehog.openChannel( null, null, json.msg_value );
                    if ( !channel_is_valid ) return;
                    var chan_id = "b_" + json.msg_value.chan_id.substring( 2 );
                    var user_pubkey = event.pubkey;
                    hedgehog_server.comms_keys[ chan_id ] = user_pubkey;

                    //get data from previous part
                    if ( !hedgehog_server.data_for_channel_opens.hasOwnProperty( event.pubkey ) ) return;
                    var prev_data = hedgehog_server.data_for_channel_opens[ event.pubkey ];
                    var channel_capacity = prev_data.channel_capacity;
                    var txfee = prev_data.fee;
                    var change_address = prev_data.change_address;
                    var need_fee_invoice = prev_data.need_fee_invoice;
                    var fee_invoice_pmthash = null;
                    var encrypted_fee_preimage = null;
                    var fee_invoice_preimage = null;
                    if ( need_fee_invoice ) {
                        fee_invoice_pmthash = prev_data.fee_invoice_pmthash;
                        encrypted_fee_preimage = prev_data.encrypted_fee_preimage;
                        fee_invoice_preimage = await super_nostr.alt_decrypt( nostr_privkey, nostr_pubkey, encrypted_fee_preimage )
                    }
                    var sum_of_utxos = 0;
                    prev_data.utxos.forEach( utxo => sum_of_utxos = sum_of_utxos + utxo.amnt );
                    var channel_scripts = hedgehog.getChannelScripts( chan_id );
                    var channel = hedgehog.getAddressData( channel_scripts, 0 )[ 0 ];

                    //check if channel funding txid and vout are correct
                    var funding_vin = [];
                    prev_data.utxos.forEach( utxo => funding_vin.push( hedgehog.getVin( utxo.txid, utxo.vout, utxo.amnt, utxo.addy ) ) );
                    var funding_tx = tapscript.Tx.create({
                        version: 2,
                        vin: funding_vin,
                        vout: [
                            hedgehog.getVout( channel_capacity, channel ),
                        ],
                    });
                    if ( sum_of_utxos - channel_capacity - txfee > 330 ) funding_tx.vout.push( hedgehog.getVout( sum_of_utxos - channel_capacity - txfee, change_address ) );
                    var encrypted_hex_priv = prev_data.encrypted_hex_priv;
                    var tx_priv = await super_nostr.alt_decrypt( nostr_privkey, nostr_pubkey, encrypted_hex_priv );
                    var tx_pub = nobleSecp256k1.getPublicKey( tx_priv, true );
                    var sig = tapscript.Signer.segwit.sign( tx_priv, funding_tx, 0, { sigflag: 1, pubkey: tx_pub });
                    funding_tx.vin[ 0 ].witness = [ sig, tx_pub ];
                    var funding_txhex = tapscript.Tx.encode( funding_tx ).hex;

                    delete hedgehog_server.data_for_channel_opens[ event.pubkey ];

                    var funding_txid = tapscript.Tx.util.getTxid( funding_tx );
                    if ( funding_txid !== hedgehog.state[ chan_id ].funding_txinfo[ 0 ] ) return;
                    if ( hedgehog.state[ chan_id ].funding_txinfo[ 1 ] !== 0 ) return;

                    if ( need_fee_invoice ) {
                        //wait til fee invoice is pending
                        var loop = async () => {
                            var error = null;
                            var method = "check_hold_invoice";
                            var params = {
                                payment_hash: fee_invoice_pmthash,
                            }
                            var fee_invoice_is_paid = null;
                            var fee_invoice_data = await queryElectrum( electrum_username, electrum_password, electrum_endpoint, method, params );
                            if ( fee_invoice_data.error && fee_invoice_data.error.message ) error = fee_invoice_data.error.message;
                            else fee_invoice_is_paid = fee_invoice_data.result.status === 'paid';

                            //TODO: if there is an error, return it

                            if ( fee_invoice_is_paid ) return;
                            await super_nostr.waitSomeSeconds( 1 );
                            return loop();
                        }
                        var fee_invoice_is_paid = await loop();
                        var message_for_user = JSON.stringify({
                            msg_type: "channel_init_reply",
                            msg_value: 'fee invoice is paid',
                        });
                        console.log( 'replying:', message_for_user );
                        var privkey = nostr_privkey;
                        var pubkey = nostr_pubkey;
                        var user_pubkey = event.pubkey;
                        var emsg = await super_nostr.alt_encrypt( privkey, user_pubkey, message_for_user );
                        var event = await super_nostr.prepEvent( privkey, emsg, 4, [ [ "p", event.pubkey ] ] );
                        super_nostr.sendEvent( event, nostr_relays[ 0 ] );
                    }

                    //broadcast the tx
                    //TODO: actually broadcast it
                    console.log( funding_txhex );

                    //settle the fee invoice
                    var method = 'settle_hold_invoice';
                    var params = {preimage: fee_invoice_preimage};
                    queryElectrum( electrum_username, electrum_password, electrum_endpoint, method, params );
                    return;
                }
                if ( json.msg_type === "request_hh_pmt_to_user" ) {
                    //prepare the needed variables
                    var { chan_id, check_amount, check_pmthash, check_absolute_timelock, check_server_id, check_encrypted_chan_id, check_encryption_pubkey } = json.msg_value;
                    var privkey = nostr_privkey;
                    var pubkey = nostr_pubkey;
                    var user_pubkey = event.pubkey;
                    var chan_id = "b_" + json.msg_value.chan_id.substring( 2 );

                    //ensure there is a corresponding inbound htlc that pays you
                    var inbound_chan_id = await super_nostr.alt_decrypt( privkey, check_encryption_pubkey, check_encrypted_chan_id );
                    inbound_chan_id = "b_" + inbound_chan_id.substring( 2 );
                    var error = null;
                    if ( !hedgehog.state.hasOwnProperty( chan_id ) ) return;

                    if ( !hedgehog.state.hasOwnProperty( inbound_chan_id ) ) return;
                    var state = hedgehog.state[ inbound_chan_id ];
                    var am_alice = !!state.alices_priv;

                    //find relevant pending htlc
                    var pmthash = check_pmthash;
                    var index_of_pending_htlc = -1;
                    var pending_htlcs = [];
                    var latest_state = state.channel_states[ state.channel_states.length - 1 ];
                    if ( latest_state && latest_state.hasOwnProperty( "pending_htlcs" ) ) pending_htlcs = latest_state.pending_htlcs;
                    if ( !pending_htlcs.length ) return;
                    pending_htlcs.every( ( htlc, index ) => {
                        if ( htlc.pmthash !== pmthash ) return true;
                        if ( htlc.sender !== "alice" ) return true;
                        index_of_pending_htlc = index;
                    });
                    if ( index_of_pending_htlc < 0 ) return;

                    //check absolute timelock info
                    //TODO: allow absolute timelocks other than 0
                    //TODO: also compare it with the one in the actual htlc
                    if ( check_absolute_timelock !== 0 ) return;

                    //check relative timelock info
                    var pending_htlc = pending_htlcs[ index_of_pending_htlc ];
                    if ( !pending_htlc.htlc_locktime || pending_htlc.htlc_locktime < 2026 ) return;

                    //ensure amount matches
                    if ( pending_htlc.amnt !== check_amount ) return;

                    //inside the hedgehog channel of the person who made the request, send an htlc with these properties: it is worth the same amount as the check; it is locked to the same payment hash as the check; and it has a cltv below the check's
                    var htlc_locktime = 20;
                    //add a buffer, because if you force close exactly 20 blocks before your inbound payment expires, you risk a race condition, as the first moment you can recover your money from your outbound payment is also the moment they get their money back, so if they sweep your payment with the preimage at that moment, and you grab the preimage from the blockchain (or mempool) and try to settle your inbound payment with it, in that same block they get to try to try to recover their money via the absolute timelock path, and then miners pick who actually gets the money, because that's a race condition
                    var htlc_buffer = 10;
                    //TODO: handle any errors returned by the fetch command below
                    var bh_data = await fetch( `https://${hedgehog_server.explorer}/testnet4/api/blocks/tip/height` );
                    var current_blockheight = await bh_data.text();
                    var current_blockheight = Number( current_blockheight );
                    var block_when_i_must_force_close = ( ( current_blockheight + min_cltv ) - htlc_locktime ) - htlc_buffer;
                    console.log( 'current_blockheight:', current_blockheight, 'block_when_i_must_force_close:', block_when_i_must_force_close );
                    var htlc_pmthash = pmthash;
                    hedgehog_server.comms_keys[ chan_id ] = user_pubkey;
                    var success_pmthash = await hedgehog.sendHtlc( chan_id, check_amount, htlc_locktime, htlc_pmthash, block_when_i_must_force_close );
                    if ( success_pmthash !== htlc_pmthash ) return `error: ${success_pmthash}`;
                    console.log( 'htlc is sent' );
                }
                if ( json.msg_type === "request_ln_pmt_to_user" ) {
                    //prepare the needed variables
                    var privkey = nostr_privkey;
                    var pubkey = nostr_pubkey;
                    var user_pubkey = event.pubkey;
                    var chan_id = "b_" + json.msg_value.chan_id.substring( 2 );

                    //prepare to make an ln invoice for the amount requested
                    var htlc_amnt = json.msg_value.amount;
                    var ln_invoice_value = hedgehog_server.satsToBitcoin( htlc_amnt );
                    ln_invoice_value = Number( ln_invoice_value );
                    //TODO: actually calculate the txfee properly
                    var txfee = 300;

                    //make the ln invoice
                    var error = null;
                    var ln_invoice_pmthash = json.msg_value.hash;
                    var method = 'add_hold_invoice';
                    var min_cltv = 294;
                    var params = {payment_hash: ln_invoice_pmthash, amount: ln_invoice_value, memo: "", min_final_cltv_expiry_delta: min_cltv};
                    var ln_invoice_data = await queryElectrum( electrum_username, electrum_password, electrum_endpoint, method, params );
                    console.log( ln_invoice_data );
                    var ln_invoice = null;
                    if ( ln_invoice_data.error && ln_invoice_data.error.message ) error = ln_invoice_data.error.message;
                    else ln_invoice = ln_invoice_data.result.invoice;

                    //TODO: if there is an error, return it

                    var message_for_user = JSON.stringify({
                        msg_type: "ln_invoice_for_user",
                        msg_value: {ln_invoice},
                    });
                    console.log( 'replying:', message_for_user );
                    var emsg = await super_nostr.alt_encrypt( privkey, user_pubkey, message_for_user );
                    var event = await super_nostr.prepEvent( privkey, emsg, 4, [ [ "p", user_pubkey ] ] );
                    super_nostr.sendEvent( event, nostr_relays[ 0 ] );

                    //wait til ln invoice is pending
                    var loop = async () => {
                        var error = null;
                        var method = "check_hold_invoice";
                        var params = {
                            payment_hash: ln_invoice_pmthash,
                        }
                        var ln_invoice_is_paid = null;
                        var ln_invoice_data = await queryElectrum( electrum_username, electrum_password, electrum_endpoint, method, params );
                        //TODO: ensure the amount received is equal to or greater than the amount requested
                        if ( ln_invoice_data.error && ln_invoice_data.error.message ) error = ln_invoice_data.error.message;
                        else ln_invoice_is_paid = ln_invoice_data.result.status === 'paid';

                        //TODO: if there is an error, return it

                        if ( ln_invoice_is_paid ) return;
                        await super_nostr.waitSomeSeconds( 1 );
                        return loop();
                    }
                    var ln_invoice_is_paid = await loop();

                    //tell user invoice is paid
                    var message_for_user = JSON.stringify({
                        msg_type: "ln_invoice_paid",
                        msg_value: 'ln invoice is paid',
                    });
                    console.log( 'replying:', message_for_user );
                    var emsg = await super_nostr.alt_encrypt( privkey, user_pubkey, message_for_user );
                    var event = await super_nostr.prepEvent( privkey, emsg, 4, [ [ "p", user_pubkey ] ] );
                    super_nostr.sendEvent( event, nostr_relays[ 0 ] );

                    //inside the hedgehog channel, send the user an htlc with these properties: it is worth the same amount as the full hodl invoice, minus a mining fee and the channel cost; it is locked to the same payment hash as the ln invoice; and it has a cltv below the hodl invoice's
                    var htlc_locktime = 20;
                    //add a buffer, because if you force close exactly 20 blocks before your inbound payment expires, you risk a race condition, as the first moment you can recover your money from your outbound payment is also the moment they get their money back, so if they sweep your payment with the preimage at that moment, and you grab the preimage from the blockchain (or mempool) and try to settle your inbound payment with it, in that same block they get to try to try to recover their money via the absolute timelock path, and then miners pick who actually gets the money, because that's a race condition
                    var htlc_buffer = 10;
                    //TODO: handle any errors returned by the fetch command below
                    var bh_data = await fetch( `https://${hedgehog_server.explorer}/testnet4/api/blocks/tip/height` );
                    var current_blockheight = await bh_data.text();
                    var current_blockheight = Number( current_blockheight );
                    var block_when_i_must_force_close = ( ( current_blockheight + min_cltv ) - htlc_locktime ) - htlc_buffer;
                    console.log( 'current_blockheight:', current_blockheight, 'block_when_i_must_force_close:', block_when_i_must_force_close );
                    var htlc_pmthash = ln_invoice_pmthash;
                    hedgehog_server.comms_keys[ chan_id ] = user_pubkey;
                    var success_pmthash = await hedgehog.sendHtlc( chan_id, htlc_amnt, htlc_locktime, htlc_pmthash, block_when_i_must_force_close );
                    if ( success_pmthash !== ln_invoice_pmthash ) return `error: ${success_pmthash}`;
                    console.log( 'htlc is sent' );
                    return;
                }
                if ( json.msg_type === "resolve_htlc_to_user" ) {
                    //prepare the needed variables
                    var privkey = nostr_privkey;
                    var pubkey = nostr_pubkey;
                    var user_pubkey = event.pubkey;
                    var chan_id = "b_" + json.msg_value.chan_id.substring( 2 );
                    var preimage = json.msg_value.preimage;
                    var state = hedgehog.state[ chan_id ];
                    var am_alice = !!state.alices_priv;

                    //settle any inbound LN invoices that use that preimage
                    var method = 'settle_hold_invoice';
                    var params = {preimage};
                    queryElectrum( electrum_username, electrum_password, electrum_endpoint, method, params );

                    //validate the preimage
                    var preimage_is_hex = hedgehog_server.isValidHex( preimage );
                    var preimage_is_right_length = preimage.length === 64;
                    if ( !preimage_is_hex || !preimage_is_right_length ) {
                        //TODO: force close the channel
                        return console.log( 'time to close the channel', preimage_is_hex, preimage_is_right_length, preimage );
                    }

                    //find the corresponding htlc
                    var pmthash = await hedgehog.sha256( hedgehog.hexToBytes( preimage ) );
                    var index_of_pending_htlc = -1;
                    var amnt_of_pending_htlc = null;
                    var pending_htlcs = [];
                    var latest_state = state.channel_states[ state.channel_states.length - 1 ];
                    if ( latest_state && latest_state.hasOwnProperty( "pending_htlcs" ) ) pending_htlcs = latest_state.pending_htlcs;
                    //TODO: force close if the error below is thrown
                    if ( !pending_htlcs.length ) return console.log( 'error, your counterparty sent you a preimage when you have no pending htlcs' );
                    pending_htlcs.every( ( htlc, index ) => {
                        if ( htlc.pmthash !== pmthash ) return true;
                        if ( !am_alice && htlc.sender === "alice" ) return true;
                        if ( am_alice && htlc.sender === "bob" ) return true;
                        index_of_pending_htlc = index;
                        amnt_of_pending_htlc = htlc.amnt;
                    });
                    if ( index_of_pending_htlc < 0 ) {
                        //TODO: force close the channel
                        return console.log( 'time to close the channel' );
                    }

                    //ensure payment is from you
                    if ( pending_htlcs[ index_of_pending_htlc ].sender !== "bob" ) {
                        //TODO: force close if the error below is thrown
                        return console.log( `your counterparty tried to cheat you by getting you to resolve a payment to them even though it's meant for you` );
                    }

                    //store the preimage
                    pending_htlcs[ index_of_pending_htlc ].pmt_preimage = preimage;

                    //create a pending_htlcs array without that htlc
                    var new_pending_htlcs = JSON.parse( JSON.stringify( pending_htlcs ) );
                    var htlc_to_remove = JSON.parse( JSON.stringify( pending_htlcs[ index_of_pending_htlc ] ) );
                    new_pending_htlcs.splice( index_of_pending_htlc, 1 );

                    //create and sign a tx1 and tx2 based on that pending_htlcs array, and with the value of the htlc added to your counterparty's side of the channel, and add the new state to your ch_states array
                    var amnt = amnt_of_pending_htlc;
                    var object_for_counterparty = await hedgehog.send( chan_id, amnt, new_pending_htlcs );

                    //get your counterparty to sign the new state
                    var message_identifier = super_nostr.getPrivkey();
                    var message_for_user = JSON.stringify({
                        msg_type: "resolve_htlc_to_user_part_two",
                        msg_value: {...object_for_counterparty, message_identifier},
                    });
                    console.log( 'replying:', message_for_user );
                    var emsg = await super_nostr.alt_encrypt( privkey, user_pubkey, message_for_user );
                    var event = await super_nostr.prepEvent( privkey, emsg, 4, [ [ "p", user_pubkey ] ] );
                    super_nostr.sendEvent( event, nostr_relays[ 0 ] );

                    //TODO: if your counterparty does not reply in a few seconds, force close
                    //get the next message from your counterparty
                    hedgehog_server.two_way_comms[ message_identifier ] = "waiting_for_info";
                    var loop = async () => {
                        await hedgehog_server.waitSomeTime( 100 );
                        if ( !hedgehog_server.two_way_comms.hasOwnProperty( message_identifier ) || ( hedgehog_server.two_way_comms.hasOwnProperty( message_identifier ) && hedgehog_server.two_way_comms[ message_identifier ] === "waiting_for_info" ) ) return loop();
                        return hedgehog_server.two_way_comms[ message_identifier ];
                    }
                    var event = await loop();
                    delete hedgehog_server.two_way_comms[ message_identifier ];

                    //parse the message from your counterparty
                    var json = JSON.parse( event.content );
                    delete json.msg_value[ "message_identifier" ];

                    //validate the new state
                    if ( json.msg_value.amnt !== 0 ) return console.log( 'error, your counterparty tried to cheat by doing a non-blank state update' );
                    var new_state_is_valid = await hedgehog.receive( json.msg_value, new_pending_htlcs );
                    //TODO: force close if the error below is thrown
                    if ( !new_state_is_valid ) return console.log( 'error, your counterparty tried to cheat you by refusing to resolve an htlc' );

                    //revoke all prior states
                    //send your counterparty the following items: your recovery-path rev_preimage, your htlc midstate rev_preimage, and a new blank state update
                    var state_update = await hedgehog.send( chan_id, 0 );
                    state_update[ "message_identifier" ] = "resolve_htlc_to_user_part_four";
                    var message_for_user = JSON.stringify({
                        msg_type: "resolve_htlc_to_user_part_four",
                        msg_value: {...state_update, s_midstate_rev_preimage: htlc_to_remove.s_midstate_rev_preimage, s_recovery_p2_rev_preimage: htlc_to_remove.s_recovery_p2_rev_preimage},
                    });
                    console.log( 'replying:', message_for_user );
                    var emsg = await super_nostr.alt_encrypt( privkey, user_pubkey, message_for_user );
                    var event = await super_nostr.prepEvent( privkey, emsg, 4, [ [ "p", user_pubkey ] ] );
                    super_nostr.sendEvent( event, nostr_relays[ 0 ] );

                    //TODO: if your counterparty does not reply in a few seconds, force close
                    //ensure your counterparty sent you their reveal-path revocation preimage, their htlc midstate rev_preimage
                    var message_identifier = "resolve_htlc_to_user_part_five";
                    delete hedgehog_server.two_way_comms[ message_identifier ];
                    hedgehog_server.two_way_comms[ message_identifier ] = "waiting_for_info";
                    var loop = async () => {
                        await hedgehog_server.waitSomeTime( 100 );
                        if ( !hedgehog_server.two_way_comms.hasOwnProperty( message_identifier ) || ( hedgehog_server.two_way_comms.hasOwnProperty( message_identifier ) && hedgehog_server.two_way_comms[ message_identifier ] === "waiting_for_info" ) ) return loop();
                        return hedgehog_server.two_way_comms[ message_identifier ];
                    }
                    var event = await loop();
                    delete hedgehog_server.two_way_comms[ message_identifier ];

                    //parse the message from your counterparty
                    var json = JSON.parse( event.content );
                    delete json.msg_value[ "message_identifier" ];

                    //verify he revoked his recovery-path and the htlc midstate
                    var recipients_rev_preimages = json.msg_value.recipients_rev_preimages;
                    var calculated_midstate_hash = await hedgehog.sha256( hedgehog.hexToBytes( recipients_rev_preimages[ 0 ] ) );
                    var expected_midstate_hash = htlc_to_remove.recipients_revhashes[ 0 ];
                    var calculated_reveal_hash = await hedgehog.sha256( hedgehog.hexToBytes( recipients_rev_preimages[ 1 ] ) );
                    var expected_reveal_hash = htlc_to_remove.recipients_revhashes[ 1 ];
                    //TODO: force close if the error below is thrown
                    if ( calculated_midstate_hash !== expected_midstate_hash || calculated_reveal_hash !== expected_reveal_hash ) return console.log( 'error, your counterparty tried to cheat you by sending invalid revocation data' );

                    //save the revocation data
                    state.channel_states[ state.channel_states.length - 4 ].pending_htlcs[ index_of_pending_htlc ].recipients_rev_preimages = recipients_rev_preimages;
                    return;
                }
                if ( json.msg_type === "resolve_htlc_to_server_part_two" ) {
                    //parse the message from the user
                    var json = JSON.parse( event.content );
                    var message_identifier = json.msg_value.message_identifier;
                    delete json.msg_value[ "message_identifier" ];
                    var preimage = json.msg_value.pmt_preimage;
                    delete json.msg_value[ "pmt_preimage" ];
                    var new_state_info = json.msg_value;
                    var chan_id = "b_" + new_state_info.chan_id.substring( 2 );
                    var privkey = nostr_privkey;
                    var user_pubkey = event.pubkey;
                    var state = hedgehog.state[ chan_id ];
                    var am_alice = !!state.alices_priv;

                    //find the to-be-resolved htlc
                    var pmthash = await hedgehog.sha256( hedgehog.hexToBytes( preimage ) );
                    var index_of_pending_htlc = -1;
                    var amnt_of_pending_htlc = null;
                    var pending_htlcs = [];
                    var latest_state = state.channel_states[ state.channel_states.length - 1 ];
                    if ( latest_state && latest_state.hasOwnProperty( "pending_htlcs" ) ) pending_htlcs = latest_state.pending_htlcs;
                    //TODO: force close if the error below is thrown
                    if ( !pending_htlcs.length ) return console.log( 'error, your counterparty sent you a preimage when you have no pending htlcs' );
                    pending_htlcs.every( ( htlc, index ) => {
                        if ( htlc.pmthash !== pmthash ) return true;
                        if ( am_alice && htlc.sender === "alice" ) return true;
                        if ( !am_alice && htlc.sender === "bob" ) return true;
                        index_of_pending_htlc = index;
                        amnt_of_pending_htlc = htlc.amnt;
                    });
                    if ( index_of_pending_htlc < 0 ) {
                        //TODO: force close the channel
                        return console.log( 'time to close the channel' );
                    }

                    //create a pending_htlcs array without that htlc
                    var new_pending_htlcs = JSON.parse( JSON.stringify( pending_htlcs ) );
                    var htlc_to_remove = JSON.parse( JSON.stringify( pending_htlcs[ index_of_pending_htlc ] ) );
                    new_pending_htlcs.splice( index_of_pending_htlc, 1 );

                    //create and sign a tx1 and tx2 based on that pending_htlcs array, and with the value of the htlc added to your side of the channel, and add the new state to your ch_states array
                    var amnt = amnt_of_pending_htlc;
                    //TODO: force close if the error below is thrown
                    if ( new_state_info.amnt !== amnt ) return console.log( 'error, your counterparty tried to cheat you by resolving an htlc for a wrong amount' );
                    // console.log( 12, `my counterparty's current revhashes are these:`, state.alices_revocation_hashes );
                    // console.log( 13, `I should be adding one if you see a revhash in here:`, json.msg_value );
                    var new_state_is_valid = await hedgehog.receive( new_state_info, new_pending_htlcs );
                    // console.log( 14, `now you can see whether I properly added one or not:`, state.alices_revocation_hashes );
                    //TODO: force close if the error below is thrown
                    if ( !new_state_is_valid ) return console.log( 0, 'error, your counterparty tried to cheat you by refusing to resolve an htlc' );

                    //revoke old state and tell counterparty
                    var state_update = await hedgehog.send( chan_id, 0 );
                    state_update[ "message_identifier" ] = message_identifier;
                    var msg_for_counterparty = JSON.stringify({
                        msg_type: "resolve_htlc_to_server_part_three",
                        msg_value: state_update,
                    });
                    var emsg = await super_nostr.alt_encrypt( privkey, user_pubkey, msg_for_counterparty );
                    var event = await super_nostr.prepEvent( privkey, emsg, 4, [ [ "p", user_pubkey ] ] );
                    super_nostr.sendEvent( event, nostr_relays[ 0 ] );

                    //TODO: if your counterparty does not reply in a few seconds, force close
                    //get counterparty's revocations
                    var message_identifier = "resolve_htlc_to_server_part_four";
                    delete hedgehog_server.two_way_comms[ message_identifier ];
                    hedgehog_server.two_way_comms[ message_identifier ] = "waiting_for_info";
                    var loop = async () => {
                        await hedgehog_server.waitSomeTime( 100 );
                        if ( !hedgehog_server.two_way_comms.hasOwnProperty( message_identifier ) || ( hedgehog_server.two_way_comms.hasOwnProperty( message_identifier ) && hedgehog_server.two_way_comms[ message_identifier ] === "waiting_for_info" ) ) return loop();
                        return hedgehog_server.two_way_comms[ message_identifier ];
                    }
                    var event = await loop();
                    delete hedgehog_server.two_way_comms[ message_identifier ];

                    //parse the message from your counterparty
                    var json = JSON.parse( event.content );

                    //validate the new state
                    var s_midstate_rev_preimage = json.msg_value.s_midstate_rev_preimage;
                    var s_recovery_p2_rev_preimage = json.msg_value.s_recovery_p2_rev_preimage;
                    delete json.msg_value[ "s_midstate_rev_preimage" ];
                    delete json.msg_value[ "s_recovery_p2_rev_preimage" ];
                    if ( json.msg_value.amnt !== 0 ) return console.log( 'error, your counterparty tried to cheat by doing a non-blank state update' );
                    var new_state_is_valid = await hedgehog.receive( json.msg_value, new_pending_htlcs );
                    //TODO: force close if the error below is thrown
                    if ( !new_state_is_valid ) return console.log( 'error, your counterparty tried to cheat you by refusing to resolve an htlc' );

                    //verify he revoked his recovery-path and the htlc midstate
                    var calculated_midstate_hash = await hedgehog.sha256( hedgehog.hexToBytes( s_midstate_rev_preimage ) );
                    var expected_midstate_hash = htlc_to_remove.s_midstate_revhash;
                    var calculated_recovery_hash = await hedgehog.sha256( hedgehog.hexToBytes( s_recovery_p2_rev_preimage ) );
                    var expected_recovery_hash = htlc_to_remove.s_recovery_p2_revhash;
                    //TODO: force close if the error below is thrown
                    if ( calculated_midstate_hash !== expected_midstate_hash || calculated_recovery_hash !== expected_recovery_hash ) return console.log( 'error, your counterparty tried to cheat you by sending invalid revocation data' );

                    //save the revocation data
                    hedgehog.state[ chan_id ].channel_states[ hedgehog.state[ chan_id ].channel_states.length - 4 ].pending_htlcs[ index_of_pending_htlc ].s_midstate_rev_preimage = s_midstate_rev_preimage;
                    hedgehog.state[ chan_id ].channel_states[ hedgehog.state[ chan_id ].channel_states.length - 4 ].pending_htlcs[ index_of_pending_htlc ].s_recovery_p2_rev_preimage = s_recovery_p2_rev_preimage;

                    //send your counterparty your reveal-path rev_preimage and your htlc midstate rev_preimage
                    var msg_for_counterparty = JSON.stringify({
                        msg_type: "resolve_htlc_to_server_part_five",
                        msg_value: {recipients_rev_preimages: htlc_to_remove.recipients_rev_preimages, message_identifier: "resolve_htlc_to_server_part_five"},
                    });
                    var emsg = await super_nostr.alt_encrypt( privkey, user_pubkey, msg_for_counterparty );
                    var event = await super_nostr.prepEvent( privkey, emsg, 4, [ [ "p", user_pubkey ] ] );
                    super_nostr.sendEvent( event, nostr_relays[ 0 ] );

                    console.log( 'htlc resolved' );
                }
                if ( json.msg_type === "resolve_htlc_to_server_part_four" ) {
                    if ( hedgehog_server.two_way_comms.hasOwnProperty( json.msg_type ) && hedgehog_server.two_way_comms[ json.msg_type ] === "waiting_for_info" ) hedgehog_server.two_way_comms[ json.msg_type ] = event;
                }
                var msg_id = json.msg_value.message_identifier;
                if ( hedgehog_server.two_way_comms.hasOwnProperty( msg_id ) && hedgehog_server.two_way_comms[ msg_id ] === "waiting_for_info" ) hedgehog_server.two_way_comms[ msg_id ] = event;
            }
            catch ( e ) {
                console.log( e );
            }
        }
        var connection = await super_nostr.newPermanentConnection( nostr_relays[ 0 ], listenFunction, handleFunction );
        return connection;
    },
    convertPubkeyAndRelaysToNprofile: ( prefix, pubkey, relays ) => {
        var relays_str = "";
        relays.forEach( relay => {
            var relay_str = hedgehog_server.textToHex( relay );
            var len = ( relay_str.length / 2 ).toString( 16 );
            if ( len.length % 2 ) len = "0" + len;
            relays_str = relays_str + "01" + len + relay_str;
        });
        var hex = relays_str + "0020" + pubkey;
        var bytes = super_nostr.hexToBytes( hex );
        var nevent = bech32.bech32.encode( prefix, bech32.bech32.toWords( bytes ), 100_000 );
        return nevent;
    },
    textToHex: text => {
        var encoded = new TextEncoder().encode( text );
        return Array.from( encoded )
            .map( x => x.toString( 16 ).padStart( 2, "0" ) )
            .join( "" );
    },
    bitcoinToSats: btc => Math.floor( btc * 100_000_000 ),
    satsToBitcoin: sats => {
        var btc = String( sats ).padStart( 8, "0" ).slice( 0,-8 ) + "." + String( sats ).padStart( 8, "0" ).slice( -8 );
        if ( btc.endsWith( "00000" ) ) {
            btc = btc.substring( 0, btc.length - 5 );
            var i; for ( i=0; i<5; i++ ) {
                if ( btc.endsWith( "0" ) ) btc = btc.substring( 0, btc.length - 1 );
            }
            if ( btc.endsWith( "." ) ) btc = btc.substring( 0, btc.length - 1 );
            if ( !btc ) btc = 0;
        }
        return btc;
    },
    getHexFromWif: wif => {
        var priv_as_array = Array.from( base58.decode( wif ).data );
        //eliminate the compression byte that is always 1 for segwit (it indicates that the address uses a compressed pubkey, which is required in segwit)
        priv_as_array.pop();
        return super_nostr.bytesToHex( new Uint8Array( priv_as_array ) );
    },
    setUpComms: async () => {
        hedgehog.communicateWithUser = async data_for_user => {
            var chan_id = data_for_user.chan_id;
            var message_identifier = hedgehog.getPrivkey();
            data_for_user[ "message_identifier" ] = message_identifier;
            var message_for_user = JSON.stringify({
                msg_type: "two_way_comms",
                msg_value: data_for_user,
            });
            console.log( 'sending data:', message_for_user );
            var privkey = nostr_privkey;
            var pubkey = nostr_pubkey;
            var user_pubkey = hedgehog_server.comms_keys[ chan_id ];
            var emsg = await super_nostr.alt_encrypt( privkey, user_pubkey, message_for_user );
            var event = await super_nostr.prepEvent( privkey, emsg, 4, [ [ "p", user_pubkey ] ] );
            super_nostr.sendEvent( event, nostr_relays[ 0 ] );

            var loop = async () => {
                await hedgehog_server.waitSomeTime( 100 );
                if ( !hedgehog_server.two_way_comms.hasOwnProperty( message_identifier ) ) return loop();
                return hedgehog_server.two_way_comms[ message_identifier ];
            }
            var reply = await loop();
            return reply;
        }
    },
    waitSomeTime: num => new Promise( resolve => setTimeout( resolve, num ) ),
    getInvoicePmthash: invoice => {
        var decoded = bolt11.decode( invoice );
        var i; for ( i=0; i<decoded[ "tags" ].length; i++ ) {
            if ( decoded[ "tags" ][ i ][ "tagName" ] === "payment_hash" ) return decoded[ "tags" ][ i ][ "data" ].toString();
        }
    },
    getInvoiceAmount: invoice => {
        var decoded = bolt11.decode( invoice );
        var amount = Math.floor( decoded[ "millisatoshis" ] / 1000 ).toString();
        return Number( amount );
    },
    askCounterpartyToResolveHtlc: async ( chan_id, preimage ) => {
        var counterparty_pubkey = hedgehog_server.comms_keys[ chan_id ];
        if ( !counterparty_pubkey ) return console.log( 'cannot ask that counterparty -- you have no nostr pubkey on file for them' );
        var privkey = nostr_privkey;
        var msg_for_counterparty = JSON.stringify({
            msg_type: "htlc_to_server_part_zero",
            msg_value: {preimage, chan_id},
        });
        var emsg = await super_nostr.alt_encrypt( privkey, counterparty_pubkey, msg_for_counterparty );
        var event = await super_nostr.prepEvent( privkey, emsg, 4, [ [ "p", counterparty_pubkey ] ] );
        super_nostr.sendEvent( event, nostr_relays[ 0 ] );
    },
}

if ( db.nostr_privkey ) {
    var nostr_privkey = db.nostr_privkey;
} else {
    var nostr_privkey = super_nostr.getPrivkey();
}
var nostr_pubkey = super_nostr.getPubkey( nostr_privkey );
var server_id = hedgehog_server.convertPubkeyAndRelaysToNprofile( "nprofile", nostr_pubkey, nostr_relays );
db.nostr_privkey = nostr_privkey;
var texttowrite = JSON.stringify( db );
fs.writeFileSync( "db.txt", texttowrite, function() {return;});

var init = async()=>{
    hedgehog_server.setUpComms();
    var connection = await hedgehog_server.listenOnNostr( nostr_pubkey );
    console.log( 'server id:' );
    console.log( server_id );
}

init();
