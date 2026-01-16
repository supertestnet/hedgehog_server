//editable settings
var admins_pubkey = '23714ef0db071f5ff0d7533887e73007cd7e4b85f0b7a6192e85c94fbf384397';

//dependencies that are packages
var nobleSecp256k1 = require( 'noble-secp256k1' );
var sha256  = nobleSecp256k1.utils.sha256;
var http = require( 'http' );
var url = require( 'url' );
var fs = require( 'fs' );

//dependencies that are not packages
var bytesToHex = bytes => bytes.reduce( ( str, byte ) => str + byte.toString( 16 ).padStart( 2, "0" ), "" );
var hexToBytes = hex => Uint8Array.from( hex.match( /.{1,2}/g ).map( byte => parseInt( byte, 16 ) ) );
var isValidJson = content => {
    if ( !content ) return;
    try {  
        var json = JSON.parse( content );
    } catch ( e ) {
        return;
    }
    return true;
}
var extractRecipientFromNostrEvent = event => {
    var recipient = null;
    event.tags.every( item => {
        if ( item[ 0 ] == "p" ) {
            recipient = item[ 1 ];
            return;
        }
        return true;
    });
    if ( recipient ) return recipient;
    return "no recipient";
}

//prepare the db
if ( fs.existsSync( "db.txt" ) ) {
    var dbtext = fs.readFileSync( "db.txt" ).toString();
    var db = JSON.parse( dbtext );
} else {
    var db = {};
    var texttowrite = JSON.stringify( db );
    fs.writeFileSync( "db.txt", texttowrite, function() {return;});
    var dbtext = fs.readFileSync( "db.txt" ).toString();
    var db = JSON.parse( dbtext );
}
var dbLoop = () => {
    var texttowrite = JSON.stringify( db );
    fs.writeFileSync( "db.txt", texttowrite, function() {return;});
    setTimeout( dbLoop, 10 );
}
dbLoop();

//prepare the server
var sendResponse = ( response, data, statusCode, content_type ) => {
    if ( response.finished ) return;
    response.setHeader( 'Access-Control-Allow-Origin', '*' );
    response.setHeader( 'Access-Control-Request-Method', '*' );
    response.setHeader( 'Access-Control-Allow-Methods', 'OPTIONS, GET, POST' );
    response.setHeader( 'Access-Control-Allow-Headers', '*' );
    response.setHeader( 'Content-Type', content_type[ "Content-Type" ] );
    response.writeHead( statusCode );
    response.end( data );
}
var collectData = ( request, callback ) => {
    var data = '';
    request.on( 'data', chunk => data += chunk );
    request.on( 'end', () => callback( data ) );
}
var error = response => sendResponse( response, JSON.stringify({error: "unknown error"}), 200, {'Content-Type': 'application/json' });
var requestListener = async function( request, response ) {
    var parts = url.parse( request.url, true );
    if ( request.method === 'GET' ) return sendResponse( response, '<p>use POST requests</p>', 200, {'Content-Type': 'text/html'} );
    collectData( request, async msg_from_user => {
        //prohibit messages over 1kb
        if ( msg_from_user.length > 1000 ) return error( response );

        //only allow json messages
        if ( !isValidJson( msg_from_user ) ) return error( response );
        var json = JSON.parse( msg_from_user );

        if ( parts.pathname == "/write" || parts.pathname == "/write/" ) {
            //only allow messages with a string id
            if ( typeof json.id !== "string" ) return error( response );

            //if the author is the admin, allow it
            if ( json.pubkey === admins_pubkey ) {

                //validate the signature
                try {
                    var preimage = JSON.stringify([
                        0,
                        json['pubkey'],
                        json['created_at'],
                        json['kind'],
                        json['tags'],
                        json['content'],
                    ]);
                    var hash = bytesToHex( await sha256( ( new TextEncoder().encode( preimage ) ) ) );
                    if ( hash !== json.id ) throw( 'hash is invalid' );
                    var sig_is_valid = await nobleSecp256k1.schnorr.verify( json.sig, hash, json.pubkey );
                    if ( !sig_is_valid ) throw( 'sig is invalid' );
                } catch ( e ) {
                    return error( response );
                }

                //save a message for the recipient
                var recipient = extractRecipientFromNostrEvent( json );
                if ( !db.hasOwnProperty( recipient ) ) db[ recipient ] = [];
                db[ recipient ].push( json );

                //delete the message after 10 seconds
                setTimeout( () => {
                    db[ recipient ].every( ( item, index ) => {
                        if ( item.id !== json.id ) return true;
                        db[ recipient ].splice( index, 1 );
                    });
                }, 10_000 );
                return sendResponse( response, JSON.stringify({success: true}), 200, {'Content-Type': 'application/json' });
            }

            //validate the signature
            try {
                var preimage = JSON.stringify([
                    0,
                    json['pubkey'],
                    json['created_at'],
                    json['kind'],
                    json['tags'],
                    json['content'],
                ]);
                var hash = bytesToHex( await sha256( ( new TextEncoder().encode( preimage ) ) ) );
                if ( hash !== json.id ) throw( 'hash is invalid' );
                var sig_is_valid = await nobleSecp256k1.schnorr.verify( json.sig, hash, json.pubkey );
                if ( !sig_is_valid ) throw( 'sig is invalid' );
            } catch ( e ) {
                return error( response );
            }

            //save a message for the recipient, but only if the recipient is the admin
            var recipient = extractRecipientFromNostrEvent( json );
            if ( recipient !== admins_pubkey ) return error( response );
            if ( !db.hasOwnProperty( recipient ) ) db[ recipient ] = [];
            db[ recipient ].push( json );

            //delete the message after 10 seconds
            setTimeout( () => {
                db[ recipient ].every( ( item, index ) => {
                    if ( item.id !== json.id ) return true;
                    db[ recipient ].splice( index, 1 );
                });
            }, 10_000 );
            return sendResponse( response, JSON.stringify({success: true}), 200, {'Content-Type': 'application/json' });
        }
        if ( parts.pathname == "/read" || parts.pathname == "/read/" ) {
            //make the user prove they are the intended recipient by validating a sig for the preset message "a".repeat( 64 )
            var { sig, pubkey } = json;
            try {
                var hash = "a".repeat( 64 );
                var sig_is_valid = await nobleSecp256k1.schnorr.verify( sig, hash, pubkey );
                if ( !sig_is_valid ) throw( 'sig is invalid' );
            } catch ( e ) {
                return error( response );
            }

            //give the user all messages sent to them
            if ( !db.hasOwnProperty( recipient ) ) return sendResponse( response, "[]", 200, {'Content-Type': 'application/json' });
            return sendResponse( response, JSON.stringify( db.recipient ), 200, {'Content-Type': 'application/json' });
        }

        //return a 404 error for any page that does not exist
        return sendResponse( response, `<p>404 page not found</p>`, 200, {'Content-Type': 'text/html' });
    });
}

//run the server
var server = http.createServer( requestListener );
server.listen( 8080 );
