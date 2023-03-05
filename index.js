const express = require('express');
const http = require('http');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const webSocket = require('ws');
const jwt = require('jsonwebtoken');
const mariadb = require('mariadb');
const getUuid = require('uuid-by-string');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const base64url = require('base64url');
const ellipticcurve = require("starkbank-ecdsa");

const app = express();
app.use(cookieParser());

const { loginPort, registerPort, updatesPort } = require(__dirname + '/ports.json');

const privkey = fs.readFileSync(__dirname + '/jwt-priv.pem');
const pubkey = fs.readFileSync(__dirname + '/jwt-pub.pem');
const databaseCredential = require(__dirname + '/sql.json')

const wssLogin = new webSocket.Server({ port: loginPort })
const wssUpdates = new webSocket.Server({ port: updatesPort });
var server = http.createServer(app).listen(registerPort, function () {
    console.log('Started Library Service, listening on ports', loginPort, registerPort, updatesPort, '. It\'s', new Date(Date.now()).toString());
});

//KEYS
app.post('/lostkey', function (req, res) {
    let postData = "";
    req.on('data', (chunk) => {
        postData += chunk.toString();
    });
    req.on('end', async () => {
        try {
            console.log('Starting key reset procedure');
            let conn = await mariadb.createConnection(databaseCredential); await conn.query('USE ' + databaseCredential.database);
            let parsedUserData = JSON.parse(postData);
            if (!parsedUserData.email) throw 'NO_EMAIL_ADDRESS_GIVEN';
            let email = parsedUserData.email;
            if (!String(email)
                .toLowerCase()
                .match(
                    /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
                )) throw 'INVALID_EMAIL_ADDRESS';
            let emailSearchResult = await conn.query('SELECT * FROM users WHERE email=?', [email]);
            if (emailSearchResult.length != 1) throw 'USER_DOES_NOT_EXIST';

            sendKeyRegistrationMail(email);

            conn.close();
            res.writeHead(200);
            res.end();
        } catch (exception) {
            console.log('Key reset procedure failed with exception', exception);
            res.writeHead(400);
            res.end(exception);

        }
    });
})
app.post('/registerKey', function (req, res) {
    console.log('registerkey');
    let postData = "";
    req.on('data', (chunk) => {
        postData += chunk.toString();
    });
    req.on('end', async () => {
        try {
            console.log('Starting key registration procedure');
            let conn = await mariadb.createConnection(databaseCredential); await conn.query('USE ' + databaseCredential.database);
            const registrationObject = JSON.parse(postData);
            let decodedResetToken = null;
            try {
                decodedResetToken = jwt.verify(registrationObject.resetToken, pubkey, { algorithm: 'ES512' });
            } catch (exception) {
                console.log(exception);
                throw 'ERROR_TOKEN_OR_SIGNATURE_INVALID';
            }
            console.log(registrationObject);
            console.log(decodedResetToken);
            if (!registrationObject.publicKey ||
                !registrationObject.keyId ||
                !registrationObject.clientDataJson ||
                decodedResetToken.iss != 'library.karol.gay' ||
                decodedResetToken.kind != 'key-reset' ||
                !decodedResetToken.nonce ||
                !decodedResetToken.iat ||
                !decodedResetToken.exp ||
                !decodedResetToken.mail ||
                !decodedResetToken.uuid
            ) throw 'INVALID_TOKEN_OR_MISSING_FIELDS';
            if (registrationObject.exp < Date.now()) throw 'TOKEN_EXPIRED';
            if (registrationObject.clientDataJson.type != 'webauthn.create') throw 'INVALID_CEREMONY_TYPE';
            if (registrationObject.clientDataJson.origin != 'https://library.karol.gay') throw 'KEY_INVALID_ORIGIN';
            if (btoa(decodedResetToken.nonce).replace('==', '') != registrationObject.clientDataJson.challenge) throw 'NONCE_MISMATCH';

            console.log('User registartion object:', registrationObject);

            let userQueryReponse = await conn.query('SELECT * FROM users WHERE uuid=?', [decodedResetToken.uuid]);
            if (userQueryReponse.length == 0) throw 'USER_NOT_FOUND';
            if (userQueryReponse[0].nonce > decodedResetToken.iat) throw 'NEWER_TOKEN_ALREADY_USED';

            await conn.query("UPDATE users SET name=?, pubkey=?, keyid=?, nonce=? WHERE uuid=?", [registrationObject.userName || decodedResetToken.email, registrationObject.publicKey, registrationObject.keyId, decodedResetToken.iat, decodedResetToken.uuid]);

            console.log('Succesfully updated key for user', decodedResetToken.uuid);

            conn.close();
            res.writeHead(200);
            res.end();
            return;

        } catch (exception) {
            console.log('Key registration procedure failed with exception', exception);
            res.writeHead(400);
            res.end(exception);
        }
    });
});
app.get('/resetdevice*', async function (req, res) {
    try {

        console.log('Starting redirect procedudre');
        let conn = await mariadb.createConnection(databaseCredential); await conn.query('USE ' + databaseCredential.database);
        let id = new URL('https://library.karol.gay' + req.url).searchParams.get('token');
        if (!id) throw 'REDIRECT_ID_NULL_OR_EMPTY'
        console.log('User redirect id:', id);
        let queryResult = await conn.query('SELECT url FROM redirect WHERE id=?', [id]);
        if (queryResult.length == 0) throw 'REDIRECT_ID_NOT_FOUND';
        let link = queryResult[0].url;
        conn.close();
        res.redirect(link);
        res.end();
        return;
    } catch (exception) {
        console.log('Redirect procedure failed with exception:', exception);
        res.redirect('https://library.karol.gay/');
        res.end();
        return;
    }
});
async function sendKeyRegistrationMail(email) {
    let conn = await mariadb.createConnection(databaseCredential); await conn.query('USE ' + databaseCredential.database);
    if (!email) throw 'EMAIL_NULL_OR_EMPTY';
    console.log('Sending key registration email to', email);
    let userQueryResponse = await conn.query('SELECT * FROM users WHERE email=?', [email]);
    if (userQueryResponse.length == 0) throw 'USER_NOT_FOUND';
    let user = userQueryResponse[0];

    var nonce = "";
    const possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (var i = 0; i < 64; i++)
        nonce += possible.charAt(Math.floor(Math.random() * possible.length));

    const claims = {
        iss: "library.karol.gay",
        kind: "key-reset",

        nonce: nonce,

        iat: Date.now(),
        exp: Date.now() + 900000,

        name: user.name || user.email,
        mail: user.email,
        uuid: user.uuid,
        admin: user.admin == 1

    }

    const token = jwt.sign(claims, privkey, { algorithm: 'ES512' });
    const url = await createRedirect('https://library.karol.gay/keyreset.html?token=' + token);

    let messageText = fs.readFileSync(__dirname + '/mail.txt').toString();
    let messageHtml = fs.readFileSync(__dirname + '/mail.html').toString();

    let message = {
        from: '"Library 📖" <library@karol.gay>',
        to: claims.mail,
        subject: 'Register new device with your account',
        text: messageText.replaceAll('{{name}}', claims.name).replaceAll('{{action_url}}', url),
        html: messageHtml.replaceAll('{{name}}', claims.name).replaceAll('{{action_url}}', url),
        attachments: []
    };
    let transporter = nodemailer.createTransport({
        host: "in-v3.mailjet.com",
        port: 587,
        secure: false,
        auth: require('./smtp.json')
    });
    try {
        await transporter.sendMail(message);
    } catch (exception) {
        console.log('Failed to send an email with exception', exception);
        throw 'EMAIL_FAILED_TO_SEND';
    }
    conn.close();
    return;
}
async function createRedirect(url) {
    if (!url) throw 'ERROR_URL_NULL_OR_EMPTY';
    console.log('Creating redirect url for url', url);
    let conn = await mariadb.createConnection(databaseCredential); await conn.query('USE ' + databaseCredential.database);
    var nonce = "";
    const possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (var i = 0; i < 64; i++)
        nonce += possible.charAt(Math.floor(Math.random() * possible.length));


    let id = crypto.createHash('sha256').update(nonce + url).digest('hex');
    console.log('ID for this url is', id);

    await conn.query('INSERT INTO redirect (id, url) VALUES (?, ?)', [id, url]);
    conn.close();
    return 'https://library.karol.gay/resetdevice?token=' + id;
}

//SIGNUP
app.post('/register', function (req, res) {
    let postData = "";
    req.on('data', (chunk) => {
        postData += chunk.toString();
    });
    req.on('end', async () => {
        try {
            console.log('Starting user signup procedure');
            let conn = await mariadb.createConnection(databaseCredential); await conn.query('USE ' + databaseCredential.database);
            let parsedUserData = JSON.parse(postData);
            if (!parsedUserData.email) throw 'NO_EMAIL_ADDRESS_GIVEN';
            let email = parsedUserData.email;
            let uuid = getUuid(email);
            if (!String(email)
                .toLowerCase()
                .match(
                    /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
                )) throw 'INVALID_EMAIL_ADDRESS';
            let emailSearchResult = await conn.query('SELECT * FROM users WHERE email=?', [email]);
            if (emailSearchResult.length == 1) throw 'EMAIL_ALREADY_TAKEN';


            await conn.query('INSERT INTO users (uuid, admin, email) VALUES (?, ?, ?)', [uuid, false, email]);

            sendKeyRegistrationMail(email);
            broadcastUpdate();

            console.log('Succesfully create an account for', uuid);

            conn.close();
            res.writeHead(200);
            res.end();
        } catch (exception) {
            console.log('User signup procedure failed with exception', exception);
            res.writeHead(400);
            res.end(exception);
        }
    });

});

//SIGNIN
wssLogin.on("connection", ws => {
    console.log('Starting user assertion procedure');

    var challange = "";
    const possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (var i = 0; i < 64; i++)
        challange += possible.charAt(Math.floor(Math.random() * possible.length));

    ws.send(JSON.stringify({ kind: 'challange', challange: challange }))

    ws.on("message", async message => {
        try {
            let conn = await mariadb.createConnection(databaseCredential); await conn.query('USE ' + databaseCredential.database);
            let assertionObject = JSON.parse(new TextDecoder().decode(message));
            if (!assertionObject.keyId ||
                !assertionObject.clientData ||
                !assertionObject.authData ||
                !assertionObject.signature
            ) throw 'ASSERTION_MISSING_FIELDS';
            let userSearchResponse = await conn.query('SELECT * FROM users WHERE keyid=?', [assertionObject.keyId]);
            if (userSearchResponse.length == 0) throw 'USER_NOT_FOUND';
            let user = userSearchResponse[0];
            console.log('Authenticating user', user);

            async function digest(data, _algorithm) {
                const hashed = await crypto.webcrypto.subtle.digest('SHA-256', data);

                return new Uint8Array(hashed);
            }
            async function toHash(data, algorithm = -7) {
                function fromUTF8String(utf8String) {
                    const encoder = new globalThis.TextEncoder();
                    return encoder.encode(utf8String);
                }
                if (typeof data === 'string') {
                    data = fromUTF8String(data);
                }

                return digest(data, algorithm);
            }
            function concat(arrays) {
                let pointer = 0;
                const totalLength = arrays.reduce((prev, curr) => prev + curr.length, 0);

                const toReturn = new Uint8Array(totalLength);

                arrays.forEach((arr) => {
                    toReturn.set(arr, pointer);
                    pointer += arr.length;
                });

                return toReturn;
            }
            function decodeAuthData(authData) {
                console.log('decode auth data');
                let FLAG_UP = 0x01; // Flag for userPresence
                let FLAG_UV = 0x04; // Flag for userVerification
                let FLAG_AT = 0x40; // Flag for attestedCredentialData
                let FLAG_ED = 0x80; // Flag for extensions

                let rpIdHash = authData.slice(0, 32);
                let flags = authData.slice(32, 33)[0];
                let signCount = authData.slice(33, 37);

                if ((flags & FLAG_AT) === 0x00) {
                    // no attestedCredentialData
                    return {
                        rpIdHash: rpIdHash,
                        flags: flags,
                        signCount: signCount
                    }
                }

                if (authData.length < 38) {
                    // attestedCredentialData missing
                    throw 'invalid authData.length';
                }

                let aaguid = authData.slice(37, 53);
                let credentialIdLength = (authData[53] << 8) + authData[54]; //16-bit unsigned big-endian integer
                let credenitalId = authData.slice(55, 55 + credentialIdLength);
                let credentialPublicKey = this.decodeCredentialPublicKey(authData.slice(55 + credentialIdLength));

                /* decoding extensions - not implemented */

                return {
                    rpIdHash: rpIdHash,
                    flags: flags,
                    signCount: signCount,
                    attestedCredentialData: {
                        aaguid: aaguid,
                        credentialId: credenitalId,
                        credentialPublicKey: credentialPublicKey
                    }
                }
            }

            let Ecdsa = ellipticcurve.Ecdsa;
            let Signature = ellipticcurve.Signature;
            let PublicKey = ellipticcurve.PublicKey;

            let decodedAuthData = decodeAuthData(assertionObject.authData.replaceAll('=', ''));
            let decodedUserData = JSON.parse(atob(assertionObject.clientData));
            console.log('User provided data:', decodedUserData);
            console.log('Authenticator provided data:', decodedAuthData);

            let publicKey = PublicKey.fromPem(user.pubkey);
            let signature = Signature.fromDer(atob(assertionObject.signature));

            let authDataBuffer = base64url.toBuffer(assertionObject.authData);
            let clientDataHash = await toHash(base64url.toBuffer(assertionObject.clientData));
            let signatureBase = concat([authDataBuffer, clientDataHash]);

            let authenticationResult = {
                signedCorrectly: Ecdsa.verify(signatureBase, signature, publicKey),
                challangeMatch: decodedUserData.challenge == btoa(challange).replace('==', ''),
                rpidMatch: decodedAuthData.rpIdHash == 'g0Wwcdu/y9I4JMxQaL9PcnCQSwMAhazy',
                ceremonyMatch: decodedUserData.type == 'webauthn.get',
                originMatch: decodedUserData.origin == 'https://library.karol.gay'
            };

            console.log('User authentication result', authenticationResult);

            if (authenticationResult.signedCorrectly && authenticationResult.challangeMatch && authenticationResult.rpidMatch && authenticationResult.ceremonyMatch && authenticationResult.originMatch) {

                let trustCookieObject = {
                    iss: 'library.karol.gay',
                    kind: 'trust-cookie',
                    nonce: challange,
                    iat: Date.now(),
                    exp: Date.now() + 86400000, //24h
                    name: user.name,
                    mail: user.mail,
                    uuid: user.uuid,
                    admin: user.admin == 1
                }
                let token = jwt.sign(trustCookieObject, privkey, { algorithm: 'ES512' });
                let cookie = 'token=' + token + ';secure;path=/;expires=' + trustCookieObject.exp;


                ws.send(JSON.stringify({ kind: 'cookie', cookie: cookie }));
                ws.close();


            } else throw 'USER_AUTHENTICATION_FAILURE';
            conn.close();

        } catch (exception) {
            console.log('User assertion procedure failed with exception', exception);
            ws.send(JSON.stringify({ kind: 'exception', error: exception }));
            ws.close();
        }
    });


});
async function getUserFromCookie(cookie) {
    let conn = await mariadb.createConnection(databaseCredential); await conn.query('USE ' + databaseCredential.database);
    if (!cookie) throw 'UNAUTHORIZED';
    let decodedCookie = null;
    try {
        decodedCookie = jwt.verify(cookie, pubkey, { algorithm: 'ES512' });
    } catch (exception) {
        console.log(exception);
        throw 'ERROR_COOKIE_OR_SIGNATURE_INVALID';
    }
    console.log('User provided cookie', decodedCookie);
    if (
        decodedCookie.iss != 'library.karol.gay' ||
        decodedCookie.kind != 'trust-cookie' ||
        !decodedCookie.nonce ||
        !decodedCookie.iat ||
        !decodedCookie.exp ||
        !decodedCookie.name ||
        !decodedCookie.uuid
    ) throw 'COOKIE_MISSING_FIELDS';
    if (decodedCookie.exp < Date.now()) throw 'COOKIE_EXPIRED';
    let user = {
        authenticated: true,
        admin: decodedCookie.admin === true,
        uuid: decodedCookie.uuid
    }
    console.log('User return with object', user);
    conn.close();
    return user;
}


//BOOKS
app.get('/books/get*', async function (req, res) {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    try {
        console.log('Starting books get procedure');
        let conn = await mariadb.createConnection(databaseCredential); await conn.query('USE ' + databaseCredential.database);
        let user = await getUserFromCookie(req.cookies['token']);
        if (!user.authenticated) throw 'UNAUTHORIZED';

        if (req.url == '/books/get') {
            let books = await conn.query('SELECT * FROM books ORDER BY title');
            let booksList = [];
            for (let i = 0; i < books.length; i++) {
                books[i].availableToRent = books[i].rentedby == null;
                books[i].rentedByYou = books[i].rentedby == user.uuid;
                if (!user.admin) delete books[i].rentedby;
                booksList.push(books[i]);
            }
            res.writeHead(200);
            res.end(JSON.stringify(booksList));


        } else {
            let bookUuid = (req.url + new Array(50).join('X')).substring(11, 47); //pad to avoid exception
            let bookSearchResult = await conn.query('SELECT * FROM books WHERE uuid=?', [bookUuid]);
            if (bookSearchResult.length == 0) throw 'BOOK_NOT_FOUND';
            let book = bookSearchResult[0];
            book.availableToRent = book.rentedby == null;
            book.rentedByYou = book.rentedby == user.uuid;
            if (!user.admin) delete book.rentedby;

            conn.close();
            res.writeHead(200);
            res.end(JSON.stringify(book));
        }
    } catch (exception) {
        console.log('Books get procedure failed with exception', exception);
        if ([
            'UNAUTHORIZED',
            'ERROR_COOKIE_OR_SIGNATURE_INVALID',
            'COOKIE_MISSING_FIELDS',
            'COOKIE_EXPIRED'
        ].includes(exception)) {
            res.writeHead(401);
            res.end(exception);
            return;
        }
        if ([
            'BOOK_NOT_FOUND'
        ].includes(exception)) {
            res.writeHead(404);
            res.end(exception);
            return;
        }
        res.writeHead(500);
        res.end(exception);

    }
})
app.post('/books/add', function (req, res) {
    let postData = "";
    req.on('data', (chunk) => {
        postData += chunk.toString();
    });
    req.on('end', async () => {
        try {
            console.log('Starting books add procedure');
            let conn = await mariadb.createConnection(databaseCredential); await conn.query('USE ' + databaseCredential.database);
            let user = await getUserFromCookie(req.cookies['token']);
            if (!user.authenticated) throw 'UNAUTHORIZED';
            if (!user.admin) throw 'USER_NOT_ADMIN';

            let book = JSON.parse(postData);

            if (
                !book.title ||
                !book.author ||
                !book.description ||
                !book.isbn
            ) throw 'BOOK_MISSING_FIELDS';

            var nonce = "";
            const possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            for (var i = 0; i < 64; i++)
                nonce += possible.charAt(Math.floor(Math.random() * possible.length));
            let uuid = getUuid(crypto.createHash('sha256').update(postData).digest('hex') + nonce);

            if (book.rentedby) {
                let userSearch = await conn.query('SELECT * FROM users WHERE uuid=?', [book.rentedby]);
                if (userSearch.length == 0) throw 'USER_NOT_FOUND';
                let user = userSearch[0];
                let rentedList = JSON.parse(user.rented);
                rentedList.push(uuid);
                await conn.query('UPDATE users SET rented=? WHERE uuid=?', [JSON.stringify(rentedList), book.rentedby]);
                await conn.query('INSERT INTO books (uuid, title, author, isbn, description, rentedby) VALUES (?, ?, ?, ?, ?, ?)',
                    [uuid, book.title, book.author, book.isbn, book.description, book.rentedby]);

                broadcastUpdate();
                conn.close();
                res.writeHead(200);
                res.end();
                return;
            }
            else {
                await conn.query('INSERT INTO books (uuid, title, author, isbn, description, rentedby) VALUES (?, ?, ?, ?, ?, NULL)',
                    [uuid, book.title, book.author, book.isbn, book.description]);

                broadcastUpdate();
                conn.close();
                res.writeHead(200);
                res.end();
                return;
            }





        } catch (exception) {
            console.log('Books add procedure failed with exception', exception);
            if ([
                'UNAUTHORIZED',
                'ERROR_COOKIE_OR_SIGNATURE_INVALID',
                'COOKIE_MISSING_FIELDS',
                'COOKIE_EXPIRED'
            ].includes(exception)) {
                res.writeHead(401);
                res.end(exception);
                return;
            }
            if ([
                'BOOK_MISSING_FIELDS',
                'USER_NOT_FOUND'
            ].includes(exception)) {
                res.writeHead(400);
                res.end(exception);
                return;
            }
            if ([
                'USER_NOT_ADMIN'
            ].includes(exception)) {
                res.writeHead(403);
                res.end(exception);
                return;
            }
            res.writeHead(500);
            res.end(exception);

        }
    })

})
app.patch('/books/update*', function (req, res) {
    console.log('books update');
    let postData = "";
    req.on('data', (chunk) => {
        postData += chunk.toString();
    });
    req.on('end', async () => {
        try {
            console.log('Starting books update procedure');
            let conn = await mariadb.createConnection(databaseCredential); await conn.query('USE ' + databaseCredential.database);
            let user = await getUserFromCookie(req.cookies['token']);
            if (!user.authenticated) throw 'UNAUTHORIZED';
            if (!user.admin) throw 'USER_NOT_ADMIN';

            let book = JSON.parse(postData);

            if (
                !book.title ||
                !book.author ||
                !book.description ||
                !book.isbn
            ) throw 'BOOK_MISSING_FIELDS';


            let uuid = (req.url + new Array(50).join('X')).substring(14, 50); //pad to avoid exception

            let bookSearchResult = await conn.query('SELECT * FROM books WHERE uuid=?', [uuid]);
            if (bookSearchResult.length == 0) throw 'BOOK_NOT_FOUND';
            let currentlyRentedBy = bookSearchResult[0].rentedby;

            if (book.rentedby) {
                let userSearch = await conn.query('SELECT * FROM users WHERE uuid=?', [book.rentedby]);
                if (userSearch.length == 0) throw 'USER_NOT_FOUND';
                let user = userSearch[0];

                if (currentlyRentedBy) {
                    let userListCurrentlyRentedBy = await conn.query('SELECT * FROM users WHERE uuid=?', [currentlyRentedBy]);
                    let list = JSON.parse(userListCurrentlyRentedBy[0].rented);
                    list = list.filter(function (value, index, arr) {
                        return value != uuid;
                    });
                    await conn.query('UPDATE users SET rented=? WHERE uuid=?', [JSON.stringify(list), currentlyRentedBy]);
                    await conn.query('UPDATE books SET rentedby=NULL WHERE uuid=?', [uuid]);
                }

                let list = JSON.parse(user.rented);
                list.push(uuid);
                await conn.query('UPDATE users SET rented=? WHERE uuid=?', [JSON.stringify(list), user.uuid]);
                await conn.query('UPDATE books SET rentedby=? WHERE uuid=?', [user.uuid, uuid]);
            }
            else if (currentlyRentedBy) {
                let userListCurrentlyRentedBy = await conn.query('SELECT * FROM users WHERE uuid=?', [currentlyRentedBy]);
                let list = JSON.parse(userListCurrentlyRentedBy[0].rented);
                list = list.filter(function (value, index, arr) {
                    return value != uuid;
                });
                await conn.query('UPDATE users SET rented=? WHERE uuid=?', [JSON.stringify(list), currentlyRentedBy]);
                await conn.query('UPDATE books SET rentedby=NULL WHERE uuid=?', [uuid]);
            }
            await conn.query('UPDATE books SET title=?, author=?, isbn=?, description=? WHERE uuid=?', [book.title, book.author, book.isbn, book.description, uuid]);

            broadcastUpdate();
            conn.close();
            res.writeHead(200);
            res.end();
            return;

        } catch (exception) {
            console.log('Books update procedure failed with exception', exception);
            if ([
                'UNAUTHORIZED',
                'ERROR_COOKIE_OR_SIGNATURE_INVALID',
                'COOKIE_MISSING_FIELDS',
                'COOKIE_EXPIRED'
            ].includes(exception)) {
                res.writeHead(401);
                res.end(exception);
                return;
            }
            if ([
                'BOOK_MISSING_FIELDS',
                'USER_NOT_FOUND'
            ].includes(exception)) {
                res.writeHead(400);
                res.end(exception);
                return;
            }
            if ([
                'BOOK_NOT_FOUND'
            ].includes(exception)) {
                res.writeHead(404);
                res.end(exception);
                return;
            }
            if ([
                'USER_NOT_ADMIN'
            ].includes(exception)) {
                res.writeHead(403);
                res.end(exception);
                return;
            }
            res.writeHead(500);
            res.end(exception);

        }
    })

})
app.delete('/books/delete*', async function (req, res) {
    try {
        console.log('Starting books delete procedure');
        let conn = await mariadb.createConnection(databaseCredential); await conn.query('USE ' + databaseCredential.database);
        let user = await getUserFromCookie(req.cookies['token']);
        if (!user.authenticated) throw 'UNAUTHORIZED';
        if (!user.admin) throw 'USER_NOT_ADMIN';

        let uuid = (req.url + new Array(50).join('X')).substring(14, 50); //pad to avoid exception

        let bookSearchResult = await conn.query('SELECT * FROM books WHERE uuid=?', [uuid]);
        if (bookSearchResult.length == 0) throw 'BOOK_NOT_FOUND';
        let currentlyRentedBy = bookSearchResult[0].rentedby;

        if (currentlyRentedBy) {
            let userListCurrentlyRentedBy = await conn.query('SELECT * FROM users WHERE uuid=?', [currentlyRentedBy]);
            let list = JSON.parse(userListCurrentlyRentedBy[0].rented);
            list = list.filter(function (value, index, arr) {
                return value != uuid;
            });
            await conn.query('UPDATE users SET rented=? WHERE uuid=?', [JSON.stringify(list), currentlyRentedBy]);
        }
        await conn.query('DELETE FROM books WHERE uuid=?', [uuid]);

        broadcastUpdate();
        conn.close();
        res.writeHead(200);
        res.end();
        return;

    } catch (exception) {
        console.log('Books delete procedure failed with exception', exception);
        if ([
            'UNAUTHORIZED',
            'ERROR_COOKIE_OR_SIGNATURE_INVALID',
            'COOKIE_MISSING_FIELDS',
            'COOKIE_EXPIRED'
        ].includes(exception)) {
            res.writeHead(401);
            res.end(exception);
            return;
        }
        if ([
            'BOOK_NOT_FOUND'
        ].includes(exception)) {
            res.writeHead(404);
            res.end(exception);
            return;
        }
        if ([
            'USER_NOT_ADMIN'
        ].includes(exception)) {
            res.writeHead(403);
            res.end(exception);
            return;
        }
        res.writeHead(500);
        res.end(exception);

    }
})
app.get('/books/search*', async function (req, res) {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    try {
        console.log('Starting books search procedure');
        let conn = await mariadb.createConnection(databaseCredential); await conn.query('USE ' + databaseCredential.database);
        let user = await getUserFromCookie(req.cookies['token']);
        if (!user.authenticated) throw 'UNAUTHORIZED';
        let search = '%' + ((new URL('https://library.karol.gay' + req.url).searchParams.get('query')) || '') + '%';
        console.log('Searching books for', search);

        let books = await conn.query('SELECT * FROM books WHERE CONCAT(title, author, isbn, description) LIKE ? ORDER BY title', [search]);
        let booksList = [];
        for (let i = 0; i < books.length; i++) {
            books[i].availableToRent = books[i].rentedby == null;
            books[i].rentedByYou = books[i].rentedby == user.uuid;
            if (!user.admin) delete books[i].rentedby;
            booksList.push(books[i]);
        }
        conn.close();
        res.writeHead(200);
        res.end(JSON.stringify(booksList));
    } catch (exception) {
        console.log('Books search procedure failed with exception', exception);
        if ([
            'UNAUTHORIZED',
            'ERROR_COOKIE_OR_SIGNATURE_INVALID',
            'COOKIE_MISSING_FIELDS',
            'COOKIE_EXPIRED'
        ].includes(exception)) {
            res.writeHead(401);
            res.end(exception);
            return;
        }
        res.writeHead(500);
        res.end(exception);

    }
})

//USERS
app.get('/users/get*', async function (req, res) {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    try {
        console.log('Starting users get procedure');
        let conn = await mariadb.createConnection(databaseCredential); await conn.query('USE ' + databaseCredential.database);
        let user = await getUserFromCookie(req.cookies['token']);
        if (!user.authenticated) throw 'UNAUTHORIZED';
        if (!user.admin) throw 'USER_NOT_ADMIN';
        if (req.url == '/users/get') {
            let usersResponse = await conn.query('SELECT * FROM users');
            let userList = [];
            for (let i = 0; i < usersResponse.length; i++)userList.push({
                uuid: usersResponse[i].uuid,
                name: usersResponse[i].name,
                email: usersResponse[i].email,
                admin: usersResponse[i].admin == 1,
		key: usersResponse[i].keyid,
                rented: JSON.parse(usersResponse[i].rented)
            });
            res.writeHead(200);
            res.end(JSON.stringify(userList));


        } else {
            let uuid = (req.url + new Array(50).join('X')).substring(11, 47); //pad to avoid exception
            let usersResponse = await conn.query('SELECT * FROM users WHERE uuid=?', [uuid]);
            if (usersResponse.length == 0) throw 'USER_NOT_FOUND';
            let user = {
                uuid: usersResponse[0].uuid,
                name: usersResponse[0].name,
                email: usersResponse[0].email,
                admin: usersResponse[0].admin == 1,
                rented: JSON.parse(usersResponse[0].rented)
            }
            conn.close();
            res.writeHead(200);
            res.end(JSON.stringify(user));
        }
    } catch (exception) {
        console.log('Users get procedure failed with exception', exception);
        if ([
            'UNAUTHORIZED',
            'ERROR_COOKIE_OR_SIGNATURE_INVALID',
            'COOKIE_MISSING_FIELDS',
            'COOKIE_EXPIRED'
        ].includes(exception)) {
            res.writeHead(401);
            res.end(exception);
            return;
        }
        if ([
            'USER_NOT_FOUND'
        ].includes(exception)) {
            res.writeHead(404);
            res.end(exception);
            return;
        }
        if ([
            'USER_NOT_ADMIN'
        ].includes(exception)) {
            res.writeHead(403);
            res.end(exception);
            return;
        }
        res.writeHead(500);
        res.end(exception);

    }

});

//RENTAL
app.get('/rental/get', async function (req, res) {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    try {
        console.log('Starting rental get procedure');
        let conn = await mariadb.createConnection(databaseCredential); await conn.query('USE ' + databaseCredential.database);
        let user = await getUserFromCookie(req.cookies['token']);
        if (!user.authenticated) throw 'UNAUTHORIZED';

        let rentedList = await conn.query('SELECT uuid, title, author, isbn, description FROM books WHERE rentedby=?', [user.uuid]);
        let list = [];
        for (let i = 0; i < rentedList.length; i++)
            list.push(rentedList[i]);
        conn.close();
        res.writeHead(200);
        res.end(JSON.stringify(list));
        return;
    } catch (exception) {
        console.log('Rental get procedure failed with exception', exception);
        if ([
            'UNAUTHORIZED',
            'ERROR_COOKIE_OR_SIGNATURE_INVALID',
            'COOKIE_MISSING_FIELDS',
            'COOKIE_EXPIRED'
        ].includes(exception)) {
            res.writeHead(401);
            res.end(exception);
            return;
        }
        res.writeHead(500);
        res.end(exception);

    }
})
app.post('/rental/rent*', async function (req, res) {
    try {
        console.log('Starting rental rent procedure');
        let conn = await mariadb.createConnection(databaseCredential); await conn.query('USE ' + databaseCredential.database);
        let user = await getUserFromCookie(req.cookies['token']);
        if (!user.authenticated) throw 'UNAUTHORIZED';

        let uuid = (req.url + new Array(50).join('X')).substring(13, 49);

        let bookQueryResult = await conn.query('SELECT * FROM books WHERE uuid=?', [uuid]);
        if (bookQueryResult.length == 0) throw 'BOOK_NOT_FOUND';

        let book = bookQueryResult[0];

        if (book.rentedby && book.rentedby != user.uuid) throw 'BOOK_UNAVAILABLE';
        if (book.rentedby == user.uuid) throw 'BOOK_ALREADY_RENTED_BY_YOU';

        let userQueryResult = await conn.query('SELECT rented FROM users WHERE uuid=?', [user.uuid]);
        if (userQueryResult.length == 0) throw 'USER_NOT_FOUND';

        let userList = JSON.parse(userQueryResult[0].rented);

        userList.push(uuid);

        await conn.query('UPDATE users SET rented=? WHERE uuid=?', [JSON.stringify(userList), user.uuid]);
        await conn.query('UPDATE books SET rentedby=? WHERE uuid=?', [user.uuid, uuid]);

        conn.close();
        broadcastUpdate();
        res.writeHead(200);
        res.end();
        return;
    } catch (exception) {
        console.log('Rental rent procedure failed with exception', exception);
        if ([
            'UNAUTHORIZED',
            'ERROR_COOKIE_OR_SIGNATURE_INVALID',
            'COOKIE_MISSING_FIELDS',
            'COOKIE_EXPIRED'
        ].includes(exception)) {
            res.writeHead(401);
            res.end(exception);
            return;
        }
        if ([
            'BOOK_NOT_FOUND'
        ].includes(exception)) {
            res.writeHead(404);
            res.end(exception);
            return;
        }
        if ([
            'BOOK_UNAVAILABLE',
            'BOOK_ALREADY_RENTED_BY_YOU',
            'USER_NOT_FOUND'
        ].includes(exception)) {
            res.writeHead(400);
            res.end(exception);
            return;
        }
        res.writeHead(500);
        res.end(exception);

    }

})
app.post('/rental/return*', async function (req, res) {
    try {
        console.log('Starting rental return procedure');
        let conn = await mariadb.createConnection(databaseCredential); await conn.query('USE ' + databaseCredential.database);
        let user = await getUserFromCookie(req.cookies['token']);
        if (!user.authenticated) throw 'UNAUTHORIZED';

        let uuid = (req.url + new Array(50).join('X')).substring(15, 51);

        let bookQueryResult = await conn.query('SELECT * FROM books WHERE uuid=?', [uuid]);
        if (bookQueryResult.length == 0) throw 'BOOK_NOT_FOUND';

        let book = bookQueryResult[0];

        if (book.rentedby && book.rentedby != user.uuid) throw 'BOOK_RENTED_BY_ANOTHER_USER';
        if (!book.rentedby) throw 'BOOK_NOT_RENTED';

        let userQueryResult = await conn.query('SELECT rented FROM users WHERE uuid=?', [user.uuid]);
        if (userQueryResult.length == 0) throw 'USER_NOT_FOUND';

        let userList = JSON.parse(userQueryResult[0].rented);

        userList = userList.filter(function (value, index, arr) {
            return value != uuid;
        });

        await conn.query('UPDATE users SET rented=? WHERE uuid=?', [JSON.stringify(userList), user.uuid]);
        await conn.query('UPDATE books SET rentedby=NULL WHERE uuid=?', [uuid]);

        conn.close();
        broadcastUpdate();
        res.writeHead(200);
        res.end();
        return;
    } catch (exception) {
        console.log('Rental return procedure failed with exception', exception);
        if ([
            'UNAUTHORIZED',
            'ERROR_COOKIE_OR_SIGNATURE_INVALID',
            'COOKIE_MISSING_FIELDS',
            'COOKIE_EXPIRED'
        ].includes(exception)) {
            res.writeHead(401);
            res.end(exception);
            return;
        }
        if ([
            'BOOK_NOT_FOUND'
        ].includes(exception)) {
            res.writeHead(404);
            res.end(exception);
            return;
        }
        if ([
            'BOOK_RENTED_BY_ANOTHER_USER',
            'BOOK_NOT_RENTED',
            'USER_NOT_FOUND'
        ].includes(exception)) {
            res.writeHead(400);
            res.end(exception);
            return;
        }
        res.writeHead(500);
        res.end(exception);

    }
})

//UPDATES
let updatesClientsList = [];
wssUpdates.on("connection", ws => {
    console.log('New client connected to updates channel.');
    updatesClientsList.push(ws);
    console.log('Updates currently connected:', updatesClientsList.length);
    ws.on("close", () => {
        console.log('User disconnected from updates channel');
        for (var i = 0; i < updatesClientsList.length; i++) {
            if (updatesClientsList[i] === ws) {
                updatesClientsList.splice(i, 1);
                i--;
            }
        }
        console.log('Updates currently connected:', updatesClientsList.length);
    })
});
function broadcastUpdate() {
    console.log('Broadcasting update to all users');
    updatesClientsList.forEach(element => {
        try {
            element.send('UPDATE')
        } catch (exception) {
            console.log('Broadcast update failed for elemenent', element, 'with exception', exception);
        }
    });
}
