const express = require('express');
const http = require('http');
const app = express();
const fs = require('fs');
const webSocket = require('ws');
const jwt = require('jsonwebtoken');
const mariadb = require('mariadb');
const getUuid = require('uuid-by-string');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const base64url = require('base64url');
const ellipticcurve = require("starkbank-ecdsa");


const loginPort = 2100;
const registerPort = 2101;
const updatesPort = 2102;

const privkey = fs.readFileSync(__dirname + '/jwt-priv.pem');
const pubkey = fs.readFileSync(__dirname + '/jwt-pub.pem');
const databaseCredential = require(__dirname + '/sql.json')

const pool = mariadb.createPool(databaseCredential);

const wssLogin = new webSocket.Server({ port: loginPort })
const wssUpdates = new webSocket.Server({ port: updatesPort });
var server = http.createServer(app).listen(registerPort, function () {
    console.log('Started Library Service, listening on ports', loginPort, registerPort, updatesPort, '. It\'s', new Date(Date.now()).toString());
});

let updatesClientsList = [];

app.post('/registerKey', function (req, response) {
    console.log('registerkey');
    let userData = "";
    req.on('data', (chunk) => {
        userData += chunk.toString();
    });
    req.on('end', () => {
        try {
            const registrationObject = JSON.parse(userData);

            let decodedResetToken = jwt.verify(registrationObject.resetToken, pubkey, { algorithm: 'PS512' });

            console.log(registrationObject);

            if (decodedResetToken.iss != 'library.karol.gay' || decodedResetToken.kind != 'key-reset' || decodedResetToken.exp < Date.now() ||
                registrationObject.clientDataJson.type != 'webauthn.create' || registrationObject.clientDataJson.origin != 'https://library.karol.gay'
            ) throw 'Exception key mismatch or invalid token';


            console.log('Connecting to database'); pool.getConnection().then(conn => {
                conn.query('USE ' + databaseCredential.database).then(() => {
                    conn.query('SELECT * FROM users WHERE uuid=?', [decodedResetToken.uuid]).then(res => {
                        if (btoa(decodedResetToken.nonce).replace('==', '') == registrationObject.clientDataJson.challenge) console.log('NONCE_MATCH');
                        if (res[0].nonce < decodedResetToken.iat &&
                            btoa(decodedResetToken.nonce).replace('==', '') == registrationObject.clientDataJson.challenge
                        ) {
                            conn.query("UPDATE users SET name=?, pubkey=?, keyid=?, nonce=? WHERE uuid=?", [registrationObject.userName, registrationObject.publicKey, registrationObject.keyId, decodedResetToken.iat, decodedResetToken.uuid]).then(res => {
                                response.writeHead(200);
                                response.end();
                                console.log('Releasing connection'); conn.release(); conn.close();
                            })
                        }
                        else {
                            console.log('TOKEN_TOO_OLD');
                            response.writeHead(400);
                            console.log('Releasing connection'); conn.release(); conn.close();
                            response.end('ERROR_TOKEN_TOO_OLD');
                        }
                    })
                }).catch(err => {
                    console.log(err);
                    response.writeHead(400);
                    console.log('Releasing connection'); conn.release(); conn.close();
                    response.end('ERROR_VALIDATING_DATA');
                })

            });

        } catch (exception) {
            console.log(exception);
            response.writeHead(400);
            response.end('ERROR_VALIDATING_DATA');
        }
    });
});
app.post('/register', function (req, res) {
    console.log('register');

    let userData = "";
    req.on('data', (chunk) => {
        userData += chunk.toString();
    });
    req.on('end', () => {
        try {
            console.log(userData);
            var data = JSON.parse(userData);
            console.log(data);
            if (!validateEmail(data.mail)) throw 'INVALID_EMAIL';
            createAccount(data.mail);
            res.writeHead(200);
            res.end();
        } catch (err) {
            console.log(err);
            res.writeHead(400);
            res.end();
        }
    });

});
app.post('/lostkey', function (req, res) {
    console.log('lostkey');
    let userData = "";
    req.on('data', (chunk) => {
        userData += chunk.toString();
    });
    req.on('end', () => {
        try {
            var data = JSON.parse(userData);
            console.log(data);
            if (!validateEmail(data.mail)) throw 'INVALID_EMAIL';
            sendKeyRegistrationMail(data.mail);
            res.writeHead(200);
            res.end();
        } catch (err) {
            console.log(err);
            res.writeHead(400);
            res.end();
        }
    });
})
wssLogin.on("connection", ws => {
    console.log('connection');

    var nonce = "";
    const possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (var i = 0; i < 64; i++)
        nonce += possible.charAt(Math.floor(Math.random() * possible.length));
    ws.send(JSON.stringify({ kind: 'challange', challange: nonce }))

    ws.on("message", message => {
        try {
            let assertionObject = JSON.parse(new TextDecoder().decode(message));


            console.log('Connecting to database'); pool.getConnection().then(conn => {
                conn.query('USE ' + databaseCredential.database).then(() => {
                    conn.query("SELECT * FROM users WHERE keyid=?", [assertionObject.keyId]).then(async res => {
                        function fromUTF8String(utf8String) {
                            const encoder = new globalThis.TextEncoder();
                            return encoder.encode(utf8String);
                        }

                        async function digest(data, _algorithm) {
                            const hashed = await crypto.webcrypto.subtle.digest('SHA-256', data);

                            return new Uint8Array(hashed);
                        }

                        async function toHash(data, algorithm = -7) {
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
                        let user = res[0];
                        console.log(user);
                        console.log(assertionObject);
                        var Ecdsa = ellipticcurve.Ecdsa;
                        var Signature = ellipticcurve.Signature;
                        var PublicKey = ellipticcurve.PublicKey;

                        let decodedAuthData = decodeAuthData(assertionObject.authData.replaceAll('=', ''));
                        let decodedUserData = JSON.parse(atob(assertionObject.clientData));
                        let publicKey = PublicKey.fromPem(user.pubkey);
                        let signature = Signature.fromDer(atob(assertionObject.signature));
                        let authDataBuffer = base64url.toBuffer(assertionObject.authData);
                        const clientDataHash = await toHash(base64url.toBuffer(assertionObject.clientData));

                        const signatureBase = concat([authDataBuffer, clientDataHash]);

                        console.log(decodedUserData);
                        console.log(decodedAuthData);
                        let signedCorrectly = Ecdsa.verify(signatureBase, signature, publicKey);
                        let nonceMatch = decodedUserData.challenge == btoa(nonce).replace('==', '');
                        let rpidMatch = decodedAuthData.rpIdHash == 'g0Wwcdu/y9I4JMxQaL9PcnCQSwMAhazy';
                        let ceremonyMatch = decodedUserData.type == 'webauthn.get';
                        let originMatch = decodedUserData.origin == 'https://library.karol.gay';

                        console.log('Signed correcly', signedCorrectly);
                        console.log('Nonce match', nonceMatch);
                        console.log('RPID Match', rpidMatch);
                        console.log('Ceremony Match', ceremonyMatch);
                        console.log('Origin match', originMatch);
                        if (signedCorrectly &&
                            rpidMatch &&
                            nonceMatch &&
                            ceremonyMatch &&
                            originMatch
                        ) {
                            console.log('user verified!');
                            const trustTokenObject = {
                                iss: 'library.karol.gay',
                                kind: 'trust-cookie',
                                nonce: nonce,
                                iat: Date.now(),
                                exp: Date.now() + 86400000, //24h
                                name: user.name,
                                mail: user.mail,
                                uuid: user.uuid,
                                admin: user.admin == 1
                            }
                            const token = jwt.sign(trustTokenObject, privkey, { algorithm: 'PS512' });
                            const cookie = JSON.stringify({ kind: 'cookie', cookie: token });

                            ws.send(cookie);
                            ws.close();
                            console.log('Releasing connection'); conn.release(); conn.close();

                        }
                        else {
                            let authenticationFailure = {
                                signedCorrectly: signedCorrectly,
                                nonceMatch: nonceMatch,
                                rpidHashMatch: rpidMatch,
                                ceremonyTypeMatch: ceremonyMatch,
                                originMatch: originMatch
                            }
                            ws.send(JSON.stringify({ kind: 'authentication-failure', reason: authenticationFailure }));
                            ws.close();
                            console.log('Releasing connection'); conn.release(); conn.close();
                        }


                    }).catch(err => {
                        console.log(err);
                        console.log('Releasing connection'); conn.release(); conn.close();
                    })

                }).catch(err => {
                    console.log(err);
                    console.log('Releasing connection'); conn.release(); conn.close();
                })
            });
        } catch (exception) {
            console.log(exception);
            console.log('Releasing connection'); conn.release(); conn.close();
        }
    });


});
app.get('/books/get*', function (req, res) {
    console.log('books get');
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    let cookie = req.headers.cookie.slice(6);

    let uuid = "";
    if (req.url != '/books/get') uuid = req.url.substring(11, 47);
    console.log(uuid);
    try {
        let decodedCookie = jwt.verify(cookie, pubkey, { algorithm: 'PS512' });
        try {
            if (decodedCookie.iss != 'library.karol.gay' || decodedCookie.kind != 'trust-cookie') throw 'INVALID_COOKIE';
            if (decodedCookie.exp < Date.now()) throw 'COOKIE_EXPIRED';
        }
        catch (ex) {
            console.log(ex);
            res.writeHead(400);
            res.end(JSON.stringify({ error: ex }));
            return;
        }

        let isUserAdmin = decodedCookie.admin === true;
        console.log('Connecting to database'); pool.getConnection().then(conn => {
            conn.query('USE ' + databaseCredential.database).then(() => {

                if (uuid)
                    conn.query('SELECT * FROM books WHERE uuid=?', [uuid]).then(response => {
                        if (response.length == 1) {
                            response[0].availableToRent = response[0].rentedby == null;
                            response[0].rentedByYou = response[0].rentedby == decodedCookie.uuid;
                            if (!isUserAdmin) delete response[0].rentedby;
                            res.writeHead(200);
                            console.log('Releasing connection'); conn.release(); conn.close();
                            res.end(JSON.stringify(response[0]));
                            return;
                        } else throw 'BOOK_DOES_NOT_EXIST';

                    }).catch(ex => {
                        console.log(ex);
                        res.writeHead(400);
                        console.log('Releasing connection'); conn.release(); conn.close();
                        res.end(JSON.stringify({ error: ex }));
                        return;

                    });
                else
                    conn.query('SELECT * FROM books ORDER BY title').then(response => {
                        let booksList = [];
                        for (let i = 0; i < response.length; i++) {
                            response[i].availableToRent = response[i].rentedby == null;
                            response[i].rentedByYou = response[i].rentedby == decodedCookie.uuid;
                            if (!isUserAdmin) delete response[i].rentedby;
                            booksList.push(response[i]);
                        }
                        res.writeHead(200);
                        console.log('Releasing connection'); conn.release(); conn.close();
                        res.end(JSON.stringify(booksList));
                    });
            }).catch(err => {
                console.log(ex);
                res.writeHead(400);
                console.log('Releasing connection'); conn.release(); conn.close();
                res.end(JSON.stringify({ error: ex }));
                return;
            })

        });


    } catch (ex) {
        console.log(ex);
        res.writeHead(400);
        res.end(JSON.stringify({ error: ex }));
        return;
    }


})
app.post('/books/add', function (req, res) {
    console.log('books add');
    let bookData = "";
    req.on('data', (chunk) => {
        bookData += chunk.toString();
    });
    req.on('end', () => {
        try {
            let cookie = req.headers.cookie.slice(6);
            let book = JSON.parse(bookData);
            console.log(book);
            try {

                let decodedCookie = jwt.verify(cookie, pubkey, { algorithm: 'PS512' });
                try {

                    if (!book.title || !book.author || !book.isbn || !book.description) throw 'INVALID_BOOK';
                    if (decodedCookie.iss != 'library.karol.gay' || decodedCookie.kind != 'trust-cookie') throw 'INVALID_COOKIE';
                    if (decodedCookie.exp < Date.now()) throw 'COOKIE_EXPIRED';
                    if (decodedCookie.admin !== true) throw 'USER_NOT_ADMIN';
                }
                catch (ex) {
                    console.log(ex);
                    res.writeHead(400);
                    res.end(JSON.stringify({ error: ex }));
                    return;
                }
                var nonce = "";
                const possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                for (var i = 0; i < 64; i++)
                    nonce += possible.charAt(Math.floor(Math.random() * possible.length));
                let uuid = getUuid(crypto.createHash('sha256').update(bookData).digest('hex') + nonce);

                console.log('Connecting to database'); pool.getConnection().then(conn => {
                    conn.query('USE ' + databaseCredential.database).then(() => {

                        if (book.rentedby) {
                            conn.query('SELECT * FROM users WHERE uuid=?', [book.rentedby]).then(response => {
                                if (response.length == 0) throw 'USER_NOT_FOUND';
                                let user = response[0];
                                try {
                                    conn.query('SELECT rentedby FROM books WHERE uuid=?', [uuid]).then(response => {

                                        if (response.length == 0) {
                                            conn.query('INSERT INTO books (uuid, title, author, isbn, description, rentedby) VALUES (?, ?, ?, ?, ?, ?)',
                                                [uuid, book.title, book.author, book.isbn, book.description, book.rentedby]
                                            ).then(() => {
                                                let list = JSON.parse(user.rented);
                                                list.push(uuid);
                                                conn.query('UPDATE users SET rented=? WHERE uuid=?', [JSON.stringify(list), book.rentedby]).then(() => {
                                                    broadcastUpdate()
                                                    res.writeHead(200);
                                                    console.log('Releasing connection'); conn.release(); conn.close();
                                                    res.end();
                                                }).catch(exception => {
                                                    console.log(exception);
                                                    res.writeHead(400);
                                                    console.log('Releasing connection'); conn.release(); conn.close();
                                                    res.end(JSON.stringify({ error: exception }));
                                                })

                                            }).catch(exception => {
                                                console.log(exception);
                                                res.writeHead(400);
                                                console.log('Releasing connection'); conn.release(); conn.close();
                                                res.end(JSON.stringify({ error: exception }));
                                            })
                                        } else throw 'BOOK_ALREADY_EXISTS';
                                    }).catch(exception => {
                                        console.log(exception);
                                        res.writeHead(400);
                                        console.log('Releasing connection'); conn.release(); conn.close();
                                        res.end(JSON.stringify({ error: exception }));
                                    })

                                } catch (ex) {
                                    console.log(ex);
                                }
                            }).catch(exception => {
                                console.log(exception);
                                res.writeHead(400);
                                console.log('Releasing connection'); conn.release(); conn.close();
                                res.end(JSON.stringify({ error: exception }));
                            })

                        }
                        else
                            try {
                                conn.query('SELECT * FROM books WHERE uuid=?', [uuid]).then(response => {
                                    if (response.length == 0) {
                                        conn.query('INSERT INTO books (uuid, title, author, isbn, description) VALUES (?, ?, ?, ?, ?)',
                                            [uuid, book.title, book.author, book.isbn, book.description]
                                        ).then(response => {
                                            broadcastUpdate()
                                            res.writeHead(200);
                                            console.log('Releasing connection'); conn.release(); conn.close();
                                            res.end();
                                        })
                                    } else throw 'BOOK_ALREADY_EXISTS';
                                }).catch(exception => {
                                    console.log(exception);
                                    res.writeHead(400);
                                    console.log('Releasing connection'); conn.release(); conn.close();
                                    res.end(JSON.stringify({ error: exception }));
                                })

                            } catch (ex) {
                                console.log(ex);
                            }
                    }).catch(err => {

                    })

                });



                console.log(decodedCookie);

            } catch (ex) {
                console.log(ex);
                res.writeHead(400);
                res.end(JSON.stringify({ error: ex }));
                return;
            }
        } catch (ex) {
            console.log(ex);
            res.writeHead(400);
            res.end(JSON.stringify({ error: ex }));
            return;
        }

    })

})
app.patch('/books/update*', function (req, res) {
    console.log('books update');
    let bookData = "";
    req.on('data', (chunk) => {
        bookData += chunk.toString();
    });
    req.on('end', () => {
        try {
            let cookie = req.headers.cookie.slice(6);
            let uuid = req.url.substring(14, 50);
            console.log(uuid);
            console.log(bookData);
            let book = JSON.parse(bookData);
            try {

                let decodedCookie = jwt.verify(cookie, pubkey, { algorithm: 'PS512' });
                try {

                    console.log(book);
                    if (!uuid || !book.title || !book.author || !book.isbn || !book.description) throw 'INVALID_BOOK';
                    if (decodedCookie.iss != 'library.karol.gay' || decodedCookie.kind != 'trust-cookie') throw 'INVALID_COOKIE';
                    if (decodedCookie.exp < Date.now()) throw 'COOKIE_EXPIRED';
                    if (decodedCookie.admin !== true) throw 'USER_NOT_ADMIN';
                }
                catch (ex) {
                    console.log(ex);
                    res.writeHead(400);
                    res.end(JSON.stringify({ error: ex }));
                    return;
                }

                console.log('Connecting to database'); pool.getConnection().then(conn => {
                    conn.query('USE ' + databaseCredential.database).then(() => {
                        try {
                            conn.query('SELECT * FROM books WHERE uuid=?', [uuid]).then(response => {
                                if (response.length == 1) {
                                    let oldBook = response[0];
                                    let rentedby = book.rentedby;
                                    console.log(oldBook);
                                    if (book.rentedby)
                                        conn.query('SELECT * FROM users WHERE uuid=?', [book.rentedby]).then(response => {
                                            if (response.length == 0) throw 'USER_NOT_FOUND';

                                            if (oldBook.rentedby) {
                                                conn.query('SELECT rented FROM users WHERE uuid=?', [oldBook.rentedby]).then(response => {
                                                    if (response.length == 0) throw 'USER_NOT_FOUND';
                                                    let rentedList = JSON.parse(response[0].rented);
                                                    console.log(rentedList);
                                                    for (let i = 0; i < rentedList.length; i++)
                                                        if (rentedList[i] == uuid)
                                                            rentedList.splice(i, 1);
                                                    console.log(rentedList);
                                                    conn.query('UPDATE users SET rented=? WHERE uuid=?', [JSON.stringify(rentedList), oldBook.rentedby]).catch(exception => {
                                                        console.log(exception);
                                                        res.writeHead(400);
                                                        console.log('Releasing connection'); conn.release(); conn.close();
                                                        res.end(JSON.stringify({ error: exception }));
                                                    })
                                                }).catch(exception => {
                                                    console.log(exception);
                                                    res.writeHead(400);
                                                    console.log('Releasing connection'); conn.release(); conn.close();
                                                    res.end(JSON.stringify({ error: exception }));
                                                })
                                            }
                                            conn.query('UPDATE books SET rentedby=? WHERE uuid=?', [rentedby, uuid]).then(() => {
                                                conn.query('SELECT rented FROM users WHERE uuid=?', [rentedby]).then(response => {
                                                    let list = JSON.parse(response[0].rented);
                                                    list.push(uuid);
                                                    conn.query('UPDATE users SET rented=? WHERE uuid=?', [JSON.stringify(list), rentedby]).then(() => {
                                                        conn.query('UPDATE books SET title=?, author=?, isbn=?, description=? WHERE uuid=?',
                                                            [book.title, book.author, book.isbn, book.description, uuid]
                                                        ).then(() => {
                                                            broadcastUpdate();
                                                            res.writeHead(200);
                                                            console.log('Releasing connection'); conn.release(); conn.close();
                                                            res.end();
                                                            return;
                                                        })



                                                    })
                                                })
                                            })
                                            //now rent the book
                                        }).catch(exception => {
                                            console.log(exception);
                                            res.writeHead(400);
                                            console.log('Releasing connection'); conn.release(); conn.close();
                                            res.end(JSON.stringify({ error: exception }));
                                        })
                                    else {
                                        if (oldBook.rentedby) {
                                            conn.query('SELECT rented FROM users WHERE uuid=?', [oldBook.rentedby]).then(response => {
                                                if (response.length == 0) throw 'USER_NOT_FOUND';
                                                let rentedList = JSON.parse(response[0].rented);
                                                console.log(rentedList);
                                                for (let i = 0; i < rentedList.length; i++)
                                                    if (rentedList[i] == uuid)
                                                        rentedList.splice(i, 1);
                                                console.log(rentedList);
                                                conn.query('UPDATE users SET rented=? WHERE uuid=?', [JSON.stringify(rentedList), oldBook.rentedby]).then(() => {
                                                    conn.query('UPDATE books SET title=?, author=?, isbn=?, description=?, rentedby=NULL WHERE uuid=?',
                                                        [book.title, book.author, book.isbn, book.description, uuid]
                                                    ).then(() => {
                                                        broadcastUpdate();
                                                        res.writeHead(200);
                                                        console.log('Releasing connection'); conn.release(); conn.close();
                                                        res.end();
                                                        return;
                                                    })
                                                }).catch(exception => {
                                                    console.log(exception);
                                                    res.writeHead(400);
                                                    console.log('Releasing connection'); conn.release(); conn.close();
                                                    res.end(JSON.stringify({ error: exception }));
                                                })
                                            }).catch(exception => {
                                                console.log(exception);
                                                res.writeHead(400);
                                                console.log('Releasing connection'); conn.release(); conn.close();
                                                res.end(JSON.stringify({ error: exception }));
                                            })
                                        } else conn.query('UPDATE books SET title=?, author=?, isbn=?, description=? WHERE uuid=?',
                                            [book.title, book.author, book.isbn, book.description, uuid]
                                        ).then(() => {
                                            broadcastUpdate();
                                            res.writeHead(200);
                                            console.log('Releasing connection'); conn.release(); conn.close();
                                            res.end();
                                            return;
                                        })

                                    }
                                } else throw 'BOOK_DOES_NOT_EXIST';
                            }).catch(exception => {
                                console.log(exception);
                                res.writeHead(400);
                                console.log('Releasing connection'); conn.release(); conn.close();
                                res.end(JSON.stringify({ error: exception }));
                            })

                        } catch (ex) {
                            console.log(ex);
                        }
                    }).catch(eex => {
                        console.log(ex);
                    })

                });



                console.log(decodedCookie);

            } catch (ex) {
                console.log(ex);
                res.writeHead(400);
                res.end(JSON.stringify({ error: ex }));
                return;
            }
        } catch (ex) {
            console.log(ex);
            res.writeHead(400);
            res.end(JSON.stringify({ error: ex }));
            return;
        }
    })

})
app.delete('/books/delete*', function (req, res) {
    console.log('books delete');

    let cookie = req.headers.cookie.slice(6);
    console
    let uuid = req.url.substring(14, 50);
    try {

        let decodedCookie = jwt.verify(cookie, pubkey, { algorithm: 'PS512' });
        try {
            if (!uuid) throw 'INVALID_BOOK';
            if (decodedCookie.iss != 'library.karol.gay' || decodedCookie.kind != 'trust-cookie') throw 'INVALID_COOKIE';
            if (decodedCookie.exp < Date.now()) throw 'COOKIE_EXPIRED';
            if (decodedCookie.admin !== true) throw 'USER_NOT_ADMIN';
        }
        catch (ex) {
            console.log(ex);
            res.writeHead(400);
            res.end(JSON.stringify({ error: ex }));
            return;
        }

        console.log('Connecting to database'); pool.getConnection().then(conn => {
            conn.query('USE ' + databaseCredential.database).then(() => {
                try {
                    conn.query('SELECT * FROM books WHERE uuid=?', [uuid]).then(response => {
                        if (response.length == 1) {

                            if (response[0].rentedby) {
                                let rentedby = response[0].rentedby;
                                conn.query('SELECT rented FROM users WHERE uuid=?', [rentedby]).then(response => {
                                    if (response.length == 0) throw 'USER_NOT_FOUND';
                                    let rentedList = JSON.parse(response[0].rented);
                                    console.log(rentedList);
                                    for (let i = 0; i < rentedList.length; i++)
                                        if (rentedList[i] == uuid)
                                            rentedList.splice(i, 1);
                                    console.log(rentedList);
                                    conn.query('UPDATE users SET rented=? WHERE uuid=?', [JSON.stringify(rentedList), decodedCookie.uuid]).then(() => {
                                        conn.query('DELETE FROM books WHERE uuid=?', [uuid]
                                        ).then(() => {
                                            broadcastUpdate()
                                            res.writeHead(200);
                                            console.log('Releasing connection'); conn.release(); conn.close();
                                            res.end();
                                        }).catch(exception => {
                                            console.log(exception);
                                            console.log('Releasing connection'); conn.release(); conn.close();
                                            res.writeHead(400);
                                            console.log('Releasing connection'); conn.release(); conn.close();
                                            res.end(JSON.stringify({ error: exception }));
                                        })
                                    })
                                })



                            } else
                                conn.query('DELETE FROM books WHERE uuid=?', [uuid]
                                ).then(response => {
                                    broadcastUpdate()
                                    res.writeHead(200);
                                    console.log('Releasing connection'); conn.release(); conn.close();
                                    res.end();
                                }).catch(exception => {
                                    console.log(exception);
                                    console.log('Releasing connection'); conn.release(); conn.close();
                                    res.writeHead(400);
                                    res.end(JSON.stringify({ error: exception }));
                                })
                        } else throw 'BOOK_DOES_NOT_EXIST';
                    }).catch(exception => {
                        console.log(exception);
                        res.writeHead(400);
                        console.log('Releasing connection'); conn.release(); conn.close();
                        res.end(JSON.stringify({ error: exception }));
                    })

                } catch (ex) {
                    console.log(ex);
                }
            }).catch(err => {

            })

        });



        console.log(decodedCookie);

    } catch (ex) {
        console.log(ex);
        res.writeHead(400);
        res.end(JSON.stringify({ error: ex }));
        return;
    }




})
app.get('/books/search*', function (req, res) {
    console.log('books search');
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    let cookie = req.headers.cookie.slice(6);

    let search = '%' + new URL('https://library.karol.gay' + req.url).searchParams.get('query') + '%';
    console.log(search);
    try {
        let decodedCookie = jwt.verify(cookie, pubkey, { algorithm: 'PS512' });
        try {
            if (decodedCookie.iss != 'library.karol.gay' || decodedCookie.kind != 'trust-cookie') throw 'INVALID_COOKIE';
            if (decodedCookie.exp < Date.now()) throw 'COOKIE_EXPIRED';
        }
        catch (ex) {
            console.log(ex);
            res.writeHead(400);
            res.end(JSON.stringify({ error: ex }));
            return;
        }
        let isUserAdmin = decodedCookie.admin === true;

        console.log('Connecting to database'); pool.getConnection().then(conn => {
            conn.query('USE ' + databaseCredential.database).then(() => {
                conn.query('SELECT * FROM books WHERE CONCAT(title, author, isbn, description) LIKE ? ORDER BY title', [search]).then(response => {
                    let booksList = [];
                    for (let i = 0; i < response.length; i++) {
                        response[i].availableToRent = response[i].rentedby == null;
                        response[i].rentedByYou = response[i].rentedby == decodedCookie.uuid;
                        if (!isUserAdmin) delete response[i].rentedby;


                        booksList.push(response[i]);
                    }
                    res.writeHead(200);
                    console.log('Releasing connection'); conn.release(); conn.close();
                    res.end(JSON.stringify(booksList));
                }).catch(ex => {
                    console.log(ex);
                    res.writeHead(400);
                    console.log('Releasing connection'); conn.release(); conn.close();
                    res.end(JSON.stringify({ error: ex }));
                    return;

                });

            }).catch(ex => {
                console.log(ex);
                res.writeHead(400);
                console.log('Releasing connection'); conn.release(); conn.close();
                res.end(JSON.stringify({ error: ex }));
                return;
            })

        });



        console.log(decodedCookie);

    } catch (ex) {
        console.log(ex);
        res.writeHead(400);
        res.end(JSON.stringify({ error: ex }));
        return;
    }





})
app.get('/resetdevice*', function (req, res) {
    console.log('resetdevice');
    let id = new URL('https://library.karol.gay' + req.url).searchParams.get('token');
    console.log(id);

    console.log('Connecting to database'); pool.getConnection().then(conn => {
        conn.query('USE ' + databaseCredential.database).then(() => {

            conn.query('SELECT url FROM redirect WHERE id=?', [id]).then(response => {
                if (response.length == 0) {
                    res.redirect('https://library.karol.gay/');
                    console.log('Releasing connection'); conn.release(); conn.close();
                    res.end();
                }
                else {

                    let url = response[0].url;
                    console.log(url);
                    res.redirect(url);
                    console.log('Releasing connection'); conn.release(); conn.close();
                    res.end();
                }


            })
        })

    });

});
app.get('/users/get*', function (req, res) {
    console.log('users get');
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    try {
        let cookie = req.headers.cookie.slice(6);
        try {

            let decodedCookie = jwt.verify(cookie, pubkey, { algorithm: 'PS512' });
            try {

                if (decodedCookie.iss != 'library.karol.gay' || decodedCookie.kind != 'trust-cookie') throw 'INVALID_COOKIE';
                if (decodedCookie.exp < Date.now()) throw 'COOKIE_EXPIRED';
                if (decodedCookie.admin !== true) throw 'USER_NOT_ADMIN';
            }
            catch (ex) {
                console.log(ex);
                res.writeHead(400);
                res.end(JSON.stringify({ error: ex }));
                return;
            }

            console.log('Connecting to database'); pool.getConnection().then(conn => {
                conn.query('USE ' + databaseCredential.database).then(() => {
                    try {
                        conn.query('SELECT uuid, name, admin, email, rented FROM users').then(response => {
                            let userList = [];
                            for (let i = 0; i < response.length; i++)userList.push({
                                uuid: response[i].uuid,
                                name: response[i].name,
                                email: response[i].email,
                                admin: response[i].admin == 1,
                                rented: JSON.parse(response[i].rented)
                            });

                            res.writeHead(200);
                            console.log('Releasing connection'); conn.release(); conn.close();
                            res.end(JSON.stringify(userList));
                        }).catch(exception => {
                            console.log(exception);
                            res.writeHead(400);
                            console.log('Releasing connection'); conn.release(); conn.close();
                            res.end(JSON.stringify({ error: exception }));
                        })

                    } catch (ex) {
                        console.log(ex);
                    }
                }).catch(err => {

                })

            });



            console.log(decodedCookie);

        } catch (ex) {
            console.log(ex);
            res.writeHead(400);
            res.end(JSON.stringify({ error: ex }));
            return;
        }
    } catch (ex) {
        console.log(ex);
        res.writeHead(400);
        res.end(JSON.stringify({ error: ex }));
        return;
    }



});
app.post('/rental/rent*', function (req, res) {
    console.log('rental rent');
    let cookie = req.headers.cookie.slice(6);

    let uuid = req.url.substring(13, 49);
    console.log(uuid);
    try {
        let decodedCookie = jwt.verify(cookie, pubkey, { algorithm: 'PS512' });
        try {
            if (decodedCookie.iss != 'library.karol.gay' || decodedCookie.kind != 'trust-cookie') throw 'INVALID_COOKIE';
            if (decodedCookie.exp < Date.now()) throw 'COOKIE_EXPIRED';
        }
        catch (ex) {
            console.log(ex);
            res.writeHead(400);
            res.end(JSON.stringify({ error: ex }));
            return;
        }

        console.log('Connecting to database'); pool.getConnection().then(conn => {
            conn.query('USE ' + databaseCredential.database).then(() => {
                conn.query('SELECT rentedby FROM books WHERE uuid=?', [uuid]).then(response => {
                    if (response.length == 0) throw 'BOOK_NOT_FOUND';
                    if (response[0].rentedby == null) {
                        //rent a book;
                        conn.query('UPDATE books SET rentedby=? WHERE uuid=?', [decodedCookie.uuid, uuid]).then(() => {
                            conn.query('SELECT rented FROM users WHERE uuid=?', [decodedCookie.uuid]).then(response => {
                                if (response.length == 0) throw 'USER_NOT_FOUND';

                                let rentedList = JSON.parse(response[0].rented);
                                console.log(rentedList);
                                rentedList.push(uuid);
                                console.log(rentedList);
                                conn.query('UPDATE users SET rented=? WHERE uuid=?', [JSON.stringify(rentedList), decodedCookie.uuid]).then(response => {

                                    broadcastUpdate();
                                    res.writeHead(200);
                                    console.log('Releasing connection'); conn.release(); conn.close();
                                    res.end();
                                })
                            })
                        })

                    } else if (response[0].rentedby == decodedCookie.uuid) throw 'BOOK_RENTED_BY_YOU'; else throw 'BOOK_RENTED_BY_ANOTHER_USER';

                }).catch(ex => {
                    console.log(ex);
                    res.writeHead(400);
                    console.log('Releasing connection'); conn.release(); conn.close();
                    res.end(JSON.stringify({ error: ex }));
                    return;

                });
            }).catch(err => {
                console.log(ex);
                res.writeHead(400);
                console.log('Releasing connection'); conn.release(); conn.close();
                res.end(JSON.stringify({ error: ex }));
                return;
            })

        });
    } catch (ex) {
        console.log(ex);
        res.writeHead(400);
        res.end(JSON.stringify({ error: ex }));
        return;
    }

})
app.post('/rental/return*', function (req, res) {
    console.log('rental return');
    let cookie = req.headers.cookie.slice(6);

    let uuid = req.url.substring(15, 51);
    console.log(uuid);
    console.log(uuid);
    try {
        let decodedCookie = jwt.verify(cookie, pubkey, { algorithm: 'PS512' });
        try {
            if (decodedCookie.iss != 'library.karol.gay' || decodedCookie.kind != 'trust-cookie') throw 'INVALID_COOKIE';
            if (decodedCookie.exp < Date.now()) throw 'COOKIE_EXPIRED';
        }
        catch (ex) {
            console.log(ex);
            res.writeHead(400);
            res.end(JSON.stringify({ error: ex }));
            return;
        }

        console.log('Connecting to database'); pool.getConnection().then(conn => {
            conn.query('USE ' + databaseCredential.database).then(() => {
                conn.query('SELECT rentedby FROM books WHERE uuid=?', [uuid]).then(response => {

                    if (response.length == 0) throw 'BOOK_NOT_FOUND';
                    if (response[0].rentedby == decodedCookie.uuid) {
                        //return a book;
                        conn.query('UPDATE books SET rentedby=null WHERE uuid=?', [uuid]).then(() => {
                            conn.query('SELECT rented FROM users WHERE uuid=?', [decodedCookie.uuid]).then(response => {
                                if (response.length == 0) throw 'USER_NOT_FOUND';

                                let rentedList = JSON.parse(response[0].rented);
                                console.log(rentedList);
                                for (let i = 0; i < rentedList.length; i++)
                                    if (rentedList[i] == uuid)
                                        rentedList.splice(i, 1);
                                console.log(rentedList);
                                conn.query('UPDATE users SET rented=? WHERE uuid=?', [JSON.stringify(rentedList), decodedCookie.uuid]).then(response => {

                                    broadcastUpdate();
                                    res.writeHead(200);
                                    console.log('Releasing connection'); conn.release(); conn.close();
                                    res.end();
                                })
                            })
                        })

                    } else if (response[0].rentedby == null) throw 'BOOK_NOT_RENTED'; else throw 'BOOK_RENTED_BY_ANOTHER_USER';

                }).catch(ex => {
                    console.log(ex);
                    res.writeHead(400);
                    console.log('Releasing connection'); conn.release(); conn.close();
                    res.end(JSON.stringify({ error: ex }));
                    return;

                });
            }).catch(err => {
                console.log(ex);
                res.writeHead(400);
                console.log('Releasing connection'); conn.release(); conn.close();
                res.end(JSON.stringify({ error: ex }));
                return;
            })

        });
    } catch (ex) {
        console.log(ex);
        res.writeHead(400);
        res.end(JSON.stringify({ error: ex }));
        return;
    }


})
app.get('/rental/get', function (req, res) {
    console.log('rental rent');
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    let cookie = req.headers.cookie.slice(6);

    try {
        let decodedCookie = jwt.verify(cookie, pubkey, { algorithm: 'PS512' });
        try {
            if (decodedCookie.iss != 'library.karol.gay' || decodedCookie.kind != 'trust-cookie') throw 'INVALID_COOKIE';
            if (decodedCookie.exp < Date.now()) throw 'COOKIE_EXPIRED';
        }
        catch (ex) {
            console.log(ex);
            res.writeHead(400);
            res.end(JSON.stringify({ error: ex }));
            return;
        }
        let isUserAdmin = decodedCookie.admin === true;

        console.log('Connecting to database'); pool.getConnection().then(conn => {
            conn.query('USE ' + databaseCredential.database).then(() => {
                conn.query('SELECT * FROM books WHERE rentedby=?', [decodedCookie.uuid]).then(response => {

                    let booksList = [];
                    for (let i = 0; i < response.length; i++) {
                        if (!isUserAdmin) delete response[i].rentedby;


                        booksList.push(response[i]);
                    }
                    console.log(booksList);
                    res.writeHead(200);
                    console.log('Releasing connection'); conn.release(); conn.close();
                    res.end(JSON.stringify(booksList));
                }).catch(ex => {
                    console.log(ex);
                    res.writeHead(400);
                    console.log('Releasing connection'); conn.release(); conn.close();
                    res.end(JSON.stringify({ error: ex }));
                    return;

                });

            }).catch(ex => {
                console.log(ex);
                res.writeHead(400);
                console.log('Releasing connection'); conn.release(); conn.close();
                res.end(JSON.stringify({ error: ex }));
                return;
            })

        });



        console.log(decodedCookie);

    } catch (ex) {
        console.log(ex);
        res.writeHead(400);
        res.end(JSON.stringify({ error: ex }));
        return;
    }





})
wssUpdates.on("connection", ws => {
    console.log('update connection');
    updatesClientsList.push(ws);
    console.log('Updates connected:', updatesClientsList.length);
    ws.on("close", () => {
        for (var i = 0; i < updatesClientsList.length; i++) {
            if (updatesClientsList[i] === ws) {
                updatesClientsList.splice(i, 1);
                i--;
            }
        }
    })
});

function validateEmail(email) {
    console.log('valudate email');
    return String(email)
        .toLowerCase()
        .match(
            /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
        );
};
function createAccount(mail) {
console.log('create account');
    console.log('Connecting to database'); pool.getConnection().then(conn => {
        conn.query('USE ' + databaseCredential.database).then(() => {
            let uuid = getUuid(mail);
            conn.query("INSERT INTO users (uuid, admin, email) VALUES (?, ?, ?)", [uuid, false, mail]).then(res => {

                console.log('Releasing connection'); conn.release(); conn.close();

                broadcastUpdate();
            }).catch(err => {
                console.log('Releasing connection'); conn.release(); conn.close();
                console.log(err);
            })
            sendKeyRegistrationMail(mail);
        }).catch(err => {
            console.log('Releasing connection'); conn.release(); conn.close();
            console.log(err);
        })

    });
}
async function sendKeyRegistrationMail(mail) {
console.log('send email');

    console.log('Connecting to database'); pool.getConnection().then(conn => {
        conn.query('USE ' + databaseCredential.database).then(() => {
            conn.query("SELECT * FROM users WHERE email=?", [mail]).then(async res => {

                let user = res[0];
                console.log(user);
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
                const token = jwt.sign(claims, privkey, { algorithm: 'PS512' });
                const url = createRedirect('https://library.karol.gay/keyreset.html?token=' + token);

                let transporter = nodemailer.createTransport({
                    host: "in-v3.mailjet.com",
                    port: 587,
                    secure: false,
                    auth: require('./smtp.json')
                });

                let messageText = `
                Use this link to reset your passkey. The link is only valid for 15 minutes

                [Library] ( https://library.karol.gay )

                ************
                Hi {{name}},
                ************

                You recently requested to reset your passkey for your Library account. Use the button below to reset it. This passkey reset is only valid for the next 15 minutes.

                Reset your passkey ( {{action_url}} )

                If you did not request a passkey reset, please ignore this email or contact support (karol.peszek@gmail.com) if you have questions.

                Thanks,
                The Library team

                If you’re having trouble with the button above, copy and paste the URL below into your web browser.

                {{action_url}}
                `;
                let messageHtml = '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"><html xmlns="http://www.w3.org/1999/xhtml"> <head> <meta name="viewport" content="width=device-width, initial-scale=1.0"/> <meta name="x-apple-disable-message-reformatting"/> <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/> <meta name="color-scheme" content="light dark"/> <meta name="supported-color-schemes" content="light dark"/> <title></title> <style type="text/css" rel="stylesheet" media="all"> /* Base ------------------------------ */ @import url("https://fonts.googleapis.com/css?family=Nunito+Sans:400,700&display=swap"); body{width: 100% !important; height: 100%; margin: 0; -webkit-text-size-adjust: none;}a{color: #3869D4;}a img{border: none;}td{word-break: break-word;}.preheader{display: none !important; visibility: hidden; mso-hide: all; font-size: 1px; line-height: 1px; max-height: 0; max-width: 0; opacity: 0; overflow: hidden;}/* Type ------------------------------ */ body, td, th{font-family: "Nunito Sans", Helvetica, Arial, sans-serif;}h1{margin-top: 0; color: #333333; font-size: 22px; font-weight: bold; text-align: left;}h2{margin-top: 0; color: #333333; font-size: 16px; font-weight: bold; text-align: left;}h3{margin-top: 0; color: #333333; font-size: 14px; font-weight: bold; text-align: left;}td, th{font-size: 16px;}p, ul, ol, blockquote{margin: .4em 0 1.1875em; font-size: 16px; line-height: 1.625;}p.sub{font-size: 13px;}/* Utilities ------------------------------ */ .align-right{text-align: right;}.align-left{text-align: left;}.align-center{text-align: center;}.u-margin-bottom-none{margin-bottom: 0;}/* Buttons ------------------------------ */ .button{background-color: #3869D4; border-top: 10px solid #3869D4; border-right: 18px solid #3869D4; border-bottom: 10px solid #3869D4; border-left: 18px solid #3869D4; display: inline-block;text-color:#ffffff; color: #ffffff; text-decoration: none; border-radius: 3px; box-shadow: 0 2px 3px rgba(0, 0, 0, 0.16); -webkit-text-size-adjust: none; box-sizing: border-box;}.button--green{background-color: #22BC66; border-top: 10px solid #22BC66; border-right: 18px solid #22BC66; border-bottom: 10px solid #22BC66; border-left: 18px solid #22BC66;}.button--red{background-color: #FF6136; border-top: 10px solid #FF6136; border-right: 18px solid #FF6136; border-bottom: 10px solid #FF6136; border-left: 18px solid #FF6136;}@media only screen and (max-width: 500px){.button{width: 100% !important; text-align: center !important;}}/* Attribute list ------------------------------ */ .attributes{margin: 0 0 21px;}.attributes_content{background-color: #F4F4F7; padding: 16px;}.attributes_item{padding: 0;}/* Related Items ------------------------------ */ .related{width: 100%; margin: 0; padding: 25px 0 0 0; -premailer-width: 100%; -premailer-cellpadding: 0; -premailer-cellspacing: 0;}.related_item{padding: 10px 0; color: #CBCCCF; font-size: 15px; line-height: 18px;}.related_item-title{display: block; margin: .5em 0 0;}.related_item-thumb{display: block; padding-bottom: 10px;}.related_heading{border-top: 1px solid #CBCCCF; text-align: center; padding: 25px 0 10px;}/* Discount Code ------------------------------ */ .discount{width: 100%; margin: 0; padding: 24px; -premailer-width: 100%; -premailer-cellpadding: 0; -premailer-cellspacing: 0; background-color: #F4F4F7; border: 2px dashed #CBCCCF;}.discount_heading{text-align: center;}.discount_body{text-align: center; font-size: 15px;}/* Social Icons ------------------------------ */ .social{width: auto;}.social td{padding: 0; width: auto;}.social_icon{height: 20px; margin: 0 8px 10px 8px; padding: 0;}/* Data table ------------------------------ */ .purchase{width: 100%; margin: 0; padding: 35px 0; -premailer-width: 100%; -premailer-cellpadding: 0; -premailer-cellspacing: 0;}.purchase_content{width: 100%; margin: 0; padding: 25px 0 0 0; -premailer-width: 100%; -premailer-cellpadding: 0; -premailer-cellspacing: 0;}.purchase_item{padding: 10px 0; color: #51545E; font-size: 15px; line-height: 18px;}.purchase_heading{padding-bottom: 8px; border-bottom: 1px solid #EAEAEC;}.purchase_heading p{margin: 0; color: #85878E; font-size: 12px;}.purchase_footer{padding-top: 15px; border-top: 1px solid #EAEAEC;}.purchase_total{margin: 0; text-align: right; font-weight: bold; color: #333333;}.purchase_total--label{padding: 0 15px 0 0;}body{background-color: #F2F4F6; color: #51545E;}p{color: #51545E;}.email-wrapper{width: 100%; margin: 0; padding: 0; -premailer-width: 100%; -premailer-cellpadding: 0; -premailer-cellspacing: 0; background-color: #F2F4F6;}.email-content{width: 100%; margin: 0; padding: 0; -premailer-width: 100%; -premailer-cellpadding: 0; -premailer-cellspacing: 0;}/* Masthead ----------------------- */ .email-masthead{padding: 25px 0; text-align: center;}.email-masthead_logo{width: 94px;}.email-masthead_name{font-size: 16px; font-weight: bold; color: #A8AAAF; text-decoration: none; text-shadow: 0 1px 0 white;}/* Body ------------------------------ */ .email-body{width: 100%; margin: 0; padding: 0; -premailer-width: 100%; -premailer-cellpadding: 0; -premailer-cellspacing: 0;}.email-body_inner{width: 570px; margin: 0 auto; padding: 0; -premailer-width: 570px; -premailer-cellpadding: 0; -premailer-cellspacing: 0; background-color: #FFFFFF;}.email-footer{width: 570px; margin: 0 auto; padding: 0; -premailer-width: 570px; -premailer-cellpadding: 0; -premailer-cellspacing: 0; text-align: center;}.email-footer p{color: #A8AAAF;}.body-action{width: 100%; margin: 30px auto; padding: 0; -premailer-width: 100%; -premailer-cellpadding: 0; -premailer-cellspacing: 0; text-align: center;}.body-sub{margin-top: 25px; padding-top: 25px; border-top: 1px solid #EAEAEC;}.content-cell{padding: 45px;}/*Media Queries ------------------------------ */ @media only screen and (max-width: 600px){.email-body_inner, .email-footer{width: 100% !important;}}@media (prefers-color-scheme: dark){body, .email-body, .email-body_inner, .email-content, .email-wrapper, .email-masthead, .email-footer{background-color: #333333 !important; color: #FFF !important;}p, ul, ol, blockquote, h1, h2, h3, span, .purchase_item{color: #FFF !important;}.attributes_content, .discount{background-color: #222 !important;}.email-masthead_name{text-shadow: none !important;}}:root{color-scheme: light dark;}</style> </head> <body> <span class="preheader">Use this link to reset your passkey. The link is only valid for 24 hours.</span> <table class="email-wrapper" width="100%" cellpadding="0" cellspacing="0" role="presentation"> <tr> <td align="center"> <table class="email-content" width="100%" cellpadding="0" cellspacing="0" role="presentation"> <tr> <td class="email-masthead"> <a href="https://library.karo.gay" class="f-fallback email-masthead_name"> Library </a> </td></tr><tr> <td class="email-body" width="570" cellpadding="0" cellspacing="0"> <table class="email-body_inner" align="center" width="570" cellpadding="0" cellspacing="0" role="presentation"> <tr> <td class="content-cell"> <div class="f-fallback"> <h1>Hi, {{name}}!</h1> <p>You recently requested to reset your passkey for your Library account. Use the button below to reset it. <strong>This passkey reset is only valid for the next 15 minutes.</strong></p><table class="body-action" align="center" width="100%" cellpadding="0" cellspacing="0" role="presentation"> <tr> <td align="center"> <table width="100%" border="0" cellspacing="0" cellpadding="0" role="presentation"> <tr> <td align="center"> <a href="{{action_url}}" class="f-fallback button button--green" target="_blank"><h4 style="color: #ffffff;">Reset your passkey</h4></a> </td></tr></table> </td></tr></table> <p>If you did not request a passkey reset, please ignore this email or <a href="mailto:karol.peszek@gmail.com">contact support</a> if you have questions.</p><p>Thanks, <br>The Library team</p><table class="body-sub" role="presentation"> <tr> <td> <p class="f-fallback sub">If you’re having trouble with the button above, copy and paste the URL below into your web browser.</p><p class="f-fallback sub">{{action_url}}</p></td></tr></table> </div></td></tr></table> </td></tr><tr> <td> <table class="email-footer" align="center" width="570" cellpadding="0" cellspacing="0" role="presentation"> <tr> <td class="content-cell" align="center"> </td></tr></table> </td></tr></table> </td></tr></table> </body></html>';

                let message = {
                    from: '"Library 📖" <library@karol.gay>',
                    to: claims.mail,
                    subject: 'Register new device with your account',
                    text: messageText.replaceAll('{{name}}', claims.name).replaceAll('{{action_url}}', url),
                    html: messageHtml.replaceAll('{{name}}', claims.name).replaceAll('{{action_url}}', url),
                    attachments: []
                };

                try {
                    await transporter.sendMail(message);
                    console.log('Releasing connection'); conn.release(); conn.close();
                } catch (ex) {
                    console.log(ex);
                    console.log('Releasing connection'); conn.release(); conn.close();
                }

            }).catch(err => {
                console.log('A', err);
                console.log('Releasing connection'); conn.release(); conn.close();
            })

        }).catch(err => {
            console.log('B', err);
            console.log('Releasing connection'); conn.release(); conn.close();
        })

    });










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
function createRedirect(url) {
    console.log('create url');
    let id = crypto.createHash('sha256').update(url).digest('hex');

    console.log('Connecting to database'); pool.getConnection().then(conn => {
        conn.query('USE ' + databaseCredential.database).then(() => {

            conn.query('INSERT INTO redirect (id, url) VALUES (?, ?)', [id, url]);
        })

    });
    return 'https://library.karol.gay/resetdevice?token=' + id;
}
function broadcastUpdate() {
    console.log('broadcast update');
    updatesClientsList.forEach(element => {
        try {
            element.send('UPDATE')
        } catch (ex) {
            console.log(ex);
        }
    });
}
