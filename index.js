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

const wssLogin = new webSocket.Server({ port: loginPort })
const wssUpdates = new webSocket.Server({ port: updatesPort });
var server = http.createServer(app).listen(registerPort, function () {
    console.log("Express server listening on port " + registerPort);
});

let updatesClientsList = [];

app.post('/registerKey', function (req, response) {
    let userData = "";
    req.on('data', (chunk) => {
        userData += chunk.toString();
    });
    req.on('end', () => {
        try {
            const registrationObject = JSON.parse(userData);

            let decodedResetToken = jwt.verify(registrationObject.resetToken, pubkey, { algorithm: 'RS256' });

            console.log(registrationObject);

            if (decodedResetToken.iss != 'library.karol.gay' || decodedResetToken.kind != 'key-reset' || decodedResetToken.exp < Date.now() ||
                registrationObject.clientDataJson.type != 'webauthn.create' || registrationObject.clientDataJson.origin != 'https://library.karol.gay'
            ) throw 'Exception key mismatch or invalid token';

            let pool = mariadb.createPool(databaseCredential);
            pool.getConnection().then(conn => {
                conn.query('USE ' + databaseCredential.database).then(() => {
                    conn.query('SELECT * FROM users WHERE uuid=?', [decodedResetToken.uuid]).then(res => {
                        if (btoa(decodedResetToken.nonce).replace('==', '') == registrationObject.clientDataJson.challenge) console.log('NONCE_MATCH');
                        if (res[0].nonce < decodedResetToken.iat &&
                            btoa(decodedResetToken.nonce).replace('==', '') == registrationObject.clientDataJson.challenge
                        ) {
                            conn.query("UPDATE users SET name=?, pubkey=?, keyid=?, nonce=? WHERE uuid=?", [registrationObject.userName, registrationObject.publicKey, registrationObject.keyId, decodedResetToken.iat, decodedResetToken.uuid]).then(res => {
                                response.writeHead(200);
                                response.end();
                                conn.close(); pool.end();
                            })
                        }
                        else {
                            console.log('TOKEN_TOO_OLD');
                            response.writeHead(400);
                            conn.close(); pool.end();
                            response.end('ERROR_TOKEN_TOO_OLD');
                        }
                    })
                }).catch(err => {
                    console.log(err);
                    response.writeHead(400);
                    conn.close(); pool.end();
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

    var nonce = "";
    const possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (var i = 0; i < 64; i++)
        nonce += possible.charAt(Math.floor(Math.random() * possible.length));
    ws.send(JSON.stringify({ kind: 'challange', challange: nonce }))

    ws.on("message", message => {
        try {
            let assertionObject = JSON.parse(new TextDecoder().decode(message));

            let pool = mariadb.createPool(databaseCredential);
            pool.getConnection().then(conn => {
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
                            const token = jwt.sign(trustTokenObject, privkey, { algorithm: 'RS256' });
                            const cookie = JSON.stringify({ kind: 'cookie', cookie: token });
                            console.log(cookie);
                            ws.send(cookie);
                            ws.close();


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
                        }


                    }).catch(err => {
                        console.log(err);
                    })

                }).catch(err => {
                    console.log(err);
                })
            });
        } catch (exception) {
            console.log(exception);
            res.writeHead(400);
            res.end(JSON.stringify({ error: exception }));
            return;
        }
    });


});
app.get('/books/get*', function (req, res) {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    let cookie = req.headers.cookie.slice(6);
    console.log(cookie);
    let uuid = "";
    if (req.url != '/books/get') uuid = req.url.substring(11, 47);
    console.log(uuid);
    try {
        let decodedCookie = jwt.verify(cookie, pubkey, { algorithm: 'RS256' });
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
        let pool = mariadb.createPool(databaseCredential);
        let isUserAdmin = decodedCookie.admin === true;
        pool.getConnection().then(conn => {
            conn.query('USE ' + databaseCredential.database).then(() => {

                if (uuid)
                    conn.query('SELECT * FROM books WHERE uuid=?', [uuid]).then(response => {
                        if (response.length == 1) {
                            response[0].availableToRent = response[0].rentedby == null;
                            response[0].rentedByYou = response[0].rentedby == decodedCookie.uuid;
                            if (!isUserAdmin) delete response[0].rentedby;
                            res.writeHead(200);
                            conn.close(); pool.end();
                            res.end(JSON.stringify(response[0]));
                            return;
                        } else throw 'BOOK_DOES_NOT_EXIST';

                    }).catch(ex => {
                        console.log(ex);
                        res.writeHead(400);
                        conn.close(); pool.end();
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
                        conn.close(); pool.end();
                        res.end(JSON.stringify(booksList));
                    });
            }).catch(err => {
                console.log(ex);
                res.writeHead(400);
                conn.close(); pool.end();
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

                let decodedCookie = jwt.verify(cookie, pubkey, { algorithm: 'RS256' });
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
                let pool = mariadb.createPool(databaseCredential);
                pool.getConnection().then(conn => {
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
                                                    conn.close(); pool.end();
                                                    res.end();
                                                }).catch(exception => {
                                                    console.log(exception);
                                                    res.writeHead(400);
                                                    conn.close(); pool.end();
                                                    res.end(JSON.stringify({ error: exception }));
                                                })

                                            }).catch(exception => {
                                                console.log(exception);
                                                res.writeHead(400);
                                                conn.close(); pool.end();
                                                res.end(JSON.stringify({ error: exception }));
                                            })
                                        } else throw 'BOOK_ALREADY_EXISTS';
                                    }).catch(exception => {
                                        console.log(exception);
                                        res.writeHead(400);
                                        conn.close(); pool.end();
                                        res.end(JSON.stringify({ error: exception }));
                                    })

                                } catch (ex) {
                                    console.log(ex);
                                }
                            }).catch(exception => {
                                console.log(exception);
                                res.writeHead(400);
                                conn.close(); pool.end();
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
                                            conn.close(); pool.end();
                                            res.end();
                                        })
                                    } else throw 'BOOK_ALREADY_EXISTS';
                                }).catch(exception => {
                                    console.log(exception);
                                    res.writeHead(400);
                                    conn.close(); pool.end();
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

                let decodedCookie = jwt.verify(cookie, pubkey, { algorithm: 'RS256' });
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
                let pool = mariadb.createPool(databaseCredential);
                pool.getConnection().then(conn => {
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
                                                    console.log(response);
                                                    let rentedList = JSON.parse(response[0].rented);
                                                    console.log(rentedList);
                                                    for (let i = 0; i < rentedList.length; i++)
                                                        if (rentedList[i] == uuid)
                                                            rentedList.splice(i, 1);
                                                    console.log(rentedList);
                                                    conn.query('UPDATE users SET rented=? WHERE uuid=?', [JSON.stringify(rentedList), oldBook.rentedby]).catch(exception => {
                                                        console.log(exception);
                                                        res.writeHead(400);
                                                        conn.close(); pool.end();
                                                        res.end(JSON.stringify({ error: exception }));
                                                    })
                                                }).catch(exception => {
                                                    console.log(exception);
                                                    res.writeHead(400);
                                                    conn.close(); pool.end();
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
                                                            conn.close(); pool.end();
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
                                            conn.close(); pool.end();
                                            res.end(JSON.stringify({ error: exception }));
                                        })
                                    else {
                                        if (oldBook.rentedby) {
                                            conn.query('SELECT rented FROM users WHERE uuid=?', [oldBook.rentedby]).then(response => {
                                                if (response.length == 0) throw 'USER_NOT_FOUND';
                                                console.log(response);
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
                                                        conn.close(); pool.end();
                                                        res.end();
                                                        return;
                                                    })
                                                }).catch(exception => {
                                                    console.log(exception);
                                                    res.writeHead(400);
                                                    conn.close(); pool.end();
                                                    res.end(JSON.stringify({ error: exception }));
                                                })
                                            }).catch(exception => {
                                                console.log(exception);
                                                res.writeHead(400);
                                                conn.close(); pool.end();
                                                res.end(JSON.stringify({ error: exception }));
                                            })
                                        } else conn.query('UPDATE books SET title=?, author=?, isbn=?, description=? WHERE uuid=?',
                                            [book.title, book.author, book.isbn, book.description, uuid]
                                        ).then(() => {
                                            broadcastUpdate();
                                            res.writeHead(200);
                                            conn.close(); pool.end();
                                            res.end();
                                            return;
                                        })

                                    }
                                } else throw 'BOOK_DOES_NOT_EXIST';
                            }).catch(exception => {
                                console.log(exception);
                                res.writeHead(400);
                                conn.close(); pool.end();
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

    let cookie = req.headers.cookie.slice(6);
    console
    let uuid = req.url.substring(14, 50);
    try {

        let decodedCookie = jwt.verify(cookie, pubkey, { algorithm: 'RS256' });
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
        let pool = mariadb.createPool(databaseCredential);
        pool.getConnection().then(conn => {
            conn.query('USE ' + databaseCredential.database).then(() => {
                try {
                    conn.query('SELECT * FROM books WHERE uuid=?', [uuid]).then(response => {
                        if (response.length == 1) {

                            if (response[0].rentedby) {
                                let rentedby = response[0].rentedby;
                                conn.query('SELECT rented FROM users WHERE uuid=?', [rentedby]).then(response => {
                                    if (response.length == 0) throw 'USER_NOT_FOUND';
                                    console.log(response);
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
                                            conn.close(); pool.end();
                                            res.end();
                                        }).catch(exception => {
                                            console.log(exception);
                                            conn.close(); pool.end();
                                            res.writeHead(400);
                                            conn.close(); pool.end();
                                            res.end(JSON.stringify({ error: exception }));
                                        })
                                    })
                                })



                            } else
                                conn.query('DELETE FROM books WHERE uuid=?', [uuid]
                                ).then(response => {
                                    broadcastUpdate()
                                    res.writeHead(200);
                                    conn.close(); pool.end();
                                    res.end();
                                }).catch(exception => {
                                    console.log(exception);
                                    conn.close(); pool.end();
                                    res.writeHead(400);
                                    res.end(JSON.stringify({ error: exception }));
                                })
                        } else throw 'BOOK_DOES_NOT_EXIST';
                    }).catch(exception => {
                        console.log(exception);
                        res.writeHead(400);
                        conn.close(); pool.end();
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
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    let cookie = req.headers.cookie.slice(6);
    console.log(cookie);
    let search = '%' + new URL('https://library.karol.gay' + req.url).searchParams.get('query') + '%';
    console.log(search);
    try {
        let decodedCookie = jwt.verify(cookie, pubkey, { algorithm: 'RS256' });
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
        let pool = mariadb.createPool(databaseCredential);
        pool.getConnection().then(conn => {
            conn.query('USE ' + databaseCredential.database).then(() => {
                conn.query('SELECT * FROM books WHERE CONCAT(title, author, isbn, description) LIKE ? ORDER BY title', [search]).then(response => {
                    console.log(response);
                    let booksList = [];
                    for (let i = 0; i < response.length; i++) {
                        response[i].availableToRent = response[i].rentedby == null;
                        response[i].rentedByYou = response[i].rentedby == decodedCookie.uuid;
                        if (!isUserAdmin) delete response[i].rentedby;


                        booksList.push(response[i]);
                    }
                    res.writeHead(200);
                    conn.close(); pool.end();
                    res.end(JSON.stringify(booksList));
                }).catch(ex => {
                    console.log(ex);
                    res.writeHead(400);
                    conn.close(); pool.end();
                    res.end(JSON.stringify({ error: ex }));
                    return;

                });

            }).catch(ex => {
                console.log(ex);
                res.writeHead(400);
                conn.close(); pool.end();
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
app.get('/redirect*', function (req, res) {
    let id = new URL('https://library.karol.gay' + req.url).searchParams.get('id');
    console.log(id);
    let pool = mariadb.createPool(databaseCredential);
    pool.getConnection().then(conn => {
        conn.query('USE ' + databaseCredential.database).then(() => {

            conn.query('SELECT url FROM redirect WHERE id=?', [id]).then(response => {
                console.log(response);
                if (response.length == 0) {
                    res.redirect('https://library.karol.gay/');
                    conn.close(); pool.end();
                    res.end();
                }
                else {

                    let url = response[0].url;
                    console.log(url);
                    res.redirect(url);
                    conn.close(); pool.end();
                    res.end();
                }


            })
        })

    });

});
app.get('/users/get*', function (req, res) {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    try {
        let cookie = req.headers.cookie.slice(6);
        try {

            let decodedCookie = jwt.verify(cookie, pubkey, { algorithm: 'RS256' });
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
            let pool = mariadb.createPool(databaseCredential);
            pool.getConnection().then(conn => {
                conn.query('USE ' + databaseCredential.database).then(() => {
                    try {
                        conn.query('SELECT uuid, name, admin, email, rented FROM users').then(response => {
                            let userList = [];
                            console.log(response);
                            for (let i = 0; i < response.length; i++)userList.push({
                                uuid: response[i].uuid,
                                name: response[i].name,
                                email: response[i].email,
                                admin: response[i].admin == 1,
                                rented: JSON.parse(response[i].rented)
                            });
                            
                            res.writeHead(200);
                            conn.close(); pool.end();
                            res.end(JSON.stringify(userList));
                        }).catch(exception => {
                            console.log(exception);
                            res.writeHead(400);
                            conn.close(); pool.end();
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
    let cookie = req.headers.cookie.slice(6);
    console.log(cookie);
    let uuid = req.url.substring(13, 49);
    console.log(uuid);
    try {
        let decodedCookie = jwt.verify(cookie, pubkey, { algorithm: 'RS256' });
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
        let pool = mariadb.createPool(databaseCredential);
        pool.getConnection().then(conn => {
            conn.query('USE ' + databaseCredential.database).then(() => {
                conn.query('SELECT rentedby FROM books WHERE uuid=?', [uuid]).then(response => {
                    if (response.length == 0) throw 'BOOK_NOT_FOUND';
                    if (response[0].rentedby == null) {
                        //rent a book;
                        conn.query('UPDATE books SET rentedby=? WHERE uuid=?', [decodedCookie.uuid, uuid]).then(() => {
                            conn.query('SELECT rented FROM users WHERE uuid=?', [decodedCookie.uuid]).then(response => {
                                if (response.length == 0) throw 'USER_NOT_FOUND';
                                console.log(response);
                                let rentedList = JSON.parse(response[0].rented);
                                console.log(rentedList);
                                rentedList.push(uuid);
                                console.log(rentedList);
                                conn.query('UPDATE users SET rented=? WHERE uuid=?', [JSON.stringify(rentedList), decodedCookie.uuid]).then(response => {
                                    console.log(response);
                                    broadcastUpdate();
                                    res.writeHead(200);
                                    conn.close(); pool.end();
                                    res.end();
                                })
                            })
                        })

                    } else if (response[0].rentedby == decodedCookie.uuid) throw 'BOOK_RENTED_BY_YOU'; else throw 'BOOK_RENTED_BY_ANOTHER_USER';

                }).catch(ex => {
                    console.log(ex);
                    res.writeHead(400);
                    conn.close(); pool.end();
                    res.end(JSON.stringify({ error: ex }));
                    return;

                });
            }).catch(err => {
                console.log(ex);
                res.writeHead(400);
                conn.close(); pool.end();
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
    let cookie = req.headers.cookie.slice(6);
    console.log(cookie);
    let uuid = req.url.substring(15, 51);
    console.log(uuid);
    console.log(uuid);
    try {
        let decodedCookie = jwt.verify(cookie, pubkey, { algorithm: 'RS256' });
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
        let pool = mariadb.createPool(databaseCredential);
        pool.getConnection().then(conn => {
            conn.query('USE ' + databaseCredential.database).then(() => {
                conn.query('SELECT rentedby FROM books WHERE uuid=?', [uuid]).then(response => {
                    console.log(response);
                    if (response.length == 0) throw 'BOOK_NOT_FOUND';
                    if (response[0].rentedby == decodedCookie.uuid) {
                        //return a book;
                        conn.query('UPDATE books SET rentedby=null WHERE uuid=?', [uuid]).then(() => {
                            conn.query('SELECT rented FROM users WHERE uuid=?', [decodedCookie.uuid]).then(response => {
                                if (response.length == 0) throw 'USER_NOT_FOUND';
                                console.log(response);
                                let rentedList = JSON.parse(response[0].rented);
                                console.log(rentedList);
                                for (let i = 0; i < rentedList.length; i++)
                                    if (rentedList[i] == uuid)
                                        rentedList.splice(i, 1);
                                console.log(rentedList);
                                conn.query('UPDATE users SET rented=? WHERE uuid=?', [JSON.stringify(rentedList), decodedCookie.uuid]).then(response => {
                                    console.log(response);
                                    broadcastUpdate();
                                    res.writeHead(200);
                                    conn.close(); pool.end();
                                    res.end();
                                })
                            })
                        })

                    } else if (response[0].rentedby == null) throw 'BOOK_NOT_RENTED'; else throw 'BOOK_RENTED_BY_ANOTHER_USER';

                }).catch(ex => {
                    console.log(ex);
                    res.writeHead(400);
                    conn.close(); pool.end();
                    res.end(JSON.stringify({ error: ex }));
                    return;

                });
            }).catch(err => {
                console.log(ex);
                res.writeHead(400);
                conn.close(); pool.end();
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
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    let cookie = req.headers.cookie.slice(6);
    console.log(cookie);
    try {
        let decodedCookie = jwt.verify(cookie, pubkey, { algorithm: 'RS256' });
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
        let pool = mariadb.createPool(databaseCredential);
        pool.getConnection().then(conn => {
            conn.query('USE ' + databaseCredential.database).then(() => {
                conn.query('SELECT * FROM books WHERE rentedby=?', [decodedCookie.uuid]).then(response => {
                    console.log(response);
                    let booksList = [];
                    for (let i = 0; i < response.length; i++) {
                        if (!isUserAdmin) delete response[i].rentedby;


                        booksList.push(response[i]);
                    }
                    console.log(booksList);
                    res.writeHead(200);
                    conn.close(); pool.end();
                    res.end(JSON.stringify(booksList));
                }).catch(ex => {
                    console.log(ex);
                    res.writeHead(400);
                    conn.close(); pool.end();
                    res.end(JSON.stringify({ error: ex }));
                    return;

                });

            }).catch(ex => {
                console.log(ex);
                res.writeHead(400);
                conn.close(); pool.end();
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
    return String(email)
        .toLowerCase()
        .match(
            /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
        );
};
function createAccount(mail) {
    let pool = mariadb.createPool(databaseCredential);
    pool.getConnection().then(conn => {
        conn.query('USE ' + databaseCredential.database).then(() => {
            let uuid = getUuid(mail);
            conn.query("INSERT INTO users (uuid, admin, email) VALUES (?, ?, ?)", [uuid, false, mail]).then(res => {
                console.log(res);
                broadcastUpdate();
            }).catch(err => {
                console.log(err);
            })
            sendKeyRegistrationMail(mail);
        }).catch(err => {
            console.log(err);
        })

    });
}
async function sendKeyRegistrationMail(mail) {

    let pool = mariadb.createPool(databaseCredential);
    pool.getConnection().then(conn => {
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

                    name: user.name | user.email,
                    mail: user.email,
                    uuid: user.uuid,
                    admin: user.admin == 1

                }
                const token = jwt.sign(claims, privkey, { algorithm: 'RS256' });
                const url = createRedirect('https://library.karol.gay/keyreset.html?token=' + token);

                let transporter = nodemailer.createTransport({
                    host: "in-v3.mailjet.com",
                    port: 587,
                    secure: false,
                    auth: require('./smtp.json')
                });

                let message = {
                    from: '"Library 📖" <library@karol.gay>',
                    to: claims.mail,
                    subject: 'Register new device with your account',
                    text: 'Click this link to register a new device with your Library account. This link is only valid for 15 minutes. Note that your old device will get deauthorized.\n\n' + url,
                    html: 'Click this link to register a new device with your Library account. This link is only valid for 15 minutes. Note that your old device will get deauthorized.\n\n' + url,
                    attachments: []
                };

                try {
                    await transporter.sendMail(message);

                } catch (ex) {

                }

            }).catch(err => {
                console.log(err);
            })

        }).catch(err => {
            console.log(err);
        })

    });










}
function decodeAuthData(authData) {
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
    let id = crypto.createHash('sha256').update(url).digest('hex');
    let pool = mariadb.createPool(databaseCredential);
    pool.getConnection().then(conn => {
        conn.query('USE ' + databaseCredential.database).then(() => {

            conn.query('INSERT INTO redirect (id, url) VALUES (?, ?)', [id, url]);
        })

    });
    return 'https://library.karol.gay/redirect?id=' + id;
}
function broadcastUpdate() {
    updatesClientsList.forEach(element => {
        try {
            element.send('UPDATE')
        } catch (ex) {
            console.log(ex);
        }
    });
}
