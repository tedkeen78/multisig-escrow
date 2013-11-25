///<reference path='d.ts/node.d.ts'/>
///<reference path='d.ts/express.d.ts'/>

import util = require('util');
import fs = require('fs');
import crypto = require('crypto');
import express = require('express');
var swig = require('swig');
var nconf = require('nconf');
var redis = require('redis');
var toobusy = require('toobusy');
var base32 = require('thirty-two');
var uuid = require('uuid');
var qrCode = require('qrcode-npm');
var notp = require('notp');
var sqlite3 = require('sqlite3');

var SATOSHI = 100000000;
var SATODIGITS = SATOSHI.toString(10).length-1;
var DUST = 5430;

var ONEDAY = 24*60*60*1000;

nconf
  .argv()
  .env()
  .file('config.json')
  .defaults({
    secret: "unset",
    audience: "http://localhost:4000",
    sitetitle: "Multisig Escrow Manager",
    transfee: 50000,
    trust_proxy: false,
    subdir: "",
    session: {
      key: "msm_session"
    },
    // google analytics
    ga: {
      ua: false,
      domain: false
    },
    listen: {
      enabled: true,
      socket: false,
      host: 'localhost',
      port: 4000
    },
    redis: {
      main: {
        enabled: false,
        socket: false,
        host: 'localhost',
        port: 6379,
        pass: '',
        db: 0
      },
      cache: {
        enabled: false,
        socket: false,
        host: 'localhost',
        port: 6380,
        pass: '',
        db: 0
      }
    },
    limits: {
      title: {
        maxchars: 128,
        maxnewlines: 0
      },
      description: {
        maxchars: 10000,
        maxnewlines: 500
      },
      comment: {
        maxchars: 5000,
        maxnewlines: 50
      }
    },
    // Transactions not yet agreed upon, or with funds still in the multisig address are never pruned.
    // The cleanup time for agreed transactions is added to their timelength value.
    cleanup: {
      minInterval: 6*60*60*1000,
      transactions: {
        canceled: 2*ONEDAY,
        agreed: 90*ONEDAY,
        complete: 90*ONEDAY
      }
    },
    sqlite: {
      filename: 'sqlite.db'
    },
    admin: {
      email: false
    }
  });

interface RedisOptions {
  host?: string;
  port?: number;
  socket?: string;
  pass?: string;
  db?: number;
}

function makeRedisClient(options: RedisOptions) {
  function throwErr(err) {
    if (err) throw err;
  }
  
  var r = redis.createClient(options.socket||options.port, options.host);
  if (options.pass) {
    r.auth(options.pass, throwErr);
  }
  if (options.db) {
    r.select(options.db, throwErr);
    r.on("connect", function() {
      r.send_anyways = true;
      r.select(options.db, throwErr);
      r.send_anyways = false;
    });
  }
  return r;
}

var secret = nconf.get("secret");

if (!secret || secret == "unset" || secret == "REPLACE WITH RANDOM SECRET") {
  console.error("'secret' setting in config.json needs to be set to a random string!");
  console.error("Here is a newly generated value that can be used:");
  var r = crypto.randomBytes(16).toString('base64');
  console.error(JSON.stringify(r));
  throw Error("secret is unset");
}

var sessionOptions = {secret: secret, store: null, key: nconf.get('session:key'), proxy: nconf.get('trust_proxy')};

if (nconf.get("redis:main:enabled")) {
  // pdb - persistent database
  var pdb = makeRedisClient({
    host: nconf.get("redis:main:host"),
    port: nconf.get("redis:main:port"),
    socket: nconf.get("redis:main:socket"),
    pass: nconf.get("redis:main:pass"),
    db: nconf.get("redis:main:db")
  });
  
  var RedisStore = require('connect-redis')(express);
  sessionOptions.store = new RedisStore({client: pdb});
  console.log("Using redis session store");
}

if (nconf.get("redis:cache:enabled")) {
  // cdb - cache database
  var cdb = makeRedisClient({
    host: nconf.get("redis:cache:host"),
    port: nconf.get("redis:cache:port"),
    socket: nconf.get("redis:cache:socket"),
    pass: nconf.get("redis:cache:pass"),
    db: nconf.get("redis:cache:db")
  });
}

if (!sessionOptions.store) {
  var SQLiteStore = require('connect-sqlite3')(express);
  sessionOptions.store = new SQLiteStore();
  console.log("Using SQLite session store");
}

var sdb = new sqlite3.Database(nconf.get('sqlite:filename'));
// Run init-sqlite.sql. Note that only "--" comments are allowed, and they
// must have nothing before them on the line besides whitespace.
sdb.exec(fs.readFileSync('init-sqlite.sql', {encoding: 'utf8'}).replace(/^\s*--.*$/gm, ''));

var marked = require('marked');
marked.setOptions({
  gfm: true,
  breaks: true,
  smartLists: true,
  sanitize: true
});

var app = express();

app.engine('html', swig.renderFile);
app.set('view engine', 'html');
app.set('views', __dirname + '/views');

app.locals({
  approot: app.path.bind(app),
  sitetitle: nconf.get('sitetitle'),
  transfee: nconf.get('transfee'),
  SATOSHI: SATOSHI,
  ga: nconf.get('ga'),
  admin: nconf.get('admin')
});

app.set('trust proxy', nconf.get('trust_proxy'));

app
  .use(express.logger())
  .use(function(req, res, next) {
    if (toobusy()) res.send(503, "I'm busy right now, sorry.");
    else next();
  })
  .use('/static', express.static(__dirname + '/static'))
  .use(express.urlencoded())
  .use(express.cookieParser())
  .use(express.session(sessionOptions))
  .use(express.csrf())
  .use(accountLoader)
  .use(databaseCleanupMiddleware);

require("express-persona")(app, {
  audience: nconf.get("audience")
});

/* Routes */

app.get('/', function(req, res, next) {
  var page = {user: req.user};
  res.render('index', page);
});

app.get('/account', function(req, res, next) {
  var page = {
    user: req.user,
    personaUser: req.session['email'] || "",
    flash: req.session['flash'],
    redirect: req.session['loginRedirect'],
    _csrf: req.csrfToken
  };
  delete req.session['flash'];
  if (req.user)
    delete req.session['loginRedirect'];
  
  res.render('account', page);
});

app.get('/transactions', requireAccount, function(req, res, next) {
  sdb.all('SELECT * FROM transactions WHERE $id IN (buyer, seller, arbitrator)',
    {$id: req.user.id}, function(err, transactions) {
      if (err)
        return next(err);
      
      var page = {
        user: req.user,
        transactions: transactions,
        _csrf: req.csrfToken
      };
      res.render('transactions', page);
    });
});

app.get('/newtransaction', requireAccount, function(req, res, next) {
  var page = {
    user: req.user,
    _csrf: req.csrfToken
  };
  res.render('newtransaction', page);
});

app.post('/newtransaction', requireAccount, function(req, res, next) {
  if (typeof req.body.title !== 'string' || typeof req.body.text !== 'string' || typeof req.body.role !== 'string' || typeof req.body.arb_fee !== 'string' || typeof req.body.timelength !== 'string')
    return showError(req, res, 400, "Fields missing or invalid");
  var title: string = req.body.title.trim();
  var text: string = req.body.text.trim();
  var role: string = req.body.role;
  var payment: number = parseBTCAmount(req.body.payment.trim());
  var arb_fee: number = parseFloat(req.body.arb_fee.trim());
  var timelength: number = parseInt(req.body.timelength.trim());
  if (!title)
    return showError(req, res, 400, "Title missing");
  if (!text)
    return showError(req, res, 400, "Description missing");
  if (!checkLimits(title, nconf.get('limits:title')))
    return showError(req, res, 400, "Title too long");
  if (!checkLimits(text, nconf.get('limits:description')))
    return showError(req, res, 400, "Description too long");
  if (['buyer','seller','arbitrator'].indexOf(role) == -1)
    return showError(req, res, 400, "Invalid role");
  if (isNaN(payment) || payment < DUST)
    return showError(req, res, 400, "Payment was not a valid number.");
  if (isNaN(arb_fee) || arb_fee < 0 || arb_fee >= 100)
    return showError(req, res, 400, "Arbitrator fee was not a valid number.");
  if (isNaN(timelength) || timelength <= 0)
    return showError(req, res, 400, "Transaction time was not a valid number.");

  makeUUIDandSecret(function(err, nid, inv_secret) {
    if (err)
      return next(err);

    sdb.run('INSERT INTO `transactions` (uuid, '+role+', inv_secret, title, text, time_made, timelength, payment, arb_fee) VALUES ($uuid, $user, $inv_secret, $title, $text, $now, $timelength, $payment, $arb_fee)',
      {$uuid: nid, $user: req.user.id, $inv_secret: inv_secret, $title: title, $text: text, $now: Date.now(), $timelength: timelength, $payment: payment, $arb_fee: arb_fee},
      function(err) {
        if (err)
          return next(err);
        if (!this.changes)
          return showError(req, res, 500, "Failed to create transaction");

        res.redirect('transactions/'+encodeURIComponent(nid));
      });
  });
});

app.get('/transactions/:uuid', requireAccount, function(req, res, next) {
  sdb.get('SELECT transactions.id, uuid, buyer.email as buyer_email, seller.email as seller_email, arbitrator.email as arbitrator_email, buyer_address, seller_address, arbitrator_address, buyer_agreed, seller_agreed, arbitrator_agreed, inv_secret, title, text, timelength, time_made, time_canceled, time_started, time_complete, payment, arb_fee FROM transactions LEFT JOIN users buyer ON transactions.buyer = buyer.id LEFT JOIN users seller ON transactions.seller = seller.id LEFT JOIN users arbitrator ON transactions.arbitrator = arbitrator.id WHERE uuid = $uuid AND $id IN (buyer, seller, arbitrator)',
    {$uuid: req.params.uuid, $id: req.user.id}, function(err, transaction) {
      if (err)
        return next(err);
      
      if (!transaction)
        return showError(req, res, 404, "Transaction does not exist, or you are not a participant of it.");
      
      transaction.players = [
        {
          role: "Buyer",
          email: transaction.buyer_email,
          address: transaction.buyer_address,
          agreed: transaction.buyer_agreed
        },
        {
          role: "Seller",
          email: transaction.seller_email,
          address: transaction.seller_address,
          agreed: transaction.seller_agreed
        },
        {
          role: "Arbitrator",
          email: transaction.arbitrator_email,
          address: transaction.arbitrator_address,
          agreed: transaction.arbitrator_agreed
        }
      ];

      if (transaction.time_fundsactive && transaction.timelength) {
        transaction.timelength_end = transaction.time_fundsactive + transaction.timelength*ONEDAY;
      }
      
      transaction.readyForAgree = (transaction.buyer_email && transaction.seller_email && transaction.arbitrator_email && !transaction.time_canceled);
      
      sdb.all('SELECT commentnum, users.email as user_email, time, text FROM transactioncomments LEFT JOIN users ON transactioncomments.user = users.id WHERE `transaction` = ? ORDER BY commentnum', [transaction.id], function(err, comments) {
        if (err)
          return next(err);
        
        transaction.text_rendered = user_markdown(transaction.text);
        
        for (var i=0; i<comments.length; i++)
          comments[i].text_rendered = user_markdown(comments[i].text);
        
        transaction.comments = comments;
        
        var page = {
          user: req.user,
          transaction: transaction,
          flash: req.session['flash'],
          invid: invitationGen(transaction.inv_secret),
          _csrf: req.csrfToken
        };
        delete req.session['flash'];
        
        res.render('transaction', page);
      });
    });
});

app.get('/transactions/:uuid/join/:role/:inv', function(req, res, next) {
  var role: string = req.params.role;
  if (['buyer','seller','arbitrator'].indexOf(role) == -1)
    return showError(req, res, 400, "Invalid role");

  sdb.get('SELECT title, inv_secret FROM transactions WHERE uuid = ? AND '+role+' IS NULL AND time_canceled IS NULL', [req.params.uuid], function(err, transaction) {
    if (err)
      return next(err);
    
    if (!transaction || invitationGen(transaction.inv_secret)(role) !== req.params.inv)
      return showError(req, res, 400, "Invalid or expired transaction invitation link");
    
    if (!req.user)
      req.session['loginRedirect'] = req.url;
    
    var page = {
      user: req.user,
      transaction: transaction,
      role: role,
      _csrf: req.csrfToken
    };
    res.render('join', page);
  });
});

app.post('/transactions/:uuid/join/:role/:inv', requireAccount, function(req, res, next) {
  var role: string = req.params.role;
  if (['buyer','seller','arbitrator'].indexOf(role) == -1)
    return showError(req, res, 400, "Invalid role");
  if (!req.body.join)
    return showError(req, res, 400, "Fields missing");

  sdb.get('SELECT id, inv_secret FROM transactions WHERE uuid = ? AND '+role+' IS NULL AND time_canceled IS NULL', [req.params.uuid], function(err, transaction) {
    if (err)
      return next(err);
    
    if (!transaction || invitationGen(transaction.inv_secret)(role) !== req.params.inv)
      return showError(req, res, 400, "Invalid or expired transaction invitation link");
    
    sdb.run('UPDATE transactions SET '+role+' = $userid WHERE id = $trid AND '+role+' IS NULL', {$trid: transaction.id, $userid: req.user.id}, function(err) {
      if (err)
        return next(err);

      if (!this.changes)
        return showError(req, res, 500, "Failed to join transaction.");
      
      res.redirect('transactions/'+encodeURIComponent(req.params.uuid));
    });
  });
});

app.post('/transactions/:uuid/setaddress', requireAccount, function(req, res, next) {
  if (typeof req.body.role !== 'string' || typeof req.body.btcaddress !== 'string')
    return showError(req, res, 400, "Fields missing or invalid");
  var role: string = req.body.role;
  var btcaddress: string = req.body.btcaddress.trim();
  if (['buyer','seller'].indexOf(role) == -1)
    return showError(req, res, 400, "Invalid role");
  
  validateStandardBTCAddress(btcaddress, function(err, valid) {
    if (err)
      return next(err);
    if (!valid)
      return showError(req, res, 400, "Invalid address");
    
    sdb.run('UPDATE transactions SET '+role+'_address = $addr WHERE uuid = $uuid AND '+role+' = $id AND '+role+'_address IS NULL AND time_started IS NULL AND time_canceled IS NULL',
      {$uuid: req.params.uuid, $addr: btcaddress, $id: req.user.id},
      function(err) {
        if (err)
          return next(err);
        if (!this.changes)
          return showError(req, res, 500, "Failed to set address");
        
        req.session['flash'] = "Set your Bitcoin address.";
        res.redirect('transactions/'+encodeURIComponent(req.params.uuid));
      });
  });
});

app.post('/transactions/:uuid/agree', requireAccount, function(req, res, next) {
  if (typeof req.body.role !== 'string')
    return showError(req, res, 400, "Fields missing or invalid");
  var role: string = req.body.role;
  markAgreement(req, res, next, req.params.uuid, role, true);
});

app.post('/transactions/:uuid/cancel', requireAccount, function(req, res, next) {
  if (typeof req.body.role !== 'string')
    return showError(req, res, 400, "Fields missing or invalid");
  var role: string = req.body.role;
  markAgreement(req, res, next, req.params.uuid, role, false);
});

app.post('/transactions/:uuid/void', requireAccount, function(req, res, next) {
  sdb.run('UPDATE transactions SET time_canceled = $now WHERE uuid = $uuid AND time_started IS NULL AND $id IN (buyer, seller, arbitrator)',
    {$uuid: req.params.uuid, $now: Date.now(), $id: req.user.id}, function(err) {
      if (err)
        return next(err);
      if (!this.changes)
        return showError(req, res, 400, "That action is not valid currently or for this transaction.");
      
      req.session['flash'] = "Canceled the entire transaction.";
      res.redirect('transactions/'+encodeURIComponent(req.params.uuid));
    });
});

app.post('/transactions/:uuid/newcomment', requireAccount, function(req, res, next) {
  if (typeof req.body.text !== 'string' || !req.body.text.trim())
    return showError(req, res, 400, "Fields missing or invalid");
  if (!checkLimits(req.body.text, nconf.get('limits:comment')))
    return showError(req, res, 400, "Comment too long");
  
  sdb.get('SELECT transactions.id FROM transactions WHERE uuid = $uuid AND $id IN (buyer, seller, arbitrator)',
    {$uuid: req.params.uuid, $id: req.user.id}, function(err, transaction) {
      if (err)
        return next(err);
      
      if (!transaction)
        return showError(req, res, 404, "Transaction does not exist, or you are not a participant of it.");
      
      sdb.run('INSERT INTO `transactioncomments` (`transaction`, `commentnum`, `user`, `time`, `text`) VALUES ($tid, (SELECT IFNULL(MAX(commentnum)+1,1) FROM `transactioncomments` WHERE `transaction` = $tid), $uid, $time, $text)',
        {$tid: transaction.id, $uid: req.user.id, $time: Date.now(), $text: req.body.text},
        function(err) {
          if (err)
            return next(err);
          
          req.session['flash'] = "Comment posted.";
          res.redirect('transactions/'+encodeURIComponent(req.params.uuid));
        });
    });
});

/* OTP related routes */

app.post('/account/enableotp', requireAccount, function(req, res, next) {
  crypto.randomBytes(16, function(err, buf) {
    if (err)
      return next(err);
    
    var key = buf.toString('base64');
    
    sdb.run('UPDATE users SET otpkey = $key WHERE id = $id', {$key: key, $id: req.user.id}, function(err) {
      if (err)
        return next(err);
      
      var key32 = base32.encode(key);
      var keyuri = 'otpauth://totp/'+encodeURIComponent(nconf.get('sitetitle'))+'?secret='+key32;
      
      var keyqr: string;
      
      try {
        var qr = qrCode.qrcode(6, 'M');
        qr.addData(keyuri);
        qr.make();
        keyqr = qr.createImgTag(4);
      } catch(e) {
        keyqr = "Error generating QR code.";
        console.error(keyqr);
        console.error(e);
      }
      
      var page = {
        user: req.user,
        otpkey: key32,
        otpkeyuri: keyuri,
        otpkeyqr_raw: keyqr,
        _csrf: req.csrfToken
      };
      res.render('enableotp', page);
    });
  });
});

app.post('/account/confirmotp', requireAccount, function(req, res, next) {
  if (!req.user.otpkey)
    return showError(req, res, 400, "Two-factor authentication is not configured on your account.");
  if (req.user.otpenabled)
    return showError(req, res, 400, "Two-factor authentication is already enabled on your account.");
  if (typeof req.body.otpcode !== 'string')
    return showError(req, res, 400, "Fields missing or invalid");
  if (!notp.totp.verify(req.body.otpcode, req.user.otpkey, {}))
    return showError(req, res, 400, "Invalid password!");
  
  sdb.run('UPDATE users SET otpenabled = 1 WHERE id = $id', {$id: req.user.id}, function(err) {
    if (err)
      return next(err);
    
    req.session['flash'] = 'Successfully enabled two-factor authentication for your account.';
    res.redirect('account');
  });
});

app.post('/account/otp', function(req, res, next) {
  if (!req['unauthUser'])
    return showError(req, res, 400, "Only semi-authenticated users can send a one-time password.");
  if (typeof req.body.otpcode !== 'string')
    return showError(req, res, 400, "Fields missing or invalid");
  if (!notp.totp.verify(req.body.otpcode, req['unauthUser'].otpkey, {}))
    return showError(req, res, 400, "Invalid password");
  
  req.session['authenticated'] = true;
  res.redirect('account');
});

app.post('/account/disableotp', requireAccount, function(req, res, next) {
  if (!req.user.otpenabled)
    return showError(req, res, 400, "Two-factor authentication is not enabled on your account.");
  
  sdb.run('UPDATE users SET otpenabled = 0 WHERE id = $id', {$id: req.user.id}, function(err) {
    if (err)
      return next(err);
    
    req.session['flash'] = 'Disabled two-factor authentication for your account.';
    res.redirect('account');
  });
});

/* Middleware */

function accountLoader(req: express.Request, res: express.Response, next: Function) {
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Cache-Control", "private");

  if (req.session['email']) {
    sdb.get('SELECT * FROM users WHERE email = ?', [req.session['email']], function(err, user) {
      if (err)
        return next(err);
      
      if (user) {
        if (!user.otpenabled || req.session['authenticated']) {
          req.session['authenticated'] = true;
          req.user = user;
        } else {
          req['unauthUser'] = user;
        }
        
        next();
      } else {
        sdb.run('INSERT INTO users (email) VALUES (?)', [req.session['email']], function(err) {
          if (err)
            return next(err);
          req.user = {id: this.lastID, email: req.session['email']};
          next();
        });
      }
    });
  } else {
    delete req.session['authenticated'];
    next();
  }
}

function requireAccount(req: express.Request, res: express.Response, next: Function) {
  if (!req.user) {
    req.session['loginRedirect'] = req.url;
    res.redirect('account');
  } else {
    next();
  }
}

/* Utility functions */

function showError(req: express.Request, res: express.Response, status: number, message: string) {
  res.status(status);
  res.render('error', {user: req.user, error: message});
}

// converts a decimal amount of bitcoins to an integer amount of Satoshis without rounding errors
function parseBTCAmount(s: string): number {
  var m = /^([0-9]+)(\.([0-9]+))?$/.exec(s);
  if (!m)
    return NaN;
  var result = parseInt(m[1], 10) * SATOSHI;
  if (m[2])
    result += Math.round(parseInt(m[3], 10) * Math.pow(10, SATODIGITS - m[3].length));
  return result;
}

function invitationGen(inv_secret: string) {
  return function(role: string): string {
    var s = crypto.createHash('sha1');
    s.update(inv_secret+role);
    return s.digest('hex').substring(0, 16);
  };
}

function makeUUIDandSecret(cb: (err: Error, nid: string, inv_secret: string)=>void) {
  crypto.randomBytes(24, function(err, buf) {
    if (err)
      return cb(err, null, null);
    
    cb(null, uuid.v4({random: buf.slice(0,16)}), buf.slice(16).toString('base64'));
  });
}

// TODO real validation
function validateStandardBTCAddress(address: string, cb: (err: Error, valid: boolean)=>void) {
  cb(null, !!/^1[1-9A-HJ-NP-Za-km-z]{33}$/.exec(address));
}

function markAgreement(req: express.Request, res: express.Response, next: Function, uuid: string, role: string, status: boolean) {
  if (['buyer','seller','arbitrator'].indexOf(role) == -1)
    return showError(req, res, 400, "Invalid role");
  
  var addrClause = ''
  if (role !== 'arbitrator')
    addrClause = 'AND '+role+'_address IS NOT NULL ';
  
  sdb.run('UPDATE transactions SET '+role+'_agreed = $status WHERE uuid = $uuid AND '+role+' = $id '+addrClause+'AND buyer IS NOT NULL AND seller IS NOT NULL AND arbitrator IS NOT NULL AND time_started IS NULL AND time_canceled IS NULL',
    {$uuid: uuid, $id: req.user.id, $status: status}, function(err, transaction) {
      if (err)
        return next(err);
      
      if (!this.changes)
        return showError(req, res, 400, "That action is not valid currently or for this transaction.");
      
      req.session['flash'] = status ? "Marked your status as agreed." : "Removed your agreement status.";
      
      checkStartTransaction(uuid, function(err) {
        if (err)
          return next(err);
        
        res.redirect('transactions/'+encodeURIComponent(uuid));
      });
    });
}

function checkStartTransaction(uuid: string, cb: (err)=>void) {
  sdb.run('UPDATE transactions SET time_started = $now WHERE uuid = $uuid AND buyer_agreed AND seller_agreed AND arbitrator_agreed AND time_started IS NULL AND time_canceled IS NULL',
    {$uuid: uuid, $now: Date.now()}, function(err) {
      if (err)
        return cb(err);
      if (!this.changes)
        return cb(null);
      
      console.log("READY");
      // TODO initialize bitcoin multisig address and start watching it
      cb(null);
    });
}

function checkLimits(text: string, limits: {maxchars?: number; maxnewlines?: number;}) {
  if (limits.maxchars != null && text.length > limits.maxchars)
    return false;
  if (limits.maxnewlines != null && text.split("\n").length-1 > limits.maxnewlines)
    return false;
  return true;
}

function markdown(text: string, sanitize: boolean = true): string {
  marked.setOptions({sanitize: sanitize});
  return marked(text);
}

function user_markdown(text: string): string {
  return markdown(text).replace('<a ', '<a rel="nofollow" ');
}

/* db cleanup */

var databaseLastCleanupTime: number = null;

// clean up the database on occasion after activity happens
function databaseCleanupMiddleware(req: express.Request, res: express.Response, next: Function) {
  next();
  if (!databaseLastCleanupTime || databaseLastCleanupTime < Date.now()-nconf.get('cleanup:minInterval'))
    databaseCleanup();
}

function databaseCleanup() {
  databaseLastCleanupTime = Date.now();
  
  var changes = 0;
  sdb.run('DELETE FROM transactions WHERE time_canceled < ?', [Date.now()-nconf.get('cleanup:transactions:canceled')], function(err) {
    if (err)
      console.error(err);
    changes += this.changes;
    
    sdb.run('DELETE FROM transactions WHERE time_started + IFNULL(timelength,0) * $oneday < $t AND time_fundsactive IS NULL AND buyer AND seller AND arbitrator', {$oneday: ONEDAY, $t: Date.now()-nconf.get('cleanup:transactions:agreed')}, function(err) {
      if (err)
        console.error(err);
      changes += this.changes;
      
      sdb.run('DELETE FROM transactions WHERE time_complete < ?', [Date.now()-nconf.get('cleanup:transactions:complete')], function(err) {
        if (err)
          console.error(err);
        changes += this.changes;
        
        console.log("Database cleanup total changes:", changes);
      });
    });
  });
}

/* Startup */

if (nconf.get('listen:enabled')) {
  var listenApp = app;
  
  if (nconf.get("subdir")) {
    listenApp = express();
    listenApp.use(nconf.get("subdir"), app);
  }
  
  var socket: string = nconf.get('listen:socket');
  var port: number = nconf.get('listen:port');
  var host: string = nconf.get('listen:host');
  
  if (!socket) {
    listenApp.listen(port, host, function() {
      console.log("Now listening on "+host+":"+port);
    });
  } else {
    fs.unlink(socket, function(err) {
      listenApp.listen(socket, function() {
        fs.chmod(socket, 0766);
        console.log("Now listening on "+socket);
      });
    });
  }
}
