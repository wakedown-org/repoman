var express             = require('express');
var path                = require('path');
var fs                  = require('fs');
var http                = require('http');
//var https               = require('https');
var url                 = require('url');
var tlsSessions         = require('strong-cluster-tls-store');
var passport            = require('passport');
var LocalApiKeyStrategy = require('passport-localapikey').Strategy;
var session             = require('express-session');
var fs                  = require('fs');
var nconf               = require('nconf');

var config_path = 'repoman-config.json';

nconf.argv().env().file({ file: config_path });

nconf.defaults({
    'sessionKey': 'someSessionKey',
    'pkgLink': 'pkg',
    'repositoriesRoot': 'repositories/',
    'http': {
      'port': (process.env.PORT || 5000) //8000
    },
  //  'https': {
  //    'port': 8443
  //  },
  //  'certificate' : {
  //    'fileKeyPath': '../../../key.pem',
  //    'fileCertPath': '../../../key-cert.pem'
  //  },
    'users' : [
      { 
        'email' : 'fumasa@wakedown.org',
        'repositories' : [
          { 
            'name': 'repo01',
            'tokens' : [
              { 
                'token' : 'bruzundungas',
                'permission' : 'rw'
              },
              { 
                'token' : 'krakatoa',
                'permission' : 'r'
              }
            ]
          },
          { 
            'name': 'repo02',
            'tokens' : [
              { 
                'token' : 'camila',
                'permission' : 'rw'
              },
              { 
                'token' : 'giovanna',
                'permission' : 'r'
              }
            ]
          }
        ],
      },
    ],
    'supportedMimeType' : {
      'html'  : 'text/html',
      'jpeg'  : 'image/jpeg',
      'jpg'   : 'image/jpeg',
      'png'   : 'image/png',
      'js'    : 'text/javascript',
      'css'   : 'text/css'
    }
});

//var httpsOptions = {
//  key: fs.readFileSync(nconf.get('certificate:fileKeyPath')),
//  cert: fs.readFileSync(nconf.get('certificate:fileCertPath'))
//};

var app = express();

app.locals.title = 'RepoMan';
app.locals.email = 'fumasa@wakedown.org';

passport.use(new LocalApiKeyStrategy(
  { apiKeyField : 'token' },
  function(token, done) {
    process.nextTick(function () {
      findUserByToken(token, function(err, user) {
        if (err) { 
          return done(err); 
        }
        if (!user) { 
          return done(null, false, { message: 'Unknown token : ' + token });
        }
        return done(null, user);
      });
    });
  }
));

app.use(function(req, res, next) {
    if (!/https/.test(req.protocol)){
      res.redirect('https://' + req.headers.host/*.replace(nconf.get('http:port'), nconf.get('https:port'))*/ + req.url);
    } else {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000');
      return next();
    } 
});

app.use(session({ 
  secret: nconf.get('sessionKey'),
  saveUninitialized: true,
  resave: true 
}));
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser(function(user, done) {
  done(null, user.email);
});

passport.deserializeUser(function(email, done) {
  findUserByEmail(email, function (err, user) {
    done(err, user);
  });
});

app.get('/', 
  function(req, res) {
    res.writeHead(200);
    if (req.isAuthenticated()) {
      res.end('welcome authenticated user\n');
    } else {
      res.end('welcome unauthenticated user\n');
    }
  }
);

app.get('/favicon.ico',
  function(req, res) {
    res.writeHead(200, {'Content-Type': 'image/x-icon'} );
    res.end();
    return; 
  }
);

app.all('/' + nconf.get('pkgLink'),
  passport.authenticate('localapikey', { failureRedirect: '/error' }),
  function(req, res) {
    if (req.method != "GET") {
      req.logout();
      res.redirect('/');
    } else {
      readRepoUser(req.query.token, function (error, fileList) {
        if (error !== null) {
          req.logout();
          res.redirect('/');
          console.log('error: ' + dumpObj(error));
          return;
        }
        res.writeHead(200);
        res.end('welcome authenticated\n' + dumpObj(fileList));
        console.log('fileList: ' + dumpObj(fileList));
      });
    }
  }
);

app.all('/' + nconf.get('pkgLink') + '/*',
  passport.authenticate('localapikey', { failureRedirect: '/error' }),
  function(req, res) {
    console.log('pkg request: ' + req.originalUrl);
    if (req.method != 'GET') {
      req.logout();
      res.redirect('/');
    } else {
      findRepoByToken(req.query.token, function (repo) {
        var mimeTypes = nconf.get('supportedMimeType');
        var uri = url.parse(req.url).pathname;
        var filename = path.join(process.cwd(), uri);
        var repository = nconf.get('repositoriesRoot') + repo.name;
        filename = filename.replace('pkg', repository);
        console.log('pkg response: ' + filename);
        fs.exists(filename, function(exists) {
          var stat = fs.statSync(filename);
          if (stat.isDirectory()) {
            readRepoUser(req.query.token, function (error, fileList) {
              if (error !== null) {
                req.logout();
                res.redirect('/');
                console.log('error: ' + dumpObj(error));
                return;
              }
              res.writeHead(200);
              res.end('welcome authenticated\n' + dumpObj(fileList));
              console.log('fileList: ' + dumpObj(fileList));
            }, uri.replace('/' + nconf.get('pkgLink'),''));
          } else
            if (stat.isFile()) {
              if(!exists) {
                req.logout();
                res.redirect('/');
                console.log('error: file not exists ' + filename);
                return;
              }
              if (mimeTypes[path.extname(filename).split('.')[1]] !== undefined) {
                var mimeType = mimeTypes[path.extname(filename).split('.')[1]];
                res.writeHead(200, { 'Content-Type': mimeType });
                var fileStream = fs.createReadStream(filename);
                fileStream.pipe(res);
              } else {
                req.logout();
                res.redirect('/');
                console.log('error: mime-type not supported ' + filename);
                return;
              }
            }
        });
      });
    }
  }
);

app.get('/error', 
  function(req, res) {
    req.logout();
    res.writeHead(401);
    res.end('welcome unauthenticated\n');
  }
);

app.all('*', function(req, res) {
  console.log('catch-all: ' + req.originalUrl);
  res.redirect('/');
});

var httpServer = http.createServer(app);
//var httpsServer = https.createServer(httpsOptions, app);

//tlsSessions(httpsServer);

httpServer.listen(nconf.get('http:port'));
//httpsServer.listen(nconf.get('https:port'));

httpServer.on('error', function (e) {
  console.log('error on httpServer:' + e);
});

//httpsServer.on('error', function (e) {
//  console.log('error on httpsServer:' + e);
//});

function dumpObj(obj) {
  var util = require('util');
  return util.inspect(obj, { showHidden: true, depth: null });
}

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) { 
    return next(); 
  }
  req.logout();
  res.redirect('/error');
}

function findUserByToken(token, fn) {
  var users = nconf.get('users');
  for (var i = 0, lenx = users.length; i < lenx; i++) {
    for (var j = 0, leny = users[i].repositories.length; j < leny; j++) {
      for (var k = 0, lenz = users[i].repositories[j].tokens.length; k < lenz; k++) {
        if (users[i].repositories[j].tokens[k].token === token) {
          return fn(null, users[i]);
        }
      }
    }
  }
  return fn(null, null);
}

function findUserByEmail(email, fn) {
  var users = nconf.get('users');
  for (var i = 0, len = users.length; i < len; i++) {
    if (users[i].email === email) {
      fn(null, users[i]);
    } else {
      fn(new Error('User ' + email + ' does not exist'));
    }
  }
}

function findRepoByToken(token, fn) {
  var users = nconf.get('users');
  for (var i = 0, lenx = users.length; i < lenx; i++) {
    for (var j = 0, leny = users[i].repositories.length; j < leny; j++) {
      for (var k = 0, lenz = users[i].repositories[j].tokens.length; k < lenz; k++) {
        if (users[i].repositories[j].tokens[k].token === token) {
          return fn(users[i].repositories[j]);
        }
      }
    }
  }
  return fn(null);
}

function readRepoUser(token, fn, path) {
  path = path || '';
  try {
    findUserByToken(token, function (err, user) {
      for (var i = 0, lenx = user.repositories.length; i < lenx; i++) {
        for (var j = 0, leny = user.repositories[i].tokens.length; j < leny; j++) {
          if (user.repositories[i].tokens[j].token === token) {
            var files = buildFileListFromPath(nconf.get('repositoriesRoot') + user.repositories[i].name + path);
            return fn(null, files);
          }
        }
      }
      return fn(null, []);
    });
  } catch (e) {
    return fn(e, null);
  }
}

function buildFileListFromPath(path) {
  var list = [];
  
  var files = fs.readdirSync(path);
  for (var i = 0, len = files.length; i < len; i++) {
    list.push(readFileInfo(path, files[i]));
  }
  
  return list;
}

function readFileInfo(path, file) {
  var fullpath = fullpath;
  var stat = fs.statSync(path + '/' + file);
  var type = (stat.isDirectory() ? 'dir' : (stat.isFile() ? 'file' : 'unknown'));
  return { file: file, type: type, stat: stat, fullpath: fullpath };
}

nconf.save();
