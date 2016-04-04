// note: run setup.js first with mongod --auth disabled
// then run this with mongod --auth enabled

// name: External user with readWrite access to 'other'
// mode: auth
// sequence: 85

db = db.getSiblingDB( '$external' )

assert(
  db.auth({
    user: 'extotherrw',
    pwd: 'extotherrw9a5S',
    mechanism: 'PLAIN',
    digestPassword: false    
  })
)

// check who we are authenticated as

var res = db.runCommand({connectionStatus : 1})

assert ( res.authInfo.authenticatedUsers[0].user == "extotherrw")

// test access

load( '_functions.js' )

authuser_assertnone( db.getSiblingDB('test') )
authuser_assertrw( db.getSiblingDB('other') )
authuser_assertnone( db.getSiblingDB('yetanother') )

