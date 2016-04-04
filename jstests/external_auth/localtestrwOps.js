// name: Local user with readWrite access to 'test'
// mode: auth
// sequence: 55 

db = db.getSiblingDB( 'test' )

assert(
  db.auth({
    user: 'localtestrw',
    pwd: 'localtestrw9a5S'
  })
)

// check who we are authenticated as

var res = db.runCommand({connectionStatus : 1})

assert ( res.authInfo.authenticatedUsers[0].user == "localtestrw")

// test access

load( '_functions.js' )

authuser_assertrw( db.getSiblingDB('test') )
authuser_assertnone( db.getSiblingDB('other') )
authuser_assertnone( db.getSiblingDB('yetanother') )

