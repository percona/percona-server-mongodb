// name: Local user with readWrite access to 'other'
// mode: auth
// sequence: 65 

db = db.getSiblingDB( 'other' )

assert(
  db.auth({
    user: 'localotherrw',
    pwd: 'localotherrw9a5S'
  })
)

// check who we are authenticated as

var res = db.runCommand({connectionStatus : 1})

assert ( res.authInfo.authenticatedUsers[0].user == "localotherrw")

// test access

load( '_functions.js' )

authuser_assertnone( db.getSiblingDB('test') )
authuser_assertrw( db.getSiblingDB('other') )
authuser_assertnone( db.getSiblingDB('yetanother') )

