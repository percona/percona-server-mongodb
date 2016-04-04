// name: Local user with read (only) access to 'other'
// mode: auth
// sequence: 60 

db = db.getSiblingDB( 'other' )

assert(
  db.auth({
    user: 'localotherro',
    pwd: 'localotherro9a5S'
  })
)

// check who we are authenticated as

var res = db.runCommand({connectionStatus : 1})

assert ( res.authInfo.authenticatedUsers[0].user == "localotherro")

// test access

load( '_functions.js' )

authuser_assertnone( db.getSiblingDB('test') )
authuser_assertro( db.getSiblingDB('other') )
authuser_assertnone( db.getSiblingDB('yetanother') )

