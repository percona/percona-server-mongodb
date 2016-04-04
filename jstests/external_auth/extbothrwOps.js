// note: run setup.js first with mongod --auth disabled
// then run this with mongod --auth enabled

// name: External user with readWrite access to both 'test' and 'other'
// mode: auth
// sequence: 105

var testUser='extbothrw'

db = db.getSiblingDB( '$external' )

assert(
  db.auth({
    user: testUser,
    pwd: testUser+'9a5S',
    mechanism: 'PLAIN',
    digestPassword: false    
  })
)

// check who we are authenticated as

var res = db.runCommand({connectionStatus : 1})

assert ( res.authInfo.authenticatedUsers[0].user == testUser)

// test access

load( '_functions.js' )

authuser_assertrw( db.getSiblingDB('test') )
authuser_assertrw( db.getSiblingDB('other') )
authuser_assertnone( db.getSiblingDB('yetanother') )

