// name: Add External Users
// mode: auth
// sequence: 20
 
db = db.getSiblingDB( 'admin' )

assert( db.auth( 'localadmin' , 'localadmin9a5S' ) )

// user counters
var exttest=0
var extother=0

// exttestro has only read on test database
db.getSiblingDB( '$external' ).createUser({
  user: 'exttestro',
  roles: [
    { role: 'read',  db: 'test' }
  ]
})
exttest++;

// exttestrw has create and write on test database
db.getSiblingDB( '$external' ).createUser({
  user: 'exttestrw',
  roles: [
    { role: 'readWrite', db: 'test' }
  ]
})
exttest++;

// extotherro has read on other database
db.getSiblingDB( '$external' ).createUser({
  user: 'extotherro',
  roles: [
    { role: 'read', db: 'other' }
  ]
})
extother++;

// extotherrw has 
db.getSiblingDB( '$external' ).createUser({
  user: 'extotherrw',
  roles: [
    { role: 'readWrite', db: 'other' }
  ]
})
extother++

// extbothro has read on test and other database
db.getSiblingDB( '$external' ).createUser({
  user: 'extbothro',
  roles: [
    { role: 'read', db: 'test' },
    { role: 'read', db: 'other' }
  ]
})
exttest++
extother++

// extotherrw has readWrite on test and other database 
db.getSiblingDB( '$external' ).createUser({
  user: 'extbothrw',
  roles: [
    { role: 'readWrite', db: 'test' },
    { role: 'readWrite', db: 'other' }
  ]
})
exttest++
extother++

// exttestrwotherro has readWrite on test and read on other database
db.getSiblingDB( '$external' ).createUser({
  user: 'exttestrwotherro',
  roles: [
    { role: 'readWrite', db: 'test' },
    { role: 'read', db: 'other' }
  ]
})
exttest++
extother++

// exttestrootherrw and read on test and readWrite on other 
db.getSiblingDB( '$external' ).createUser({
  user: 'exttestrootherrw',
  roles: [
    { role: 'read', db: 'test' },
    { role: 'readWrite', db: 'other' }
  ]
})
exttest++
extother++

// display users from test database

print( 'test database:' )
print( '--------------' )

var findtest=0
db.getSiblingDB( 'admin' ).system.users.find(
  { '$and': [
    { user: /ext.*/ },
    { roles: { '$elemMatch': {db: 'test'} } } ]
  }).forEach(
    function(u) {
      print( "user: " + u.user );
      findtest++;
    }
)
assert ( exttest == findtest )


// display users from other database

print( '' )
print( 'other database:' )
print( '--------------' )

var findother=0
db.getSiblingDB( 'admin' ).system.users.find(
  { '$and': [
    { user: /ext.*/ },
    { roles: { '$elemMatch': {db: 'other'} } } ]
  }).forEach(
    function(u) {
      print( "user: " + u.user );
      findother++;
    }
)
assert ( extother == findother )
