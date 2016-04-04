// name: Retrieve External Users
// mode: auth
// sequence: 20 

db = db.getSiblingDB( 'admin' )

assert( db.auth( 'localadmin' , 'localadmin9a5S' ) )

// display users from test database

print( 'test database:' )
print( '--------------' )

var findtest=0

db.getSiblingDB( '$external' ).system.users.find().forEach(
  function(u) {
    printjson(u);
    findtest++;
  }
)

