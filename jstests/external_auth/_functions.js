// functions used by the external authentication tests

// random word

// from linuxask.com

function randomString(len) { 
  var chars = "abcdefghiklmnopqrstuvwxyz"; 
  var randomstring = ''; 
  var string_length = len;
  for (var i=0; i<string_length; i++) { 
    var rnum = Math.floor(Math.random() * chars.length); 
    randomstring += chars.substring(rnum,rnum+1); 
  } 
  return randomstring; 
} 

var toType = function(obj) {
  return ({}).toString.call(obj).match(/\s([a-zA-Z]+)/)[1].toLowerCase()
}

// this should be run against db to which the user has read (only) access

function authuser_assertro(d) {

  print( "\tDatabase: " + d.getName() )

  // test query
  
  print( "\tTesting query in read privilege" )

  var q = d.query1;

  assert( q.count() == 1 )  

  // test insert

  print( "\tTesting insert for read privilege" )

  var insVal = Random.randInt( 16536 )

  c = d.collection1;

  c.insert( { a : insVal } );

  assert ( c.count( { a : insVal } ) == 0 )

  // test update

  print( "\tTesting update for read privilege" )

  c.update( { a : insVal }, { $inc: { a: +1} } )

  assert ( c.count( { a : insVal } ) == 0 )

  assert ( c.count( { a : insVal+1 } ) == 0 )

  // test remove 

  print( "\tTesting remove for read privilege" )

  c.remove( { a : insVal+1 } );

  assert ( c.count( { a : insVal+1 } ) == 0 )
}

// this should be run against db to which the user has readWrite access

function authuser_assertrw(d) {

  db = d

  print( "\tDatabase: " + d.getName() )

  // test query

  print( "\tTesting query for readWrite privilege" )

  var q = d.query1;

  assert( q.count() == 1 )  

  // test insert

  print( "\tTesting insert for readWrite privilege" )

  var insVal = Random.randInt( 16536 )

  c = d.collection1;

  c.insert( { a : insVal } );

  assert ( c.count( { a : insVal } ) == 1 )

  // test update

  print( "\tTesting update for readWrite privilege" )

  c.update( { a : insVal }, { $inc: { a: +1} } )

  assert ( c.count( { a : insVal } ) == 0 )

  assert ( c.count( { a : insVal+1 } ) == 1 )

  // test remove 

  print( "\tTesting remove for readWrite privilege" )

  c.remove( { a : insVal+1 } );

  assert ( c.count( { a : insVal+1 } ) == 0 )

}


// this should be run against db to which the user has no access

function authuser_assertnone(d) {

  db = d

  print( "\tDatabase: " + d.getName() )

  try {

    // test query

    print( "\tTesting query for no privileges" )

    var q = d.query1;

    assert( q.count() == 0 )  

  } catch (e) {

    if (e.message.match(/not authorized/)) {
      print( "\tnot authorized exception thrown (expected)" )
    }

    assert ( e.message.match(/not authorized/) )

  }

  try {

    // test insert

    print( "\tTesting insert for no privileges" )

    var insVal = Random.randInt( 16536 )

    c = d.collection1;

    c.insert( { a : insVal } );

    assert ( c.count( { a : insVal } ) == 0 )

  } catch (e) {

    if (e.message.match(/not authorized/)) {
      print( "\tnot authorized exception thrown (expected)" )
    }

    assert ( e.message.match(/not authorized/) )

  }

  try {

    // test update

    print( "\tTesting update for no privileges" )

    c.update( { a : insVal }, { $inc: { a: +1} } )

    assert ( c.count( { a : insVal } ) == 0 )

    assert ( c.count( { a : insVal+1 } ) == 0 )

  } catch (e) {

    if (e.message.match(/not authorized/)) {
      print( "\tnot authorized exception thrown (expected)" )
    }

    assert ( e.message.match(/not authorized/) )

  }

  try {

    // test remove 

    print( "\tTesting remove for no privileges" )

    c.remove( { a : insVal+1 } );

    assert ( c.count( { a : insVal+1 } ) == 0 )

  } catch (e) {

    if (e.message.match(/not authorized/)) {
      print( "\tnot authorized exception thrown (expected)" )
    }

    assert ( e.message.match(/not authorized/) )

  }

}
