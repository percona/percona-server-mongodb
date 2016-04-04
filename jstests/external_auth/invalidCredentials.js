// note: run setup.js first with mongod --auth disabled
// then run this with mongod --auth enabled

// name: Test invalid account names and passwords 
// mode: auth
// sequence: 40

// we are going to check all of these accounts

var accounts = [
  "localadmin",
  "localtestro",
  "localtestrw",
  "localotherro",
  "localotherrw",
  "exttestro",
  "exttestrw",
  "extotherro",
  "extotherrw",
  "extbothro",
  "extbothrw",
  "exttestrwotherro",
  "exttestrootherrw"
];

// should match setup/settings.conf LDAP_PASS_SUFFIX

var passSuffix='9a5S';


// build an array of strings to add to the beginning
// and end of account names and passwords to test
// all permutations of invalidity.

var overkills=[];
for (var b=15; b >= 0; b--) {
  iValid = b == 0 ? 1 : 0;  // only 0 is valid and at end
  strAccountPrefix  = b & 0x1 ? 'x' : '';
  strAccountSuffix  = b & 0x2 ? 'x' : '';
  strPasswordPrefix = b & 0x4 ? 'x' : '';
  strPasswordSuffix = b & 0x8 ? 'x' : '';
  overkills.push({
    valid: iValid,
    aprefix: strAccountPrefix,
    asuffix: strAccountSuffix,
    pprefix: strPasswordPrefix,
    psuffix: strPasswordSuffix
  });
}

// iterate over all of the accounts

for (var i in accounts) {
  account = accounts[i];
  print("\tTesting account: "+account);

  // pick the correct database for the account
  
  dbNames=[];
  if (/.*admin/.test(account)) {
    dbNames.push('admin');
  } else if (/^ext.*/.test(account)) {
    dbNames.push('$external');
  } else if (/.*test.*/.test(account)) {
    dbNames.push('test');
  } else if (/.*other.*/.test(account)) {
    dbNames.push('other');
  }

  // make sure a database name was picked

  assert(dbNames.length > 0, "\tI don't know how to handle this account.");

  // there should be only one for the current version

  for (j in dbNames) {

    dbName=dbNames[j];
    print ( "\tDatabase: " + dbName );

    // switch to the database

    db = db.getSiblingDB( dbName );

    // Iterate thru permutations of invalid
    // accounts and passwords including one
    // valid set for each account

    for (o in overkills) {

      overkill = overkills[o];

        // test valid login

        var success;
        
        try {

          success = 0;

          // build strings based on overkill, account name, and normal password suffix
          strUser = overkill.aprefix+account+overkill.asuffix;
          strPassword = overkill.pprefix+account+passSuffix+overkill.psuffix;

          if (/ext.*/.test(strUser)) {
            // external auth
            db.auth({
              user: strUser,
              pwd: strPassword,
              mechanism: 'PLAIN',
              digestPasswd: false
            })
          } else {
            // local auth
            db.auth({
              user: strUser,
              pwd: strPassword
            })
          }
          
          // check who we are authenticated as

          var res = db.runCommand({connectionStatus : 1})

          success = ( res.authInfo.authenticatedUsers[0].user == strUser ) ? 1 : 0;

          db.logout();

        } catch (e) {
        }

        // success must equal overkill.valid 
        assert(success == overkill.valid, "\t"+
               (overkill.valid ? "Valid credentials failed" : "Invalid credentials succeded") +
               " (user:"+strUser+") (pwd:"+strPassword+") (overkill:"+tojson(overkill)+")");

        if (overkill.valid == 1) {
          print( "Login succeeded with valid credentials" );
          print( "\t(Success was expected)" );
        } else {
          print( "\t(Failure was expected)" );
        }

    }

  }

}
