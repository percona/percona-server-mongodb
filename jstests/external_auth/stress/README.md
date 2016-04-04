# Percona Server for MongoDB - External authentication stress test

This directory contains a stress test that will run external authentication
under `valgrind --massif` to check for memory leaks and another operational
failures.

Before running this test you will need to deploy a test LDAP/SASL server.

See `support-files/ldap-sasl/README.md` for scripts to deploy
OpenLDAP slapd and Cyrus saslauthd (Ubuntu 14.x / 15.x)

- Set your binary destination directory

    ```
    export MONGODB_HOME=/ssd/percona-server-for-mongodb-dbg
    ```

- Compiling

  You should first build Percona Server for MongoDB with full debug support:

    ```
    scons --allocator=system --opt=off --dbg=on --use-sasl-client --prefix=${MONGODB_HOME} install
    ```

- Setup the database

  This will create a 'data' directory under your install directory.

      ```
      ./1-setup.sh
      ```

- Run the stress test

      ```
      ./2-run.sh
      ```

      You will see the mongo processes by running `ps aux`

- When you are satisfied,  stop the test.

      ```
      ./3-stop.sh
      ```

- You can now analyze the massif\*.out output using ms_print or massif-visualizer

