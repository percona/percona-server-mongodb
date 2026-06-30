"""Mongot community fixture for executing JSTests against.

The mongot-community binary is configured exclusively via a YAML config file and
exposes only a gRPC ingress interface (no MongoRPC). This fixture generates that
config file and launches mongot-community with ``--config``.
"""

import os
import shutil
import time
import urllib.error
import urllib.request

import yaml

from buildscripts.resmokelib.testing.fixtures import interface


def _scram_auth_block(mongot_community_options, auth_source):
    """Build a scramAuth block for a MongoConnectionConfig (replicaSet or router)."""
    return {
        "username": mongot_community_options.get("syncUsername", "__system"),
        "passwordFile": mongot_community_options["passwordFile"],
        "authSource": auth_source,
    }


def _generate_mongot_community_config(mongot_community_options):
    """Build the mongot-community YAML config from fixture options."""
    replica_auth_source = mongot_community_options.get("replicaAuthSource", "local")
    sync_source = {
        "replicaSet": {
            "hostAndPort": mongot_community_options["mongodHostAndPort"],
            "scramAuth": _scram_auth_block(mongot_community_options, replica_auth_source),
        },
    }

    if "routerHostAndPort" in mongot_community_options:
        router_auth_source = mongot_community_options.get("routerAuthSource", "admin")
        sync_source["router"] = {
            "hostAndPort": mongot_community_options["routerHostAndPort"],
            "scramAuth": _scram_auth_block(mongot_community_options, router_auth_source),
        }

    return {
        "syncSource": sync_source,
        "storage": {"dataPath": mongot_community_options["dataPath"]},
        "server": {
            "grpc": {
                "address": "127.0.0.1:{}".format(mongot_community_options["grpcPort"]),
                "tls": {"mode": "disabled"},
            }
        },
        "metrics": {"enabled": False},
        "healthCheck": {
            "address": "127.0.0.1:{}".format(mongot_community_options["healthCheckPort"])
        },
        "logging": {"verbosity": "INFO"},
    }


class MongoTCommunityFixture(interface.Fixture, interface._DockerComposeInterface):
    """Fixture which provides JSTests with a mongot-community process."""

    def __init__(self, logger, job_num, fixturelib, dbpath_prefix=None, mongot_community_options=None):
        interface.Fixture.__init__(self, logger, job_num, fixturelib, dbpath_prefix=dbpath_prefix)
        self.mongot_community_options = self.fixturelib.default_if_none(mongot_community_options, {})
        self.mongot_executable = self.fixturelib.default_if_none(
            self.config.MONGOT_COMMUNITY_EXECUTABLE, self.config.DEFAULT_MONGOT_COMMUNITY_EXECUTABLE
        )
        self.grpc_port = self.mongot_community_options["grpcPort"]
        self.health_check_port = self.mongot_community_options["healthCheckPort"]
        self.data_dir = self.mongot_community_options["dataPath"]
        self.config_path = self.mongot_community_options["configPath"]
        self.password_file = self.mongot_community_options["passwordFile"]
        self.mongot = None

    def _write_config_files(self):
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)

        with open(self.mongot_community_options["keyFile"], "r", encoding="utf-8") as key_file:
            key_file_contents = key_file.read()

        with open(self.password_file, "w", encoding="utf-8") as password_file:
            password_file.write(key_file_contents)
        os.chmod(self.password_file, 0o400)

        config_contents = _generate_mongot_community_config(self.mongot_community_options)
        with open(self.config_path, "w", encoding="utf-8") as config_file:
            yaml.safe_dump(config_contents, config_file, default_flow_style=False)

    def setup(self):
        """Set up and launch mongot-community."""
        self._write_config_files()

        launcher = MongotCommunityLauncher(self.fixturelib)
        mongot, _ = launcher.launch_mongot_community_program(
            self.logger,
            self.job_num,
            executable=self.mongot_executable,
            config_path=self.config_path,
        )

        try:
            msg = (
                "Starting mongot-community on grpc port {} ...\n{}".format(
                    self.grpc_port, mongot.as_command()
                )
            )
            self.logger.info(msg)
            mongot.start()
            msg = "mongot-community started on grpc port {} with pid {}".format(
                self.grpc_port, mongot.pid
            )
            self.logger.info(msg)
        except Exception as err:
            msg = "Failed to start mongot-community on grpc port {:d}: {}".format(
                self.grpc_port, err
            )
            self.logger.exception(msg)
            raise self.fixturelib.ServerFailure(msg)

        self.mongot = mongot

    def _all_mongo_d_s_t(self):
        """Return the `mongot-community` `Process` instance."""
        return [self]

    def pids(self):
        """:return: pids owned by this fixture if any."""
        out = [self.mongot.pid] if self.mongot is not None else []
        if not out:
            self.logger.debug(
                "Mongot-community not running when gathering mongot community fixture pid."
            )
        return out

    def _do_teardown(self, finished=False, mode=None):
        if self.config.NOOP_MONGO_D_S_PROCESSES:
            self.logger.info(
                "This is running against an External System Under Test setup with "
                "`docker-compose.yml` -- skipping teardown."
            )
            return

        if self.mongot is None:
            self.logger.warning("The mongot-community fixture has not been set up yet.")
            return

        if mode == interface.TeardownMode.ABORT:
            self.logger.info(
                "Attempting to send SIGABRT from resmoke to mongot-community on grpc port "
                "%d with pid %d...",
                self.grpc_port,
                self.mongot.pid,
            )
        else:
            self.logger.info(
                "Stopping mongot-community on grpc port %d with pid %d...",
                self.grpc_port,
                self.mongot.pid,
            )

        if not self.is_running():
            exit_code = self.mongot.poll()
            msg = (
                "mongot-community on grpc port {:d} was expected to be running, but wasn't. "
                "Process exited with code {:d}."
            ).format(self.grpc_port, exit_code)
            self.logger.warning(msg)
            raise self.fixturelib.ServerFailure(msg)

        self.mongot.stop(mode)
        exit_code = self.mongot.wait()

        if exit_code == 143 or (mode is not None and exit_code == -(mode.value)):
            self.logger.info(
                "Successfully stopped mongot-community on grpc port {:d}.".format(self.grpc_port)
            )
        else:
            self.logger.warning(
                "Stopped mongot-community on grpc port {:d}. Process exited with code {:d}.".format(
                    self.grpc_port, exit_code
                )
            )
            raise self.fixturelib.ServerFailure(
                "mongot-community on grpc port {:d} with pid {:d} exited with code {:d}".format(
                    self.grpc_port, self.mongot.pid, exit_code
                )
            )

        self.logger.info("Begin deleting mongot-community data files in fixture teardown")
        for path in (self.data_dir, self.config_path, self.password_file):
            try:
                if os.path.isdir(path):
                    shutil.rmtree(path)
                elif os.path.isfile(path):
                    os.remove(path)
            except OSError as error:
                self.logger.error("Hit OS error trying to delete %s: %s", path, error)
        self.logger.info("Finished deleting mongot-community data files in fixture teardown")

    def is_running(self):
        """Return true if mongot-community is still operating."""
        return self.mongot is not None and self.mongot.poll() is None

    def get_dbpath_prefix(self):
        """Return the _dbpath, as this is the root of the data directory."""
        return self._dbpath

    def get_node_info(self):
        """Return a list of NodeInfo objects."""
        if self.mongot is None:
            self.logger.warning("The mongot-community fixture has not been set up yet.")
            return []

        info = interface.NodeInfo(
            full_name=self.logger.full_name,
            name=self.logger.name,
            port=self.grpc_port,
            pid=self.mongot.pid,
        )
        return [info]

    def get_internal_connection_string(self):
        """Return the internal gRPC connection string."""
        return "localhost:{}".format(self.grpc_port)

    def await_ready(self):
        """Block until mongot-community's health check endpoint reports SERVING."""
        deadline = time.time() + MongoTCommunityFixture.AWAIT_READY_TIMEOUT_SECS
        health_url = "http://127.0.0.1:{}/health".format(self.health_check_port)

        while True:
            exit_code = self.mongot.poll()
            if exit_code is not None:
                raise self.fixturelib.ServerFailure(
                    "Could not connect to mongot-community health check on port {}, process "
                    "ended unexpectedly with code {}.".format(self.health_check_port, exit_code)
                )

            try:
                with urllib.request.urlopen(health_url, timeout=1) as response:
                    if 200 <= response.status < 300:
                        break
            except urllib.error.HTTPError as err:
                # Mongot returns 503 until replication is initialized.
                if err.code == 503:
                    pass
                else:
                    raise self.fixturelib.ServerFailure(
                        "Unexpected HTTP status {} from mongot-community health check on port "
                        "{}.".format(err.code, self.health_check_port)
                    )
            except (urllib.error.URLError, TimeoutError):
                pass

            remaining = deadline - time.time()
            if remaining <= 0.0:
                raise self.fixturelib.ServerFailure(
                    "Failed to connect to mongot-community health check on port {} after "
                    "{} seconds".format(
                        self.health_check_port,
                        MongoTCommunityFixture.AWAIT_READY_TIMEOUT_SECS,
                    )
                )

            self.logger.info(
                "Waiting for mongot-community health check on port %d to report SERVING.",
                self.health_check_port,
            )
            time.sleep(0.1)

        self.logger.info(
            "Successfully contacted mongot-community health check on port %d.",
            self.health_check_port,
        )


class MongotCommunityLauncher(object):
    """Class with utilities for launching mongot-community."""

    def __init__(self, fixturelib):
        """Initialize MongotCommunityLauncher."""
        self.fixturelib = fixturelib
        self.config = fixturelib.get_config()

    def launch_mongot_community_program(
        self, logger, job_num, executable=None, config_path=None, process_kwargs=None
    ):
        """Return a Process instance that starts mongot-community with ``--config``."""
        executable = self.fixturelib.default_if_none(
            executable, self.config.DEFAULT_MONGOT_COMMUNITY_EXECUTABLE
        )
        return self.fixturelib.mongot_community_program(
            logger, job_num, executable, config_path, process_kwargs
        )
