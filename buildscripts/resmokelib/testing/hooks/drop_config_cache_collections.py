"""Test hook for dropping entries in config.cache.collections ."""

import os.path
import random
import threading
import time

import pymongo.errors

from buildscripts.resmokelib import errors
from buildscripts.resmokelib.testing.fixtures import shardedcluster
from buildscripts.resmokelib.testing.hooks import interface
from buildscripts.resmokelib.testing.hooks import lifecycle as lifecycle_interface


class DropConfigCacheCollections(interface.Hook):
    """Randomly drop entries of config.cache.collections in shards."""

    DESCRIPTION = (
        "DropConfigCacheCollections, randomly drops entries of config.cache.collections in shards."
    )

    IS_BACKGROUND = True

    # The hook does not affect the fixture itself.
    STOPS_FIXTURE = False

    def __init__(
        self,
        hook_logger,
        fixture,
        is_fsm_workload=False,
        auth_options=None,
    ):
        """Initialize DropConfigCacheCollections.

        Args:
            hook_logger: the logger instance for this hook.
            fixture: the target fixture (replica sets or a sharded cluster).
            is_fsm_workload: Whether the hook is running as an FSM workload is executing
            auth_options: dictionary of auth options.
        """
        interface.Hook.__init__(self, hook_logger, fixture, DropConfigCacheCollections.DESCRIPTION)

        self._fixture = fixture

        self._thread = None

        self._auth_options = auth_options

        # The action file names need to match the same construction as found in
        # jstests/concurrency/fsm_libs/resmoke_runner.js.
        dbpath_prefix = fixture.get_dbpath_prefix()

        # When running an FSM workload, we use the file-based lifecycle protocol
        # in which a file is used as a form of communication between the hook and
        # the FSM workload to decided when the hook is allowed to run.
        if is_fsm_workload:
            # Each hook uses a unique set of action files - the uniqueness is brought
            # about by using the hook's name as a suffix.
            self.__action_files = lifecycle_interface.ActionFiles._make(
                [
                    os.path.join(dbpath_prefix, field + "_" + self.__class__.__name__)
                    for field in lifecycle_interface.ActionFiles._fields
                ]
            )
        else:
            self.__action_files = None

    def before_suite(self, test_report):
        """Before suite."""
        if self.__action_files is not None:
            lifecycle = lifecycle_interface.FileBasedThreadLifecycle(self.__action_files)
        else:
            lifecycle = lifecycle_interface.FlagBasedThreadLifecycle()

        self._thread = _DropConfigCacheCollectionsThread(
            self.logger,
            lifecycle,
            self._fixture,
            self._auth_options,
        )
        self.logger.info("Starting the drop config.cache.collections thread.")
        self._thread.start()

    def after_suite(self, test_report, teardown_flag=None):
        """After suite."""
        self.logger.info("Stopping the drop config.cache.collections thread.")
        self._thread.stop()
        self.logger.info("drop config.cache.collections thread stopped.")

    def before_test(self, test, test_report):
        """Before test."""
        # Enable the failpoint in all shard nodes.
        try:
            for shard in self._fixture.shards:
                for node in shard.nodes:
                    client = node.mongo_client()
                    client.admin.command(
                        {
                            "configureFailPoint": "noCacheMetadataTassert",
                            "mode": "alwaysOn",
                        }
                    )
        except pymongo.errors.OperationFailure as err:
            msg = (
                "Unable to enable failpoint noCacheMetadataTassert on mongod on port "
                + f"{node.port}: {err.args[0]}"
            )
            self.logger.exception(msg)
            raise errors.ServerFailure(msg)

        self.logger.info("Resuming the drop config.cache.collections thread.")
        self._thread.pause()
        self._thread.resume()

    def after_test(self, test, test_report):
        """After test."""
        self.logger.info("Pausing the drop config.cache.collections thread.")
        self._thread.pause()
        self.logger.info("Paused the drop config.cache.collections thread.")

        # Drop all entries of config.cache.collections except config.system.sessions,
        # so that subsequent tests don't have "stale" entries from older tests and the
        # thread doesn't waste time deleting entries that aren't going to be used.
        for shard in self._fixture.shards:
            try:
                shard.mongo_client().config.cache.collections.delete_many(
                    {"_id": {"$ne": "config.system.sessions"}}
                )
            except pymongo.errors.PyMongoError as err:
                self.logger.exception(
                    "DropConfigCacheCollections: exception when deleting all entries of "
                    + f"config.cache.collections in shard {shard.replset_name}: {err}"
                )


class _DropConfigCacheCollectionsThread(threading.Thread):
    def __init__(
        self,
        logger,
        drop_lifecycle,
        fixture,
        auth_options=None,
    ):
        """Initialize _DropConfigCacheCollectionsThread."""
        threading.Thread.__init__(self, name="DropConfigCacheCollectionsThread")
        self.daemon = True
        self.logger = logger
        self.__lifecycle = drop_lifecycle
        self._fixture = fixture
        self._auth_options = auth_options

        if not isinstance(self._fixture, shardedcluster.ShardedClusterFixture):
            msg = "Can only drop entries in config.cache.collections for sharded cluster fixtures."
            self.logger.error(msg)
            raise errors.TestFailure(msg)

        self._last_exec = time.time()
        # Event set when the thread has been stopped using the 'stop()' method.
        self._is_stopped_evt = threading.Event()
        # Event set when the thread is .
        self._is_idle_evt = threading.Event()
        self._is_idle_evt.set()

    def run(self):
        """Execute the thread."""
        try:
            while True:
                self._is_idle_evt.set()

                permitted = self.__lifecycle.wait_for_action_permitted()
                if not permitted:
                    break

                self._is_idle_evt.clear()

                # Choose a random shard and then a random entry from config.cache.collections,
                # then drop that entry.
                shards = self._fixture.shards
                random_shard = random.choice(shards)
                primary_conn = random_shard.mongo_client()

                try:
                    all_entries = primary_conn.config.cache.collections.find({}).to_list()
                    if all_entries:
                        random_entry = random.choice(all_entries)
                        primary_conn.config.cache.collections.delete_one(
                            {"_id": random_entry["_id"]}
                        )
                        self.logger.info(
                            f'Deleted "{random_entry["_id"]}" from config.cache.collections in '
                            + f"shard {random_shard.replset_name}"
                        )
                except pymongo.errors.PyMongoError as err:
                    self.logger.exception(
                        f"DropConfigCacheCollections Thread: exception on find or delete: {err}"
                    )

                found_idle_request = self.__lifecycle.poll_for_idle_request()
                if found_idle_request:
                    self.__lifecycle.send_idle_acknowledgement()
                    continue

                # Choose a random number of seconds to wait, between 0 and 8.
                wait_secs = random.randint(0, 8)
                self.__lifecycle.wait_for_action_interval(wait_secs)
        except Exception:
            # Proactively log the exception when it happens so it will be
            # flushed immediately.
            self.logger.exception("DropConfigCacheCollections Thread threw exception")
            # The event should be signaled whenever the thread is not performing stepdowns.
            self._is_idle_evt.set()

    def stop(self):
        """Stop the thread."""
        self.__lifecycle.stop()
        self._is_stopped_evt.set()
        # Unpause to allow the thread to finish.
        self.resume()
        self.join()

    def pause(self):
        """Pause the thread."""
        self.__lifecycle.mark_test_finished()

        # Wait until we are no longer executing stepdowns.
        self._is_idle_evt.wait()
        # Check if the thread is alive in case it has thrown an exception while running.
        self._check_thread()

    def resume(self):
        """Resume the thread."""
        self.__lifecycle.mark_test_started()

    def _wait(self, timeout):
        # Wait until stop or timeout.
        self._is_stopped_evt.wait(timeout)

    def _check_thread(self):
        if not self.is_alive():
            msg = "The drop config.cache.collections thread is not running."
            self.logger.error(msg)
            raise errors.ServerFailure(msg)
