"""Thread lifecycle management for periodic hooks such as ContinuousStepdown."""

import collections
import os.path
import threading
import time

import buildscripts.resmokelib.utils.filesystem as fs
from buildscripts.resmokelib import errors

ActionFiles = collections.namedtuple("ActionFiles", ["permitted", "idle_request", "idle_ack"])


class HookThreadState:
    """Track background hook thread state and failures."""

    _IDLE = "idle"
    _RUNNING = "running"
    _STOPPING = "stopping"
    _STOPPED = "stopped"
    _FAILED = "failed"

    def __init__(self):
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._state = self._IDLE
        self._phase = "init"
        self._failure = None

    def mark_idle(self, phase="idle"):
        with self._lock:
            self._state = self._IDLE
            self._phase = phase
            self._cond.notify_all()

    def mark_running(self, phase):
        with self._lock:
            self._state = self._RUNNING
            self._phase = phase
            self._cond.notify_all()

    def mark_stopping(self, phase="stopping"):
        with self._lock:
            self._state = self._STOPPING
            self._phase = phase
            self._cond.notify_all()

    def mark_stopped(self, phase="stopped"):
        with self._lock:
            self._state = self._STOPPED
            self._phase = phase
            self._cond.notify_all()

    def mark_failed(self, exception, phase):
        with self._lock:
            self._state = self._FAILED
            self._phase = phase
            self._failure = exception
            self._cond.notify_all()

    def set_phase(self, phase):
        with self._lock:
            self._phase = phase
            self._cond.notify_all()

    def wait_until_idle(self, timeout_secs, thread_name):
        deadline = time.time() + timeout_secs
        with self._lock:
            while self._state not in (self._IDLE, self._FAILED, self._STOPPED):
                remaining = deadline - time.time()
                if remaining <= 0:
                    raise errors.ServerFailure(
                        f"Timed out waiting for {thread_name} thread to become idle; "
                        f"state={self._state}, phase={self._phase}, timeout={timeout_secs}s."
                    )
                self._cond.wait(remaining)

    def assert_healthy(self, is_alive, thread_name, allow_stopped=False):
        with self._lock:
            if self._failure is not None:
                raise errors.ServerFailure(
                    f"{thread_name} thread failed during phase '{self._phase}': {self._failure}"
                ) from self._failure
            if allow_stopped and self._state == self._STOPPED:
                return
            if not is_alive:
                raise errors.ServerFailure(
                    f"The {thread_name} thread is not running "
                    f"(state={self._state}, phase={self._phase})."
                )

    def describe(self):
        with self._lock:
            return self._state, self._phase


class FlagBasedThreadLifecycle(object):
    """Class for managing the various states of a continuously running hook thread.

    The job thread alternates between calling mark_test_started() and mark_test_finished(). The
    hook thread is allowed to perform actions at any point between these two calls. Note that
    the job thread synchronizes with the hook thread outside the context of this object to know
    it isn't in the process of running an action.
    """

    _TEST_STARTED_STATE = "start"
    _TEST_FINISHED_STATE = "finished"

    def __init__(self):
        """Initialize the FlagBasedThreadLifecycle instance."""
        self.__lock = threading.Lock()
        self.__cond = threading.Condition(self.__lock)

        self.__test_state = self._TEST_FINISHED_STATE
        self.__should_stop = False

    def mark_test_started(self):
        """Signal to the hook thread that a new test has started.

        This function should be called during before_test(). Calling it causes the
        wait_for_action_permitted() function to no longer block and to instead return true.
        """
        with self.__lock:
            self.__test_state = self._TEST_STARTED_STATE
            self.__cond.notify_all()

    def mark_test_finished(self):
        """Signal to the hook thread that the current test has finished.

        This function should be called during after_test(). Calling it causes the
        wait_for_action_permitted() function to block until mark_test_started() is called again.
        """
        with self.__lock:
            self.__test_state = self._TEST_FINISHED_STATE
            self.__cond.notify_all()

    def stop(self):
        """Signal to the hook thread that it should exit.

        This function should be called during after_suite(). Calling it causes the
        wait_for_action_permitted() function to no longer block and to instead return false.
        """
        with self.__lock:
            self.__should_stop = True
            self.__cond.notify_all()

    def wait_for_action_permitted(self):
        """Block until actions are permitted, or until stop() is called.

        :return: true if actions are permitted, and false if steps are not permitted.
        """
        with self.__lock:
            while not self.__should_stop:
                if self.__test_state == self._TEST_STARTED_STATE:
                    return True

                self.__cond.wait()

        return False

    def wait_for_action_interval(self, timeout):
        """Block for 'timeout' seconds, or until stop() is called."""
        with self.__lock:
            self.__cond.wait(timeout)

    def poll_for_idle_request(self):  # noqa: D205,D400
        """Return true if the hook thread should continue running actions, or false if it
        should temporarily stop running actions.
        """
        with self.__lock:
            return self.__test_state == self._TEST_FINISHED_STATE

    def send_idle_acknowledgement(self):
        """No-op.

        This method exists so this class has the same interface as FileBasedThreadLifecycle.
        """
        pass


class FileBasedThreadLifecycle(object):
    """Class for managing the various states of the hook thread using files.

    Unlike in the FlagBasedThreadLifecycle class, the job thread alternating between calls to
    mark_test_started() and mark_test_finished() doesn't automatically grant permission for the
    hook thread to perform actions. Instead, the test will part-way through allow actions to
    be performed and then will part-way through disallow actions from continuing to be performed.

    See jstests/concurrency/fsm_libs/resmoke_runner.js for the other half of the file-base protocol.

        Python inside of resmoke.py                     JavaScript inside of the mongo shell
        ---------------------------                     ------------------------------------

                                                        FSM workload starts.
                                                        Call $config.setup() function.
                                                        Create "permitted" file.

        Wait for "permitted" file to be created.

        Action runs.
        Check if "idle_request" file exists.

        Action runs.
        Check if "idle_request" file exists.

                                                        FSM workload threads all finish.
                                                        Create "idle_request" file.

        Action runs.
        Check if "idle_request" file exists.
        Create "idle_ack" file.
        (No more actions run.)

                                                        Wait for "idle_ack" file.
                                                        Call $config.teardown() function.
                                                        FSM workload finishes.

    Note that the job thread still synchronizes with the hook thread outside the context of this
    object to know it isn't in the process of running an action.
    """

    def __init__(self, action_files):
        """Initialize the FileBasedThreadLifecycle instance."""
        self.__action_files = action_files

        self.__lock = threading.Lock()
        self.__cond = threading.Condition(self.__lock)

        self.__should_stop = False

    def mark_test_started(self):
        """Signal to the hook thread that a new test has started.

        This function should be called during before_test(). Calling it does nothing because
        permission for running actions is given by the test itself writing the "permitted" file.
        """
        pass

    def mark_test_finished(self):
        """Signal to the hook thread that the current test has finished.

        This function should be called during after_test(). Calling it causes the
        wait_for_action_permitted() function to block until the next test gives permission for
        running actions.
        """
        # It is possible something went wrong during the test's execution and prevented the
        # "permitted" and "idle_request" files from being created. We therefore don't consider it an
        # error if they don't exist after the test has finished.
        fs.remove_if_exists(self.__action_files.permitted)
        fs.remove_if_exists(self.__action_files.idle_request)
        fs.remove_if_exists(self.__action_files.idle_ack)

    def stop(self):
        """Signal to the hook thread that it should exit.

        This function should be called during after_suite(). Calling it causes the
        wait_for_action_permitted() function to no longer block and to instead return false.
        """
        with self.__lock:
            self.__should_stop = True
            self.__cond.notify_all()

    def wait_for_action_permitted(self):
        """Block until actions are permitted, or until stop() is called.

        :return: true if actions are permitted, and false if steps are not permitted.
        """
        with self.__lock:
            while not self.__should_stop:
                if os.path.isfile(self.__action_files.permitted):
                    return True

                # Wait a little bit before checking for the "permitted" file again.
                self.__cond.wait(0.1)

        return False

    def wait_for_action_interval(self, timeout):
        """Block for 'timeout' seconds, or until stop() is called."""
        with self.__lock:
            self.__cond.wait(timeout)

    def poll_for_idle_request(self):  # noqa: D205,D400
        """Return true if the hook thread should continue running actions, or false if it
        should temporarily stop running actions.
        """
        if os.path.isfile(self.__action_files.idle_request):
            with self.__lock:
                return True

        return False

    def send_idle_acknowledgement(self):
        """Signal to the running test that the hook thread won't continue to run actions."""

        with open(self.__action_files.idle_ack, "w"):
            pass

        # We remove the "permitted" file to revoke permission for the hook thread to continue
        # performing actions.
        fs.remove_if_exists(self.__action_files.permitted)
