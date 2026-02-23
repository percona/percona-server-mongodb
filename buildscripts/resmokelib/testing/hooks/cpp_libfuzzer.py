"""Test hook that does maintainence tasks for libfuzzer tests."""

from buildscripts.resmokelib.testing.hooks import interface


class LibfuzzerHook(interface.Hook):
    """Merges inputs after a fuzzer run."""

    DESCRIPTION = "Merges inputs after a fuzzer run"

    IS_BACKGROUND = False

    def __init__(self, hook_logger, fixture):
        """Initialize the ContinuousStepdown.

        Args:
            hook_logger: the logger instance for this hook.
            fixture: the target fixture.
        """
        interface.Hook.__init__(self, hook_logger, fixture, LibfuzzerHook.DESCRIPTION)

        self._fixture = fixture

    def before_suite(self, test_report):
        """Before suite."""
        pass

    def after_suite(self, test_report, teardown_flag=None):
        """After suite."""
        pass

    def before_test(self, test, test_report):
        """Before test."""
        pass

    def after_test(self, test, test_report):
        """After test."""
        pass  # this will eventually be used to generate code coverage
