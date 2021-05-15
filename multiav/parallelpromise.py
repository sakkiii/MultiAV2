from sys import exc_info
from threading import Thread, Event
from promise import Promise

# These are the potential states of a promise
STATE_PENDING = -1
STATE_REJECTED = 0
STATE_FULFILLED = 1


# starts the executor function non blocking in a seperate thread
class ParallelPromise(Promise):
    def __init__(self, executor=None, scheduler=None):
        Promise.__init__(self, executor, scheduler)

    def wait(self, timeout=None):
        e = Event()

        def on_resolve_or_reject(_):
            e.set()

        self._then(on_resolve_or_reject, on_resolve_or_reject)
        waited = e.wait(timeout)
        if not waited:
            raise Exception("Timeout")

    def _resolve_from_executor(self, executor):
        """
        # type: (Callable[[Callable[[T], None], Callable[[Exception], None]], None]) -> None
        # self._capture_stacktrace()
        """
        synchronous = True

        def resolve(value):
            """# type: (T) -> None"""
            self._resolve_callback(value)

        def reject(reason, traceback=None):
            """# type: (Exception, TracebackType) -> None"""
            self._reject_callback(reason, synchronous, traceback)

        error = None
        traceback = None
        try:
            self.thread = Thread(target=executor, args=(resolve, reject))
            self.thread.daemon = True
            self.thread.start()
        except Exception as e:
            traceback = exc_info()[2]
            error = e

        synchronous = False

        if error is not None:
            self._reject_callback(error, True, traceback)
