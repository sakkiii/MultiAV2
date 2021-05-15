import threading
from sys import exc_info
from promise import Promise


# starts the executor function non blocking in a seperate thread
class ThreadedPromise(Promise):
    def __init__(self, executor=None, scheduler=None):
        Promise.__init__(self, executor, scheduler)
        self.thread = threading.Thread()

    def wait(self):
        try:
            self.join()
        except Exception as e:
            print(e)

    def _resolve_from_executor(self, executor):
        """
        # type: (Callable[[Callable[[T], None], Callable[[Exception], None]], None]) -> None
        # self._capture_stacktrace()
        """
        synchronous = True

        def resolve(value):
            """
            # type: (T) -> None
            """
            self._resolve_callback(value)

        def reject(reason, traceback=None):
            """# type: (Exception, TracebackType) -> None"""
            self._reject_callback(reason, synchronous, traceback)

        error = None
        traceback = None
        try:
            self.thread = threading.Thread(target=executor, args=(resolve, reject))
            self.thread.start()
        except Exception as e:
            traceback = exc_info()[2]
            error = e

        synchronous = False

        if error is not None:
            self._reject_callback(error, True, traceback)
