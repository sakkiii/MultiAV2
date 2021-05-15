from promise import Promise


# -----------------------------------------------------------------------
class MultiActionPromise(Promise):
    def __init__(self, engine_promises=None):
        Promise.__init__(self)

        self._engine_promises = dict()
        self._engine_name_lookup = dict()
        if engine_promises is not None:
            for engine, engine_promise in engine_promises.items():
                engine_promise.then(self._did_all_engine_promises_run, self._did_all_engine_promises_run)
                self._engine_promises[engine] = engine_promise
                self._engine_name_lookup[engine.container_name] = engine_promise

    def _did_all_engine_promises_run(self, res):
        not_pending = True
        failed_promises = []
        for engine, engine_promise in self._engine_promises.items():
            not_pending &= engine_promise._state != -1
            if engine_promise._state == 0:
                failed_promises.append(engine.name)

        if not_pending:
            if len(failed_promises) == 0:
                self.do_resolve("All done")
            else:
                self.do_reject(Exception("Failed: " + ", ".join(failed_promises)))

    def get_engine_promise(self, engine):
        if isinstance(engine, str):
            return self._engine_name_lookup[engine]
        else:
            return self._engine_name_lookup[engine.name]

    def engine_then(self, did_fulfill=None, did_reject=None):
        # print(self._engine_promises)
        for engine, engine_promise in self._engine_promises.items():
            engine_promise.then(did_fulfill, did_reject)

        return self

    def get_scanning_engines(self):
        return list(self._engine_promises)
