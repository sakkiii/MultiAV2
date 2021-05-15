import threading
import json

from rwlock import RWLock
from promise import Promise
from queue import Queue


class PromiseExecutorPool:
    def __init__(self, num_threads, workers_maxsize = 0):
        self.workers_maxsize = workers_maxsize
        self.tasks = Queue()
        self.min_threads = num_threads
        self.workers = []

        self._worker_lock = RWLock()
        self._tasks_lock = RWLock()

        with self._worker_lock.writer_lock:
            for _ in range(num_threads):
                self.workers.append(Worker(self.tasks, self._stop_worker_callback))

    '''def find_workers_to_remove(self):
        with self._worker_lock.reader_lock:
            with self._tasks_lock.reader_lock:
                queue_size= self.get_queue_size()
                if queue_size >= self.get_worker_amount():
                    return []

                idle_workers = list(filter(lambda w: not w.working, self.workers))
                total_idle_workers = len(idle_workers)
                max_removalble_workers = self.get_worker_amount() - self.min_threads

                if total_idle_workers <= max_removalble_workers:
                    return idle_workers[:total_idle_workers]

                return idle_workers[:max_removalble_workers]'''

    def add_worker(self, amount=1):
        if amount <= 0:
            return

        if self.workers_maxsize <= 0:
            return

        with self._worker_lock.writer_lock:
            amount = amount if len(self.workers) + amount <= self.workers_maxsize else self.workers_maxsize - len(self.workers)

            for _ in range(amount):
                self.workers.append(Worker(self.tasks, self._stop_worker_callback))

        print("created {0} new worker(s)".format(amount))

    def remove_workers(self, amount):
        with self._worker_lock.writer_lock:
            active_workers = self._get_active_workers()

            if amount > len(active_workers):
                amount = len(active_workers)

            workers_to_remove = active_workers[-amount:]

            for worker in workers_to_remove:
                worker.mark_for_removal()

        print("marked {0} worker(s) for removal".format(amount))

    def _get_active_workers(self):
        with self._worker_lock.reader_lock:
            return list(filter(lambda worker: not worker.is_marked_for_removal(), self.workers))

    def _stop_worker_callback(self, worker):
        with self._worker_lock.writer_lock:
            self.workers.remove(worker)

    def get_queue_size_including_active_workers(self):
        with self._tasks_lock.reader_lock:
            return self.tasks.qsize() + len(self.get_working_workers())

    def get_queue_size(self):
        with self._tasks_lock.reader_lock:
            return self.tasks.qsize()

    def get_working_workers(self):
        return list(filter(lambda worker: worker.is_working(), self.workers))

    def get_worker_amount(self):
        return len(self._get_active_workers())

    def add_task(self, func, *args, **kargs):
        """ Add a task to the queue """
        with self._tasks_lock.writer_lock:
            print("adding task to queue")
            p = Promise(lambda resolve, reject: self.tasks.put((resolve, reject, func, args, kargs)))

        return p

    def map(self, func, args_list):
        """ Add a list of tasks to the queue """
        promises = []
        for args in args_list:
            promises.append(self.add_task(func, args))

        return promises

    def wait_completion(self):
        """ Wait for completion of all the tasks in the queue """
        self.tasks.join()


class Worker(threading.Thread):
    """ Thread executing tasks from a given tasks queue """
    def __init__(self, tasks, stop_callback=None):
        threading.Thread.__init__(self)
        self.tasks = tasks
        self.daemon = True
        self._lock = RWLock()
        self.working = False
        self.marked_for_removal = False
        self._stop_callback = stop_callback
        self.start()

    def run(self):
        while True:
            try:
                resolve, reject, func, args, kargs = self.tasks.get(False, 1)

                with self._lock.writer_lock:
                    self.working = True

                try:
                    # run task and resolve with return value
                    # will execute the function doing the http request. it's therefor usable for all plugins
                    res = func(*args, **kargs)
                    resolve(json.dumps(res))
                except Exception as e:
                    # reject promise with exception
                    reject(e)

                finally:
                    with self._lock.writer_lock:
                        self.working = False

                    # Mark this task as done, whether the promise is rejected or resolved
                    self.tasks.task_done()
            except Exception as e:
                # get timeout
                pass
            finally:
                with self._lock.reader_lock:
                    if self.marked_for_removal:
                        print("stopping thread as marked for removal")
                        if self._stop_callback is not None:
                            self._stop_callback(self)
                        return

    def mark_for_removal(self):
        with self._lock.writer_lock:
            self.marked_for_removal = True

    def is_marked_for_removal(self):
        with self._lock.reader_lock:
            return self.marked_for_removal

    def is_working(self):
        with self._lock.reader_lock:
            return self.working
