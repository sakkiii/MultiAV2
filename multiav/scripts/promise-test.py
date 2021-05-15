import time
import threading
import sys
import uuid

try:
    from timer_cm import Timer
except ImportError:
    print("Run cmd -> pip install timer-cm")
from promise import Promise
from rwlock import RWLock

IS_PY2 = sys.version_info < (3, 0)

if IS_PY2:
    from Queue import Queue
else:
    from queue import Queue


class Worker(threading.Thread):
    """ Thread executing tasks from a given tasks queue """

    def __init__(self, tasks):
        threading.Thread.__init__(self)
        self.tasks = tasks
        self.daemon = True
        self.working = False
        self.marked_for_removal = False
        self.start()

    def run(self):
        while True:
            self.working = False
            try:
                resolve, reject, func, args, kargs = self.tasks.get(False, 1)
                self.working = True

                try:
                    # run task and resolve with return value
                    # will execute the function doing the http request. it's therefor usable for all plugins
                    resolve(func(*args, **kargs))
                except Exception as e:
                    # reject promise with exception
                    reject(e)

                finally:
                    # Mark this task as done, whether the promise is rejected or resolved
                    self.tasks.task_done()
            except Exception as e:
                # get timeout
                pass
            finally:
                if self.marked_for_removal:
                    print("stopping thread as marked for removal")
                    return

    def mark_for_removal(self):
        self.marked_for_removal = True


class ThreadPool:
    """ Pool of threads consuming tasks from a queue """

    def __init__(self, num_threads, workers_maxsize=0):
        self.workers_maxsize = workers_maxsize
        self.tasks = Queue()
        self.min_threads = num_threads
        self.workers = []

        for _ in range(num_threads):
            self.workers.append(Worker(self.tasks))

    def _find_workers_to_remove(self):
        queue_size = self.get_queue_size()
        if queue_size >= self.get_worker_amount():
            return []

        idle_workers = list(filter(lambda w: not w.working, self.workers))
        total_idle_workers = len(idle_workers)
        max_removalble_workers = self.get_worker_amount() - self.min_threads

        if total_idle_workers <= max_removalble_workers:
            return idle_workers[:total_idle_workers]

        return idle_workers[:max_removalble_workers]

    def add_worker(self, amount=1):
        if self.workers_maxsize <= 0:
            return

        if amount <= 0:
            return

        amount = amount if len(self.workers) + amount <= self.workers_maxsize else self.workers_maxsize - len(
            self.workers)
        for _ in range(amount):
            self.workers.append(Worker(self.tasks))

        if amount != 0:
            print("created {0} new worker(s)".format(amount))

    def remove_worker(self, workers):
        if self.workers_maxsize <= 1:
            return

        if len(workers) <= 0:
            return

        for worker in workers:
            worker.mark_for_removal()
            self.workers.remove(worker)

        print("marked {0} worker(s) for removal".format(len(workers)))

    def get_queue_size(self):
        return self.tasks.qsize()

    def get_worker_amount(self):
        return len(self.workers)

    def add_task(self, func, *args, **kargs):
        """ Add a task to the queue """
        print("adding task to queue")
        p = Promise(lambda resolve, reject: self.tasks.put((resolve, reject, func, args, kargs)))

        # set a post task
        p.then(
            lambda res: self.remove_worker(self._find_workers_to_remove()),
            lambda res: self.remove_worker(self._find_workers_to_remove()))
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


class Strategy:
    def _scan_internal(self, strategy_name, engine, file_buffer, duration):
        self._pre_scan(engine, file_buffer)

        print("{2} scanning {0} using {1}".format(file_buffer, engine.name, strategy_name))
        time.sleep(duration)

        self._post_scan(engine, file_buffer)
        return file_buffer + " OK"

    def _pre_scan(self, engine, file_buffer):
        print("_pre_scan")

    def _post_scan(self, engine, file_buffer):
        print("_post_scan")

    def scan(self, engine, file_buffer, duration):
        pass


class LocalDockerStrategy(Strategy):
    def __init__(self, num_threads):
        # use thread pool to handle overload without scaling
        self.pool = ThreadPool(num_threads)
        print("LocalDockerStrategy: initialized thread pool using {0} threads".format(num_threads))

    def scan(self, engine, file_buffer, duration):
        scan_promise = self.pool.add_task(self._scan_internal, "LocalDockerStrategy", engine, file_buffer, duration)
        # return Promise.promisify(self._scan_internal)(, engine, file_buffer, duration)
        return scan_promise

    def wait_completion(self):
        self.pool.wait_completion()


class JustRunLocalDockerStrategy(Strategy):
    def __init__(self):
        self.threads = []

    def _scan_promise_wrapper(self, resolve, reject, engine, file_buffer, duration):
        def fn():
            try:
                resolve(self._scan_internal("JustRunLocalDockerStrategy", engine, file_buffer, duration))
            except Exception as e:
                reject(e)
            finally:
                # make sure to remove thread from running list
                self.threads.remove(thread)

        thread = threading.Thread(target=fn)
        thread.start()
        self.threads.append(thread)

    def scan(self, engine, file_buffer, duration):
        scan_promise = Promise(
            lambda resolve, reject: self._scan_promise_wrapper(resolve, reject, engine, file_buffer, duration)
        )
        return scan_promise

    def wait(self, promise, timeout=None):
        e = threading.Event()

        def on_resolve_or_reject(_):
            e.set()

        promise._then(on_resolve_or_reject, on_resolve_or_reject)
        waited = e.wait(timeout)
        if not waited:
            raise Exception("Timeout")


class DockerMachine():
    def __init__(self, max_containers_per_machine, max_scans_per_container):
        self.id = str(uuid.uuid1())
        self.ip = []
        self.networks = []
        self.containers = []
        self._lock = RWLock()
        self.max_scans_per_container = max_scans_per_container
        self.max_containers_per_machine = max_containers_per_machine

    def _create_machine(self):
        pass

    def _create_container(self, engine):
        with self._lock.writer_lock:
            container = DockerContainer([10, 10, 20, 10], 8080, engine, self.max_scans_per_container, self)
            self.containers.append(container)
            print("Created docker container {0} with engine: {1} on machine {2}".format(container.id,
                                                                                        container.engine.name, self.id))
            return container

    def try_do_scan(self, engine, report_id):
        if self.max_scans_per_container == 1:
            # do we have the resources to add a new container?
            with self._lock.reader_lock:
                if len(self.containers) == self.max_containers_per_machine:
                    return None, None

            with self._lock.writer_lock:
                container = self._create_container(engine)
                if not container.try_do_scan(report_id):
                    return None, None

                return container, self

        # multiple scans per container are allowed
        with self._lock.reader_lock:
            if len(self.containers) != 0:
                # check if we can use a running container
                for container in self.containers:
                    if container.engine == engine and container.try_do_scan(report_id):
                        print("using container for multiple scans")
                        return container, self

            # create a new container for scan
        with self._lock.writer_lock:
            container = self._create_container(engine)
            if not container.try_do_scan(report_id):
                return None, None

            return container, self

    def remove_scan_from_container_by_ip(self, ip, report_id):
        for container in self.containers:
            if container.ip == ip:
                container.remove_scan(report_id)

                if len(container.scans) == 0:
                    self.containers.remove(container)
                    print("removed container {0} with engine {1} from machine {2}".format(container.id,
                                                                                          container.engine.name,
                                                                                          self.id))


class DockerContainer():
    def __init__(self, ip, port, engine, max_scans_per_container, machine):
        self.id = str(uuid.uuid1())
        self.ip = ip
        self.port = port
        self.engine = engine
        self.scans = []
        self._lock = RWLock()
        self._machine = machine
        self.max_scans_per_container = max_scans_per_container

    def _run_command(self, command):
        cmd = "eval $(docker-machine env {0}); {1}; eval $(docker-machine env -u)".format(self._machine.id, command)
        # output = check_output(cmd.split[" "])
        print(cmd)

    def _create_continer(self):
        pass

    def try_do_scan(self, report_id):
        with self._lock.reader_lock:
            if len(self.scans) >= self.max_scans_per_container:
                return False

        with self._lock.writer_lock:
            self.scans.append(report_id)
            return True

    def remove_scan(self, report_id):
        with self._lock.reader_lock:
            if not report_id in self.scans:
                return False

        with self._lock.writer_lock:
            self.scans.remove(report_id)
            return True


class AutoScaleDockerStrategy(Strategy):
    def __init__(self, max_machines, max_containers_per_machine, max_scans_per_container):
        # use thread pool to handle overload when maxed out scaling => tasks will stay in queue
        min_threads = max_containers_per_machine * max_scans_per_container
        max_threads = max_machines * max_containers_per_machine * max_scans_per_container
        self.pool = ThreadPool(min_threads, max_threads)
        print("AutoScaleDockerStrategy: initialized thread pool using {0} threads (max: {1})".format(min_threads,
                                                                                                     max_threads))

        self._machines = []
        self.max_machines = max_machines
        self.max_containers_per_machine = max_containers_per_machine
        self.max_scans_per_container = max_scans_per_container
        print(
            "AutoScaleDockerStrategy: initialized using max_machines: {0} max_containers_per_machine: {1} max_scans_per_container: {2}".format(
                max_machines, max_containers_per_machine, max_scans_per_container))

    def _pre_scan(self, engine, file_buffer):
        # call scan now to get a machine and container for the scan
        container = self._get_container_for_scan(engine, file_buffer)

        # set container ip for engine
        # engine.set_endpoints_from_container(container)
        engine.ip = container.ip
        self._print_machine_stats()

    def _post_scan(self, engine, file_buffer):
        # remove scan from container
        ip = engine.ip
        self._remove_scan_from_container_by_ip(ip, file_buffer)
        self._print_machine_stats()

    def _print_machine_stats(self):
        for m in self._machines:
            engines = ",".join(list(map(lambda c: c.engine.name, m.containers)))
            print("--- STATS: Machine {0} Containers {1} ({2})".format(m.id, len(m.containers), engines))

    def _remove_scan_from_container_by_ip(self, ip, report_id):
        removable_machines = []
        machines_with_free_spots = []
        for m in self._machines:
            m.remove_scan_from_container_by_ip(ip, report_id)
            if len(m.containers) == 0:
                removable_machines.append(m)
            elif len(m.containers) < self.max_containers_per_machine:
                machines_with_free_spots.append(m)

        if len(removable_machines) > 1 or len(machines_with_free_spots) != 0:
            if len(removable_machines):
                # remove all but one machine (let it run in case we need a spot)
                for m in removable_machines[1:]:
                    self._shutdown_machine(m)
                    removable_machines.remove(m)

            if len(machines_with_free_spots) and self.pool.get_queue_size() == 0:
                # if there's free spots on the running machines and the queue is empty, remove the empty one anyway
                for m in removable_machines:
                    self._shutdown_machine(m)

    def _create_machine(self):
        if len(self._machines) + 1 > self.max_machines:
            return None

        machine = DockerMachine(self.max_containers_per_machine, self.max_scans_per_container)
        self._machines.append(machine)
        print("starting new machine {0}".format(machine.id))
        return machine

    def _shutdown_machine(self, machine):
        self._machines.remove(machine)
        print("shutting down machine {0}!".format(machine.id))

    def _get_container_for_scan(self, engine, report_id):
        container = None
        machine = None

        # search for a free spot on a running machine
        for m in self._machines:
            container, machine = m.try_do_scan(engine, report_id)
            if container is not None:
                print("found container {0} on machine {1}".format(container.id, machine.id))
                break

        if container is None:
            m = self._create_machine()
            container, machine = m.try_do_scan(engine, report_id)
            if container is None:
                raise Exception("Could not get a container on a newly created machine. something's wrong...")

            print("found container {0} on machine {1}".format(container.id, machine.id))

        return container

    def scan(self, engine, file_buffer, duration):
        scan_promise = self.pool.add_task(self._scan_internal, "AutoScaleDockerStrategy", engine, file_buffer, duration)

        # increase workforce if required and possible
        if self.pool.get_queue_size() > self.pool.get_worker_amount():
            # the docker container
            # self.create_container(engine)
            # the caller thread
            self.pool.add_worker()

        return scan_promise

    def wait_completion(self):
        self.pool.wait_completion()


# this is basically a promise for the whole scan and for all subscans. use engine_then to setup the subtask callbacks
class ScanPromise(Promise):
    def __init__(self):
        Promise.__init__(self)
        self.engine_promises = []

    def _did_all_engine_promises_run(self, res):
        ret = True
        all_fulfilled = True
        for engine_promise in self.engine_promises:
            ret &= engine_promise._state != -1
            all_fulfilled &= engine_promise._state == 1

        if ret:
            if all_fulfilled:
                self.do_resolve("All done")
            else:
                self.do_reject("Some failed")

    def engine_then(self, did_fulfill=None, did_reject=None):
        for engine_promise in self.engine_promises:
            engine_promise.then(did_fulfill, did_reject)
            engine_promise.then(self._did_all_engine_promises_run, self._did_all_engine_promises_run)

        return self


class Engine():
    def __init__(self, name, duration, ip):
        self.name = name
        self.ip = ip
        self.duration = duration


class MultiScanner:
    def __init__(self, strategy):
        self.engines = [Engine("sophos", 4, list()), Engine("defender", 2, list()), Engine("clam", 1, list()),
                        Engine("ikarus", 2, list()), Engine("trendmicro", 3, list()), Engine("kaspersky", 2, list())]

        if isinstance(strategy, Strategy):
            self.docker_strategy = strategy
        else:
            print("error invalid strategy")

    def scan(self, file_buffer):
        scan_promise = ScanPromise()

        for engine in self.engines:
            engine_promise = self.docker_strategy.scan(engine, file_buffer, engine.duration)
            scan_promise.engine_promises.append(engine_promise)

        return scan_promise


if __name__ == "__main__":
    with Timer('Execution time') as timer:
        # scanner
        local_docker_strategy = LocalDockerStrategy(2)
        just_run_docker_strategy = JustRunLocalDockerStrategy()

        auto_scale_strategy = AutoScaleDockerStrategy(3, 6, 1)

        ms = MultiScanner(auto_scale_strategy)

        # add tasks
        t1 = ms.scan("task 1").engine_then(
            lambda res: print("did_fulfill: " + res),
            lambda res: print("did_reject: " + res)
        ).then(
            lambda res: print("DONE did_fulfill: " + res),
            lambda res: print("DONE did_reject: " + res)
        )

        t2 = ms.scan("task 2").engine_then(
            lambda res: print("did_fulfill: " + res),
            lambda res: print("did_reject: " + res)
        ).then(
            lambda res: print("DONE did_fulfill: " + res),
            lambda res: print("DONE did_reject: " + res)
        )
        t3 = ms.scan("task 3").engine_then(
            lambda res: print("did_fulfill: " + res),
            lambda res: print("did_reject: " + res)
        ).then(
            lambda res: print("DONE did_fulfill: " + res),
            lambda res: print("DONE did_reject: " + res)
        )
        t4 = ms.scan("task 4").engine_then(
            lambda res: print("did_fulfill: " + res),
            lambda res: print("did_reject: " + res)
        ).then(
            lambda res: print("DONE did_fulfill: " + res),
            lambda res: print("DONE did_reject: " + res)
        )

        # Add the jobs in bulk to the thread pool. Alternatively you could use
        # `pool.add_task` to add single jobs. The code will block here, which
        # makes it possible to cancel the thread pool with an exception when
        # the currently running batch of workers is finished.
        print("Tasks added. Waiting for completion")

        if ms.docker_strategy == local_docker_strategy:
            local_docker_strategy.wait_completion()
        elif ms.docker_strategy == just_run_docker_strategy:
            just_run_docker_strategy.wait(t1)
            just_run_docker_strategy.wait(t2)
            just_run_docker_strategy.wait(t3)
            just_run_docker_strategy.wait(t4)
        elif ms.docker_strategy == auto_scale_strategy:
            auto_scale_strategy.wait_completion()
            print("worker count: {0}, queue size: {1} machines up: {2}".format(
                auto_scale_strategy.pool.get_worker_amount(), auto_scale_strategy.pool.get_queue_size(),
                len(auto_scale_strategy._machines)))
            for m in auto_scale_strategy._machines:
                print("machine {0} with {1} container(s)".format(m.id, len(m.containers)))
    print("end")
