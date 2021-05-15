import threading
import json
import os
import time
import math
import random
import datetime
import traceback

from functools import reduce
from rwlock import RWLock
from promise import Promise
from subprocess import check_output, CalledProcessError, STDOUT
from threading import Event

from multiav.exceptions import CreateDockerMachineMachineException, StopDockerMachineMachineException
from multiav.multiactionpromise import MultiActionPromise
from multiav.promiseexecutorpool import PromiseExecutorPool
from multiav.parallelpromise import ParallelPromise
from multiav.dockerabstraction import LocalDynamicDockerMachine, DockerMachineMachine, DockerMachine


# -----------------------------------------------------------------------
class ScannerStrategy:
    def __init__(self, config_parser):
        self.cfg_parser = config_parser
        self._event_subscribers = dict()

        self.max_scans_per_container = int(self.cfg_parser.gets("MULTIAV", "MAX_SCANS_PER_CONTAINER", 1))

        # statistics in seconds
        self.scan_time_average = (1, int(self.cfg_parser.gets("MULTIAV", "INITIAL_SCAN_TIME_AVERAGE", 20)))
        self._scan_time_lock = RWLock()

        # update mechanism
        self._update_lock = RWLock()
        self._update_start_event = Event()
        self._update_finished_event = Event()

        # check docker installation
        if not self._is_docker_installed():
            raise Exception("Please install docker! MultiAV won't work without it!")

        if not self._is_docker_accessible():
            raise Exception("Docker not accessible by current user. Please run the tool as root.")

    def _is_docker_installed(self):
        # e.g: docker: /usr/bin/docker /etc/docker /usr/share/docker.io /usr/share/man/man1/docker.1.gz
        return len(self._execute_command("whereis docker").split("docker")) > 2

    def _is_docker_accessible(self):
        return not ("Got permission denied" in self._execute_command("docker ps"))

    def _add_scan_time(self, scan_time):
        with self._scan_time_lock.writer_lock:
            new_scan_amount = self.scan_time_average[0] + 1
            new_scan_average = ((self.scan_time_average[1] * self.scan_time_average[0]) + scan_time) / new_scan_amount
            # print("_add_scan_time: old amount: {0} old average: {1} new amount: {2} new average: {3}".format(self.scan_time_average[0], self.scan_time_average[1], new_scan_amount, new_scan_average))
            self.scan_time_average = (new_scan_amount, new_scan_average)

    def _get_average_scan_time(self):
        with self._scan_time_lock.reader_lock:
            # print("_get_average_scan_time Sample Size: {0} Avg: {1}".format(self.scan_time_average[0], self.scan_time_average[1]))
            return int(self.scan_time_average[1])

    def _set_update_lock(self):
        with self._update_lock.writer_lock:
            # signal update thread to start
            self._update_start_event.set()

            # wait for signal from update thread to release lock
            self._update_finished_event.wait()

            # reset event objects
            self._update_start_event.clear()
            self._update_finished_event.clear()

    def _scan_internal(self, engine, file_buffer):
        try:
            # acquire reader lock to prevent updates while scanning
            with self._update_lock.reader_lock:
                # measure scan time
                start_time = time.time()

                self._pre_scan(engine, file_buffer)

                # set container for scan
                engine.container, reduce_scan_time_by = self._get_container_for_scan(engine, file_buffer)

                print("[{0}] Scanning {1} using {2} on container {3} on machine {4}".format(engine.name, file_buffer, engine.name, engine.container.id, engine.container.machine.id))
                res = engine.scan(file_buffer)

                res["name"] = engine.name
                res["plugin_type"] = engine.plugin_type.value
                res["speed"] = engine.speed.value
                res["has_internet"] = engine.container_requires_internet

                if "error" in res:
                    print("[{0}] Scan failed. Error: {1}".format(engine.name, res["error"]))
                else:
                    print("[{0}] Scan complete.".format(engine.name))

                self._post_scan(engine, file_buffer)

                # measure scan time
                scan_time = time.time() - start_time - reduce_scan_time_by

                self._add_scan_time(scan_time)
                print("[{0}] Scan time: {1}s seconds(reduced by: {3}s). New average: {2}s".format(engine.name, scan_time, self._get_average_scan_time(), reduce_scan_time_by))

                return res
        except Exception as e:
            print("[{0}] Scan internal error: {1}".format(engine.name, e))
            traceback.print_exc()
            return {
                "name": engine.name,
                "error": "{0}".format(e),
                "engine": "",
                "updated": "",
                "plugin_type": engine.plugin_type.value,
                "speed": engine.speed.value,
                "has_internet": engine.container_requires_internet
            }

    def _rise_event(self, event, file_to_scan, *args, **kargs):
        # print("_rise_event: {0} for file: {1}".format(event, file_to_scan))
        if event in self._event_subscribers and file_to_scan in self._event_subscribers[event]:
            for handler in self._event_subscribers[event][file_to_scan]:
                handler(*args, **kargs)

    def on(self, event, file_to_scan, handler):
        if event in self._event_subscribers and file_to_scan in self._event_subscribers[event]:
            self._event_subscribers[event][file_to_scan].append(handler)
        else:
            self._event_subscribers[event] = {file_to_scan: [handler]}
            # print(self._event_subscribers)

    def unsubscribe_event_handler(self, event, file_to_scan, handler):
        if event in self._event_subscribers and file_to_scan in self._event_subscribers[event]:
            self._event_subscribers[event][file_to_scan].remove(handler)

    def _pre_scan(self, engine, file_to_scan):
        self._rise_event("pre", file_to_scan, engine, file_to_scan)

    def _post_scan(self, engine, file_path):
        try:
            self._rise_event("post", file_path, engine, file_path)

            # remove scan from container
            print("_post_scan: removing scan {0} from container {1}".format(file_path, engine.container.id))
            engine.container.remove_scan(file_path)

            # remove / stop container if needed
            if self.max_scans_per_container == 1:
                engine.container.machine.remove_container(engine.container)

        except Exception as e:
            print("_post_scan Exception: {0}".format(e))
            traceback.print_exc()

    def startup(self, engines):
        self.engine_classes = []
        for engine in engines:
            self.engine_classes.append(engine)

        self._startup()

    def _execute_command(self, command, shell=False):
        try:
            print("--execute command: {0}".format(command))
            output = check_output(command.split(" "), shell=shell, stderr=STDOUT)
        except CalledProcessError as e:
            output = e.output

        return str(output.decode("utf-8"))

    def _startup(self):
        # abstract
        pass

    def _get_container_for_scan(self, engine, file_to_scan):
        # abstract
        pass

    def scan(self, engine, file_buffer):
        # abstract
        pass

    def update(self):
        # abstract
        pass

    def get_signature_version(self, engine):
        # abstract
        pass

    def get_statistics(self):
        # abstract
        pass


# -----------------------------------------------------------------------
class LocalDockerStrategy(ScannerStrategy):
    def __init__(self, config_parser):
        ScannerStrategy.__init__(self, config_parser)
        self.DOCKER_NETWORK_NO_INTERNET_NAME = self.cfg_parser.get("MULTIAV", "DOCKER_NETWORK_NO_INTERNET_NAME")
        self.DOCKER_NETWORK_INTERNET_NAME = self.cfg_parser.get("MULTIAV", "DOCKER_NETWORK_INTERNET_NAME")
        self.machine = None

    def _start_containers(self, engines):
        for engine in engines:
            if engine.is_disabled():
                continue

            if not self.machine.create_container(engine):
                return False
        return True

    def _get_container_for_scan(self, engine, file_to_scan):
        # search for a free spot on the local machine
        reduce_scan_time_by = 0
        container, machine = self.machine.try_do_scan(engine, file_to_scan)

        return container, reduce_scan_time_by

    def scan(self):
        # abstract
        pass

    def update(self):
        # abstract
        pass

    def get_signature_version(self, engine):
        containers = self.machine.find_containers_by_engine(engine)

        if len(containers) == 0:
            return "-"

        for container in containers:
            if container.is_running():
                return containers[0].get_signature_version()

        return "-"

    def get_statistics(self):
        # asbtract
        pass


# -----------------------------------------------------------------------
class LocalLimitDockerStrategy(LocalDockerStrategy):
    def __init__(self, config_parser):
        LocalDockerStrategy.__init__(self, config_parser)

        # use thread pool to handle overload without scaling
        self.max_containers_per_machine = int(self.cfg_parser.gets("MULTIAV","MAX_CONTAINERS", 8))
        if self.max_containers_per_machine <= 0:
            raise Exception("MAX_CONTAINERS invalid. Must be bigger than 0!")

        self.worker_amount = self.max_containers_per_machine * self.max_scans_per_container
        if self.worker_amount <= 0:
            raise Exception("MAX_SCANS_PER_CONTAINER invalid. Must be bigger than 0!")

        self.pool = PromiseExecutorPool(self.worker_amount)
        print("LocalDockerStrategy: initialized thread pool using {0} threads".format(self.worker_amount))

    def _startup(self):
        self.machine = LocalDynamicDockerMachine(cfg_parser=self.cfg_parser, engine_classes=self.engine_classes, max_containers_per_machine=self.max_containers_per_machine, max_scans_per_container=self.max_scans_per_container, id_overwrite="localhost")

    def scan(self, plugin, file_buffer):
        scan_promise = self.pool.add_task(self._scan_internal, plugin, file_buffer)
        return scan_promise

    def _update_internal(self, update_promise):
        try:
            # wait for signal that update lock is aquired
            print("waiting for update start event...")
            self._update_start_event.wait()

            # update images
            int_update_promise = self.machine.update()

            # update real promise
            int_update_promise.engine_then(
                lambda res: update_promise["engine_update_promise"].get_engine_promise(res["container_name"]).do_resolve(res),
                None
            )

            # signal lock thread to release update lock on update finish
            int_update_promise.then(
                lambda res: self._update_finished_event.set(),
                lambda err: self._update_finished_event.set()
            )
        except:
            print("_update_internal: EXCEPTION")
            traceback.print_exc()

    def _wait_for_update_start_event(self, update_promise):
        self._update_start_event.wait()
        update_promise["update_lock_set_promise"].do_resolve(datetime.datetime.now())

    def update(self):
        # add update task to queue => sets the event when called and blocks all other tasks
        self.pool.add_task(self._set_update_lock)

        # create update promise
        active_engines = [e(self.cfg_parser) for e in self.engine_classes if not e(self.cfg_parser).is_disabled()]
        update_promise = {
            "engine_update_promise": MultiActionPromise(dict(zip(
                active_engines,
                [Promise() for e in active_engines]))),
            "update_lock_set_promise": Promise()
        }

        # start lock watcher thread to resolve load_started_promise
        lock_watcher_thread = threading.Thread(target=self._wait_for_update_start_event, args=(update_promise,))
        lock_watcher_thread.start()

        # start update mechanism async
        thread = threading.Thread(target=self._update_internal, args=(update_promise,))
        thread.start()

        return update_promise

    def _calculate_time_to_finish_queue(self):
        queue_size = self.pool.get_queue_size_including_active_workers()
        avg_scan_time = self._get_average_scan_time()
        total_workers = self.pool.get_worker_amount()

        return math.ceil(queue_size / total_workers) * avg_scan_time

    def get_statistics(self):
        statistics = {
            "strategy_name": "LocalLimitDockerStrategy",
            "max_containers": self.max_containers_per_machine,
            "max_scans_per_container": self.max_scans_per_container,
            "worker_threads": self.pool.get_worker_amount(),
            "worker_threads_working": len(self.pool.get_working_workers()),
            "average_scan_time": self._get_average_scan_time(),
            "queue_size": self.pool.get_queue_size(),
            "time_to_finish_queue": self._calculate_time_to_finish_queue(),
            "container_amount": len(self.machine.containers),
            "containers": list(map(lambda container: {
                "id": container.id,
                "engine": container.engine.name,
                "scan_count": len(container.scans)
                }, self.machine.containers)) if len(self.machine.containers) != 0 else "None"
        }
        return statistics


# -----------------------------------------------------------------------
class LocalNoLimitDockerStrategy(LocalDockerStrategy):
    def __init__(self, config_parser):
        LocalDockerStrategy.__init__(self, config_parser)

        # thread array, not limited in size
        self.threads = []

    def _startup(self):
        self.machine = LocalDynamicDockerMachine(cfg_parser=self.cfg_parser, engine_classes=self.engine_classes, max_containers_per_machine=-1, max_scans_per_container=self.max_scans_per_container, id_overwrite="localhost")

    def _scan_promise_wrapper(self, resolve, reject, engine, file_buffer):
        def fn():
            try:
                with self._update_lock.reader_lock:
                    res = self._scan_internal(engine, file_buffer)

                resolve(json.dumps(res))
            except Exception as e:
                print("[{1}] _scan_promise_wrapper exception: {0}".format(e, engine.name))
                traceback.print_exc()
                reject(e)

        thread = threading.Thread(target=fn)
        thread.start()

    def scan(self, plugin, file_buffer):
        scan_promise = Promise(
            lambda resolve, reject: self._scan_promise_wrapper(resolve, reject, plugin, file_buffer)
        )
        return scan_promise

    def _update_internal(self, update_promise):
        try:
            # set update lock
            thread = threading.Thread(target=self._set_update_lock)
            thread.start()

            # wait for signal that update lock is aquired
            print("waiting for update start event...")
            self._update_start_event.wait()

            # update images
            int_update_promise = self.machine.update()

            # update real promise
            int_update_promise.engine_then(
                lambda res: update_promise.get_engine_promise(res["container_name"]).do_resolve(res),
                None
            )

            # signal lock thread to release update lock on update finish
            int_update_promise.then(
                lambda res: self._update_finished_event.set(),
                lambda err: self._update_finished_event.set()
            )
        except:
            print("_update_internal: EXCEPTION")
            traceback.print_exc()

    def update(self):
        active_engines = [e(self.cfg_parser) for e in self.engine_classes if not e(self.cfg_parser).is_disabled()]

        update_promise = MultiActionPromise(dict(zip(
            active_engines,
            [Promise() for e in active_engines])))

        # start update mechanism async
        thread = threading.Thread(target=self._update_internal, args=(update_promise,))
        thread.start()

        return update_promise

    def get_statistics(self):
        statistics = {
            "strategy_name": "LocalNoLimitDockerStrategy",
            "max_scans_per_container": self.max_scans_per_container,
            "worker_threads": len(self.threads),
            "average_scan_time": self._get_average_scan_time(),
            "container_amount": len(self.machine.containers),
            "containers": list(map(lambda container: {
                "id": container.id,
                "engine": container.engine.name,
                "scan_count": len(container.scans)
                }, self.machine.containers)) if len(self.machine.containers) != 0 else "None"
        }
        return statistics


# -----------------------------------------------------------------------
class AutoScaleDockerStrategy(ScannerStrategy):
    def __init__(self, config_parser):
        ScannerStrategy.__init__(self, config_parser)
        # variables
        self.minimal_machine_run_time = int(self.cfg_parser.gets("MULTIAV", "MINIMAL_MACHINE_RUN_TIME", 480))
        self.min_machines = int(self.cfg_parser.gets("MULTIAV", "MIN_MACHINES", 1))
        self.max_machines = int(self.cfg_parser.gets("MULTIAV", "MAX_MACHINES", 1))
        self.max_scans_per_container = int(self.cfg_parser.gets("MULTIAV", "MAX_SCANS_PER_CONTAINER", 1))
        self.max_containers_per_machine = int(self.cfg_parser.gets("MULTIAV", "MAX_CONTAINERS_PER_MACHINE", 8))

        # machine startup time
        self._expected_machine_startup_time = (1, int(self.cfg_parser.gets("MULTIAV", "EXPECTED_MACHINE_STARTUP_TIME", 130)))
        self._machine_startup_time_lock = RWLock()

        # sample copying to worker nodes
        self._scanning_samples = dict()
        self._workers_mounted_storage_lock = RWLock()

        # locks
        self._machine_lock = RWLock()
        self._worker_lock = RWLock()
        self._machines_starting = dict() # Event = amount of workers waiting

        # use thread pool to handle overload when maxed out scaling => tasks will stay in queue
        self._min_workers = self.min_machines * self.max_containers_per_machine * self.max_scans_per_container
        self._max_workers = self.max_machines * self.max_containers_per_machine * self.max_scans_per_container
        self.pool = PromiseExecutorPool(self._min_workers, self._max_workers)
        print("AutoScaleDockerStrategy: initialized thread pool using {0} threads (max: {1})".format(self._min_workers, self._max_workers))

        # machine vars
        self._machines = []
        print("AutoScaleDockerStrategy: initialized using min_machines: {0} max_machines: {1} max_containers_per_machine: {2} max_scans_per_container: {3}".format(self.min_machines, self.max_machines, self.max_containers_per_machine, self.max_scans_per_container))

        # check if docker-machine is installed
        if not self._is_docker_machine_installed():
            raise Exception("Docker-machine is not installed. Please install docker-machine to allow auto-scale to work.")

    def _is_docker_machine_installed(self):
        # e.g. docker-machine: /usr/local/bin/docker-machine
        return len(self._execute_command("whereis docker-machine").split("docker-machine")) > 2

    def _add_machine_startup_time(self, time):
        with self._machine_startup_time_lock.writer_lock:
            new_amount = self._expected_machine_startup_time[0] + 1
            new_average = ((self._expected_machine_startup_time[1] * self._expected_machine_startup_time[0]) + time) / new_amount
            self._expected_machine_startup_time = (new_amount, new_average)

    def _get_average_machine_startup_time(self):
        with self._machine_startup_time_lock.reader_lock:
            return int(self._expected_machine_startup_time[1])

    def _list_docker_machines(self):
        cmd = "docker-machine ls"
        response = self._execute_command(cmd)
        machines = list(map(lambda x: list(filter(lambda q: q != "", str(x).split(" "))), response.split("\n")[1:]))
        # [['multiav-test', '-', 'openstack', 'Running', 'tcp://10.0.0.51:2376', 'v18.09.3'], ...]
        return machines

    def _startup(self):
        # remove /tmp/multiav-* directories (cleanup)
        print("cleaning up /tmp/multiav-* directories...")
        self._execute_command("rm -fr /tmp/multiav-*")

        # check images on manager
        manager_machine = DockerMachine(cfg_parser=self.cfg_parser, engine_classes=self.engine_classes, max_containers_per_machine=0, max_scans_per_container=0, id_overwrite=None,enable_startup_logic=False)
        manager_machine.pull_all_containers()
        manager_machine.export_all_images()

        # check for running machines
        started_machine_counter = 0
        running_machines = self._list_docker_machines()
        for machine in running_machines:
            if len(machine) == 0:
                continue

            # descide what to do
            if not "Running" in machine:
                print("detected running machine {0} in ERRORNEOUS state!".format(machine[0]))
                instance = DockerMachineMachine(self.cfg_parser, self.engine_classes, self.max_containers_per_machine, self.max_scans_per_container, create_machine = False, execute_startup_checks = False, minimal_machine_run_time = self.minimal_machine_run_time, id_overwrite = machine[0], never_shutdown=False)
                if not instance.try_shutdown():
                    print("tried to clean up machine {0} but failed. please clean up manually!".format(machine[0]))
                    raise StopDockerMachineMachineException()

                print("machine {0} removed to regain a clean state...".format(machine[0]))
            elif len(self._machines) >= self.max_machines:
                # too many machines running
                instance = DockerMachineMachine(self.cfg_parser, self.engine_classes, self.max_containers_per_machine, self.max_scans_per_container, create_machine = False, execute_startup_checks = False, minimal_machine_run_time = self.minimal_machine_run_time, id_overwrite = machine[0], never_shutdown=False)
                if not instance.try_shutdown():
                    print("tried to remove machine {0} (max_machines already satisified) but failed. please clean up manually!".format(machine[0]))
                    raise StopDockerMachineMachineException()

                print("machine {0} removed as max_machines is already satisifed...".format(machine[0]))
            else:
                # use it!
                never_shutdown = started_machine_counter < self.min_machines
                instance = DockerMachineMachine(self.cfg_parser, self.engine_classes, self.max_containers_per_machine, self.max_scans_per_container, create_machine = False, minimal_machine_run_time = self.minimal_machine_run_time, id_overwrite = machine[0], never_shutdown=never_shutdown)
                instance.on("shutdown", self._on_machine_shutdown)
                print("detected running machine {0} in operational state".format(machine[0]))
                self._machines.append(instance)
                started_machine_counter += 1
                print("readding machine {0} to the list of machines now...".format(machine[0]))

        machine_count = len(self._machines)
        if machine_count != 0:
            print("readded {0} machines which were already runnning...".format(machine_count))

        # do we need to start machines to satisfy min_machines requirement?
        if machine_count < self.min_machines:
            amount_of_machines_to_start = self.min_machines - machine_count
            print("starting {0} machines due to min_machines requirement now...".format(amount_of_machines_to_start))
            start_promises = []

            # start machines async
            for i in range(0, amount_of_machines_to_start):
                start_promises.append(self._create_machine_async(never_shutdown=True))

            # wait for machines to start
            for promise in start_promises:
                promise.wait()
                if promise.is_rejected:
                    print("could not create machine on first try. retrying now...")
                    raise CreateDockerMachineMachineException()

        # handle workers for possible newly detected machines
        with self._worker_lock.writer_lock:
            current_worker_amount = self.pool.get_worker_amount()
            required_workers_for_machines = machine_count * self.max_containers_per_machine * self.max_scans_per_container
            required_workers_for_machines = self._max_workers if required_workers_for_machines > self._max_workers else required_workers_for_machines

            workers_to_add = required_workers_for_machines - current_worker_amount
            if workers_to_add > 0:
                print("increasing workers by {0} as {1} running machines were detected.".format(workers_to_add, machine_count))
                self.pool.add_worker(amount=workers_to_add)

        # start dir watchdogs
        # self._start_malware_dir_watchdogs()

    def _create_machine_async(self, never_shutdown=False):
        def promise_function(resolve, reject, never_shutdown):
            machine, startup_time = self._create_machine(never_shutdown)
            if machine == None:
                reject(CreateDockerMachineMachineException())

            resolve(machine)

        return ParallelPromise(lambda resolve,reject: promise_function(resolve, reject, never_shutdown))

    def _create_machine(self, never_shutdown=False):
            if len(self._machines) + 1 > self.max_machines:
                print("create machine called but limit reached")
                return None

            try:
                with self._machine_lock.writer_lock:
                    startup_event = Event()
                    self._machines_starting[startup_event] = 0

                print("starting new machine...")
                start_time = time.time()

                machine = DockerMachineMachine(self.cfg_parser, self.engine_classes, self.max_containers_per_machine, self.max_scans_per_container, True, self.minimal_machine_run_time, execute_startup_checks=True, never_shutdown=never_shutdown)
                machine.on("shutdown", self._on_machine_shutdown)

                print("New machine {0} started! Copying samples to machine now...".format(machine.id))

                # copy active samples to machine
                with self._workers_mounted_storage_lock.writer_lock:
                    for path_to_sample in self._scanning_samples:
                        self._execute_command("cp -u {0} /tmp/{1}/".format(path_to_sample, machine.id))

                with self._machine_lock.writer_lock:
                    self._machines.append(machine)
                    startup_event.set()
                    del self._machines_starting[startup_event]

                startup_time = time.time() - start_time
                self._add_machine_startup_time(startup_time)
                print("New average machine startup time: {0}s (machine started in {1}s)".format(self._get_average_machine_startup_time(), startup_time))

                return machine, startup_time
            except CreateDockerMachineMachineException as e:
                print(e)
                return None

    def _on_machine_shutdown(self, machine):
        with self._machine_lock.writer_lock:
            print("_on_machine_shutdown")
            self.pool.remove_workers(self.max_containers_per_machine * self.max_scans_per_container)
            self._machines.remove(machine)
            print("removed machine {0}!".format(machine.id))

    def _get_container_for_scan(self, engine, file_path):
        container = None
        machine = None
        reduce_scan_time_by = 0

        machine_count = len(self._machines)

        # search for a free spot on a running machine: iterate over machines in random order for better spreading
        for m in random.sample(self._machines, machine_count):
            print("looking for container with engine {1} on machine {0}".format(m.id, engine.name))
            container, machine = m.try_do_scan(engine, file_path)
            if container is not None:
                print("found container {0} with engine {2} on machine {1}".format(container.id, machine.id, engine.name))
                break

        if container is None:
            # check if we are already starting a machine
            self._machine_lock.writer_lock.acquire()
            if len(self._machines_starting) != 0:
                # iterate over starting machine and check if we can wait for one
                for event, workers_waiting in self._machines_starting.items():
                    if workers_waiting != self.max_containers_per_machine * self.max_scans_per_container:
                        # release lock and wait for machine startup
                        self._machines_starting[event] += 1
                        self._machine_lock.writer_lock.release()
                        event.wait()
                        container, reduce_scan_time_by = self._get_container_for_scan(engine, file_path)
                        reduce_scan_time_by = self._get_average_machine_startup_time()
                        return container, reduce_scan_time_by

            self._machine_lock.writer_lock.release()

            # start a new machine
            m, startup_time = self._create_machine() # blocks for as long as the machine startup takes

            if m is None:
                return self._get_container_for_scan(engine, file_path)

            container, machine = m.try_do_scan(engine, file_path)

            # add time reduction due to start
            reduce_scan_time_by = startup_time

        return container, reduce_scan_time_by

    def _increase_workforce_if_possible(self):
        with self._worker_lock.writer_lock:
            queue_size = self.pool.get_queue_size_including_active_workers()
            worker_amount = self.pool.get_worker_amount()

            if queue_size <= worker_amount:
                print("_increase_workforce_if_possible: queue is still smaller ({0}) than the current worker count ({1})".format(queue_size, worker_amount))
                return

            if worker_amount >= self._max_workers:
                print("_increase_workforce_if_possible: max workers reached {0}".format(self._max_workers))
                return

            # would require machine start. is it worth it? (calc worst case)
            times = self._calculate_times_to_finish_queue_for_startable_machines()
            # print("_increase_workforce_if_possible: times {0}".format(times))
            amount_of_machines, time_to_finish_queue = self._get_lowest_work_time_and_machines_to_start_from_times_touple_list(times)
            # print("_increase_workforce_if_possible: amount_of_machines {0} queue_size: {1} average_scan_time: {2} time_to_finish_queue: {3}".format(amount_of_machines, queue_size, self._get_average_scan_time(), time_to_finish_queue))

            if amount_of_machines == 0:
                # finishing the queue is faster than starting a new machine
                print("_increase_workforce_if_possible: finishing queue without starting new machine is faster")
                return

            for _j in range(0, amount_of_machines):
                # start new machine by adding a worker who will do it pre scan
                print("_increase_workforce_if_possible: creating {0} workers for new machine".format(self.max_containers_per_machine * self.max_scans_per_container))
                for _i in range(0, self.max_containers_per_machine * self.max_scans_per_container):
                    self.pool.add_worker()

    def _get_lowest_work_time_and_machines_to_start_from_times_touple_list(self, times):
        amount_of_machines = times[0][0]
        work_to_finish_queue = times[0][1]
        amount_of_times = len(times)

        for i in range(0, amount_of_times):
            machines_to_start, time_to_finish_queue = times[amount_of_times - 1 - i]

            if amount_of_times -1 -i -1 >= 0:
                machines_to_start_prev, time_to_finish_queue_prev = times[amount_of_times - 1 - i - 1]
                if time_to_finish_queue_prev > time_to_finish_queue:
                    amount_of_machines = machines_to_start
                    work_to_finish_queue = time_to_finish_queue

        return amount_of_machines, work_to_finish_queue

    def _calculate_times_to_finish_queue_for_startable_machines(self):
        times = list()

        queue_size = self.pool.get_queue_size_including_active_workers()
        avg_scan_time = self._get_average_scan_time()
        total_workers = self.pool.get_worker_amount()

        machines_starting = len(self._machines_starting)

        for i in range(machines_starting, self.max_machines):
            machines_to_start = i - machines_starting

            # calculate time when starting
            workers_per_machine = self.max_containers_per_machine * self.max_scans_per_container
            workers_waiting_for_machine_start = machines_starting * workers_per_machine
            currently_working_workers = len(self._machines) * workers_per_machine
            # print("machines_starting: {0} currently_working_workers: {1} workers_waiting_for_machine_start: {2} workers_per_machine: {3}".format(machines_starting, currently_working_workers, workers_waiting_for_machine_start, workers_per_machine))

            items_completable_in_machine_startup_time = int(self._get_average_machine_startup_time() / avg_scan_time) * currently_working_workers
            items_to_complete_post_startup = queue_size - items_completable_in_machine_startup_time

            if items_completable_in_machine_startup_time < queue_size:
                if currently_working_workers != 0:
                    # as we round down before, we need to calculate the correct time now
                    time = items_completable_in_machine_startup_time * avg_scan_time / currently_working_workers
                else:
                    time = self._get_average_machine_startup_time()

                workers_post_startup = currently_working_workers + (i * workers_per_machine)

                if workers_post_startup != 0:
                    additional_computation_time = math.ceil(items_to_complete_post_startup / workers_post_startup) * avg_scan_time
                else:
                    additional_computation_time = float("inf")

                time += additional_computation_time
            else:
                if currently_working_workers != 0:
                    time = math.ceil(queue_size / currently_working_workers) * avg_scan_time
                elif queue_size == 0:
                    time = 0
                else:
                    time = float("inf")

            times.append((machines_to_start, time))

        # print(times)
        return times

    def _post_engine_scan_sample_cleanup_check(self, path_to_sample):
        with self._workers_mounted_storage_lock.writer_lock:
            self._scanning_samples[path_to_sample] -= 1

            if self._scanning_samples[path_to_sample] == 0:
                print("last scan finished for {0}. removing from machines now...".format(path_to_sample))
                with self._machine_lock.reader_lock:
                    for m in self._machines:
                        self._execute_command("rm /tmp/{0}/{1}".format(m.id, os.path.basename(path_to_sample)))

    def scan(self, engine, path_to_sample):
        with self._workers_mounted_storage_lock.writer_lock:
            if not path_to_sample in self._scanning_samples:
                print("first scan for {0}. copying to machines now...".format(path_to_sample))
                with self._machine_lock.reader_lock:
                    for m in self._machines:
                        self._execute_command("cp -u {0} /tmp/{1}/".format(path_to_sample, m.id))
                self._scanning_samples[path_to_sample] = 1
            else:
                self._scanning_samples[path_to_sample] += 1

        scan_promise = self.pool.add_task(self._scan_internal, engine, path_to_sample)
        # schedule cleanup
        scan_promise.then(lambda result: self._post_engine_scan_sample_cleanup_check(path_to_sample))

        # increase workforce if required and possible
        self._increase_workforce_if_possible()

        return scan_promise

    def get_signature_version(self, engine):
        containers = self._machines[0].find_containers_by_engine(engine)

        if len(containers) == 0:
            return "-"

        for container in containers:
            if container.is_running():
                return container.get_signature_version()

        return "-"

    def check_if_this_engine_is_updated_on_all_machines(self, result, machine_update_promises, update_promise):
        result = json.loads(result)
        engine_name = result["engine"]
        # print("check_if_this_engine_is_updated_on_all_machines: engine {0}".format(engine_name))
        not_pending = True
        failed_promises = 0
        for promise in machine_update_promises[engine_name]:
            not_pending &= promise._state != -1
            if promise._state == 0:
                failed_promises += 1

        # print("check_if_this_engine_is_updated_on_all_machines: engine {0}, not_pending: {1}, failed_promises: {2}".format(engine_name, not_pending, failed_promises))
        if not_pending:
            # last one will trigger this
            for engine, value_promise in update_promise._engine_promises.items():
                if engine.name == engine_name:
                    if failed_promises == 0:
                        # print("check_if_this_engine_is_updated_on_all_machines: resolving engine {0}".format(engine_name))
                        value_promise.do_resolve(result)
                    else:
                        # print("check_if_this_engine_is_updated_on_all_machines: rejecting engine {0}".format(engine_name))
                        value_promise.do_reject(Exception("Update of {0} failed on {1} machines".format(engine_name, failed_promises)))
                    return

    def _post_engine_update(self, update_promise, manager_machine, result):
        try:
            engine_name = result["container_name"]
            print("_post_engine_update for engine {0}".format(engine_name))

            # resolve update promise for this engine
            update_promise["engine_update_promise"].get_engine_promise(engine_name).do_resolve(result)

            # export image
            update_promise["engine_export_start_date"][engine_name] = datetime.datetime.now()
            export_file_name = "/tmp/multiav-update-{0}.tar".format(engine_name)

            export_image_promise = manager_machine.export_images(export_file_name, [engine_name])
            export_image_promise.then(
                lambda res: self._post_engine_export(update_promise, engine_name, manager_machine, res, export_file_name),
                lambda err: update_promise["engine_export_promise"].get_engine_promise(engine_name).do_reject(err)
            )
        except Exception as e:
            print("EXCEPTION: _post_engine_update")
            traceback.print_exc()
            update_promise["engine_export_promise"].get_engine_promise(engine_name).do_reject(e)
            update_promise["update_complete_promise"].do_reject(e)

    def _post_engine_export(self, update_promise, engine_name, manager_machine, result, export_file_name):
        try:
            print("_post_engine_export for engine {0}".format(engine_name))

            # resolve export promise
            update_promise["engine_export_promise"].get_engine_promise(engine_name).do_resolve(result)

            if len(self._machines) > 0:
                # scp to workers
                print("starting to copy update file {0} via scp to worker machines...".format(export_file_name))
                scp_promises = list()
                for machine in self._machines:
                    update_promise["scp_to_workers_start_date"][machine][engine_name] = datetime.datetime.now()
                    scp_promises.append(machine.copy_image_to_machine(engine_name, export_file_name))
                    scp_promises[-1].then(
                        lambda res: self._post_update_file_scp(update_promise, engine_name, res, export_file_name),
                        lambda err: update_promise["scp_to_workers_promises"][machine].get_engine_promise(engine_name).do_reject(err)
                    )
            else:
                # update finished for this engine
                # resolve if all done
                pending_promises = list(filter(
                    lambda x: x._state == -1,
                    update_promise["engine_export_promise"]._engine_promises.values()))
                if len(pending_promises) == 0:
                    print("_post_engine_export: all engine_export_promise done. resolving update_complete_promise...")
                    # resolve update promise
                    update_promise["update_complete_date"] = datetime.datetime.now()
                    update_promise["update_complete_promise"].do_resolve(str(update_promise["update_complete_date"]))

                    # set event to signalize the update task to release the update lock (allows scans to execute again)
                    self._update_finished_event.set()
                else:
                    print("_post_engine_export: there are still some engine_export_promise pending..")

        except Exception as e:
            print("EXCEPTION: _post_engine_export: {0}".format(e))
            traceback.print_exc()
            update_promise["update_complete_promise"].do_reject(e)

    def _wait_for_update_start_event(self, update_promise):
        self._update_start_event.wait()
        update_promise["worker_image_load_unlocked_promise"].do_resolve(datetime.datetime.now())

    def _post_update_file_scp(self, update_promise, engine_name, result, export_file_name):
        try:
            machine = result["machine"]
            print("_post_update_file_scp for engine {0} on machine {1}".format(engine_name, machine.id))

            update_promise["scp_to_workers_promises"][machine].get_engine_promise(engine_name).do_resolve(result)

            # wait for update task to be executed by a worker => signals to start updating workers
            print("waiting for update start event...")
            self._update_start_event.wait()

            # load new image
            update_promise["worker_images_load_start_date"][machine][engine_name] = datetime.datetime.now()
            print("starting update of engine {0} on worker machine {1}...".format(engine_name, machine.id))
            image_load_promise = machine.load_update_file(export_file_name, engine_name)
            image_load_promise.then(
                lambda res: self._post_update_loaded(update_promise, machine, engine_name, res),
                lambda err: update_promise["worker_images_load_promises"][machine].do_reject(err)
            )
        except Exception as e:
            print("EXCEPTION: _post_update_file_scp: {0}".format(e))
            traceback.print_exc()
            update_promise["update_complete_promise"].do_reject(e)

    def _post_update_loaded(self, update_promise, machine, engine_name, result):
        try:
            print("_post_update_loaded for engine {0} on machine {1}".format(engine_name, machine.id))
            update_promise["worker_images_load_promises"][machine].get_engine_promise(engine_name).do_resolve(result)

            # resolve if all done
            pending_promises = list(filter(
                lambda x: x._state == -1,
                reduce(
                    lambda x, y: x and y,
                    [list(multi_action_promise._engine_promises.values()) for m, multi_action_promise in update_promise["worker_images_load_promises"].items()])))
            if len(pending_promises) == 0:
                print("_post_update_loaded: all worker_images_load_promises done. resolving update_complete_promise...")
                # resolve update promise
                update_promise["update_complete_date"] = datetime.datetime.now()
                update_promise["update_complete_promise"].do_resolve(str(update_promise["update_complete_date"]))

                # set event to signalize the update task to release the update lock (allows scans to execute again)
                self._update_finished_event.set()
            else:
                print("_post_update_loaded: there are still some worker_images_load_promises pending..")
        except Exception as e:
            print("EXCEPTION: _post_update_loaded: {0}".format(e))
            traceback.print_exc()
            update_promise["update_complete_promise"].do_reject(e)

    def _update_internal(self, update_promise):
        try:
            with self._machine_lock.reader_lock:
                # create promise to do the update on the host
                manager_machine = DockerMachine(cfg_parser=self.cfg_parser, engine_classes=self.engine_classes, max_containers_per_machine=0, max_scans_per_container=0, id_overwrite=None,enable_startup_logic=False)

                # do engine updates on the manager machine
                update_promise["engine_update_start_date"] = datetime.datetime.now()
                print("starting update on manager machine...")
                engine_update_promise = manager_machine.update()

                # set up promises
                engine_update_promise.engine_then(
                    lambda res: self._post_engine_update(update_promise, manager_machine, res),
                    lambda err: update_promise["engine_update_promise"]._engine_promises.get_engine_promise(err["container_name"]).do_reject(err)
                )
                engine_update_promise.then(
                    lambda res: update_promise["engine_update_promise"].do_resolve(res),
                    lambda err: update_promise["engine_update_promise"].do_reject(err)
                )
        except Exception as e:
            print("EXCEPTION: _update_internal: {0}".format(e))
            traceback.print_exc()
            update_promise["update_complete_date"] = datetime.datetime.now()
            update_promise["update_complete_promise"].do_reject(e)

    def update(self):
        # create update promise structure to represent the current update state
        # end dates are returned as promise result if resolved
        active_engines = [e(self.cfg_parser) for e in self.engine_classes if not e(self.cfg_parser).is_disabled()]
        update_promise = {
            "update_start_date": None,
            "update_complete_date": None,

            "engine_update_promise": MultiActionPromise(dict(zip(
                active_engines,
                [Promise() for e in active_engines]))),                                                         # dict: [engine] = Promise()
            "engine_export_start_date": dict(zip(
                    [engine.container_name for engine in active_engines],
                    [None for e in active_engines])),
            "engine_export_promise": MultiActionPromise(dict(zip(
                active_engines,
                [Promise() for e in active_engines]))),                                                         # dict: [engine] = Promise()
            "scp_to_workers_start_date": dict(zip(
                [m for m in self._machines],
                [dict(zip(
                    [engine.container_name for engine in active_engines],
                    [None for e in active_engines])) for m in self._machines])),
            "scp_to_workers_promises": dict(zip(
                [m for m in self._machines],
                [MultiActionPromise(dict(zip(
                    active_engines,
                    [Promise() for e in active_engines]))) for m in self._machines])),      # dict: [machine] = {engine: Promise()}
            "worker_image_load_unlocked_promise": Promise(),
            "worker_images_load_start_date": dict(zip(
                [m for m in self._machines],
                [dict(zip(
                    [engine.container_name for engine in active_engines],
                    [None for e in active_engines])) for m in self._machines])),
            "worker_images_load_promises": dict(zip(
                [m for m in self._machines],
                [MultiActionPromise(dict(zip(
                    active_engines,
                    [Promise() for e in active_engines]))) for m in self._machines])),  # dict: [machine] = {engine: Promise()}
            "update_complete_promise": Promise()
        }

        # add update task to queue => sets the event when called and blocks all other tasks
        if len(self._machines) > 0:
            self.pool.add_task(self._set_update_lock)
        else:
            update_lock_thread = threading.Thread(target=self._set_update_lock)
            update_lock_thread.start()

        # start lock watcher thread to resolve load_started_promise
        lock_watcher_thread = threading.Thread(target=self._wait_for_update_start_event, args=(update_promise,))
        lock_watcher_thread.start()

        # start update mechanism async
        thread = threading.Thread(target=self._update_internal, args=(update_promise,))
        thread.start()

        return update_promise

    def get_statistics(self):
        statistics = {
            "strategy_name": "AutoScaleDockerStrategy",
            "max_scans_per_container": self.max_scans_per_container,
            "worker_threads": self.pool.get_worker_amount(),
            "worker_threads_working": len(self.pool.get_working_workers()),
            "worker_per_machine": self.max_containers_per_machine * self.max_scans_per_container,
            "worker_threads_min": self._min_workers,
            "woerker_threads_max": self._max_workers,
            "machines_active": len(self._machines),
            "machines_starting": len(self._machines_starting),
            "machines_min": self.min_machines,
            "machines_max": self.max_machines,
            "queue_size": self.pool.get_queue_size(),
            "average_scan_time": self._get_average_scan_time(),
            "time_to_finish_queue": self._get_lowest_work_time_and_machines_to_start_from_times_touple_list(self._calculate_times_to_finish_queue_for_startable_machines())[1],
            "average_machine_startup_time": self._get_average_machine_startup_time(),
            "minimal_machine_run_time": self.minimal_machine_run_time,
            "machines": list(map(lambda machine: {
                machine.id: {
                    "never_shutdown": machine.never_shutdown,
                    "shutdown_check_backoff": machine._shutdown_check_backoff if not machine.never_shutdown else "-",
                    "shutdown_check_last_date": str(machine._shutdown_check_last_date) if not machine.never_shutdown else "-",
                    "shutdown_check_next_date": str(machine._shutdown_check_last_date + datetime.timedelta(0, machine.minimal_machine_run_time ** machine._shutdown_check_backoff)) if machine._shutdown_check_backoff != None else "-",
                    "container_amount": len(machine.containers),
                    "containers": list(map(lambda container: {
                        "id": container.id,
                        "engine": container.engine.name,
                        "scan_count": len(container.scans)
                        }, machine.containers)) if len(machine.containers) != 0 else "None"
                    }
                }, self._machines))
        }
        return statistics
