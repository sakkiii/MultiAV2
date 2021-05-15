# -*- coding: utf-8 -*-


# MultiAV scanner wrapper version 0.0.1
# Copyright (c) 2014, Joxean Koret
#
# License:
#
# MultiAV is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser Public License as published by the
# Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# MultiAV is distributed in the hope that it will be  useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Lesser Public License for more details.
#
# You should have received a copy of the GNU Lesser Public License
# along with DoctestAll.  If not, see
# <http://www.gnu.org/licenses/>.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>
#
# Description:
#
# This script implements a very basic wrapper around various AV engines
# available for Linux using their command line scanners with the only
# exception of ClamAV. The currently supported AV engines are listed
# below:
#
#   * ClamAV (Fast)
#   * F-Prot (Fast)
#   * Comodo (Fast)
#   * BitDefender (Medium)
#   * ESET (Slow)
#   * Avira (Slow)
#   * Sophos (Medium)
#   * Avast (Fast)
#   * AVG (Fast)
#   * DrWeb (Slow)
#   * McAfee (Very slow, only enabled when running all the engines)
#   * Ikarus (Medium, using wine in Linux/Unix)
#   * F-Secure (Fast)
#   * Kaspersky (Fast)
#   * Zoner Antivirus (Fast)
#   * MicroWorld-eScan (Fast)
#   * Cyren (Fast)
#   * QuickHeal (Fast)
#
# Support for the Kaspersky AV engine includes MacOSX, Windows, and Linux
#
# Features:
#
#   * Parallel scan, by default, based on the number of CPUs.
#   * Analysis by AV engine speed.
#

import os
import json

from enum import Enum
from hashlib import sha1
from tempfile import NamedTemporaryFile
from multiprocessing import Process, Queue, cpu_count

from multiav.multiactionpromise import MultiActionPromise
from multiav.scannerstrategy import ScannerStrategy


class OrderedEnum(Enum):
  def __ge__(self, other):
    if self.__class__ is other.__class__:
      return self.value >= other.value
    return NotImplemented
  def __gt__(self, other):
    if self.__class__ is other.__class__:
      return self.value > other.value
    return NotImplemented
  def __le__(self, other):
    if self.__class__ is other.__class__:
      return self.value <= other.value
    return NotImplemented
  def __lt__(self, other):
    if self.__class__ is other.__class__:
      return self.value < other.value
    return NotImplemented


class AV_SPEED(OrderedEnum):
  ALL = 3  # Run only when all engines must be executed
  ULTRA = -1
  FAST = 0
  MEDIUM = 1
  SLOW = 2


class PLUGIN_TYPE(OrderedEnum):
  #LEGACY = 0
  AV = 1
  METADATA = 2
  INTEL = 3
  FILE_FORMATS = 4


class CDockerAvScanner():
  def __init__(self, cfg_parser, name):
    self.cfg_parser = cfg_parser
    self.name = name
    self.speed = AV_SPEED.SLOW
    self.plugin_type = None
    self.container_name = None
    self.scan_timeout = int(self.cfg_parser.gets("MULTIAV", "SCAN_TIMEOUT", 120))
    self.container = None
    self.container_requires_internet = int(self.cfg_parser.gets(self.name, "ENABLE_INTERNET_ACCESS", 0)) == 1
    self.container_build_url_override = self.cfg_parser.gets(self.name, "DOCKER_BUILD_URL_OVERRIDE", None)
    self.container_run_command_arguments = dict()
    self.container_run_docker_parameters = dict()
    self.container_build_params = dict()
    self.update_pull_supported = True
    self.update_command_supported = True
    self.binary_path = "/bin/avscan"
    self.container_additional_files = []

  def is_disabled(self):
    try:
      val = self.cfg_parser.get(self.name, "DISABLED")

      if val == "0" or val.lower() == "false":
        return False

      return True
    except:
      return False

  def scan(self, path):
    try:
        # build request params
        filename = os.path.basename(path)

        if self.container.machine.max_scans_per_container == 1:
          # run and scan command only, container is removed post scan by docker
          run_cmd = self.container.get_run_and_scan_command(filename)
          response = self.container.machine.execute_command(run_cmd)
        else:
          '''
          e.g.
          sudo docker cp /tmp/tmp_f5nzdm1 multiav-clamav-TEST:/malware/tmp_f5nzdm1 > /dev/null 2>&1;
          sudo docker exec multiav-clamav-TEST /bin/avscan /malware/tmp_f5nzdm1;
          sudo docker exec multiav-clamav-TEST rm /malware/tmp_f5nzdm1 > /dev/null 2>&1"
          '''
          copy_cmd = "docker cp {0} {1}:/malware/{2} > /dev/null 2>&1".format(path, self.container.id, filename)
          scan_cmd = "docker exec {0} {2} --timeout {3} {1}".format(self.container.id, filename, self.binary_path, self.scan_timeout)
          cleanup_cmd = "docker exec {0} rm /malware/{1} > /dev/null 2>&1".format(self.container.id, filename)

          cmd = " && ".join([copy_cmd, scan_cmd, cleanup_cmd])
          response = self.container.machine.execute_command(cmd)

        # remove non json outputs (could be errors reported to stdout)
        response_json = response[:]
        if response_json[0] != "{":
          response_json = response_json[response_json.find("{"):]
        if response_json[-1] != "}":
          response_json = response_json[:response_json.rfind("}")+1]

        # dont try to deserialize if empty result
        if len(response_json) < len("{\"0\":0}"):
          raise Exception("non json result: {0}".format(response))

        response_obj = json.loads(response_json)
        return self._normalize_results(response_obj)
    except Exception as e:
        print("[{0}] Container: {2} Exception in scan method: {1}".format(self.name, e, self.container.id))
        try:
          print(response)
        except:
          pass
        return {
            "error": "{0}".format(e),
            "infected": False,
            "engine": "-",
            "updated": "-",
            "has_internet": self.container_requires_internet,
            "speed": self.speed.name
        }

  def _normalize_results(self, response_obj):
    result = {}

    # normalize
    if self.plugin_type == PLUGIN_TYPE.AV:
      result = response_obj[list(response_obj)[0]]
    elif self.plugin_type == PLUGIN_TYPE.METADATA or self.plugin_type == PLUGIN_TYPE.FILE_FORMATS:
      result = response_obj
    elif self.plugin_type == PLUGIN_TYPE.INTEL:
      if len(response_obj) == 1:
        result = response_obj[list(response_obj)[0]]
      else:
        result = response_obj

    # remove empty errors
    if "error" in result and result["error"] == "":
      del result["error"]

    return result


class CDockerHashLookupService(CDockerAvScanner):
  def __init__(self, cfg_parser, name):
    CDockerAvScanner.__init__(self, cfg_parser, name)

  def scan(self, path):
    try:
      with open(path, "rb") as binary_file:
        # Read the whole file at once
        buf = binary_file.read()

      # calculate hash
      filehash = sha1(buf).hexdigest()

      # scan
      cmd = self.container.get_run_and_scan_command("lookup {0}".format(filehash))

      response = ""
      while len(response) < len("{\"0\":0}"):
        response = self.container.machine.execute_command(cmd)
        if len(response) < len("{\"0\":0}"):
          print("[{0}] Scan response empty. trying again...".format(self.name))

      # deserialize
      if response[0] != "{":
        # remove errors which could be in front of the json output
        response = response[response.find("{"):]

      response_obj = json.loads(response)

      return self._normalize_results(response_obj)

    except Exception as e:
      print("[{0}] Container: {2} Exception in scan method: {1}".format(self.name, e, self.container.id))
      try:
        print(response)
      except:
        pass
      return {
          "error": "{0}".format(e),
          "infected": False,
          "engine": "-",
          "updated": "-",
          "has_internet": self.container_requires_internet,
          "speed": self.speed.name
      }


class CFileInfo(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "FileInfo")
    self.speed = AV_SPEED.ULTRA
    self.plugin_type = PLUGIN_TYPE.METADATA
    self.container_name = "fileinfo"
    self.binary_path = "/bin/info"
    self.update_command_supported = False


class CPEScanMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "PEScan")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.FILE_FORMATS
    self.container_name = "pescan"
    self.binary_path = "/usr/sbin/pescan"
    self.container_run_command_arguments["scan"] = None
    self.update_command_supported = False


class CFlossMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "Floss")
    self.speed = AV_SPEED.SLOW
    self.plugin_type = PLUGIN_TYPE.FILE_FORMATS
    self.container_name = "floss"
    self.binary_path = "/bin/flscan"
    self.update_command_supported = False


# Update and download servers not reachable anymore :/
'''class CZonerMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "Zoner")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "zoner"
    self.container_enviroment_variables["ZONE_KEY"] = cfg_parser.get(self.name, "LICENSE_KEY")'''


class CWindowsDefenderMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "WindowsDefender")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "windows-defender"
    self.container_run_docker_parameters["--security-opt"] = "seccomp=seccomp.json"
    self.container_additional_files.append("seccomp.json")


class CSophosMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "Sophos")
    self.speed = AV_SPEED.SLOW
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "sophos"


class CAvastMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "Avast")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "avast"
    self.container_additional_files.append("license.avastlic")
    self.container_run_docker_parameters["-v /home/ubuntu/license.avastlic:/etc/avast/license.avastlic"] = None


class CAvgMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "Avg")
    self.speed = AV_SPEED.ULTRA
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "avg"


class CBitDefenderMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "BitDefender")
    self.speed = AV_SPEED.MEDIUM
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "bitdefender"
    self.container_build_params["BDKEY"] = cfg_parser.get(self.name, "LICENSE_KEY")


class CClamAVMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "ClamAV")
    self.speed = AV_SPEED.ULTRA
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "clamav"


class CComodoMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "Comodo")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "comodo"


class CDrWebMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "DrWeb")
    self.speed = AV_SPEED.SLOW
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "drweb"


class CEScanMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "EScan")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "escan"


class CFProtMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "FProt")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "fprot"


class CFSecureMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "FSecure")
    self.speed = AV_SPEED.MEDIUM
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "fsecure"


class CKasperskyMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "Kaspersky")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "kaspersky"


class CMcAfeeMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "McAfee")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "mcafee"


class CYaraMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "Yara")
    self.speed = AV_SPEED.MEDIUM
    self.plugin_type = PLUGIN_TYPE.METADATA
    self.container_name = "yara"
    self.binary_path = "/bin/scan"
    self.update_command_supported = False


class CShadowServerMalicePlugin(CDockerHashLookupService):
  def __init__(self, cfg_parser):
    CDockerHashLookupService.__init__(self, cfg_parser, "ShadowServer")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.INTEL
    self.container_name = "shadow-server"
    self.binary_path = "/bin/shadow-server"
    self.update_command_supported = False


class CVirusTotalMalicePlugin(CDockerHashLookupService):
  def __init__(self, cfg_parser):
    CDockerHashLookupService.__init__(self, cfg_parser, "VirusTotal")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.INTEL
    self.container_name = "virustotal"
    self.container_run_command_arguments["--api"] = cfg_parser.get(self.name, "API_KEY")
    self.binary_path = "/bin/virustotal"
    self.update_command_supported = False


class CNationalSoftwareReferenceLibraryMalicePlugin(CDockerHashLookupService):
  def __init__(self, cfg_parser):
    CDockerHashLookupService.__init__(self, cfg_parser, "NSRL")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.INTEL
    self.container_name = "nsrl"
    self.binary_path = "/bin/nsrl"
    self.update_command_supported = False


class CIkarusMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "Ikarus")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "ikarus"
    self.container_run_docker_parameters["--shm-size"] = "256m" # default is 64m. Bus error on scan if omitted


class CAviraMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "Avira")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "avira"


class InvalidScannerStrategyException(Exception):
  pass

# -----------------------------------------------------------------------
class CMultiAV:
  def __init__(self, scanner_strategy, config_parser, auto_pull = False, auto_start = False):
    self.engines = [CFileInfo, CWindowsDefenderMalicePlugin,
                    CSophosMalicePlugin, CAvastMalicePlugin, CAvgMalicePlugin,
                    CBitDefenderMalicePlugin, CClamAVMalicePlugin, CComodoMalicePlugin,
                    CDrWebMalicePlugin, CEScanMalicePlugin, CFProtMalicePlugin,
                    CFSecureMalicePlugin, CKasperskyMalicePlugin, CMcAfeeMalicePlugin,
                    CYaraMalicePlugin, CShadowServerMalicePlugin, CVirusTotalMalicePlugin,
                    CNationalSoftwareReferenceLibraryMalicePlugin, CPEScanMalicePlugin,
                    CFlossMalicePlugin, CIkarusMalicePlugin, CAviraMalicePlugin]

    self.processes = cpu_count()
    self.parser = config_parser

    # set scanner strategy
    if isinstance(scanner_strategy, ScannerStrategy):
        self.scanner_strategy = scanner_strategy
    else:
        raise InvalidScannerStrategyException("error invalid strategy")

    # make sure /tmp/malware exists
    if "No such file or directory" in self.scanner_strategy._execute_command("ls /tmp/malware"):
        self.scanner_strategy._execute_command("mkdir /tmp/malware")
    else:
        # cleanup if existing
        self.scanner_strategy._execute_command("rm /tmp/malware/*")

    # startup checks
    self.scanner_strategy.startup(self.engines)

  def exec_func_multi_processes(self, object_list, func, args = None):
    q = Queue()
    objects = object_list
    running = []
    results = {}

    while len(objects) > 0 or len(running) > 0:
      if len(objects) > 0 and len(running) < self.processes:
        obj = objects.pop()

        args_combined = (obj, results, q)
        if args != None: args_combined += args

        p = Process(target=func, args=args_combined)
        p.start()
        running.append(p)

      # check if processes is still running
      newrunning = []
      for p in list(running):
        p.join(0.1)
        if p.is_alive():
          newrunning.append(p)
      running = newrunning

    results = {}
    print("update dict from queue...")
    while not q.empty():
      results.update(q.get())

    print("update dict from queue complete!")
    return results

  def scan(self, path, max_speed=AV_SPEED.ALL, allow_internet=False, event_handlers = dict()):
    if not os.path.exists(path):
      raise Exception("Path not found")

    # register events if required
    if len(event_handlers) != 0:
      for event, handlers in event_handlers.items():
        for handler in handlers:
          self.scanner_strategy.on(event, path, handler)

    scan_promises = dict()
    for engine_class in self.engines:
      # create engine instance
      engine = engine_class(self.parser)

      if engine.is_disabled():
        continue

      if engine.container_requires_internet == True and not allow_internet:
        print("[{0}] Skipping. Internet policy doesn't match".format(engine.name))
        continue

      if max_speed == None or engine.speed.value <= max_speed.value:
        engine_promise = self.scanner_strategy.scan(engine, path)
        scan_promises[engine] = engine_promise
      else:
        print("[{0}] Skipping scan. Too slow! AV: {1} Max: {2}".format(engine.name, engine.speed.value, max_speed.value))
        continue

    scan_promise = MultiActionPromise(engine_promises=scan_promises)

    # unregister events post scan
    if len(event_handlers) != 0:
      for event, handlers in event_handlers.items():
        for handler in handlers:
          scan_promise.then(
            lambda res: self.scanner_strategy.unsubscribe_event_handler(event, path, handler),
            lambda res: self.scanner_strategy.unsubscribe_event_handler(event, path, handler)
          )

    return scan_promise

  def scan_buffer(self, buf, max_speed=AV_SPEED.ALL, allow_internet=False, event_handlers = dict()):
    f = NamedTemporaryFile(delete=False, dir="/tmp/malware")
    f.write(buf)
    f.close()

    fname = f.name
    os.chmod(f.name, 436)

    scan_promise = self.scan(fname, max_speed, allow_internet, event_handlers)

    # unlink temp file if scan is done
    scan_promise.then(
      lambda res: self._unlink_temporary_file(fname),
      lambda res: self._unlink_temporary_file(fname)
    )

    return scan_promise

  def _unlink_temporary_file(self, fname):
    print("unlinking file")
    os.unlink(fname)
    print("unlinking complete")

  def get_scanners_state(self):
    scanners = {}
    for engine_class in self.engines:
      # create engine instance
      engine = engine_class(self.parser)

      scanners[engine.name] = not engine.is_disabled()

    return scanners

  def get_scanners(self):
    scanners = {}
    for engine_class in self.engines:
      # create engine instance
      engine = engine_class(self.parser)

      if engine.is_disabled():
        continue

      containers = self.scanner_strategy.find_containers_by_engine(engine)

      signature_version = containers[0].get_signature_version() if len(containers) != 0 else "-"

      scanners[engine.name] = {
        'signature_version': signature_version,
        'plugin_type': engine.plugin_type,
        'has_internet': engine.container_requires_internet
      }

    return scanners

  def update(self):
    return self.scanner_strategy.update()
