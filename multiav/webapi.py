import datetime
import os
import sys
import time
import traceback
import web
import json
import base64

from hashlib import md5, sha1, sha256
from multiprocessing import cpu_count
from rwlock import RWLock
from multiav.core import AV_SPEED, PLUGIN_TYPE, CMultiAV
from multiav.enumencoder import EnumEncoder
from multiav.exceptions import (CreateNetworkException, PullPluginException,
                                StartPluginException)
from multiav.safeconfigparserextended import SafeConfigParserExtended
from multiav.scannerstrategy import (AutoScaleDockerStrategy,
                                     LocalLimitDockerStrategy,
                                     LocalNoLimitDockerStrategy)

urls = (
    # web pages
    '/', 'index',
    '/upload', 'upload',
    '/about', 'about',
    '/last', 'last',
    '/search', 'search',
    '/export/csv', 'export_csv',
    '/update', 'update',
    '/system', 'system',
    # API endpoints
    '/api/v1/sample', 'api_sample',
    '/api/v1/sample/(.*)', 'api_manage_sample',
    '/api/v1/scanner', 'api_scanner'
)

app = web.application(urls, globals())
ROOT_PATH = os.path.dirname(__file__)
CURRENT_PATH = os.getcwd()
TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), 'templates')

# -----------------------------------------------------------------------
# MultiAV Instance
try:
    config_name = "config.cfg"

    # initialize config parser
    parser = SafeConfigParserExtended()
    parser.optionxform = str
    parser.read(config_name)

    # initialize correct scan strategy
    scan_strategies = {
        "local-no-limit": LocalNoLimitDockerStrategy,
        "local-limit": LocalLimitDockerStrategy,
        "auto-scale": AutoScaleDockerStrategy
    }
    scan_strategy = scan_strategies[parser.gets("MULTIAV", "SCAN_STRATEGY", "local-no-limit")](parser)

    # initialize multiav instance
    CAV = CMultiAV(scan_strategy, parser, auto_start=True, auto_pull=True)

    ENABLED_SCANNERS = CAV.get_scanners_state()
except PullPluginException as e:
    print(e)
    exit(2)
except StartPluginException as e:
    print(e)
    exit(3)
except CreateNetworkException as e:
    print(e)
    exit(4)

if not os.path.isdir(os.path.join(CURRENT_PATH, 'static')):
    raise Exception('runserver.py must be run in the directory {0}'.format(ROOT_PATH))


# -----------------------------------------------------------------------
class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


# -----------------------------------------------------------------------
class CDbSamples:
    def __init__(self, cfg_parser=parser):
        self.cfg_parser = cfg_parser
        self.plugin = self.cfg_parser.gets("MULTIAV", "DATABASE_PLUGIN", "postgres")
        self.name = self.cfg_parser.gets("MULTIAV", "DATABASE_NAME", "default-db")
        self.user = self.cfg_parser.gets("MULTIAV", "DATABASE_USER", "default-user")
        self.passwd = self.cfg_parser.gets("MULTIAV", "DATABASE_PASSWORD", "default-pass")
        self.host = self.cfg_parser.gets("MULTIAV", "DATABASE_HOST", "localhost")
        self.db = web.database(dbn=self.plugin, db=self.name, user=self.user, pw=self.passwd, host=self.host)
        self.db.printing = False
        self.create_schema()
        self.reports_lock = RWLock()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.db._unload_context(self.db._getctx())

    def create_schema(self):
        with self.db.transaction():
            try:
                self.db.query("""create table if not exists samples(
                                                id SERIAL NOT NULL primary key,
                                                name text,
                                                md5 text unique,
                                                sha1 text unique,
                                                sha256 text unique,
                                                size text)""")
                self.db.query("""create table if not exists reports(
                                                id SERIAL NOT NULL primary key,
                                                sample_id integer,
                                                infected integer,
                                                start_date text,
                                                end_date text,
                                                FOREIGN KEY(sample_id) REFERENCES samples(id) ON DELETE CASCADE)""")
                self.db.query("""create table if not exists scanners(
                                                id SERIAL NOT NULL primary key,
                                                name text,
                                                plugin_type integer,
                                                signature_version text,
                                                engine_version text,
                                                has_internet integer,
                                                speed text)""")
                self.db.query("""create table if not exists results(
                                                id SERIAL NOT NULL primary key,
                                                report_id integer,
                                                scanner_id integer,
                                                scanning boolean,
                                                queued boolean,
                                                result text,
                                                FOREIGN KEY(report_id) REFERENCES reports(id) ON DELETE CASCADE,
                                                FOREIGN KEY(scanner_id) REFERENCES scanners(id) ON DELETE CASCADE)""")
            except Exception as err1:
                print("Error:", sys.exc_info())[1]
                print("Database schema creation failed:", err1)

    def finish_sample_report(self, report_id):
        with self.reports_lock.writer_lock:
            try:
                with self.db.transaction():
                    '''where = 'report_id like $report_id'
          rows = self.db.select("results", where=where, vars={'report_id': report_id}).list()

          # calculate infected percentage
          result_clean = 0
          for row in rows:
            result = json.loads(row['result'])
            if not result["infected"]:
              result_clean += 1

          if result_clean == 0:
            infected = 0
          else:
            infected = ( result_clean / len(rows) ) * 100
          print("webapi: finish_sample_report infected: {0}%".format(infected))'''

                    where = 'id = $report_id'
                    self.db.update("reports", vars={'report_id': report_id}, where=where, end_date=time.asctime())
            except Exception as e:
                print("finish_sample_report exception:")
                print(e)

    def create_sample_report(self, name, buf):
        # default values
        infected = -1

        # calculate file properties
        md5_hash = md5(buf).hexdigest()
        sha1_hash = sha1(buf).hexdigest()
        sha256_hash = sha256(buf).hexdigest()
        size = len(buf)

        try:
            with self.reports_lock.writer_lock:
                with self.db.transaction():
                    # insert sample if not exists
                    query = "INSERT INTO samples(name, md5, sha1, sha256, size) SELECT $name, $md5, $sha1, $sha256, " \
                            "$size WHERE NOT EXISTS(SELECT 1 FROM samples WHERE sha256 = $sha256) "
                    self.db.query(query, vars={"name": name, "md5": md5_hash, "sha1": sha1_hash, "sha256": sha256_hash,
                                               "size": size})

                    # get sample id
                    res = self.search_sample_by_hash(sha256_hash)
                    sample_id = res[0].id

                    # insert report with sample_id
                    report_id = self.db.insert('reports', infected=infected, start_date=time.asctime(), end_date=None,
                                               sample_id=sample_id)

                    return report_id
        except Exception as e:
            print("Error Summary:", str(e))
            print("Error:", sys.exc_info()[1], md5_hash, sha1_hash, sha256_hash)
            return -1

    def add_scan_result(self, report_id, result, queued, scanning):
        # result e.g. {u'engine': u'0.100.2', u'updated': u'20190219', u'name': u'ClamAVMalice', u'has_internet':
        # False, u'infected': False, u'result': u'', u'speed': u'ULTRA', u'plugin_type': u'AV'}
        try:
            with self.reports_lock.writer_lock:
                with self.db.transaction():
                    scanners = self.get_scanner(result["name"]).list()

                    if len(scanners) == 0:
                        scanner_id = self.insert_scanner(
                            name=result["name"],
                            plugin_type=int(result["plugin_type"]),
                            has_internet=result["has_internet"],
                            speed=int(result["speed"]),
                            signature_version=result["updated"],
                            engine_version=result["engine"])
                    else:
                        scanner_id = scanners[0]["id"]

                    # skip insert if already exists
                    where = 'report_id = $report_id AND scanner_id = $scanner_id'
                    if len(list(self.db.select('results', where=where,
                                               vars={'report_id': report_id, 'scanner_id': scanner_id}))) != 0:
                        return

                    self.db.insert('results', report_id=report_id, scanner_id=scanner_id, queued=queued,
                                   scanning=scanning, result=json.dumps(result, cls=EnumEncoder))
        except Exception as err:
            print(err)

    def update_scan_result(self, report_id, result, queued, scanning):
        try:
            with self.reports_lock.writer_lock:
                with self.db.transaction():
                    scanners = self.get_scanner(result["name"]).list()

                    if len(scanners) == 0:
                        scanner_id = self.insert_scanner(
                            name=result["name"],
                            plugin_type=int(result["plugin_type"]),
                            has_internet=result["has_internet"],
                            speed=int(result["speed"]),
                            signature_version=result["updated"],
                            engine_version=result["engine"])
                    else:
                        scanner_id = scanners[0]["id"]

                    where = 'report_id = $report_id AND scanner_id = $scanner_id'
                    res = self.db.update('results', where=where,
                                         vars={'report_id': report_id, 'scanner_id': scanner_id}, queued=queued,
                                         scanning=scanning, result=json.dumps(result, cls=EnumEncoder))

                    if res == 0:
                        # no row updated, probably update called prior to add => it's a race
                        self.add_scan_result(report_id, result, queued, scanning)

        except Exception as e1:
            print("webapi: update_scan_result exception! report_id: {0} result: {1}".format(report_id, result))
            print(e1)

    def search_results_by_report_id(self, report_id):
        with self.reports_lock.reader_lock:
            with self.db.transaction():
                where = 'report_id = $report_id'
                rows = self.db.select("results", where=where, vars={'report_id': report_id}).list()

        results = []
        for row in rows:
            result = json.loads(row["result"])
            result["queued"] = row["queued"]
            result["scanning"] = row["scanning"]
            results.append(result)

        return results

    def search_report_by_id(self, report_id):
        with self.reports_lock.reader_lock:
            with self.db.transaction():
                query = "SELECT reports.id,samples.name,samples.md5,samples.sha1,samples.sha256,samples.size," \
                        "reports.infected,reports.start_date,reports.end_date " \
                        "FROM samples " \
                        "LEFT JOIN reports ON samples.id = reports.sample_id " \
                        "WHERE reports.id = $report_id"
                rows = self.db.query(query, vars={"report_id": report_id}).list()
                for row in rows:
                    row["result"] = self.search_results_by_report_id(report_id)
                return rows

    def search_sample_by_hash(self, file_hash):
        with self.reports_lock.reader_lock:
            with self.db.transaction():
                query = "SELECT samples.id,samples.name,samples.md5,samples.sha1,samples.sha256,samples.size," \
                        "reports.id AS report_id,reports.infected,reports.start_date,reports.end_date,results.result " \
                        "FROM samples " \
                        "LEFT JOIN reports ON samples.id = reports.sample_id " \
                        "LEFT JOIN results ON results.report_id = reports.id " \
                        "WHERE md5=$hash OR sha1=$hash OR sha256=$hash OR samples.name like $hash"
                rows = self.db.query(query, vars={"hash": file_hash})
                return rows

    def search_samples(self, value):
        with self.reports_lock.reader_lock:
            with self.db.transaction():
                if value is None:
                    query = "SELECT samples.id,samples.name,samples.md5,samples.sha1,samples.sha256,samples.size," \
                            "reports.id AS report_id,reports.infected,reports.start_date,reports.end_date " \
                            "FROM samples " \
                            "LEFT JOIN reports ON samples.id = reports.sample_id "
                    rows = self.db.query(query).list()
                else:
                    query = "SELECT samples.id,samples.name,samples.md5,samples.sha1,samples.sha256,samples.size," \
                            "reports.id AS report_id,reports.infected,reports.start_date,reports.end_date " \
                            "FROM samples " \
                            "LEFT JOIN reports ON samples.id = reports.sample_id " \
                            "WHERE md5=$val OR sha1=$val OR sha256=$val OR samples.name like $val"
                    rows = self.db.query(query, vars={"val": value}).list()

                for row in rows:
                    row["result"] = self.search_results_by_report_id(row["report_id"])
                return rows

    def count_reports(self):
        with self.reports_lock.reader_lock:
            with self.db.transaction():
                query = "SELECT COUNT(*) as total_reports FROM reports"
                return int(list(self.db.query(query))[0]["total_reports"])

    def last_samples(self, limit, page):
        with self.reports_lock.reader_lock:
            with self.db.transaction():
                offset = limit * page
                query = "SELECT samples.id,samples.name,samples.md5,samples.sha1,samples.sha256,samples.size," \
                        "reports.id AS report_id,reports.infected,reports.start_date,reports.end_date " \
                        "FROM samples " \
                        "LEFT JOIN reports ON samples.id = reports.sample_id " \
                        "ORDER BY reports.id desc " \
                        "LIMIT $limit " \
                        "OFFSET $offset"
                rows = self.db.query(query, vars={'limit': limit, 'offset': offset}).list()
                for row in rows:
                    row["result"] = self.search_results_by_report_id(row["report_id"])
                return rows

    def get_samples(self):
        with self.reports_lock.reader_lock:
            with self.db.transaction():
                query = "SELECT reports.id AS id,samples.name,samples.md5,samples.sha1," \
                        "samples.sha256,samples.size,reports.start_date,reports.end_date " \
                        "FROM samples " \
                        "LEFT JOIN reports ON samples.id = reports.sample_id "
                return self.db.query(query).list()

    def get_scanners(self):
        with self.db.transaction():
            rows = self.db.select("scanners")
            return rows

    def get_scanner(self, name):
        with self.db.transaction():
            where = 'name like $name'
            rows = self.db.select("scanners", where=where, vars={'name': name})
            return rows

    def insert_scanner(self, name, plugin_type, has_internet, speed, signature_version, engine_version):
        if isinstance(plugin_type, int):
            plugin_type_value = plugin_type
        else:
            plugin_type_value = plugin_type.value

        has_internet = 1 if has_internet is True else 0

        try:
            with self.db.transaction():
                row = self.get_scanner(name)
                if len(row.list()) == 0:
                    row = self.db.insert("scanners", name=name, plugin_type=plugin_type_value,
                                         has_internet=has_internet, speed=speed,
                                         signature_version=str(signature_version), engine_version=str(engine_version))

                return row
        except Exception as e:
            print("Exception insert_scanner")
            print(locals())
            print(e)
            return False

    def update_scanner(self, name, plugin_type, has_internet, speed, signature_version, engine_version=None):
        # prevent unknown type errors
        if isinstance(plugin_type, int):
            plugin_type_value = plugin_type
        else:
            plugin_type_value = plugin_type.value

        has_internet = 1 if has_internet is True else 0

        # store data
        where = 'name = $name'

        try:
            with self.db.transaction():
                if engine_version is not None:
                    updated_rows = self.db.update("scanners", vars={"name": name}, where=where, \
                                                  plugin_type=plugin_type_value, has_internet=has_internet, speed=speed, \
                                                  signature_version=str(signature_version),
                                                  engine_version=str(engine_version))
                else:
                    updated_rows = self.db.update("scanners", vars={"name": name}, where=where, \
                                                  plugin_type=plugin_type_value, has_internet=has_internet, speed=speed, \
                                                  signature_version=str(signature_version))
        except Exception as e:
            print("Exception update_scanner")
            print(locals())
            print(e)

        # insert new scanner if none existed)
        if updated_rows == 0:
            self.insert_scanner(
                name=name,
                plugin_type=plugin_type,
                has_internet=has_internet,
                speed=speed,
                signature_version=signature_version,
                engine_version=engine_version if engine_version is not None else "-")

        return updated_rows


# -----------------------------------------------------------------------
def convert_result_rows_to_ui_datastructure(rows):
    result_array = []
    for scan_result in rows:
        # calculate additionally used data and setup result object
        result = {
            "start_date": datetime.datetime.strptime(scan_result['start_date'], '%a %b %d %H:%M:%S %Y')
            if scan_result['start_date'] is not None else None,
            "end_date": datetime.datetime.strptime(scan_result['end_date'], '%a %b %d %H:%M:%S %Y')
            if scan_result['end_date'] is not None else None,
            "hashes": {
                "md5": scan_result['md5'],
                "sha1": scan_result['sha1'],
                "sha256": scan_result['sha256']
            },
            "file": {
                "name": scan_result['name'],
                "size": scan_result['size'],
            },
            "statistics": {
                "engine_count": 0,
                "engine_detected_count": 0
            }
        }

        for plugin_type in PLUGIN_TYPE:
            result[plugin_type] = {}

        # sort results by plugin_type
        for res_obj in scan_result['result']:
            # store result
            plugin_type = PLUGIN_TYPE(res_obj["plugin_type"])
            result[plugin_type][res_obj["name"]] = res_obj

            if plugin_type == PLUGIN_TYPE.AV:
                # update statistics
                has_error, error = result_has_error(res_obj)
                if not has_error:
                    result["statistics"]["engine_count"] += 1

                    if res_obj["infected"]:
                        result["statistics"]["engine_detected_count"] += 1

        if result["statistics"]["engine_count"] != 0:
            result["statistics"]["infected"] = int(float(result["statistics"]["engine_detected_count"]) / float(
                result["statistics"]["engine_count"]) * 100)
        else:
            result["statistics"]["infected"] = 0
        result_array.append(result)

    return result_array


def plugin_type_to_string(plugin_type):
    return PLUGIN_TYPE(plugin_type).name.lower()


def result_has_error(result):
    if not "error" in result:
        return False, None

    if result["error"] == "":
        return False, None

    return True, result["error"]


# -----------------------------------------------------------------------
class last:
    def GET(self):
        try:
            i = web.input()
            if 'limit' in i:
                limit = int(i['limit'])
            else:
                limit = 20

            if 'page' in i:
                page = int(i['page']) - 1
                if page < 0:
                    page = 0
            else:
                page = 0

            with CDbSamples() as db:
                rows = db.last_samples(limit, page)

            result_array = convert_result_rows_to_ui_datastructure(rows)

            # calculate the pagination stuff
            total_reports_count = db.count_reports()
            total_pages = int(total_reports_count / limit)

            nextpage = page + 1
            if nextpage > total_pages:
                nextpage = total_pages
                print(nextpage)

            pagination = {
                "backpage": 0,
                "backpage_disabled": False,
                "currentpage": page + 1,
                "nextpage": nextpage + 1,
                "nextpage_disabled": False
            }

            pagenumbers = {0}
            if page > 1:
                pagenumbers.add(page)

            if total_pages > 1 and total_pages != page + 1:
                pagenumbers.add(total_pages - 1)
            else:
                pagination["nextpage_disabled"] = True

            # show next 2 page numbers
            max_pages_to_add = 2
            added_pages = 0
            for i in range(page, total_pages):
                if added_pages > max_pages_to_add:
                    break
                pagenumbers.add(i)
                added_pages += 1

            # show last 2 page numbers
            added_pages = 0
            for i in range(page - max_pages_to_add, page):
                if added_pages > max_pages_to_add:
                    break

                if i <= 0:
                    continue

                pagenumbers.add(i)
                added_pages += 1

            # increase all added numbers by one => ui => page 0 = page 1
            pagination["pages"] = sorted(map(lambda page: page + 1, pagenumbers))

            if page + 1 == 1:
                pagination["backpage"] = 1
                pagination["backpage_disabled"] = True
            else:
                # page + 1 - 1 = page
                pagination["backpage"] = page

            render = web.template.render(TEMPLATE_PATH, globals={
                "type": type,
                "map": map,
                "sorted": sorted,
                "result_has_error": result_has_error,
                "PLUGIN_TYPE": PLUGIN_TYPE})
            return render.last(result_array, pagination)
        except Exception as e:
            return '{exception: {0}}'.format(e)


# -----------------------------------------------------------------------
class search:
    def GET(self):
        # support search using GET parameters
        i = web.input(q="", id="")
        if i["q"] != "" or i["id"] != "":
            return self.POST()

        # show search mask
        render = web.template.render(TEMPLATE_PATH)
        return render.search(None)

    def POST(self):
        render = web.template.render(TEMPLATE_PATH, globals={
            "type": type,
            "map": map,
            "sorted": sorted,
            "result_has_error": result_has_error,
            "plugin_type_to_string": plugin_type_to_string,
            "PLUGIN_TYPE": PLUGIN_TYPE})

        # Get querys from params
        querylist = []
        search = None

        with CDbSamples() as db:
            i = web.input(q="", id="")
            if i["q"] != "":
                querylist = i["q"].split(',')
                search = db.search_samples
            elif i["id"] != "":
                querylist = i["id"].split(',')
                search = db.search_report_by_id
            else:
                return render.search(None)

        # perform search
        result_array = []

        for query in list(set(querylist)):
            rows = search(query)
            result_array += convert_result_rows_to_ui_datastructure(rows)

        if len(result_array) == 0:
            return render.search("No match")

        return render.search_results(result_array, ','.join(querylist))


# -----------------------------------------------------------------------
class export_csv:
    def process_query_result(self, rows, headers):
        data = []
        for row in rows:
            data_row = {}
            result = row['result']
            '''[
          {'magic': {'mime': 'text/xml', 'description': 'XML 1.0 document, UTF-8 Unicode (with BOM) text, with CRLF line terminators'}, 'ssdeep': '24:JdFHvQdjzgMFUAuKRMkNgwcYSejipyK0Y9WvcQqpQqSb8FQorZWKAikCDK3ArKyk:3FSzWEfNPipyfY0UnpnSHH0kCD6sc1pN', 'trid': ['72.7% (.XML) Generic XML (UTF-8) (8000/1)', '27.2% (.TXT) Text - U
        TF-8 encoded (3000/1)'], 'exiftool': {'ExifToolVersionNumber': '11.11', 'FileSize': '1303 bytes', 'FileType': 'XML', 'FileTypeExtension': 'xml', 'MIMEType': 'application/xml', 'PrefsDataAdaptiveTrainingEnabled': 'False', 'PrefsDataAnimalNameMode': 'None', 'PrefsDataAutosaveIntervalDays': '1', 'PrefsDataCustomCursorE
        nabled': 'True', 'PrefsDataDevMode': 'False', 'PrefsDataEdgeScreenScroll': 'True', 'PrefsDataExtremeDifficultyUnlocked': 'True', 'PrefsDataFullscreen': 'True', 'PrefsDataHatsOnlyOnMap': 'False', 'PrefsDataLangFolderName': 'English', 'PrefsDataLogVerbose': 'False', 'PrefsDataMaxNumberOfPlayerSettlements': '1', 'Prefs
        DataPauseOnError': 'False', 'PrefsDataPauseOnLoad': 'False', 'PrefsDataPauseOnUrgentLetter': 'True', 'PrefsDataPlantWindSway': 'True', 'PrefsDataPreferredNames': '', 'PrefsDataResetModsConfigOnCrash': 'True', 'PrefsDataResourceReadoutCategorized': 'True', 'PrefsDataRunInBackground': 'True', 'PrefsDataScreenHeight':
        '1440', 'PrefsDataScreenWidth': '2560', 'PrefsDataShowRealtimeClock': 'True', 'PrefsDataTemperatureMode': 'Celsius', 'PrefsDataTestMapSizes': 'False', 'PrefsDataUiScale': '1', 'PrefsDataVolumeAmbient': '1', 'PrefsDataVolumeGame': '0.8', 'PrefsDataVolumeMusic': '0.4'}, 'name': 'FileInfo', 'plugin_type': 2, 'speed': -
        1, 'has_internet': False, 'queued': 0, 'scanning': 0},
        {'infected': False, 'result': '', 'engine': '4.6.5.141', 'updated': '20190509', 'name': 'FProt', 'plugin_type': 1, 'speed': 0, 'has_internet': False, 'queued': 0, 'scanning': 0},
        {'infected': False, 'result': '', 'engine': '3.0.0', 'database': '19050802', 'updated': '20190508', 'name': 'Avast', 'plugin_type': 1, 'speed': 0, 'has_internet': False, 'queued': 0, 'scanning': 0},
        {'infected': False, 'result': '', 'engine': '', 'database': '', 'updated': '', 'error': 'exit status 2', 'name': 'Avg', 'plugin_type': 1, 'speed': -1, 'has_internet': False, 'queued': 0, 'scanning': 0},
        {'infected': False, 'result': '', 'engine': '7.141118', 'updated': '20190509', 'name': 'BitDefender', 'plugin_type': 1, 'speed': 1, 'has_internet': False, 'queued': 0, 'scanning': 0},
        {'infected': False, 'result': '', 'engine': '0.100.2', 'known': '6802108', 'updated': '20190509', 'name': 'ClamAV', 'plugin_type':1, 'speed': -1, 'has_internet': False, 'queued': 0, 'scanning': 0},
        {'infected': False, 'result': '', 'engine': '5.0.163652.1142', 'updated': '20190509', 'name': 'Comodo', 'plugin_type': 1, 'speed': 0, 'has_internet': False, 'queued': 0, 'scanning': 0},
        {'infected': False, 'result': '', 'engine': '7.0-20', 'updated': '20190509', 'name': 'EScan', 'plugin_type': 1, 'speed': 0, 'has_internet': False, 'queued': 0, 'scanning': 0},
        {'infected': False, 'result': '', 'results': {'fse': '', 'aquarius': ''}, 'engine': '11.10 build 68', 'database': '2019-05-01_03', 'updated': '20190509', 'name': 'FSecure', 'plugin_type': 1, 'speed': 1, 'has_internet': False, 'queued': 0, 'scanning': 0},
        {'infected': False, 'result': '', 'engine': '5600.1067', 'database': '9251', 'updated': '20190509', 'name': 'McAfee', 'plugin_type': 1, 'speed': 0, 'has_internet': False, 'queued': 0, 'scanning': 0},
        {'infected': False, 'result': '', 'engine': '5.01.05', 'database':'09.05.2019 07:41:53 (Build: 101547)', 'updated': '20190509', 'name': 'Ikarus', 'plugin_type': 1, 'speed': 0, 'has_internet': False, 'queued': 0, 'scanning': 0},
        {'infected': False, 'result': '', 'engine': '5.53.0', 'database': '5.63', 'updated': '20190509', 'name': 'Sophos', 'plugin_type': 1, 'speed': 2, 'has_internet': False, 'queued': 0, 'scanning': 0}
        ]'''

            for value in result:
                if not "name" in value:
                    continue

                name = value["name"]
                if int(value["plugin_type"]) == PLUGIN_TYPE.AV.value:
                    version = value['engine'].replace('\n', ' ').replace('\r', '') + \
                              ' ' + \
                              value['updated'].replace('\n', ' ').replace('\r', '')

                    has_error, error = result_has_error(value)

                    if has_error:
                        res = error
                    elif value["queued"] == 1:
                        res = "queued"
                    elif value["scanning"] == 1:
                        res = "scanning"
                    else:
                        # no error, not scanning or queued => should be done :)
                        if "results" in value:
                            # fsecure returning results of 2 engines. entry's called resultS with s instead of result
                            res = " ".join(value['results'].values())
                        else:
                            res = value['result'] if len(value['result']) != 0 else 'clean'

                    data_row[name] = res
                    data_row[name + '-version'] = version
                else:
                    data_row[name] = json.dumps(value, cls=EnumEncoder)

            for key in headers:
                data_row[key] = row[key]

            data.append(data_row)
        return data

    def GET(self):
        headers = ['name', 'md5', 'sha1', 'sha256', 'start_date']
        data = []

        with CDbSamples() as db:
            # get querys
            i = web.input(q=None, l=None, p=None)
            if i["q"] != None:
                print("all results with query")
                querys = list(set(i["q"].split(',')))

                # execute search
                for query in querys:
                    rows = db.search_samples(query)
                    data += self.process_query_result(rows, headers)

            elif i["l"] != None and i["p"] != None:
                print("limited search")
                limit = int(i["l"])
                page = int(i["p"])
                rows = db.last_samples(limit, page)
                data += self.process_query_result(rows, headers)

            else:
                print("all results")
                rows = db.search_samples(None)
                data += self.process_query_result(rows, headers)

        # generate headers
        engines = set()
        for row in data:
            engines.update(row)
        engines = list(engines - set(headers))
        engines.sort()

        # return & generate csv
        csv = []
        csv.append(';'.join(headers + engines))
        for report in data:
            row = []
            for key in headers:
                if key in report:
                    row.append(report[key])
                else:
                    row.append('n/a')

            for key in engines:
                if key in report:
                    row.append(report[key])
                else:
                    row.append('not scanned')

            csv.append(';'.join(row))

        web.header('Content-Type', 'text/csv')
        web.header('Content-disposition', 'attachment; filename=multi-av-export.csv')

        return '\n'.join(csv)


# -----------------------------------------------------------------------
class index:
    def GET(self):
        with CDbSamples() as db:
            db_scanners = db.get_scanners().list()

        for scanner in db_scanners:
            scanner["enabled"] = ENABLED_SCANNERS[scanner.name]
            scanner["speed"] = AV_SPEED(int(scanner["speed"])).name.lower().capitalize()
            scanner["plugin_type"] = PLUGIN_TYPE(int(scanner["plugin_type"])).name.lower().capitalize()

        render = web.template.render(TEMPLATE_PATH, globals={"sorted": sorted})
        return render.index(db_scanners, cpu_count(), AV_SPEED)


# -----------------------------------------------------------------------
class about:
    def GET(self):
        render = web.template.render(TEMPLATE_PATH)
        return render.about()


# -----------------------------------------------------------------------
class api_manage_sample:
    def GET(self, sample_id):
        try:
            sample_id = int(sample_id)
            if sample_id <= 0:
                raise Exception("invalid sample id")

            with CDbSamples() as db:
                result = db.search_report_by_id(sample_id)

            if len(result) != 1:
                print("webapi: error returning report for id {0}: not found".format(sample_id))
                raise Exception("report not found")

            print("webapi: returning report for id {0}".format(sample_id))

            web.header("Content-Type", "application/json")
            return json.dumps(result[0])
        except Exception as e:
            raise web.HTTPError(status="400 Bad Request", headers={"Content-Type": "application/json"},
                                data=json.dumps({
                                    "error": str(e)
                                }))


# -----------------------------------------------------------------------
class api_sample:
    def GET(self):
        try:
            with CDbSamples() as db:
                samples = db.get_samples()

            web.header("Content-Type", "application/json")
            return json.dumps(samples)
        except Exception as e:
            raise web.HTTPError(status="400 Bad Request", headers={"Content-Type": "application/json"},
                                data=json.dumps({
                                    "error": str(e)
                                }))

    def POST(self):
        try:
            request_data = json.loads(web.data())

            # get request data
            if not "minspeed" in request_data:
                raise Exception("missing parameter: minspeed")

            minspeed = request_data["minspeed"]
            av_min_speed = AV_SPEED(int(minspeed))

            if not "allow_internet" in request_data:
                raise Exception("missing parameter: allow_internet")

            av_allow_internet = request_data["allow_internet"].lower() == "true"

            if not "sample" in request_data:
                raise Exception("missing parameter: sample")
            if not "sample_name" in request_data:
                raise Exception("missing parameter: sample_name")

            buf = base64.b64decode(request_data["sample"])
            filename = request_data["sample_name"]

            # Setup the report (the json response)
            report = {
                "hashes": {
                    "md5": md5(buf).hexdigest(),
                    "sha1": sha1(buf).hexdigest(),
                    "sha256": sha256(buf).hexdigest()
                },
                "file": {
                    "name": filename,
                    "size": len(buf),
                }
            }

            # Persist report to db
            print("webapi: starting insert")
            with CDbSamples() as db:
                report["id"] = db.create_sample_report(filename, buf)
                print("webapi: insert complete")

                # Queue the file scan
                scan_promise = CAV.scan_buffer(
                    buf,
                    av_min_speed,
                    av_allow_internet,
                    {"pre": [lambda engine, filename: self.pre_scan_action(report["id"], engine, filename)]})

                scan_promise.engine_then(
                    lambda res: self.post_engine_scan_action(report["id"], res),
                    lambda res: self.post_engine_scan_action(report["id"], res)
                )
                scan_promise.then(
                    lambda res: self.post_scan_action(report["id"], res),
                    lambda res: self.post_scan_action(report["id"], res)
                )

                print("webapi: scan queued")

                # Create initial scan reports in db
                for engine in scan_promise.get_scanning_engines():
                    initial_scan_report = {
                        'engine': '',
                        'updated': '',
                        'name': engine.name,
                        'has_internet': engine.container_requires_internet,
                        'infected': '',
                        'result': '',
                        'speed': engine.speed.value,
                        'plugin_type': engine.plugin_type.value
                    }
                    db.add_scan_result(report["id"], initial_scan_report, queued=True, scanning=False)

            web.header("Content-Type", "application/json")
            return json.dumps(report, cls=EnumEncoder)
        except Exception as e:
            raise web.HTTPError(status="400 Bad Request", headers={"Content-Type": "application/json"},
                                data=json.dumps({
                                    "error": str(e)
                                }))

    # Function to call after a scan task is processed
    def post_engine_scan_action(self, report_id, res):
        try:
            res = json.loads(res)
            scanner_name = res["name"]

            print("webapi: updateing result from scanner {0}".format(scanner_name))
            with CDbSamples() as db:
                db.update_scan_result(report_id, res, queued=False, scanning=False)
                print("webapi: updated result from {0}".format(scanner_name))

                # Update scanner db
                if "error" in res:
                    return

                signature_version = res["updated"] if "updated" in res else "-"
                engine_version = res["engine"] if "engine" in res else "-"
                plugin_type = res["plugin_type"]
                has_internet = res["has_internet"]
                speed = res["speed"]

                print("webapi: updating scanner data for {0}".format(scanner_name))
                db.update_scanner(
                    name=scanner_name,
                    plugin_type=plugin_type,
                    has_internet=has_internet,
                    speed=speed,
                    signature_version=signature_version,
                    engine_version=engine_version)
                print("webapi: scanner db update for {0} complete".format(scanner_name))

        except Exception as e:
            print("webapi: post engine scan exception")
            print(e)

    def post_scan_action(self, report_id, res):
        print("webapi: finishing scan report {0}".format(report_id))
        try:
            with CDbSamples() as db:
                db.finish_sample_report(report_id)

            print("webapi: Scan report for {0} finished".format(report_id))
        except Exception as e:
            print("webapi: post scan action exception")
            print(e)

    def pre_scan_action(self, report_id, engine, filename):
        print("webapi: scanning file of report {0} with engine {1}...!".format(report_id, engine.name))
        try:
            with CDbSamples() as db:
                db.update_scan_result(report_id, {
                    'scanning': True,
                    'engine': '',
                    'updated': '',
                    'name': engine.name,
                    'has_internet': engine.container_requires_internet,
                    'infected': '',
                    'result': '',
                    'speed': engine.speed.value,
                    'plugin_type': engine.plugin_type.value
                }, queued=False, scanning=True)

            print("webapi: state of engine {1} in report {0} is set to scanning".format(report_id, engine.name))
        except Exception as e:
            print("webapi: pre scan action exception")
            print(e)


# -----------------------------------------------------------------------
# Legacy non js upload via web form
class upload:
    def POST(self):
        render = web.template.render(TEMPLATE_PATH)

        i = web.input(file_upload={})
        if i["file_upload"] is None or i["file_upload"] == "":
            return render.error("No file uploaded or invalid file.")

        buf = i["file_upload"].value
        filename = i["file_upload"].filename

        # Scan the file
        scan_results = CAV.scan_buffer(buf)

        # Calculate the hashes
        hashes = {
            "md5": md5(buf).hexdigest(),
            "sha1": sha1(buf).hexdigest(),
            "sha256": sha256(buf).hexdigest()
        }

        # File properties
        file_properties = {
            "name": filename,
            "size": len(buf)
        }

        # Persist results to db
        with CDbSamples() as db:
            report_id = db.create_sample_report(filename, buf)

            # Update scanner db
            for scanner_name in scan_results:
                signature_version = scan_results[scanner_name]["updated"] if "updated" in scan_results[
                    scanner_name] else "-"
                engine_version = scan_results[scanner_name]["engine"] if "engine" in scan_results[scanner_name] else "-"
                plugin_type = scan_results[scanner_name]["plugin_type"]
                has_internet = scan_results[scanner_name]["has_inernet"]
                speed = int(scan_results[scanner_name]["speed"])

                db.update_scanner(
                    name=scanner_name,
                    plugin_type=plugin_type,
                    has_internet=has_internet,
                    speed=speed,
                    signature_version=signature_version,
                    engine_version=engine_version)

        # And show the results
        return render.results(report_id, scan_results, hashes, file_properties)


# -----------------------------------------------------------------------
update_results = {
    "start_date": "-",
    "end_date": "-",
    "is_auto_scale_strategy": False,
    "last_refresh": None,
    "update_scan_lock": None,
    "results": dict()
}


class update:
    def GET(self):
        if update_results["start_date"] == "-" and update_results["end_date"] == "-":
            return index().GET()

        # show results
        render = web.template.render(TEMPLATE_PATH,
                                     globals={"sorted": sorted, "plugin_type_to_string": plugin_type_to_string})
        update_results['last_refresh'] = datetime.datetime.now()
        return render.update(update_results)

    def _post_engine_update(self, result):
        try:
            scanner_name = result['engine']
            print("webapi: update of {0} complete!".format(scanner_name))

            # store to temp object
            if update_results['is_auto_scale_strategy']:
                result["exported"] = "..."

            update_results['results'][result['container_name']] = result

            # update db if required
            update_successs = result['updated'] != "error"
            if update_successs:
                plugin_type = result["plugin_type"]
                has_internet = result["has_internet"]
                signature_version = result["signature_version"]
                engine_version = result["signature_version"] if "signature_version" in result else "-"
                speed = int(result["speed"].value)

                with CDbSamples() as db:
                    db.update_scanner(
                        name=scanner_name,
                        plugin_type=plugin_type,
                        has_internet=has_internet,
                        speed=speed,
                        signature_version=signature_version,
                        engine_version=engine_version)

        except Exception as e:
            print("webapi: _post_engine_update EXCEPTION")
            traceback.print_exc()

    def _post_all_engines_updated(self, result):
        try:
            update_results['engine_update_complete_date'] = datetime.datetime.now()
            print("webapi: all engines updated")
        except Exception as e:
            print("webapi: _post_all_engines_updated EXCEPTION")
            traceback.print_exc()

    def _post_engine_export(self, result):
        try:
            '''result = {
          "machine_id": self.id,
          "engine_names": [engine_name, ...],
          "images": images,
          "date": datetime.datetime.now()}'''
            if isinstance(result, Exception):
                print("webapi: exception in _post_engine_export result detected")
                print(result)
                return

            print("webapi: export process finished: machine_id: {0} engine: {1}".format(result['machine_id'], " ".join(
                result['engine_names'])))
            for engine_name in result["engine_names"]:
                # set exported as ok
                update_results['results'][engine_name]["exported"] = "ok"
                # set scp as ongoing
                for machine_id in list(update_results['machine_results']):
                    update_results['machine_results'][machine_id][engine_name] = "scp"
        except Exception as e:
            print("webapi: _post_engine_export EXCEPTION")
            traceback.print_exc()

    def _post_all_engine_exported(self, result):
        try:
            update_results['engine_export_complete_date'] = datetime.datetime.now()
            print("webapi: all engines exported")
        except Exception as e:
            print("webapi: _post_all_engine_exported EXCEPTION")
            traceback.print_exc()

    def _post_scp_to_workers(self, result):
        try:
            '''result = {
          "machine_id": manager_machine.id,
          "file": update_file,
          "engine_name": engine_name,
          "date": datetime.datetime.now()}'''
            if isinstance(result, Exception):
                print("webapi: exception in scp_process result detected")
                print(result)
                return

            engine_name = result['engine_name']
            print("webapi: scp process finished: machine_id: {0} engine: {1}".format(result['machine'].id, engine_name))

            for machine_id in list(update_results['machine_results']):
                if update_results["update_scan_lock"]:
                    update_results['machine_results'][machine_id][engine_name] = "load"
                else:
                    update_results['machine_results'][machine_id][engine_name] = "wait"

            # check if all promises are resolved
            all_resolved = True
            for machine_id in list(update_results['machine_results']):
                for engine_name in list(update_results['machine_results'][machine_id]):
                    if update_results['machine_results'][machine_id][engine_name] == "-":
                        all_resolved = False

            if all_resolved:
                print("webapi: all scp promises fullfiled. setting scp_complete_date...")
                update_results['scp_complete_date'] = datetime.datetime.now()

        except:
            print("webapi: _post_scp_to_workers EXCEPTION")
            print(result)
            traceback.print_exc()

    def _worker_image_load_unlocked(self, result):
        try:
            for machine_id in list(update_results['machine_results']):
                for engine_name in list(update_results['machine_results'][machine_id]):
                    if update_results['machine_results'][machine_id][engine_name] == "wait":
                        update_results['machine_results'][machine_id][engine_name] = "load"

            update_results['update_scan_lock'] = "set"
            update_results['load_started_date'] = result
        except Exception as e:
            print("webapi: _worker_image_load_started EXCEPTION")
            traceback.print_exc()

    def _post_worker_image_load(self, result):
        try:
            ''' result = {
            "machine_id": machine_id,
            "engine_name": engine_name,
            "update_file": update_file,
            "date": str(datetime.datetime.now())}'''
            if isinstance(result, Exception):
                print("webapi: exception in _post_worker_image_load result detected")
                print(result)
                return

            print("webapi: image load finished: machine_id: {0} engine: {1}".format(result['machine_id'],
                                                                                    result['engine_name']))
            update_results['machine_results'][result['machine_id']][result['engine_name']] = "ok"
            # no need to check if all promises are resolved => if so, update promise if resolved
        except Exception as e:
            print("webapi: _post_worker_image_load EXCEPTION")
            traceback.print_exc()

    def _update_complete(self, result):
        try:
            update_results['end_date'] = datetime.datetime.now()
            update_results["update_scan_lock"] = "unset"
            print("webapi: update complete")
        except Exception as e:
            print("webapi: _update_complete EXCEPTION")
            traceback.print_exc()

    def _initialize_update_data_structure(self):
        update_results = {
            "start_date": "-",
            "end_date": "-",
            'is_auto_scale_strategy': False,
            "last_refresh": None,
            "results": dict()
        }

    def POST(self):
        # check if update is already running / pending
        if update_results["start_date"] != "-" and update_results["end_date"] == "-":
            return self.GET()

        # Initialize data structure
        self._initialize_update_data_structure()

        # Update
        update_results['start_date'] = datetime.datetime.now()
        update_results['is_auto_scale_strategy'] = isinstance(CAV.scanner_strategy, AutoScaleDockerStrategy)

        print("wabapi: starting update of all containers...")
        update_promise = CAV.update()

        if update_results['is_auto_scale_strategy']:
            # AUTO SCALE STRATEGY UPDATE
            update_results['engine_update_complete_date'] = "-"
            update_results['engine_export_complete_date'] = "-"
            update_results['scp_complete_date'] = "-"
            update_results['load_started_date'] = "-"
            update_results['update_scan_lock'] = "queue"
            update_results['machine_results'] = dict()

            # update temp data structure with results
            update_promise["engine_update_promise"].engine_then(
                lambda res: self._post_engine_update(res),
                lambda res: self._post_engine_update(res)
            ).then(
                lambda res: self._post_all_engines_updated(res),
                lambda res: self._post_all_engines_updated(res)
            )

            # export promises
            update_promise["engine_export_promise"].engine_then(
                lambda res: self._post_engine_export(res),
                lambda res: self._post_engine_export(res)
            ).then(
                lambda res: self._post_all_engine_exported(res),
                lambda res: self._post_all_engine_exported(res)
            )

            # scp promises
            for worker, multi_action_promise in update_promise["scp_to_workers_promises"].items():
                multi_action_promise.engine_then(
                    lambda res: self._post_scp_to_workers(res),
                    lambda res: self._post_scp_to_workers(res)
                )
            # load unlocked promise (hits when lock tasks is executed by the pool)
            update_promise["worker_image_load_unlocked_promise"].then(
                lambda res: self._worker_image_load_unlocked(res),
                None
            )

            # load promises
            for worker, multi_action_promise in update_promise["worker_images_load_promises"].items():
                multi_action_promise.engine_then(
                    lambda res: self._post_worker_image_load(res),
                    lambda res: self._post_worker_image_load(res)
                )

            update_promise['update_complete_promise'].then(
                lambda res: self._update_complete(res),
                lambda res: self._update_complete(res)
            )

            # set initial data in temp data structure
            for machine, engine_dict in update_promise["scp_to_workers_promises"].items():
                update_results['machine_results'][machine.id] = dict()
                for engine, values in engine_dict._engine_promises.items():
                    update_results['machine_results'][machine.id][engine.container_name] = "-"

            for engine in update_promise["engine_update_promise"].get_scanning_engines():
                update_results["results"][engine.container_name] = {
                    'engine': engine.name,
                    'updated': "...",
                    'exported': "-",
                    'old_signature_version': "...",
                    'old_container_build_time': "...",
                    'signature_version': "...",
                    'container_build_time': "...",
                    'plugin_type': engine.plugin_type,
                    'has_internet': engine.container_requires_internet,
                    'speed': engine.speed
                }
        elif isinstance(CAV.scanner_strategy, LocalNoLimitDockerStrategy):
            update_results["update_scan_lock"] = "set"

            # update temp data structure with results
            update_promise.engine_then(
                lambda res: self._post_engine_update(res),
                lambda res: self._post_engine_update(res)
            ).then(
                lambda res: self._update_complete(res),
                lambda res: self._update_complete(res)
            )

            for engine in update_promise.get_scanning_engines():
                update_results["results"][engine.container_name] = {
                    'engine': engine.name,
                    'updated': "...",
                    'exported': "-",
                    'old_signature_version': "...",
                    'old_container_build_time': "...",
                    'signature_version': "...",
                    'container_build_time': "...",
                    'plugin_type': engine.plugin_type,
                    'has_internet': engine.container_requires_internet,
                    'speed': engine.speed
                }
        elif isinstance(CAV.scanner_strategy, LocalLimitDockerStrategy):
            # update temp data structure with results
            update_promise["engine_update_promise"].engine_then(
                lambda res: self._post_engine_update(res),
                lambda res: self._post_engine_update(res)
            ).then(
                lambda res: self._update_complete(res),
                lambda res: self._update_complete(res)
            )

            # load unlocked promise (hits when lock tasks is executed by the pool)
            def update_lock_state(state):
                update_results['update_scan_lock'] = state

            update_promise["update_lock_set_promise"].then(
                lambda res: update_lock_state("set"), None
            )

            update_results['update_scan_lock'] = "queue"
            for engine in update_promise["engine_update_promise"].get_scanning_engines():
                update_results["results"][engine.container_name] = {
                    'engine': engine.name,
                    'updated': "...",
                    'exported': "-",
                    'old_signature_version': "...",
                    'old_container_build_time': "...",
                    'signature_version': "...",
                    'container_build_time': "...",
                    'plugin_type': engine.plugin_type,
                    'has_internet': engine.container_requires_internet,
                    'speed': engine.speed
                }

            print(update_results)

        return self.GET()


# -----------------------------------------------------------------------
class system:
    def GET(self):
        statistics = scan_strategy.get_statistics()

        statistics["cpu_count"] = cpu_count()

        render = web.template.render(TEMPLATE_PATH, globals={"type": type})
        return render.system(statistics)
