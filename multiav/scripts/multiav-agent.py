import os
import sys
import time
import glob

from multiav import postfile
from multiav.core import AV_SPEED
from multiav.parallelpromise import ParallelPromise


# -----------------------------------------------------------------------
class MultiAVClient:
    def __init__(self, host):
        self.host = host

    def scan(self, filename, minspeed=AV_SPEED.ALL, allow_internet=False):
        def upload_function(resolve, reject):
            try:
                selector = "/api/v1/sample"
                file_buf = open(filename, "rb").read()
                files = [("file_upload", os.path.basename(filename), file_buf)]
                fields = [("minspeed", str(minspeed.value)), ("allow_internet", "true" if allow_internet else "false")]

                response = postfile.post_multipart(self.host, selector, fields, files)

                if response is None:
                    raise Exception("invalid response from host")

                if response["file"]["name"] != os.path.basename(filename):
                    raise Exception("filenames of report and upload don't match!")

                # get report id from response
                report_id = response["id"]
                report_finished = False

                # query report and return as soon as the report has no queued or scanning entries
                while not report_finished:
                    selector = "/api/v1/sample/"
                    fields = [("id", str(report_id))]
                    report = postfile.get_report(self.host, selector, fields, [])

                    report_finished = True
                    for scan_report in report["result"]:
                        if scan_report["queued"] == 1 or scan_report["scanning"] == 1:
                            report_finished = False
                            break

                    if not report_finished:
                        # wait some seconds before requering
                        # print("report not finished yet. rechecking in 5s...")
                        time.sleep(5)
                        continue

                    print("report finished")
                    resolve(report)
            except Exception as e:
                print("[MultiAVClient] Exception: {0}".format(e))
                print(e)
                reject(e)
                return

        return ParallelPromise(lambda resolve, reject: upload_function(resolve, reject))


# -----------------------------------------------------------------------
def usage():
    print("Usage:", sys.argv[0], "<multi-av host> <folder-path> [--minspeed speed] [--allow-internet]")


# -----------------------------------------------------------------------
def main(url, filename, minspeed=AV_SPEED.ALL, allow_internet=False):
    def print_result(res):
        print(filename)
        print("[MultiAVClient] Scan finished:")
        # pprint.pprint(res)

    scanner = MultiAVClient(url)
    scan_promise = scanner.scan(filename, minspeed, allow_internet)
    scan_promise.then(
        lambda res: print_result(res),
        lambda res: print_result(res)
    )
    print("scan scheduled. waiting for result (could take a while...)")
    scan_promise.wait()


def pathmain(url, path, minspeed=AV_SPEED.ALL, allow_internet=False):
    all_files = glob.glob(path + "*")
    for filename in all_files:
        try:
            main(url, filename, minspeed, allow_internet)
            os.remove(filename)
        except Exception as e:
            print(e)


if __name__ == "__main__":
    print("[MultiAVClient]")
    if len(sys.argv) < 3:
        usage()
    else:
        allow_internet = False
        minspeed = AV_SPEED.ALL

        # handle optional args
        if len(sys.argv) > 3:
            remaining_args = sys.argv[3:]
            for arg in remaining_args:
                if arg == "--allow-internet":
                    allow_internet = True
                    print("- internet access allowed")
                elif arg == "--minspeed":
                    minspeed = AV_SPEED(int(remaining_args[remaining_args.index(arg) + 1]))
                    print("- minspeed set to {0}".format(minspeed.value))

        pathmain(sys.argv[1], sys.argv[2], minspeed=minspeed, allow_internet=allow_internet)
