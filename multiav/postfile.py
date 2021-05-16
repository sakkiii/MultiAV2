import requests
import base64


def post_multipart(host, selector, fields, files):
    """
    Post fields and files to an http host as multipart/form-data.
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be uploaded as files
    Return the server's response page.
    """
    r = requests.post('http://' + host + ':8080/api/v1/sample', json={'allow_internet': fields[1][1],
                                                                      'minspeed': int(fields[0][1]),
                                                                      'sample': base64.b64encode(files[0][2]),
                                                                      'sample_name': files[0][1]})
    return r.json()


def get_report(host, selector, fields, files):
    r = requests.get('http://' + host + ':8080/api/v1/sample/' + str(fields[0][1]))
    return r.json()
