#!/usr/bin/python3

import sys
import re
import subprocess

wrkcmd = 'wrk'
separator = ';'

def wrk_data(wrk_output):
    return str(wrk_output.get('lat_avg')) + separator + str(wrk_output.get('lat_stdev')) + separator + str(
        wrk_output.get('lat_max')) + separator + str(wrk_output.get('req_avg')) + separator + str(
        wrk_output.get('req_stdev')) + separator + str(wrk_output.get('req_max')) + separator + str(
        wrk_output.get('lat_distrib_50%')) + separator + str(wrk_output.get('lat_distrib_75%')) + separator + str(
        wrk_output.get('lat_distrib_90%')) + separator + str(wrk_output.get('lat_distrib_99%')) + separator + str(
        wrk_output.get('bytes_sec_tot')) + separator + str(wrk_output.get('req_sec_tot')) + separator  + str(
        wrk_output.get('tot_requests')) + separator + str(wrk_output.get('tot_duration')) + separator + str(wrk_output.get('err_connect')) + separator + str(
        wrk_output.get('err_read')) + separator + str(wrk_output.get('err_write')) + separator + str(
        wrk_output.get('err_timeout'))

def get_bytes(size_str):
    x = re.search("^(\d+\.*\d*)(\w+)$", size_str)
    if x is not None:
        size = float(x.group(1))
        suffix = (x.group(2)).lower()
    else:
        return size_str

    if suffix == 'b':
        return size
    elif suffix == 'kb' or suffix == 'kib':
        return size * 1024
    elif suffix == 'mb' or suffix == 'mib':
        return size * 1024 ** 2
    elif suffix == 'gb' or suffix == 'gib':
        return size * 1024 ** 3
    elif suffix == 'tb' or suffix == 'tib':
        return size * 1024 ** 3
    elif suffix == 'pb' or suffix == 'pib':
        return size * 1024 ** 4

    return False


def get_number(number_str):
    x = re.search("^(\d+\.*\d*)(\w*)$", number_str)
    if x is not None:
        size = float(x.group(1))
        suffix = (x.group(2)).lower()
    else:
        return number_str

    if suffix == 'k':
        return size * 1000
    elif suffix == 'm':
        return size * 1000 ** 2
    elif suffix == 'g':
        print(size)
        return size * 1000 ** 3
    elif suffix == 't':
        return size * 1000 ** 4
    elif suffix == 'p':
        return size * 1000 ** 5
    else:
        return size

    return False


def get_ms(time_str):
    x = re.search("^(\d+\.*\d*)(\w*)$", time_str)
    if x is not None:
        size = float(x.group(1))
        suffix = (x.group(2)).lower()
    else:
        return time_str

    if suffix == 'us':
        return size / 1000
    elif suffix == 'ms':
        return size
    elif suffix == 's':
        return size * 1000
    elif suffix == 'm':
        return size * 1000 * 60
    elif suffix == 'h':
        return size * 1000 * 60 * 60
    else:
        return size

    return False


def parse_wrk_output(wrk_output):
    retval = {}
    for line in wrk_output.splitlines():
        x = re.search("^\s+Latency\s+(\d+\.\d+\w*)\s+(\d+\.\d+\w*)\s+(\d+\.\d+\w*).*$", line)
        if x is not None:
            retval['lat_avg'] = get_ms(x.group(1))
            retval['lat_stdev'] = get_ms(x.group(2))
            retval['lat_max'] = get_ms(x.group(3))
        x = re.search("^\s+Req/Sec\s+(\d+\.\d+\w*)\s+(\d+\.\d+\w*)\s+(\d+\.\d+\w*).*$", line)
        if x is not None:
            retval['req_avg'] = get_number(x.group(1))
            retval['req_stdev'] = get_number(x.group(2))
            retval['req_max'] = get_number(x.group(3))
        x = re.search("^\s+(\d+)\ requests in (\d+\.\d+\w*)\,\ (\d+\.\d+\w*)\ read.*$", line)
        if x is not None:
            retval['tot_requests'] = get_number(x.group(1))
            retval['tot_duration'] = get_ms(x.group(2))
            retval['read'] = get_bytes(x.group(3))
        x = re.search("^Requests\/sec\:\s+(\d+\.*\d*).*$", line)
        if x is not None:
            retval['req_sec_tot'] = get_number(x.group(1))
        x = re.search("^Transfer\/sec\:\s+(\d+\.*\d*\w+).*$", line)
        if x is not None:
            print(x.group(1))
            retval['bytes_sec_tot'] = get_bytes(x.group(1))
        x = re.search(
            "^\s+Socket errors:\ connect (\d+\w*)\,\ read (\d+\w*)\,\ write\ (\d+\w*)\,\ timeout\ (\d+\w*).*$", line)
        if x is not None:
            retval['err_connect'] = get_number(x.group(1))
            retval['err_read'] = get_number(x.group(2))
            retval['err_write'] = get_number(x.group(3))
            retval['err_timeout'] = get_number(x.group(4))
    x = re.search("^\s+Latency Distribution\s+50%\s+(\d+.\d+\w+)\s+75%\s+(\d+.\d+\w+)\s+90%\s+(\d+.\d+\w+)\s+99%\s+(\d+.\d+\w+).*$", wrk_output, re.M)
    if x is not None:
        retval['lat_distrib_50%'] = get_ms(x.group(1))
        retval['lat_distrib_75%'] = get_ms(x.group(2))
        retval['lat_distrib_90%'] = get_ms(x.group(3))
        retval['lat_distrib_99%'] = get_ms(x.group(4))
    if 'err_connect' not in retval:
        retval['err_connect'] = 0
    if 'err_read' not in retval:
        retval['err_read'] = 0
    if 'err_write' not in retval:
        retval['err_write'] = 0
    if 'err_timeout' not in retval:
        retval['err_timeout'] = 0
    return retval

def execute_wrk(cmd):
    cmd =  ' '.join([str(elem) for elem in cmd])
    cmd = wrkcmd + ' ' + str(cmd)
    process = subprocess.run(cmd.split(' '), check=True, stdout=subprocess.PIPE, universal_newlines=True)
    output = process.stdout
    return output

def main(cmd):
    print("****wrk output: \n")
    wrk_output = execute_wrk(cmd)
    print(str(wrk_output) + "\n")
    print("****wrk output dict: \n")
    wrk_output_dict = parse_wrk_output(wrk_output)
    print(str(wrk_output_dict) + "\n")
    print("****wrk output csv line: \n")
    wrk_output_csv = wrk_data(wrk_output_dict)
    print(str(wrk_output_csv))

if __name__ == '__main__':
    main(sys.argv[1:])
