#!/usr/bin/env python3

import sys
import ipaddress

start = '''apiVersion: v1
kind: Endpoints
metadata:
  name: scale-test-svc
subsets:
  - addresses:'''

end = '''    ports:
      - port: 8000'''

def generate_endpoint(count):
    print(start)
    ip = ipaddress.ip_address('10.128.0.1')
    for i in range(count):
        print('    - ip: ' + str(ip))
        ip += 1
    print(end)


if __name__ == '__main__':
    count = int(sys.argv[1])
    generate_endpoint(count)