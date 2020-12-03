#!/usr/bin/env python3

from flask import Flask
from subprocess import getoutput
from re import compile

ESTABLISHED = compile(r'(.+?)\[.+?: ESTABLISHED')
INSTALLED = compile(r'(.+?)\{.+?:  INSTALLED')
BYTES = compile(r'(.+?)\{.+?:.+? (\d+) bytes_i.+(\d+) bytes_o')
CONNECTION = compile(r'^conn (.+)')

app = Flask(__name__)


def flatten(items):
    return [item for sublist in items for item in sublist]


def extract(lines, re):
    return set(flatten(list(map(re.findall, lines))))


def make_output(data, key):
    name = f'ipsec_connection_{key}'
    header = f'# HELP {name} \n# TYPE {name} gauge\n'

    def make_line(entry):
        id = entry['id']
        value = entry[key]
        return f'{name}{{id="{id}"}} {value}'

    entries = list(map(make_line, data))
    if len(entries) > 0:
        return header + '\n'.join(entries)
    else:
        return ''


def transfers(lines):
    ingress = {}
    egress = {}
    for line in lines:
        m = BYTES.match(line)
        if m:
            ingress[m.group(1)] = m.group(2)
            egress[m.group(1)] = m.group(3)
    return ingress, egress


@app.route('/')
def home():
    return "IPSEC Exporter, see /metrics"


@app.route('/metrics')
def metrics():
    lines = getoutput('sudo ipsec statusall').split('\n')
    config = getoutput('sudo cat /etc/strongswan/ipsec.conf').split('\n')
    ids = extract(config, CONNECTION)
    established = extract(lines, ESTABLISHED)
    installed = extract(lines, INSTALLED)
    ingress, egress = transfers(lines)

    def consolidate(id):
        return {
            'id': id,
            'installed': 1 if id in installed else 0,
            'established': 1 if id in established else 0,
            'bytes_i': ingress[id] if id in ingress else 0,
            'bytes_o': egress[id] if id in egress else 0
        }

    data = list(map(consolidate, ids))
    keys = ['installed', 'established', 'bytes_i', 'bytes_o']
    outputs = list(map(lambda key: make_output(data, key), keys))

    return '\n'.join(outputs) + '\n'


app.run(debug=False, port=9200, host='0.0.0.0')
