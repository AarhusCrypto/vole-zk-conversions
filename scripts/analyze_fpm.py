#!/usr/bin/env python3

import copy
import json
import os
import re
import sys
import numpy as np
import pandas as pd
from math import sqrt

RE_NETWORK = re.compile(r'__network=((?!__).+)__')
RE_BW = re.compile(r'(\d+)(m|g)bit')
RE_MS = re.compile(r'(\d+)ms')

def compute_stash_size(log_db_size):
    return round(sqrt(1 << log_db_size))


def load_data(path):
    data = []
    with os.scandir(path) as it:
        for entry in it:
            if entry.is_file() and entry.name.startswith('fpm__') and entry.name.endswith('.json'):
                if entry.stat().st_size == 0:
                    continue
                with open(entry.path, 'r') as f:
                    d = json.load(f)
                network_setting = re.search(RE_NETWORK, entry.name)[1]
                d['network_setting'] = network_setting
                d['protocol_stats'] = d['protocol_stats'][0]['FixedPointMult']
                d_single = d.copy()
                time_stats = d['protocol_stats']['time_stats']
                for t_stats in time_stats:
                    d_single['protocol_stats']['time_stats'] = t_stats
                    data.append(copy.deepcopy(d_single))
    return data


def make_dataframe(raw_data):
    df = pd.concat(pd.json_normalize(rd) for rd in raw_data)

    for c in df.columns:
        if c.endswith('.secs') or c.endswith('.nanos'):
            df[c] = df[c].astype('Int64')
        if c.endswith('_kb_sent'):
            df[c.removesuffix('_kb_sent') + '_b_sent'] = (df[c] * 1024).astype('Int64')
        if c.endswith('_kb_received'):
            df[c.removesuffix('_kb_received') + '_b_received'] = (df[c] * 1024).astype('Int64')
    for c in df.columns:
        if c.startswith('network_options.'):
            del df[c]
        elif c.startswith('meta_data.'):
            del df[c]
        elif c.startswith('protocol_stats.comm_stats.'):
            df[c.removeprefix('protocol_stats.comm_stats.')] = df[c]
            del df[c]
        elif c.startswith('protocol_stats.time_stats.'):
            df[c.removeprefix('protocol_stats.time_stats.')] = df[c]
            del df[c]
        elif c.startswith('protocol_stats.'):
            df[c.removeprefix('protocol_stats.')] = df[c]
            del df[c]
    for c in df.columns:
        if c.startswith('voles_f2_stats.') or c.startswith('voles_fp_stats.'):
            del df[c]
            continue
        if c.endswith('.num_vole_extensions_performed'):
            del df[c]
            continue
    df = df[(df['party'] == 'Prover')]
    del df['party']
    for phase in ['init', 'voles', 'commit', 'check']:
        df[f'{phase}_time.nanos'] = 10**9 * df[f'{phase}_time.secs'] + df[f'{phase}_time.nanos']
        df[f'{phase}_time.micros'] = df[f'{phase}_time.nanos'] / 10**3
        del df[f'{phase}_time.secs']


    for phase in ['voles', 'commit', 'check']:
        df[f'{phase}_ns_per_fpm'] = df[f'{phase}_time.nanos'] / df['num']
        df[f'{phase}_us_per_fpm'] = df[f'{phase}_time.micros'] / df['num']
        df[f'{phase}_b_sent_per_fpm'] = df[f'{phase}_b_sent'] / df['num']
        df[f'{phase}_b_received_per_fpm'] = df[f'{phase}_b_received'] / df['num']
        df[f'{phase}_b_comm_per_fpm'] = df[f'{phase}_b_sent_per_fpm'] + df[f'{phase}_b_received_per_fpm']
        if phase != 'voles':
            df[f'{phase}_f2_voles_per_fpm'] = df[f'{phase}_f2_stats.num_voles_used'] / df['num']
            df[f'{phase}_fp_voles_per_fpm'] = df[f'{phase}_fp_stats.num_voles_used'] / df['num']

    df['total_ns_per_fpm'] = sum(df[f'{phase}_ns_per_fpm'] for phase in ['voles', 'commit', 'check'])
    df['total_us_per_fpm'] = sum(df[f'{phase}_us_per_fpm'] for phase in ['voles', 'commit', 'check'])
    df['total_b_sent_per_fpm'] = sum(df[f'{phase}_b_sent_per_fpm'] for phase in ['voles', 'commit', 'check'])
    df['total_b_received_per_fpm'] = sum(df[f'{phase}_b_received_per_fpm'] for phase in ['voles', 'commit', 'check'])
    df['total_b_comm_per_fpm'] = sum(df[f'{phase}_b_comm_per_fpm'] for phase in ['voles', 'commit', 'check'])
    df['total_f2_voles_per_fpm'] = sum(df[f'{phase}_f2_voles_per_fpm'] for phase in ['commit', 'check'])
    df['total_fp_voles_per_fpm'] = sum(df[f'{phase}_fp_voles_per_fpm'] for phase in ['commit', 'check'])

    agg_dict = {}
    for phase in ['voles', 'check', 'total']:
        agg_dict[f'{phase}_us_per_fpm'] = ['mean']
        agg_dict[f'{phase}_b_comm_per_fpm'] = ['first']
        if phase != 'voles':
            agg_dict[f'{phase}_f2_voles_per_fpm'] = ['first']
            agg_dict[f'{phase}_fp_voles_per_fpm'] = ['first']

    df['fp_params'] = list(zip(df['integer_size'], df['fraction_size']))

    df.sort_values(['network_setting', 'num', 'fp_params', 'protocol'], inplace=True)
    df = df.groupby(['network_setting', 'num', 'fp_params', 'protocol'], as_index=False).agg(agg_dict)

    return df


def make_tables(df):
    tab = df.copy()
    tab.set_index(['network_setting', 'num', 'protocol'], inplace=True)
    return tab


def print_tables(df):
    print("=====================")
    print("===== Complete =====")
    print("=====================")
    print(df.to_string())
    print("=====================\n")


def main(argv):
    if len(argv) != 2:
        print(f'usage: {argv[0]} <results-directory>')
        exit(1)
    path = argv[1]

    # uncomment the following to cache the dataframe for faster loading
    # (cache needs to be deleted whenever the json files change) ...
    #  assert '__' not in path
    #  cache_name = 'fpm_cache__' + path.replace('/', '__')
    #  try:
    #      with open(cache_name, 'rb') as f:
    #          df = pd.read_pickle(f)
    #  except:
    #      raw_data = load_data(path)
    #      df = make_dataframe(raw_data)
    #      with open(cache_name, 'wb') as f:
    #          df.to_pickle(f)

    # ... and comment out these lines
    raw_data = load_data(path)
    df = make_dataframe(raw_data)

    tab = make_tables(df)
    print_tables(tab)


if __name__ == '__main__':
    main(sys.argv)
