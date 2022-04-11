from datetime import datetime as dt
from datetime import date, timedelta
import numpy as np
import pandas as pd
from readlog import readlogline
import sys
import re
import subprocess
from scapy.all import *
import math
import pickle

def main(re_name):
    apps = ['snort', 'suricata', 'Lastline', 'pa3220', 'ddi4100', 'sourcefire']
    base_dir = './%s/' % (re_name)
    replay_log = base_dir + '%s.log' % (re_name)
    outses = base_dir + '%sses.csv' % (re_name)
    #outgroup = base_dir + '%sgroup.csv' % (re_name)
    #c_outgroup = base_dir + '%scgroup.csv' % (re_name)
    outgroup_pkl = base_dir + '%sgroup.pkl' % (re_name)
    c_outgroup_pkl = base_dir + '%scgroup.pkl' % (re_name)
    ori_pcap = base_dir + '%s.pcap' % (re_name[5:])
    re_pcap = base_dir + '%s.pcap' % (re_name)

    binary_pkl = base_dir + '%sbinary.pkl' % (re_name)
    multi_pkl = base_dir + '%smulti.pkl' % (re_name)
    binary_csv = base_dir + '%sbinary.csv' % (re_name)
    multi_csv = base_dir + '%smulti.csv' % (re_name)

    alert_df = mk_alert_df(outgroup_pkl, c_outgroup_pkl);
    binary_df, multi_df = convert2bypkt(alert_df, re_pcap)
    save_df(binary_df, multi_df, binary_pkl, multi_pkl, binary_csv, multi_csv)



def save_df(binary_df, multi_df, binary_pkl, multi_pkl, binary_csv, multi_csv):
    with open(binary_pkl, 'wb') as f:
        pickle.dump(binary_df, f)
    with open(multi_pkl, 'wb') as f:
        pickle.dump(multi_df, f)
    binary_df.to_csv(binary_csv)
    multi_df.to_csv(multi_csv)
    
    return 0

def convert2bypkt(df, re_pcap):
    binary_list = []
    multi_list = []
    cnt = 0
    with PcapReader(re_pcap) as cap:
        for pkt in cap:
            cnt += 1
            if cnt % 10000 == 0:
                print(cnt)
            timestamp = dt.fromtimestamp(float(pkt.time))
            target_df = df[df['timestamps'].apply(lambda x: timestamp in x)]
            if len(target_df) == 1:
                binary_list.append([cnt, 1])
                cat = target_df['cat']
                multi_list.append([cnt, cat])
            elif len(target_df) > 1:
                binary_list.append([cnt, 1])
                cat = target_df['cat'].iloc[0]
                multi_list.append([cnt, cat])
                #print('error')
                #print(target_df)
            else:
                binary_list.append([cnt, 0])
                multi_list.append([cnt, 0])
    binary_df = pd.DataFrame(binary_list, columns=['frame', 'label'])
    multi_df = pd.DataFrame(multi_list, columns=['frame', 'label'])

    return binary_df, multi_df

def mk_alert_df(outgroup_pkl, c_outgroup_pkl):
    with open(outgroup_pkl, 'rb') as f:
        oss_df = pickle.load(f)
    with open(c_outgroup_pkl, 'rb') as f:
        reco_df = pickle.load(f)
    #alert_df = pd.read_csv(outses, dtype={'timestamps':'object', 'ids':'object', 'id':'str', 'msg':'str',\
    #                                      'classification':'str', 'priority':'object', 'protocol':'str', 'src':'str',\
    #                                      'spt':'str', 'dst':'str', 'dpt':'str', 'app':'object', 'index':'object'})
    #oss_df = pd.read_csv(outgroup, dtype={'src':'str', 'spt':'str', 'dst':'str', 'dpt':'str'})
    #reco_df = pd.read_csv(c_outgroup, dtype={'src':'str', 'spt':'str', 'dst':'str', 'dpt':'str'})
    alert_df = pd.concat([oss_df, reco_df], axis=0)
    alert_df['cat'] = alert_df['cat'].apply(lambda x: tuple(x))
    alert_df['ids'] = alert_df['ids'].apply(lambda x: tuple(x))
    alert_df['index'] = alert_df['index'].apply(lambda x: tuple(x))
    alert_df['date'] = alert_df['date'].apply(lambda x: tuple(x))
    alert_df['lev'] = alert_df['lev'].apply(lambda x: tuple(x))
    alert_df['app'] = alert_df['app'].apply(lambda x: tuple(x))
    print(alert_df)
    alert_df = grouping(alert_df)
    return alert_df


def grouping(df):
    groupdf = df.groupby('timestamps', as_index=False).agg(\
        {'ids': 'first',
         'index': list,
         'date': list,
         'cat': set,
         'lev': list,
         'src': 'first',
         'spt': 'first',
         'dst': 'first',
         'dpt': 'first',
         'app': set})
    return groupdf


if __name__ == '__main__':
    #start = dt(2021, 11, 15, 2, 50, 16)
    #end = dt(2021, 11, 15, 11, 47, 0)
    #re_name = '1115-2018Wed'
    re_name = sys.argv[1]
    #year = sys.argv[2]
    sys.exit(main(re_name))
