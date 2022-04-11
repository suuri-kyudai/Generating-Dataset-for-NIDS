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

def main(re_name, year):
    apps = ['snort', 'suricata']
    base_dir = './%s/' % (re_name)
    snort_file = base_dir + '%s_snort.txt' % (re_name)
    suricata_file = base_dir + '%s_suricata.txt' % (re_name)
    re_pcap = base_dir + '%s.pcap' % (re_name)
    replay_log = base_dir + '%s.log' % (re_name)
    outses = base_dir + '%sses.csv' % (re_name)
    outgroup = base_dir + '%sgroup.csv' % (re_name)
    outses_pkl = base_dir + '%sses.pkl' % (re_name)
    outgroup_pkl = base_dir + '%sgroup.pkl' % (re_name)
    caps_4e_alert = base_dir + 'caps_4e_alert/'
    caps_4e_group = base_dir + 'caps_4e_group/'

    print(replay_log)
    (start, end) = get_params(replay_log)

    mkdir0 = ['mkdir', '-p', base_dir]
    mkdir1 = ['mkdir', '-p', caps_4e_alert]
    mkdir2 = ['mkdir', '-p', caps_4e_group]
    subprocess.run(mkdir0)
    subprocess.run(mkdir1)
    subprocess.run(mkdir2)

    alerts = []
    with open(snort_file, 'r') as f:
        snort_alerts = f.readlines()
        alerts.append(snort_alerts)
    with open(suricata_file, 'r') as f:
        suricata_alerts = f.readlines()
        alerts.append(suricata_alerts)
    df = pd.DataFrame(index=[], columns=['date', 'cat', 'lev', 'src', 'spt', 'dst', 'dpt', 'app'])
    for (nids_alerts, app) in zip(alerts, apps):
        nids_df = list_to_df(nids_alerts, app, year)
        print(nids_df)
        df = pd.concat([df, nids_df])
    df = exdf(df, start, end)
    #print(len(df))
    #sys.exit()
    outdf = ex_ses(df, re_pcap, outses, caps_4e_alert, base_dir)
    outdf = outdf[outdf['timestamps'] != ()]
    with open(outses_pkl, 'wb') as f:
        pickle.dump(outdf, f)
    groupdf = grouping(outdf, outgroup)
    with open(outgroup_pkl, 'wb') as f:
        pickle.dump(groupdf, f)
    #grouping_cap(groupdf, caps_4e_alert, caps_4e_group)

    print(outdf)
    print(groupdf)
    print('snort_alerts: {}  suricata_alerts: {}'.format(len(snort_alerts), len(suricata_alerts)))
    return 0


def get_params(replay_log):
    with open(replay_log, 'r') as f:
        relog = f.read()
    start = re.search('start time: (.*)\n', relog).group(1)
    start = dt.strptime(start, '%Y-%m-%d %H:%M:%S')
    extime = re.search('sent in (.*?) seconds', relog).group(1)
    end = start + timedelta(seconds=math.ceil(float(extime)))
    print(start, end)
    
    return start, end


def ex_ses(df, re_pcap, outses, caps_4e_alert, base_dir):
    tmpfile = base_dir + 'oss_tmp.pcap'
    tmpfile5 = base_dir + 'oss_tmp5.pcap'
    tmpfile6 = base_dir + 'oss_tmp6.pcap'
    devnull = open('/dev/null', 'w')
    outdf = pd.DataFrame(index=[], columns=['timestamps', 'ids', 'date', 'cat', 'lev', 'src', 'spt', 'dst', 'dpt', 'app'])
    for i, (index, alert) in enumerate(df.iterrows()):
        if i%100 == 0: 
            print(i)
        '''
        if i >= 20:
            break
        '''
        (rt, srcip, dstip, dpt, spt) = get_items(alert) # logfileから必要な情報を取得
        rt = rt + timedelta(seconds=1)
        rt = rt.strftime('%Y-%m-%d %H:%M:%S')
        # 当日，前日，翌日の各ファイルからIP, port条件に合致するパケットを抽出
        if spt == 'none' or dpt == 'none':
            args1 = ['tcpdump', 'host', srcip, 'and', 'host', dstip, '-r', re_pcap, '-w', tmpfile]
        else:
            args1 = ['tcpdump', 'host', srcip, 'and', 'host', dstip, 'and', 'port', dpt, 'and', 'port', spt, '-r', re_pcap, '-w', tmpfile]
        # args1 = ['tshark', '-r', re_pcap, '-Y', "ip.addr=={} and ip.addr=={} and ((tcp.port=={} and tcp.port=={}) or (udp.port=={} and udp.port=={})) ".format(srcip, dstip, spt, dpt, spt, dpt), '-w', tmpfile]
        subprocess.run(args1, stderr=devnull)
        # 時間条件で抽出
        args2 = ['editcap', '-B', rt, tmpfile, tmpfile5] # rt以前のパケット
        subprocess.run(args2)
        args3 = ['editcap', '-A', rt, tmpfile, tmpfile6] # rt以降のパケット
        subprocess.run(args3)

        capname = caps_4e_alert + str(i) + '.pcap'
        outcap = PcapWriter(capname, sync=True)
        cap = rdpcap(tmpfile5)
        length = len(cap)
        # print(index, alert, args1, args2, args3, length)
        syn = 0
        seqs = []
        first = 0
        session = []
        ids = []
        # rtを境目にパケットを遡る
        for m in range(length):
            if length == 0:
                break
            clen = length - (1 + m)
            try:
                iptest = cap[clen]['IP'].proto
            except:
                be = clen
                continue
            if first == 0:
                proto = cap[clen]['IP'].proto # 初期設定
                first = 1
            if proto != cap[clen]['IP'].proto: # 違うプロトコルが紛れ込むと終了
                break
            if cap[clen]['IP'].proto != 6: # TCP以外であればプロトコルが変わるか最後まで遡る
                be = clen
                continue
                # be = 0
                #break
            if bin(int(cap[clen]['TCP'].flags))[-2] == '1': # synパケット
                if cap[clen]['TCP'].seq not in seqs: # 再送等の重複パケットでなければ
                    if syn == 2:
                        break
                    syn += 1
                    seqs.append(cap[clen]['TCP'].seq)
                be = clen
            elif syn == 2: # synフラグがたったパケットが2回(syn, syn ackを想定)来た後の普通のパケットがあれば終了
                break
            be = clen
        if length > 0:
            for n in range(be, length):
                session.append(dt.fromtimestamp(float(cap[n].time)))
                #ids.append(cap[n]['IP'].id)
                #outcap.write(cap[n])
        else:
            pass

        # 同様に別のセッションのsynパケットが見つかるか最後迄パケットを見て行く
        with PcapReader(tmpfile6) as pcap:
            for pk in pcap:
                try:
                    iptest = pk['IP'].proto
                except:
                    session.append(dt.fromtimestamp(float(pk.time)))
                    #outcap.write(pk)
                    continue
                if first == 0:
                    proto = pk['IP'].proto # 初期設定
                    first = 1
                if pk['IP'].proto != proto:
                    break
                if pk['IP'].proto != 6:
                    session.append(dt.fromtimestamp(float(pk.time)))
                    #ids.append(pk['IP'].id)
                    #outcap.write(pk)
                    continue
                elif bin(int(pk['TCP'].flags))[-2] == '1':
                    if pk['TCP'].seq in seqs:
                        session.append(dt.fromtimestamp(float(pk.time)))
                        #ids.append(pk['IP'].id)
                        #outcap.write(pk)
                    elif syn < 2:
                        session.append(dt.fromtimestamp(float(pk.time)))
                        #ids.append(pk['IP'].id)
                        #outcap.write(pk)
                        seqs.append(pk['TCP'].seq)
                        syn += 1
                    else:
                        break
                else:
                    session.append(dt.fromtimestamp(float(pk.time)))
                    #ids.append(pk['IP'].id)
                    #outcap.write(pk)
        
        session = tuple(session)
        ids = tuple(ids)
        '''
        n_session = []
        numbers = []
        for timestamp in session:
            get_args = ['tshark', '-r', re_pcap, '-Y', "'frame.time == {}'".format(timestamp), '-T', 'fields', '-e', "'frame.number'"]
            number = subprocess.run(get_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            numbers.append(number)

        if proto == 6:
            get_tcpstream = ['tshark', '-r', re_pcap, '-Y', "frame.time == {}".format(session[0]), '-T', 'fields', '-e', "tcp.stream"]
            result = subprocess.run(get_tcpstream, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            tcpstream = result.stdout
        '''
        if len(session) == 0:
            print(alert)
        outdf.loc[i, 'timestamps':'ids'] = [session, ids]
        outdf.loc[i, 'date':] = alert.values
        
    outdf['index'] = outdf.index
    outdf.to_csv(outses)
    return outdf


def grouping(outdf, outgroup):
    groupdf = outdf.groupby('timestamps', as_index=False).agg(\
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
    groupdf.to_csv(outgroup)
    return groupdf


def grouping_cap(groupdf, caps_4e_alert, caps_4e_group):
    for (index, group) in groupdf.iterrows():
         representative = min(group['index'])
         srccap = caps_4e_alert + str(representative) + '.pcap'
         dstcap = caps_4e_group + str(index) + '.pcap'
         cpcap = ['cp', srccap, dstcap]
         subprocess.run(cpcap)
    return 0


# Convert Python list to pd.Dataframe based on blanks and lines
def list_to_df(loglist, app, year):
    logmat = []
    for log in loglist:
        if app == 'snort':
            try:
                #items = re.search('(.*?).*\[(.*?)\] "([^"]*)" \[\*\*\].*\[Priority: (.*?)\].*{(.*?)} (.*?):(.*?) \-> (.*?):(.*)', log).groups()
                items = re.search('(.*?) .* "([^"]*)" .* \[Priority: (.*?)\] .* (.*?):(.*?) \-> (.*?):(.*)', log).groups()
            except:
                #items = re.search('(.*?) \[\*\*\] \[(.*?)\] "([^"]*)" \[\*\*\] \[Classification: (.*?)\] \[Priority: (.*?)\].*{(.*?)} (.*?) \-> (.*)', log).groups()
                items = re.search('(.*?) .* "([^"]*)" .* \[Priority: (.*?)\] .* (.*?) \-> (.*)', log).groups()
                items = list(items)
                items.insert(5, 'none')
                items.insert(7, 'none')
          
        elif app == 'suricata':
            try:
                #items = re.search('(.*?)  \[\*\*\] \[(.*?)\] (.*) \[\*\*\] \[Classification: (.*?)\] \[Priority: (.*?)\].*{(.*?)} (.*?):(.*?) \-> (.*?):(.*)', log).groups()
                items = re.search('(.*?) .*\] (.*) \[\*.* \[Priority: (.*?)\] .* (.*?):(.*?) \-> (.*?):(.*)', log).groups()
            except:
                #items = re.search('(.*?)  \[\*\*\] \[(.*?)\] (.*) \[\*\*\] \[Classification: (.*?)\] \[Priority: (.*?)\].*{(.*?)} (.*?) \-> (.*)', log).groups()
                items = re.search('(.*?) .*\] (.*) \[.* \[Priority: (.*?)\] .* (.*?) \-> (.*)', log).groups()
                items = list(items)
                items.insert(5, 'none')
                items.insert(7, 'none')
        items = list(items)
        items.append(app)
        logmat.append(items)
            
    #df = pd.DataFrame(logmat, columns=['date', 'id', 'cat', 'classification', 'lev', 'protocol', 'src', 'spt', 'dst', 'dpt', 'app'])
    df = pd.DataFrame(logmat, columns=['date', 'cat', 'lev', 'src', 'spt', 'dst', 'dpt', 'app'])
    if app == 'snort':
        df['date'] = pd.to_datetime(year+'/'+df['date'], format='%Y/%m/%d-%H:%M:%S.%f')
    elif app == 'suricata':
        df['date'] = pd.to_datetime(df['date'], format='%m/%d/%Y-%H:%M:%S.%f')
    #df = df.drop(['id', 'classification', 'protocol'], axis=1)
    return df


def exdf(df, start, end):
    df = df[(start <= df['date']) & (df['date'] <= end)]
    return df


def get_items(alert):
    rt = alert['date']
    srcip = alert['src']
    dstip = alert['dst']
    spt = alert['spt']
    dpt = alert['dpt']

    return rt, srcip, dstip, spt, dpt

if __name__ == '__main__':
    #start = dt(2021, 11, 15, 2, 50, 16)
    #end = dt(2021, 11, 15, 11, 47, 0)
    #re_name = '1115-2018Wed'
    re_name = sys.argv[1]
    year = sys.argv[2]
    sys.exit(main(re_name, year))
 

