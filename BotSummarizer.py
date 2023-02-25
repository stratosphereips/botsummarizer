#!/usr/bin/python
#  Copyright (C) 2009  Sebastian Garcia, Veronica Valeros
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#
# Author:
# Sebastian Garcia, sebastian.garcia@agents.fel.cvut.cz, sgarcia@exa.unicen.edu.ar, eldraco@gmail.com
# Collaborator:
# Veronica Valeros, valerver@fel.cvut.cz, vero.valeros@gmail.com
#
# Description
# A tool to detect botnet Command and control channels using a model.

# standard imports
import getopt
import sys
import time
from datetime import datetime
from datetime import timedelta
import threading
####################

# Global Variables
debug = 0
vernum = "0.1"
verbose = False
time_window_number = 0
kill_thread = False
offline = False
#########


# Print version information and exit
def version():
    print("+----------------------------------------------------------------------+")
    print("| BotSummarizer.py Version "+ vernum +"                                |")
    print("| This program is free software; you can redistribute it and/or modify |")
    print("| it under the terms of the GNU General Public License as published by |")
    print("| the Free Software Foundation; either version 2 of the License, or    |")
    print("| (at your option) any later version.                                  |")
    print("|                                                                      |")
    print("| Author: Garcia Sebastian, eldraco@gmail.com                          |")
    print("| UNICEN-ISISTAN, Argentina. CTU, Prague-ATG                           |")
    print("+----------------------------------------------------------------------+")
    print()


# Print help information and exit:
def usage():
    print("+----------------------------------------------------------------------+")
    print("| BotSummarizer.py Version "+ vernum +"                                |")
    print("| This program is free software; you can redistribute it and/or modify |")
    print("| it under the terms of the GNU General Public License as published by |")
    print("| the Free Software Foundation; either version 2 of the License, or    |")
    print("| (at your option) any later version.                                  |")
    print("|                                                                      |")
    print("| Author: Garcia Sebastian, eldraco@gmail.com                          |")
    print("| UNICEN-ISISTAN, Argentina. CTU, Prague-ATG                           |")
    print("+----------------------------------------------------------------------+")
    print("\nusage: %s <options>" % sys.argv[0])
    print("options:")
    print("  -h, --help                 Show this help message and exit")
    print("  -v, --verbose              Output more information.")
    print("  -D, --debug                Debug.")
    print("  -f, --file                 Input netflow file to analize. If - is used, netflows are read from stdin. Remember to pass the header!")
    print("  -w, --width                Width of the time window in minutes.")
    print("  -r, --rrdfile              RRD file name to output to.")
    print("  -l, --offline              Process an offline pcap. Always use this for an offline pcap.")
    print()
    sys.exit(1)



class time_window:
    """
    Class for storing flow data in a time window
    """
    def __init__(self, stateModel):
        global time_window_number
        self.dns_packets = 0
        self.dns_flows = 0
        self.dns_est_flows = 0
        self.dns_est_packets = 2
        self.spam_packets = 0
        self.spam_flows = 0
        self.web_packets = 0
        self.web_flows = 0
        self.ssl_packets = 0
        self.ssl_flows = 0
        self.ssh_packets = 0
        self.ssh_flows = 0
        self.tcp_packets = 0
        self.tcp_flows = 0
        self.udp_packets = 0
        self.udp_flows = 0
        self.ipv6_packets = 0
        self.ipv6_flows = 0



        self.total_flows = 0
        self.starttime = datetime.now()
        self.endtime = 0

        self.id = time_window_number
        time_window_number += 1

        self.srcaddrs = []
        self.sports = []
        self.dstaddrs = []
        self.dports = []
        self.dstports = []
        self.byteses = []
        self.total_bytes = 0
        self.durations = []
        self.total_duration = 0
        self.runtimes = []
        self.total_runtime = 0
        self.labels = []
        self.protos = []
        self.states = []
        self.packetses = []
        self.total_packets = 0
        self.stateModel = stateModel

        self.udp_est_ips = []
        self.udp_est_bytes = 0
        self.udp_int_ips = []
        self.udp_est_new_ips = []
        self.udp_est_new_bytes = 0
        self.udp_int_new_ips = []

        self.tcp_CC_est_ips = []
        self.tcp_CC_est_bytes = 0
        self.TCP_CC_HTTP_Custom_Encryption_bytes = 0
        self.TCP_CC_HTTP_Custom_Encryption_ips = []

        self.tcp_web_ips = []

        self.tcp_google_ips = []

        self.TCP_CC_HTTP_bytes = 0
        self.TCP_CC_HTTP_ips = []

        self.tcp_web_bytes = 0
        self.tcp_google_bytes = 0

        self.tcp_ssl_google_ips = []
        self.tcp_ssl_google_bytes = 0

        self.udp_est_dns_ips = []
        self.udp_est_dns_bytes = 0

        self.tcp_custom_enc_ips = []
        self.tcp_custom_enc_bytes = 0

    def set_time_window_width(self,width):
        self.time_window_width = timedelta(seconds=width)
        self.endtime = self.starttime + self.time_window_width

    def set_starttime(self,starttime):
        self.starttime = starttime

    def print_data(self):
        """
        Print data
        """
        # DNS, SPAM, WEB, SSL, SSH, TCP, UDP, IPV6
        sys.stdout.write('update {} {}:{}:{}:{}:{}:{}:{}:{}:{}\n'.format(self.rrdfile, time.mktime(self.starttime.timetuple()), self.dns_packets, self.spam_packets, self.web_packets, self.ssl_packets, self.ssh_packets, self.tcp_packets, self.udp_packets, self.ipv6_packets))
        sys.stdout.flush()

    def add_srcaddr(self,srcaddr):
        self.srcaddr = srcaddr
        self.srcaddrs.append(srcaddr)

    def add_sport(self,sport):
        self.sport = sport
        self.sports.append(sport)

    def add_dstaddr(self,dstaddr):
        self.dstaddr = dstaddr
        self.dstaddrs.append(dstaddr)

    def add_dport(self,dport):
        self.dport = dport
        self.dports.append(dport)

    def add_bytes(self,bytes):
        self.bytes = bytes
        self.byteses.append(bytes)
        self.total_bytes += bytes

    def add_duration(self,duration):
        self.duration = duration
        self.durations.append(duration)
        self.total_duration += duration

    def add_runtime(self,runtime):
        self.runtime = runtime
        self.runtimes.append(runtime)
        self.total_runtime += runtime

    def add_label(self,label):
        self.label = label
        self.labels.append(label)

    def add_proto(self,proto):
        self.proto = proto
        self.protos.append(proto)

    def add_flow_state(self,flow_state):
        self.state = flow_state
        self.states.append(flow_state)

    def add_packets(self,packets):
        self.packets = packets
        self.packetses.append(packets)
        self.total_packets += packets

    def uniquify(self,seq, idfun=None):
       # order preserving
       if idfun is None:
           def idfun(x): return x
       seen = {}
       result = []
       for item in seq:
           marker = idfun(item)
           # in old Python versions:
           # if seen.has_key(marker)
           # but in new ones:
           if marker in seen: continue
           seen[marker] = 1
           result.append(item)
       return result

    def compute_info(self):
        """
        Compute the info
        """
        try:

            if debug:
                print('dport:{}, proto:{}, state:{}, daddr:{}, packets:{}'.format(self.dport, self.proto, self.state, self.dstaddr, self.packets))

            # Separate also the state of the sender and receiver. Usually only for tcp.
            if '_' in self.state:
                sender_state = self.state.split('_')[0]
                receiver_state = self.state.split('_')[1]
            else:
                sender_state = self.state
                receiver_state = self.state

            # Amount of DNS packets
            if self.dport == '53' and self.proto.upper() == 'UDP':
                self.dns_flows += 1
                self.dns_packets += self.packets

            # Amount of established DNS packets
            if self.dport == '53' and self.proto.upper() == 'UDP' and 'CON' in self.state.upper():
                self.dns_est_flows += 1
                self.dns_est_packets += self.packets
            # Amont of Spam packets
            #if self.dport == '25' and self.proto.upper() == 'TCP' and 'S' in self.state:
            if  self.proto.upper() == 'TCP' and self.dport == '25' and ('S' in self.state or ('PA' in sender_state and 'PA' in receiver_state)):
                self.spam_flows += 1
                self.spam_packets += self.packets
            # Amount of Web packets
            if (self.dport == '80') and self.proto.upper() == 'TCP' and 'S' in self.state:
                self.web_flows += 1
                self.web_packets += self.packets
            # Amount of SSL packets
            if (self.dport == '443') and self.proto.upper() == 'TCP' and 'S' in self.state:
                self.ssl_flows += 1
                self.ssl_packets += self.packets
            # Amount of SSH packets
            if (self.dport == '22') and self.proto.upper() == 'TCP' and 'S' in self.state:
                self.ssh_flows += 1
                self.ssh_packets += self.packets
            # Amount of TCP packets
            if self.proto.upper() == 'TCP':
                self.tcp_flows += 1
                self.tcp_packets += self.packets
            # Amount of UDP packets
            if self.proto.upper() == 'UDP':
                self.udp_flows += 1
                self.udp_packets += self.packets
            # Amount of IPV6 packets
            if ':' in self.dstaddr or 'IPV6' in self.proto.upper():
                self.ipv6_flows += 1
                self.ipv6_packets += self.packets

            if debug:
                print('dns:{}, spam:{}, web:{}, ssl:{}, ssh:{}, tcp:{}, udp:{}, ipv6:{}'.format(self.dns_packets, self.spam_packets, self.web_packets, self.ssl_packets, self.ssh_packets, self.tcp_packets , self.udp_packets , self.ipv6_packets ))

            # Amount of established UDP flows, not ipv6, not dns and not netbios
            if not ':' in self.srcaddr and 'udp' in self.proto and 'CON' in self.state and self.dport != '53' and self.dport != '137':
                self.udp_est_ips.append(self.dstaddr)
                self.udp_est_bytes += self.bytes
                # Amount of new UDP Establised IPs
                try:
                    is_there = self.stateModel.all_time_est_udp_dstaddrs[self.dstaddr]
                    # Was there, do nothing
                except KeyError:
                    # It is new
                    self.udp_est_new_ips.append(self.dstaddr)
                    # bytes
                    self.udp_est_new_bytes += self.bytes
                    self.stateModel.all_time_est_udp_dstaddrs[self.dstaddr] = ""

            # Amount of attempted UDP flows in the CC channel
            if not ':' in self.srcaddr and 'udp' in self.proto and 'INT' in self.state and self.dport != '53' and self.dport != '137' :
                self.udp_int_ips.append(self.dstaddr)
                # Amount of new UDP attempted IPs
                try:
                    is_there = self.stateModel.all_time_int_udp_dstaddrs[self.dstaddr]
                    # Was there, do nothing
                except KeyError:
                    # It is new
                    self.udp_int_new_ips.append(self.dstaddr)
                    self.stateModel.all_time_int_udp_dstaddrs[self.dstaddr] = ""


            # All TCP-CC-HTTP
            # Amount of bytes of the established TCP flows for the tuple TCP-CC-HTTP-Custom-Encryption
            if not ':' in self.srcaddr and 'tcp' in self.proto and 'TCP-CC-HTTP-Custom-Encryption' in self.label:
                # For it self
                self.TCP_CC_HTTP_Custom_Encryption_bytes += self.bytes
                self.TCP_CC_HTTP_Custom_Encryption_ips.append(self.dstaddr)
                # For all the TCP-CC-HTTP together
                self.TCP_CC_HTTP_ips.append(self.dstaddr)
                self.TCP_CC_HTTP_bytes += self.bytes

            # All TCP-CC (all have Custom-Encryption)
            # Amount of established CC TCP flows
            if not ':' in self.srcaddr and 'tcp' in self.proto and 'TCP-CC-Custom-Encryption' in self.label:
                self.tcp_CC_est_ips.append(self.dstaddr)
                self.tcp_CC_est_bytes += self.bytes

            # Amount of WEB flows and bytes
            if not ':' in self.srcaddr and 'tcp' in self.proto and 'WEB' in self.label:
                self.tcp_web_ips.append(self.dstaddr)
                self.tcp_web_bytes += self.bytes
            # Amount of google (and ssl) flows and bytes
            if not ':' in self.srcaddr and 'tcp' in self.proto and 'Google' in self.label:
                self.tcp_google_ips.append(self.dstaddr)
                self.tcp_google_bytes += self.bytes
            if not ':' in self.srcaddr and 'tcp' in self.proto and 'SSL-Google' in self.label:
                self.tcp_ssl_google_ips.append(self.dstaddr)
                self.tcp_ssl_google_bytes += self.bytes

            # Amount of DNS established flows and bytes
            if not ':' in self.srcaddr and 'udp' in self.proto and 'DNS' in self.label and not 'Attempt' in self.label:
                self.udp_est_dns_ips.append(self.dstaddr)
                self.udp_est_dns_bytes += self.bytes

            # TCP-Custom-Encryption
            if not ':' in self.srcaddr and 'tcp' in self.proto and 'TCP-Custom-Encryption' in self.label:
                self.tcp_custom_enc_ips.append(self.dstaddr)
                self.tcp_custom_enc_bytes += self.bytes

        except Exception as inst:
            print('Problem in compute_info() in class time_window')
            print(type(inst))     # the exception instance
            print(inst.args)      # arguments stored in .args
            print(inst)           # __str__ allows args to printed directly
            exit(-1)



class stateModels:
    """
    This class handles all the models
    """
    def __init__(self):
        # Hold all the original netflows
        self.original_netflows = {}
        self.current_time_window = False
        self.time_window_width = timedelta(seconds=0)
        # To hold all the dst ip ever seen by the botnet
        self.all_time_est_udp_dstaddrs = {}
        self.all_time_int_udp_dstaddrs = {}
        self.lock = ""
        # Holds the now
        self.now = False
        # Small comparison time
        self.comparison_time = datetime.strptime(str('1971/02/10 00:00:00.000000'), '%Y/%m/%d %H:%M:%S.%f')

    def add_netflow(self,netflowArray):
        """
        Receives a netflow and adds it to the model
        """
        try:
            global debug
            global verbose
            global offline

            # Just in case they are not in the file
            runtime = -1
            sport = -1
            dport = -1

            for col in netflowArray:
                if 'StartTime' in list(col.keys())[0]:
                    starttime = datetime.strptime(str(list(col.values())[0]), '%Y/%m/%d %H:%M:%S.%f')
                    if starttime < self.comparison_time:
                        starttime += self.now
                elif 'SrcAddr' in list(col.keys())[0]:
                    srcaddr = str(list(col.values())[0])
                elif 'Sport' in list(col.keys())[0]:
                    sport = str(list(col.values())[0])
                elif 'DstAddr' in list(col.keys())[0]:
                    dstaddr = str(list(col.values())[0])
                elif 'Dport' in list(col.keys())[0]:
                    dport = str(list(col.values())[0])
                elif 'TotBytes' in list(col.keys())[0]:
                    try:
                        bytes = int(list(col.values())[0])
                    except ValueError:
                        bytes = 0
                elif 'Dur' in list(col.keys())[0]:
                    duration = float(list(col.values())[0])
                elif 'RunTime' in list(col.keys())[0]:
                    runtime = float(list(col.values())[0])
                elif 'Label' in list(col.keys())[0]:
                    label = str(list(col.values())[0])
                elif 'Proto' in list(col.keys())[0]:
                    proto = str(list(col.values())[0])
                elif 'State' in list(col.keys())[0]:
                    flow_state = str(list(col.values())[0])
                elif 'TotPkts' in list(col.keys())[0]:
                    try:
                        packets = int(list(col.values())[0])
                    except ValueError:
                        packets = 0
            #if debug:
                #print 'Stime:{0}, sddr:{1}, sport:{2}, proto:{9}, dddr:{3}, dport:{4}, bytes:{5}, dur:{6}, runtime:{7}, label={8}'.format(starttime, srcaddr, sport, dstaddr, dport, bytes, duration, runtime, label, proto)

            if not offline:
                with self.lock:
                    self.current_time_window.total_flows += 1
                    if not self.current_time_window.starttime:
                        self.current_time_window.set_starttime(starttime)
                    self.current_time_window.add_srcaddr(srcaddr)
                    self.current_time_window.add_sport(sport)
                    self.current_time_window.add_dstaddr(dstaddr)
                    self.current_time_window.add_dport(dport)
                    self.current_time_window.add_bytes(bytes)
                    self.current_time_window.add_duration(duration)
                    self.current_time_window.add_runtime(runtime)
                    self.current_time_window.add_label(label)
                    self.current_time_window.add_proto(proto)
                    self.current_time_window.add_flow_state(flow_state)
                    self.current_time_window.add_packets(packets)
                    self.current_time_window.compute_info()
            else:
                # We are offline
                # We are in a current time window

                if starttime > self.current_time_window.endtime:
                    # Out of the previous time window

                    time_diff = starttime - self.current_time_window.endtime
                    time_windows_in_the_middle = int(time_diff.seconds/self.time_window_width)
                    #print 'Got a starttime: {}, Time diff: {}. twmiddle: {}'.format(starttime, time_diff, time_windows_in_the_middle)
                    last_endtime = self.current_time_window.endtime
                    while time_windows_in_the_middle:
                        self.current_time_window.print_data()
                        self.current_time_window = time_window(self)
                        self.current_time_window.set_starttime(last_endtime)
                        self.current_time_window.set_time_window_width(self.time_window_width)
                        self.current_time_window.rrdfile = self.rrdfile
                        last_endtime = self.current_time_window.endtime
                        time_windows_in_the_middle = time_windows_in_the_middle - 1
                        #print 'A New time window. start: {}. Ends: {}'.format(self.current_time_window.starttime, self.current_time_window.endtime)

                    self.current_time_window.print_data()
                    self.current_time_window = time_window(self)
                    self.current_time_window.set_starttime(last_endtime)
                    self.current_time_window.set_time_window_width(self.time_window_width)
                    self.current_time_window.rrdfile = self.rrdfile
                    #print 'New time window. start: {}. Ends: {}'.format(self.current_time_window.starttime, self.current_time_window.endtime)

                self.current_time_window.total_flows += 1
                self.current_time_window.add_srcaddr(srcaddr)
                self.current_time_window.add_sport(sport)
                self.current_time_window.add_dstaddr(dstaddr)
                self.current_time_window.add_dport(dport)
                self.current_time_window.add_bytes(bytes)
                self.current_time_window.add_duration(duration)
                self.current_time_window.add_runtime(runtime)
                self.current_time_window.add_label(label)
                self.current_time_window.add_proto(proto)
                self.current_time_window.add_flow_state(flow_state)
                self.current_time_window.add_packets(packets)
                self.current_time_window.compute_info()



        except Exception as inst:
            print('Problem in add_netflow() in class stateModels')
            print(type(inst))     # the exception instance
            print(inst.args)      # arguments stored in .args
            print(inst)           # __str__ allows args to printed directly
            exit(-1)




    def process_netflows(self,netflowFile):
        """
        This function takes the netflowFile and parse it.
        """
        try:
            global debug
            global verbose

            if verbose:
                print('Processing the netflow file {0}'.format(netflowFile))

            # Read the netflow and parse the input
            try:
                # From stdin or file?
                if netflowFile == '-':
                    f = sys.stdin
                else:
                    f = open(netflowFile,'r')
            except Exception as inst:
                print('Some problem opening the input netflow file. In process_netflow()')
                print(type(inst))     # the exception instance
                print(inst.args)      # arguments stored in .args
                print(inst)           # __str__ allows args to printed directly
                exit(-1)


            # Just to monitor how many lines we read
            self.netflow_id = 0
            line = f.readline().strip()
            self.netflow_id += 1

            ##################
            # Argus processing...

            columnDict = {}
            templateColumnArray = []
            columnArray = []
            columnNames = line.split(',')

            # So far argus does no have a column Date
            for col in columnNames:
                columnDict[col] = ""
                templateColumnArray.append(columnDict)
                columnDict = {}

            columnArray = templateColumnArray


            # Read the second line to start processing
            line = f.readline().strip()
            self.netflow_id += 1

            # To store the netflows we should put the data in a dict
            self.original_netflows[self.netflow_id] = line

            while (True):
                if not offline and not line:
                        line = f.readline().strip()
                        continue
                elif offline and not line:
                    break
                if debug:
                    print('Netflow line: {0}'.format(line))

                # Parse the columns
                columnValues = line.split(',')

                i = 0
                for col in columnValues:
                    tempDict = columnArray[i]
                    tempDictName = list(tempDict.keys())[0]
                    tempDict[tempDictName] = col
                    columnArray[i] = tempDict
                    i += 1

                # Add the netflow to the model.
                # The self.netflow_id is the id of this netflow
                self.add_netflow(columnArray)


                # Go back to the empty array
                columnArray = templateColumnArray

                line = f.readline().strip()
                self.netflow_id += 1
                self.original_netflows[self.netflow_id] = line

            # End while

            if verbose:
                print('Amount of lines read: {0}'.format(self.netflow_id))

        except Exception as inst:
            print('Problem in process_netflow()')
            print(type(inst))     # the exception instance
            print(inst.args)      # arguments stored in .args
            print(inst)           # __str__ allows args to printed directly
            exit(-1)



def process_time_windows(width,stateModel,lock):
    """
    This function is run by the thread to process the time windows in real time.
    """
    try:
        global kill_thread
        while not kill_thread:
            # First wait, then act
            time.sleep(width)
            if verbose:
                print('Time: {}'.format(time.time()))
            with lock:
                stateModel.current_time_window.print_data()
                # Create a new time window
                del stateModel.current_time_window
                stateModel.current_time_window = time_window(stateModel)
                stateModel.current_time_window.rrdfile = stateModel.rrdfile

    except Exception as inst:
        print('Problem in process_time_windows()')
        print(type(inst))     # the exception instance
        print(inst.args)      # arguments stored in .args
        print(inst)           # __str__ allows args to printed directly
        exit(-1)





def main():
    try:
        global debug
        global verbose
        global kill_thread
        global offline

        netflowFile = ""
        width = 60

        opts, args = getopt.getopt(sys.argv[1:], "vDhf:w:r:l", ["help","version","verbose","debug","file=","width=","rrdfile=","offline"])
    except getopt.GetoptError: usage()

    for opt, arg in opts:
        if opt in ("-h", "--help"): usage()
        if opt in ("-v", "--verbose"): verbose = True
        if opt in ("-D", "--debug"): debug = 1
        if opt in ("-f", "--file"): netflowFile = str(arg)
        if opt in ("-w", "--width"): width = float(arg)*60
        if opt in ("-r", "--rrdfile"): rrdfile = str(arg)
        if opt in ("-l", "--offline"): offline = True
    try:
        try:
            if debug:
                verbose = True

            if netflowFile == "":
                usage()
                sys.exit(1)

            elif netflowFile != "":
                stateModel = stateModels()
                stateModel.rrdfile = rrdfile
                stateModel.time_window_width = width

                # Lock
                lock = threading.Lock()

                # Create the first time window
                stateModel.current_time_window = time_window(stateModel)
                stateModel.current_time_window.rrdfile = rrdfile
                stateModel.current_time_window.set_time_window_width(width)
                stateModel.lock = lock

                # If we are online, because of the problem of virtualbox, we should store the now() time so we can add it later
                # get the now, convert to epoch, convert to timedelta
                stateModel.now = timedelta(seconds=time.mktime(datetime.now().timetuple()))

                if not offline:
                    # Start the timer
                    timer = threading.Thread(target=process_time_windows, args=[width,stateModel,lock])
                    timer.start()

                stateModel.process_netflows(netflowFile)

                kill_thread = True

            else:
                    usage()
                    sys.exit(1)

        except Exception as e:
                print("misc. exception (runtime error from user callback?):", e)
        except KeyboardInterrupt:
                sys.exit(1)


    except KeyboardInterrupt:
        # CTRL-C pretty handling.
        print("Keyboard Interruption!. Exiting.")
        sys.exit(1)


if __name__ == '__main__':
    main()
