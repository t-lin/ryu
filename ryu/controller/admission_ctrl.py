# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (C) 2013, The SAVI Project.
#
# Author: Jieyu Lin (Eric) (jieyu.lin@mail.utoronto.ca)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import gflags

FLAGS = gflags.FLAGS
gflags.DEFINE_integer('adm_ctrl_sample', 20, 'number of samples for each measurement interval')
gflags.DEFINE_integer('adm_ctrl_time_interval', 1, 'the time interval for measurement') 

class RateControl (object):
    def __init__(self):
        self.rate_list = {}
        #TODO need to make this configurable through config file
        self.SAMPLES = FLAGS.adm_ctrl_sample #the max number of request allows in the TIME_INTERVAL
        self.TIME_INTERVAL = FLAGS.adm_ctrl_time_interval #the time interval for measure, use with self.SAMPLES
        
    def check_if_over_rate (self, dpid, in_port, src_mac, dst_mac, ts):

        curr_rate_info = self.get_rate_info (dpid, in_port, src_mac, dst_mac)
        if curr_rate_info == {}: #mean no request like this seen before yet
            curr_rate_info['last_ts'] = ts  #last packet time
            curr_rate_info['begin_ts'] = ts #the beginning timestamp of time measurement period
            curr_rate_info['mean_rate'] = 0
            curr_rate_info['count'] = 1
            return True
        else:
            last_rate = curr_rate_info['mean_rate']
            last_ts = curr_rate_info['last_ts']
            count = curr_rate_info['count']
            t_diff = ts - last_ts
            
            if count<self.SAMPLES:
                if t_diff > self.TIME_INTERVAL:
                    curr_rate_info['last_ts'] = ts  #last packet time
                    curr_rate_info['begin_ts'] = ts #the beginning timestamp of time measurement period
                    curr_rate_info['mean_rate'] = 0
                    curr_rate_info['count'] = 1
                    #print "restart the counting process"
                else:
                    curr_rate_info['count'] = count+1
                    curr_rate_info['last_ts'] = ts
                    #print "counting: ", count
                return True
            else:
                if t_diff > self.TIME_INTERVAL:
                    curr_rate_info['last_ts'] = ts  #last packet time
                    curr_rate_info['begin_ts'] = ts #the beginning timestamp of time measurement period
                    curr_rate_info['mean_rate'] = 0
                    curr_rate_info['count'] = 1
                    #print "restart the counting process"
                    return True
                #print "required number of samples received: ", self.SAMPLES
                t_measure = ts - curr_rate_info['begin_ts']
                curr_rate_info['mean_rate'] = self.SAMPLES/t_measure
                curr_rate_info['last_ts'] = ts
                curr_rate_info['begin_ts'] = ts
                curr_rate_info['count'] = 1
                if t_measure < self.TIME_INTERVAL:
                    print "Over limit: ", curr_rate_info['mean_rate']
                    
                    return False
                else:
                    print "within Limit", curr_rate_info['mean_rate']
                    return True
            
    def calculate_mean_rate(self, mean_prev, t_diff):
        return (mean_prev*(self.SAMPLES -1) + t_diff)/self.SAMPLES
            
    def get_rate_info (self, dpid, in_port, src_mac, dst_mac):
        dpid_dict = self.rate_list.setdefault(dpid, {})
        inport_dict = dpid_dict.setdefault(in_port, {})
        smac_dict = inport_dict.setdefault(src_mac, {})
        rate_info = smac_dict.setdefault(dst_mac, {})
        return rate_info
    
    
