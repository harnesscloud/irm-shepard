#!/usr/bin/env python

import deps

from flask.ext.classy import FlaskView, route
from flask import request
from hresman.utils import json_request, json_reply, json_error
from hresman.reservations_view import ReservationsView
import uuid
import json
from hresman.utils import post, delete_
from shepard_resources_view import SHResourcesView
import subprocess
import copy

def register_monitor(data, IP, IP_IB, rID):
   try:
      if 'DFECluster' not in data:
         return
      
      req_metrics = copy.deepcopy(data['DFECluster'])
      
      for metric in req_metrics:
         if metric == "DFE_UTILISATION":
            req_metrics[metric]['command'] = "maxtop -r %s^%s -v | grep \"FPGA usage\"" \
                                             " | gawk '{ sub(\"%%\", \"\", $3); sum += $3; n++ } END" \
                                             " { if (n > 0) print sum /n;}'" % (rID, IP_IB)
         elif metric == "DFE_POWER":
            req_metrics[metric]['command'] = "maxtop -r %s^%s -v | grep \"Power usage\"" \
                                             " | gawk '{ sum += $3; n++ } END" \
                                             " { if (n > 0) print sum /n;  }'" % (rID, IP_IB)
         elif metric == "DFE_TEMPERATURE":
            req_metrics[metric]['command'] = "maxtop -r %s^%s -v | grep \"Temperature\"" \
                                             " | gawk '{ sub(\"C\", \"\", $3); sum += $3; n++ } END" \
                                             " { if (n > 0) print sum/n; } ' " \
                                             % (rID, IP_IB)                                                                                       
         elif metric != "PollTime":
            pass # should probably give a warning  
         req_metrics[metric]['type'] = "FLOAT"
         if 'PollTimeMultiplier' not in req_metrics[metric]: 
            req_metrics[metric]['PollTimeMultiplier'] = 1
                
      if "PollTime" in req_metrics:
         polltime = req_metrics['PollTime']
         del req_metrics['PollTime']
      else:
         polltime = 1000
         
      ret=post({"metrics": req_metrics, "instanceType": "generic", "PollTime": polltime, "uuid": rID},
           "createAgent", 12000, IP)
   except Exception as e:
      print "[!] Monitoring agent not set up correctly!"
      pass
        
def unregister_monitor(IP, rID):
    try:
       ret= delete_({ "uuid": rID }, "terminateAgent", 12000, IP)
    except Exception as e:
      print "[!] Monitoring agent not set up correctly!"
      pass       
    #   {u'Message': u'Terminated', u'Agent': u'SHEP-a5a31585c8b9'}
    
class SHReservationsView(ReservationsView):
    DUMMY_DFES_AVAILABLE = 0
    ###############################################  create reservation ############ 
    def _create_reservation(self, scheduler, alloc_req, alloc_constraints, monitor):
    
        uid = str(uuid.uuid4().hex[:12])        
        rID = "SHEP-" + uid
        
        cfg = self.config
        
        topology_spec = ""
        model = cfg['ORCH_MODEL']
        dfes_allocated = 0
        for req in alloc_req:
           if req['Type'] != 'DFECluster':
              raise Exception("Type '%s' not supported!" % req['Type'])
           if 'ID' in req:
              if req['ID'] != 'orch:%s' % cfg['ORCH_HOST']:
                 raise Exception("Invalid resource ID: %s" % req['ID'])
              
           if 'Topology' not in req['Attributes']:
              req_topology = 'SINGLETON'
           else:
              req_topology = req['Attributes']['Topology']
           
           print req_topology    
           if req_topology not in SHResourcesView.TopologyTypes:
              raise Exception("Topology '%s' not supported!" % req_topology)
              
           if 'NumDFEs' not in req['Attributes']:
              raise Exception("Expected 'NumDFEs' field in 'Attributes'!")
            
           numDFEs = req['Attributes']['NumDFEs']               
           
           if req_topology == 'GROUP':
              term =  "GROUP(%s,%d)" % (model, numDFEs)
           elif (req_topology == "RING"):
              term =  "ARRAY(%s,%d)" % (model, numDFEs)           
           elif (req_topology == "SINGLETON"):
              term = "%s * %d" % (model, numDFEs) 
           dfes_allocated += numDFEs
           
           if (topology_spec == ""):           
              topology_spec = term
           else:
              topology_spec += ", " + term           
  
        if cfg['USE_ORCH']:
           if cfg['ORCH_REMOTE'] != "":
              command = '%s "%s/maxorch -r %s -c reserve -i %s -t \\"%s\\""' % \
                        (cfg['ORCH_REMOTE'], cfg['ORCH_DIR'], cfg['ORCH_IP_IB'], 
                         rID, topology_spec)
           else:
              command = '%s/maxorch -r %s -c reserve -i %s -t "%s"' % \
                        (cfg['ORCH_DIR'], cfg['ORCH_IP_IB'], 
                         rID, topology_spec)           
        
           print "command issued: ", command            
        
           try:
              orch_ret = subprocess.check_output(command,stderr=subprocess.STDOUT, shell=True)
           except subprocess.CalledProcessError as c:
              orch_ret = c.output
              pass     
              
           if (orch_ret[:7] != "success"):
              raise Exception("cannot create reservation: " + orch_ret)                    
        else:
           if SHReservationsView.DUMMY_DFES_AVAILABLE - dfes_allocated < 0:
              raise Exception("cannot create reservation: Insufficient resources")
           SHReservationsView.DUMMY_DFES_AVAILABLE -= dfes_allocated            
           
        ReservationsView.reservations[rID] = {"size": dfes_allocated, "topology": topology_spec }
        if monitor != {}:
           register_monitor(monitor, cfg['ORCH_IP'], cfg['ORCH_IP_IB'], rID)
              
        print "Monitor:", monitor
        print ReservationsView.reservations
        return { "ReservationID" : [rID] }          
           
    ###############################################  check reservation ############   
    def _check_reservation(self, reservations):
       check_result = { "Instances": {} }
 
       for resID in reservations:
          if resID not in ReservationsView.reservations: 
             raise Exception("cannot find reservation: " + resID)
             
          check_result["Instances"][resID] = { "Ready": "True", 
                                               "Address": ["%s^%s" % (resID, self.config['ORCH_IP_IB'])] }
                                               
       return check_result
    
    ###############################################  release reservation ############ 
    def _release_reservation(self, reservations):
       cfg = self.config
       for resID in reservations:
          unregister_monitor(cfg['ORCH_IP'], resID)
          if resID not in ReservationsView.reservations: 
             raise Exception("cannot find reservation: " + resID)

          if cfg['USE_ORCH']:
             if cfg['ORCH_REMOTE'] != "":
                 command = '%s "%s/maxorch -r %s -c unreserve -i %s"' % \
                        (cfg['ORCH_REMOTE'], cfg['ORCH_DIR'], cfg['ORCH_IP_IB'], 
                         resID)
             else:
                 command = '%s/maxorch -r %s -c unreserve -i %s' % \
                        (cfg['ORCH_DIR'], cfg['ORCH_IP_IB'], 
                         resID)           
        
             print "command issued: ", command            
        
             try:
                 orch_ret = subprocess.check_output(command,stderr=subprocess.STDOUT, shell=True)
             except subprocess.CalledProcessError as c:
                 orch_ret = c.output
                 pass     
              
             if (orch_ret[:7] != "success"):
                 raise Exception("cannot release reservation: " + orch_ret)                    
          else:
             SHReservationsView.DUMMY_DFES_AVAILABLE += ReservationsView.reservations[resID]["size"]            
          
          del ReservationsView.reservations[resID]
                
       return { }   
    
    ###############################################  release all reservations ############        
    def _release_all_reservations(self):
       cfg = self.config
       try:
          ret= delete_({}, "terminateAllAgents", 12000, cfg['ORCH_IP'])
       except Exception as e:
          print "[!] Monitoring agent not set up correctly!"
          pass              
             
       if cfg['USE_ORCH']:
          if cfg['ORCH_REMOTE'] != "":
              command = "%s \"%s/maxtop -r %s | grep SHEP | awk '{ print $1 }' | xargs -L 1 " \
                        "%s/maxorch -c unreserve -r %s -i\"" % \
                     (cfg['ORCH_REMOTE'], cfg['ORCH_DIR'], cfg['ORCH_IP_IB'],
                      cfg['ORCH_DIR'], cfg['ORCH_IP_IB']) 
                      
          else:
              command = "%s/maxtop -r %s | grep SHEP | awk '{ print $1 }' | xargs -L 1 " \
                        "%s/maxorch -c unreserve -r %s -i" % \
                     (cfg['ORCH_DIR'], cfg['ORCH_IP_IB'],
                      cfg['ORCH_DIR'], cfg['ORCH_IP_IB']) 
          
          
          print "command issued: ", command            
          
          try:
              orch_ret = subprocess.check_output(command,stderr=subprocess.STDOUT, shell=True)
          except subprocess.CalledProcessError as c:
              orch_ret = c.output
              if (orch_ret[:7] != "success"):
                 raise Exception("cannot release all reservations!") 
           
       else:
          SHReservationsView.DUMMY_DFES_AVAILABLE = cfg['DUMMY_RESOURCES']            
       
       ReservationsView.reservations = {}
       
       return {}            
                  
  

