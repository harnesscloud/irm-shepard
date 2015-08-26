#!/usr/bin/env python

from hresman import utils
from hresman.utils import json_request, json_reply, json_error
from hresman.resources_view import ResourcesView
from hresman.utils import get, post
import subprocess
import copy

class SHResourcesView(ResourcesView):
    TopologyTypes = set(["SINGLETON", "GROUP", "RING"])
    def _get_resources(self):     
        cfg = self.config  

        if cfg['USE_ORCH']:
           command = "%s python %s/maxorchfree.py %s %s" % \
                (cfg['ORCH_REMOTE'], cfg['ORCH_DIR'],  cfg['ORCH_IP_IB'], cfg['ORCH_MODEL']) 
           
           print "==> command invoked: ", command
           resources = subprocess.check_output(command,shell=True)
        else:
           resources = cfg['DUMMY_RESOURCES']
           
        lst = resources.split(":")        
        numDFEs = int(lst[0])
                      
        ret = { "Resources" : { "orch:%s" % cfg['ORCH_HOST']: { 
                                  "IP": cfg['ORCH_IP'], 
                                  "Type": "DFECluster", 
                                  "Attributes":
                                      {
                                         "Model":cfg['ORCH_MODEL'],
                                         "NumDFEs": numDFEs,
                                         "MPCX_Capacity": int(cfg['ORCH_MPCX_CAPACITY'])                                        
                                      }
                                 }}}                               
                                           
       
        return ret
          
    ################################  get allocation specification ##############  
    def _get_alloc_spec(self):
        return { "Types": {
                     "NumDFEs": { "Description": "Number of dataflow engines to allocate", "DataType": "int" },
                     "Topology": { "Description": "Supported topologies: SINGLETON, GROUP, RING", "DataType": "int" }
                 },
                 "Monitor": {
                    "DFE_UTILISATION": { "Description": "DFE utilisation (%)", "DataType": "float"},
                    "DFE_TEMPERATURE": { "Description": "Temperature (C)", "DataType": "float"},
                    "DFE_POWER":  { "Description": "Power (W)", "DataType": "float"}
                 } 
               }
   
    def _calculate_capacity(self, resource, allocation, release):
        
        if "Type" not in resource:
           raise Exception("'Type' field missing in 'Resource'")
        if "Attributes" not in resource:
           raise Exception("'Attributes' field missing in 'Resource'")  
                    
        if resource["Type"] != "DFECluster":
           raise Exception("Type '%s' not supported by IRM-SHEPARD!" % resource["Type"])
           
        if "NumDFEs" not in resource["Attributes"]:
           raise Exception("'NumFields' field missing in 'Resource/Attributes'")           

        if "MPCX_Capacity" not in resource["Attributes"]:
           raise Exception("'MPCX_Capacity' field missing in 'Resource/Attributes'")
           
        
        numDFEs = resource["Attributes"]["NumDFEs"]
                
        rel = [ r["Attributes"]["NumDFEs"] for r in release]
        
        numDFEs += sum(rel)
        
        for alloc in allocation:
           
           if "Topology" not in alloc["Attributes"]:
              topology = "SINGLETON"
           else:
              topology = alloc["Attributes"]["Topology"]
              
           if topology not in SHResourcesView.TopologyTypes:
              return {}
           if topology == "SINGLETON":
              if alloc["Attributes"]["NumDFEs"] > numDFEs:
                 return {}
           elif topology == "GROUP" or topology == "RING":
              if alloc["Attributes"]["NumDFEs"] > int(self.config['ORCH_MPCX_CAPACITY']):
                 return {}
           numDFEs -= alloc["Attributes"]["NumDFEs"]                      
        
        ret_resource = copy.deepcopy(resource)
        ret_resource["Attributes"]["NumDFEs"] = numDFEs
        return { "Resource": ret_resource }  
       
   
ResourcesView._class = SHResourcesView                                                                             
