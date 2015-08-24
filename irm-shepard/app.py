#!/usr/bin/env python

import deps
from flask.ext.classy import FlaskView, route
from flask import  render_template
import threading;
from hresman.manager import HarnessResourceManager
import hresman.utils
import logging
from optparse import OptionParser
import ConfigParser

from shepard_resources_view import SHResourcesView
from shepard_reservations_view import SHReservationsView
  

sh_views = [
            SHResourcesView,
            SHReservationsView
           ]        
mgr = HarnessResourceManager(sh_views)

##################################################### Options
parser = OptionParser()
parser.add_option("-d", "--disable-crs", dest="CRS_DISABLE", default=False,
                  help="disable CRS", action="store_true") 

parser.add_option('-c','--config', action='store', default="irm-shepard.cfg", dest='CONFIG',\
                  help='config file to run IRM-SHEPARD')
                      
options = parser.parse_args()[0]

###################################################### Configuration
CONFIG = ConfigParser.RawConfigParser()
try:
   ret=CONFIG.read(options.CONFIG)
   if len(ret) != 1: 
      raise Exception()
except:
   print "[x] Cannot read configuration file: %s" % options.CONFIG
   exit(0) 

config = {}
config['IRM_PORT']  = CONFIG.get('main', 'IRM_PORT')
                     
config['ORCH_DIR'] = CONFIG.get('main', 'ORCH_DIR')
config['ORCH_IP_IB'] = CONFIG.get('main', 'ORCH_IP_IB')
config['ORCH_IP'] = CONFIG.get('main', 'ORCH_IP')       

config['ORCH_HOST'] = CONFIG.get('main', 'ORCH_HOST')       
config['ORCH_MODEL'] = CONFIG.get('main', 'ORCH_MODEL')

if (CONFIG.has_option('main', 'ORCH_REMOTE')):
   config['ORCH_REMOTE'] = CONFIG.get('main', 'ORCH_REMOTE')
else:
   config['ORCH_REMOTE'] = ''

if CONFIG.has_option('main', 'DUMMY_RESOURCES'):
   config['DUMMY_RESOURCES'] = int(CONFIG.get('main', 'DUMMY_RESOURCES'))
   SHReservationsView.DUMMY_DFES_AVAILABLE = config['DUMMY_RESOURCES']
   print "[i] using dummy DFE resources: %s" % config['DUMMY_RESOURCES']
   config['USE_ORCH'] = False
else:
   config['USE_ORCH']=True
   
config['ORCH_MPCX_CAPACITY'] =  CONFIG.get('main', 'ORCH_MPCX_CAPACITY')  

for v in sh_views:
   v.config = config

############################################## CRS
if not options.CRS_DISABLE:
   if CONFIG.has_option('main', 'CRS_HOST'):
      crs_host = CONFIG.get('main', 'CRS_HOST')
   else:
      crs_host = 'localhost'   

   if CONFIG.has_option('main', 'CRS_PORT'):
      crs_port = CONFIG.get('main', 'CRS_PORT')
   else:
      crs_port = 56788
   
   try:     
      out=hresman.utils.post({"Port":config['IRM_PORT'], "Name": "IRM-SHEPARD"} , 
                             'registerManager',
                              crs_port,
                              crs_host) 
                           
      if 'result' not in out:
         raise Exception(str(out))
         
   except Exception as e:
      print "[x] Error connecting to the CRS: ", str(e) 
      exit(-1)   


############################################## Logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
        
##################################### up, up and away...        
mgr.run(config['IRM_PORT'])

   
   

      

  
   

