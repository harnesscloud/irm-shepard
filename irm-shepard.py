#!/usr/bin/env python
# Description
#
# How it works
# - check the help
#    - ./irm-nova.py -h 
# - start the API
#    - e.g. ./irm-nova.py -a 192.168.56.108:5000 -t admin -u admin -w password -i eth0 -p 8888
# 
# - use any rest client (e.g. RESTClient for firefox) to make calls to the API
#
# - available APIs
#   - /getAvailableResources
#   - /checkReservation/<ID>
#   - /reserveResources
#   - /releaseResources/<ID>
#

#from openstack import OpenStackCloud
import requests, json, pickle, sys, os, subprocess,optparse, time, thread
import re
from bottle import route, run,response,request,re
import ConfigParser
from threading import Thread
import logging
import logging.handlers as handlers
import socket, uuid

#Config and format for logging messages
logger = logging.getLogger("Rotating Log")
logger.setLevel(logging.INFO)
formatter = logging.Formatter(fmt='%(asctime)s.%(msecs)d - %(levelname)s: %(filename)s - %(funcName)s: %(message)s', datefmt='%d/%m/%Y %H:%M:%S')
handler = handlers.TimedRotatingFileHandler("s-irm.log",when="H",interval=24,backupCount=0)

## Logging format
handler.setFormatter(formatter)

logger.addHandler(handler)

################################################################### Calculators #######
@route('/method/calculateResourceCapacity/', method='POST')
@route('/method/calculateResourceCapacity', method='POST')
def calculateResourceCapacity():
    logger.info("Called")
    try:
        obj = rest_read()
        
        # get base
        base = obj["Resource"]
        exceed_capacity = False
        
        if base["Type"] == "DFECluster":
		     # release
		     release_qt = 0
		     if "Release" in obj:
		        release = obj["Release"]
		        for r in release:
		           attrib = r["Attributes"]
		           if "Size" in attrib:
		              release_qt = release_qt + int(r["Attributes"]["Size"])
		                   
		     # reserve
		     reserve_qt = 0
		     if "Reserve" in obj:
		        reserve = obj["Reserve"]
		        for r in reserve:
		           attrib = r["Attributes"]
		           if "Size" in attrib:
		              reserve_qt = reserve_qt + int(r["Attributes"]["Size"])     
		     
		     if ("Size" in base["Attributes"]):      
		        bqty = int(base["Attributes"]["Size"]) + release_qt - reserve_qt
		        base["Attributes"]["Size"] = bqty
		        exceed_capacity = (bqty < 0) 
		     ret = obj["Resource"]
        else:
           ret = { }        
        logger.info("Completed")    
        if (exceed_capacity):
           return rest_write({ })         
        else:
           return rest_write({"Resource":base}) 
    except Exception, msg:
        return rest_error(msg)

@route('/method/calculateResourceAgg/', method='POST')
@route('/method/calculateResourceAgg', method='POST')
def calculateResourceCapacity():
    logger.info("Called")
    try:
        obj = rest_read()
        
        # get resourcs array
        resources = obj["Resources"]
        
        base = { }
        qty = 0
        for res in resources:
           if res["Type"] == "DFECluster":
             if base == { }:
                base = res
             if "Size" in res["Attributes"]:
                qty = qty + int(res["Attributes"]["Size"])
        
        if base == {}:
           raise Exception("Invalid input!")
        if ("Size" in base["Attributes"]):
           base["Attributes"]["Size"] = qty
       
    
        logger.info("Completed")                        
        return rest_write(base)  
    	             
    except Exception, msg:
        return rest_error(msg)
     

################################################################### Reservation #######
@route('/method/reserveResources/', method='POST')
@route('/method/reserveResources', method='POST')
def reserveResources():
    logger.info("Called")
    try:           
        obj = rest_read()
        uid = uuid.uuid4().hex[:12]
        
        reservID = "IRES-" + uid
        orchID = "SHEP-" + uid
        
        requests = obj["Resources"]
        topology = ""
       
        for req in requests:
           if (req["Type"] == "DFECluster"):
              attribs = req["Attributes"]
              if ("Topology" not in attribs):
                 attribs["Topology"] = "SINGLETON"
              if ("Model" not in attribs):
                 attribs["Model"] = "MAIA"
              if (attribs["Topology"] == "GROUP"):
                 term = "GROUP(" +  attribs["Model"] + ", " + str(attribs["Size"]) + ")"
              elif (attribs["Topology"] == "MAXRING"):
                 term = "ARRAY(" +  attribs["Model"] + ", " + str(attribs["Size"]) + ")"
              elif (attribs["Topology"] == "SINGLETON"):
                 term = attribs["Model"] + "*" + str(attribs["Size"])
              else:
              	  raise Exception("Invalid topology in request! => " + str(attribs))
           if (topology == ""):           
              topology = term
           else:
              topology = topology + ", " + term
           
        if (topology == ""):
           raise Exception("Must specify topology for reservations!")
        
        if (ORCH_REMOTE != ""):
		     command = (ORCH_REMOTE + " \"" + ORCH_DIR + "/maxorch" + 
		                " -r "+ ORCH_IP_IB + 
		                " -c reserve" +
		                " -i " + orchID + 
		                " -t \\\"" + topology + "\\\"\"")
        
        else:
		     command = (ORCH_DIR + "/maxorch" + 
		                " -r "+ ORCH_IP_IB + 
		                " -c reserve" +
		                " -i " + orchID + 
		                " -t \"" + topology + "\"")        
        try:
           orch_ret = subprocess.check_output(command,stderr=subprocess.STDOUT, shell=True)
        except subprocess.CalledProcessError as c:
           orch_ret = c.output
           pass

        if (orch_ret[:7] != "success"):
           raise Exception("cannot create reservation: " + orch_ret)
        
        # update reservations   
        global RESERVATIONS
        RESERVATIONS["Reservations"][reservID] = orchID
                              
        ret = { "Reservations": [ reservID ] }                
        logger.info("Completed")           
        return rest_write(ret) 
    	             
    except Exception, msg:
        return rest_error(msg)
  
    
@route('/method/releaseResources/', method='POST')
@route('/method/releaseResources', method='POST')
def releaseResources():
    logger.info("Called")
    try:
        obj = rest_read()
        reservations = obj["Reservations"]

        global RESERVATIONS, ORCH_REMOTE, ORCH_IP_IB
        for resID in reservations:
           orchID =  RESERVATIONS["Reservations"][resID]
           if ORCH_REMOTE != "":
				  command = (ORCH_REMOTE + " \"" + ORCH_DIR + "/maxorch" + 
				             " -r "+ ORCH_IP_IB + 
				             " -c unreserve" +
				             " -i " + orchID + "\"")
           else:
				  command = (ORCH_DIR + "/maxorch" + 
				             " -r "+ ORCH_IP_IB + 
				             " -c unreserve" +
				             " -i " + orchID)        
           try:
              orch_ret = subprocess.check_output(command,stderr=subprocess.STDOUT, shell=True)
           except subprocess.CalledProcessError as c:
		        orch_ret = c.output
		        pass

           if (orch_ret[:7] != "success"):
              raise Exception("cannot remove reservation [" + orchID + "]: " + orch_ret)
		        
           RESERVATIONS["Reservations"].pop(resID)        
      	             
        logger.info("Completed")              
        return rest_write({})  
            	             
    except Exception, msg:
        return rest_error(msg)
    
    
@route('/method/verifyResources/', method='POST')
@route('/method/verifyResources', method='POST')
def verifyResources():
    logger.info("Called")
    try:
        obj = rest_read()
        res_req = obj["Reservations"]
        
        global RESERVATIONS, ORCH_IP_IB
        
        ret = { "Reservations" : [ ], "AvailableResources": { } }
        
        regReservations = RESERVATIONS["Reservations"]

        for resID in res_req:
           if resID not in regReservations:
              raise Exception("Cannot verify reservation [" + resID + "]: does not exist!")
             
           status = { "ID" : resID, "Ready": True, "Address":  regReservations[resID] + "^" + ORCH_IP_IB }           
           ret["Reservations"].append(status)
           
        avail = json.loads(getAvailableResources())
        
        print(avail)

        ret["AvailableResources"] = avail["result"]["Resources"]
   
        avail_res = ret["AvailableResources"]        
        global cluster_info        
        i = 0        
        for r in avail_res:
           r["ID"] = cluster_info["DFECluster"][i]["ID"] + r["ID"]        
           r["Cost"] = cluster_info["DFECluster"][i]["Cost"]
           i = i + 1

        logger.info("Completed")                   
        return rest_write(ret)
    	             
    except Exception, msg:
        return rest_error(msg)

@route('/method/releaseAllResources/', method='POST')
@route('/method/releaseAllResources', method='POST')
def releaseAllResources():
    logger.info("Called")
    try:
        global ORCH_REMOTE, ORCH_IP_IB
        
        #maxtop -r 192.168.0.1 | grep SHEP | awk '{ print $1 }' | xargs -L 1 maxorch -c unreserve -r 192.168.0.1
        
        command = ""
        if ORCH_REMOTE != "":
           command = ORCH_REMOTE + " " 
        
        command = command + "\"" + ORCH_DIR + "/maxtop -r " + ORCH_IP_IB + \
                  "| grep SHEP | awk '{ print $1 }' | xargs -L 1 " + \
                  ORCH_DIR + "/maxorch -c unreserve -r " + \
                  ORCH_IP_IB + " -i\""
        try:
           orch_ret = subprocess.check_output(command,stderr=subprocess.STDOUT, shell=True)
        except subprocess.CalledProcessError as c:
	        orch_ret = c.output
	        pass

        RESERVATIONS["Reservations"] = { } 	             
        logger.info("Completed")              
        return rest_write({})  
            	             
    except Exception, msg:
        return rest_error(msg)
            
      

################################################################### Discovery #########

# To be fixed with GET
@route('/method/getResourceTypes/', method='POST')
@route('/method/getResourceTypes', method='POST')
def getResourceTypes():
    logger.info("Called")
    try:
        types = {"Types":[]}
        data = {"Type":"DFECluster","Attributes":{"Model":{"Description":"model","DataType":"string"},"Size":{"Description":"number of units","DataType":"int"},"Topology":{"Description":"Group or Array","DataType":"string"}}}
        types["Types"].append(data)
               
        return rest_write(types)
        
    except Exception, msg:
        return rest_error(msg)
    
    logger.info("Completed!")
    

# To be fixed with GET
@route('/method/getAvailableResources/', method='POST')
@route('/method/getAvailableResources', method='POST')
def getAvailableResources(): 
    logger.info("Called")

    try:    	
        global ORCH_DIR, ORCH_MODEL, ORCH_REMOTE, DUMMY_RESOURCES, ORCH_IP, ORCH_HOST, ORCH_IP_IB

        command = ORCH_REMOTE + " " + "python " + ORCH_DIR + "/maxorchfree.py " + ORCH_IP_IB + " " + ORCH_MODEL
        
        if DUMMY_RESOURCES == 0:
           resources = subprocess.check_output(command,shell=True)
           #resources = "8:8"
           lst = resources.split(":")        
           # the first element has all the DFEs available
           numDFEs = int(lst[0])
        else:
           numDFEs = DUMMY_RESOURCES                    
                
        global IRM_ADDR, HOSTNAME
        ret = { "Resources" : [ { "IP": ORCH_IP, 
                                  "ID": IRM_ADDR + "/DFECluster/" + ORCH_HOST,
                                  "Type": "DFECluster", 
                                  "Attributes":
                                      {
                                         "Model":ORCH_MODEL,
                                         "Size":numDFEs,
                                      }
                                } ] }                                
       
        global cluster_info        
        i = 0
        for res in ret["Resources"]:
           res["ID"] = cluster_info["DFECluster"][i]["ID"] + res["ID"]
           res["Cost"] = cluster_info["DFECluster"][i]["Cost"]
           i = i + 1                                
       
        logger.info("Completed")   
        return rest_write(ret)    	             
    except Exception, msg:
        return rest_error(msg)
    


################################################################### INITIALISATION ####
##################### move to a python package
def log(msg):
   logger.info(msg)
   print "[i] " + msg 
   
def rest_error(msg):
   smsg = str(msg)
   print("[x] ERROR: " + smsg) 
   logger.error(smsg)    
   response.set_header('Content-Type', 'application/json')     
   return {"error":{"message":smsg, "code":400}}

def rest_read():
   return json.load(request.body)   
   
def rest_write(jsobj):
   response.set_header('Content-Type', 'application/json')
   return json.dumps({"result":jsobj})
   
def verify_keys(keys, obj):
   for k in keys:
      if k not in obj:
         raise Exception("No '" + k + "' found in request!")
############################################################################	

def registerIRM():
    logger.info("Called")
    if CONFIG.has_option('main', 'CRS_URL'):
       CRS_URL = CONFIG.get('main', 'CRS_URL')
       print "Registering with CRS...", CRS_URL

       headers = {'content-type': 'application/json'}
       global IRM_ADDR, IRM_PORT
       try:
		    data = json.dumps(\
		    {\
		    "Manager":"IRM",\
		    "Hostname":IRM_ADDR,\
		    "Port":IRM_PORT,\
		    "Name":"IRM-SHEPARD"\
		    })
       except AttributeError:
		 	logger.error("Failed to json.dumps into data")
		
		 # add here a check if that flavor name exists already and in that case return the correspondent ID
		 # without trying to create a new one as it will fail
       r = requests.post(CONFIG.get('main', 'CRS_URL')+'/method/addManager', data, headers=headers)
    else:
    	log("skipping CRS!")
    	
    logger.info("Completed!")
    
def getifip(ifn):
    '''
Provided network interface returns IP adress to bind on
'''
    import socket, fcntl, struct
    sck = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(sck.fileno(), 0x8915, struct.pack('256s', ifn[:15]))[20:24])
    #return '131.254.16.173'
    
def startAPI():
    # check if irm already running
    command = "ps -fe | grep irm-shepard.py | grep python | grep -v grep"
    proccount = subprocess.check_output(command,shell=True).count('\n')
    proc = subprocess.check_output(command,shell=True)
    global IRM_ADDR, IRM_PORT 
    if proccount > 1:
        print "---Check if irm is already running. Connection error---"
        sys.exit(0)
    else:
        Thread(target=registerIRM).start()       
        run(host=IRM_ADDR, port=IRM_PORT)

def loadClusterInfo():
     logger.info("Called")
     cluster_info = None
     with open('cluster.cfg') as f:
          try:
             cluster_info = json.load(f)
          except AttributeError:
             log("Attempt to load variable f into hosts failed")

          f.close()
     logger.info("Completed!")          
     return cluster_info

def main():

    global CONFIG
    CONFIG = ConfigParser.RawConfigParser()
    CONFIG.read('irm-shepard.cfg') 

    usage = "Usage: %prog [option] arg"
    epilog= "HARNESS project"
    description="""IRM is small api that enables the Cross Resource Scheduler (CRS) to talk to the nova API"""
    parser = optparse.OptionParser(usage=usage,epilog=epilog,description=description)
    
    parser.add_option('-v','--version', action='store_true', default=False,dest='version',help='show version information')
    parser.add_option('-c','--crs', action='store_true', default=False,dest='crs',help='connect to CRS')

    global options
    options, args = parser.parse_args()

    if options.version:
        VERSION = "0.1"
        print VERSION
        sys.exit(1)
    
    try:     
       global IRM_ADDR       
       if CONFIG.has_option('main', 'IRM_HOST'):
          IRM_ADDR = CONFIG.get('main', 'IRM_HOST')
       else:
         IRM_ADDR = getifip(CONFIG.get('main', 'IRM_IF'))
                 
       global IRM_PORT 
       IRM_PORT  = CONFIG.get('main', 'IRM_PORT')
                     
       global ORCH_DIR
       ORCH_DIR = CONFIG.get('main', 'ORCH_DIR')
             
       global ORCH_IP_IB
       ORCH_IP_IB = CONFIG.get('main', 'ORCH_IP_IB')
       
       global ORCH_IP
       ORCH_IP = CONFIG.get('main', 'ORCH_IP')       

       global ORCH_HOST
       ORCH_HOST = CONFIG.get('main', 'ORCH_HOST')       
       
       global ORCH_MODEL
       ORCH_MODEL = CONFIG.get('main', 'ORCH_MODEL')
       
       global ORCH_REMOTE
       if (CONFIG.has_option('main', 'ORCH_REMOTE')):
          ORCH_REMOTE = CONFIG.get('main', 'ORCH_REMOTE')
       else:
          ORCH_REMOTE = ''
                   
       global cluster_info
       cluster_info = loadClusterInfo()
       
       global HOSTNAME
       HOSTNAME=socket.gethostname()
       
       
       global RESERVATIONS
       RESERVATIONS = {"Reservations": {}}  
       
       global DUMMY_RESOURCES
       if (CONFIG.has_option('main', 'DUMMY_RESOURCES')):
          DUMMY_RESOURCES = int(CONFIG.get('main', 'DUMMY_RESOURCES'))
          print "[i] using dummy DFE resources ", DUMMY_RESOURCES
       else:
          DUMMY_RESOURCES = 0
            
       startAPI()
    except Exception, e:
       e = sys.exc_info()[1]
       print "Error",e

if __name__ == '__main__':   
    main()
    
