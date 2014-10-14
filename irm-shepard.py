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
#from pudb import set_trace; set_trace()

#Config and format for logging messages
logger = logging.getLogger("Rotating Log")
logger.setLevel(logging.INFO)
formatter = logging.Formatter(fmt='%(asctime)s - %(levelname)s: %(filename)s - %(funcName)s: %(message)s', datefmt='%d/%m/%Y %H:%M:%S %p')
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
        global SHEPAPI 	
        
        if SHEPAPI == "":
           raise Exception("No SHEPARD compute node has been registered!")
           
        obj = json.load(request.body)
        headers = {'content-type': 'application/json'}
        r = requests.post('http://'+SHEPAPI+'/method/calculateResourceCapacity', headers=headers, data=json.dumps(obj))
        ret = r.json()       
        if ("error" in ret):
          raise Exception(ret['error']['message'])
        
        resources = ret["result"]
        
        return rest_write(resources)
    	             
    except Exception, msg:
        return rest_error(msg)
    
    logger.info("Completed")   
    return result  

################################################################### Reservation #######
@route('/method/reserveResources/', method='POST')
@route('/method/reserveResources', method='POST')
def reserveResources():
    logger.info("Called")
    try:
        global SHEPAPI 	
        
        if SHEPAPI == "":
           raise Exception("No SHEPARD compute node has been registered!")
           
        obj = json.load(request.body)
        headers = {'content-type': 'application/json'}
        r = requests.post('http://'+SHEPAPI+'/method/reserveResources', headers=headers, data=json.dumps(obj))
        ret = r.json()       
        if ("error" in ret):
          raise Exception(ret['error']['message'])
        
        resources = ret["result"]
        
        return rest_write(resources)
    	             
    except Exception, msg:
        return rest_error(msg)
    
    logger.info("Completed")   
    return result  
    
@route('/method/releaseResources/', method='POST')
@route('/method/releaseResources', method='POST')
def releaseResources():
    logger.info("Called")
    try:
        global SHEPAPI 	
        
        if SHEPAPI == "":
           raise Exception("No SHEPARD compute node has been registered!")
           
        obj = json.load(request.body)

        headers = {'content-type': 'application/json'}
        r = requests.post('http://'+SHEPAPI+'/method/releaseResources', headers=headers, data=json.dumps(obj))
        ret = r.json()       
        if ("error" in ret):
          raise Exception(ret['error']['message'])
        
        resources = ret["result"]
        
        return rest_write(resources)
    	             
    except Exception, msg:
        return rest_error(msg)
    
    logger.info("Completed")   
    return result      
    
@route('/method/verifyResources/', method='POST')
@route('/method/verifyResources', method='POST')
def verifyResources():
    logger.info("Called")
    try:
        global SHEPAPI 	
        
        if SHEPAPI == "":
           raise Exception("No SHEPARD compute node has been registered!")
           
        obj = json.load(request.body)

        headers = {'content-type': 'application/json'}
        r = requests.post('http://'+SHEPAPI+'/method/verifyResources', headers=headers, data=json.dumps(obj))
        ret = r.json()       
        if ("error" in ret):
          raise Exception(ret['error']['message'])
        
        resources = ret["result"]
        
        avail_res = resources["AvailableResources"]
        
        global cluster_info
        
        i = 0        
        for r in avail_res:
           r["ID"] = cluster_info["DFECluster"][i]["ID"] + r["ID"]        
           r["Cost"] = cluster_info["DFECluster"][i]["Cost"]
           i = i + 1
                
        return rest_write(resources)
    	             
    except Exception, msg:
        return rest_error(msg)
    
    logger.info("Completed")   
    return result  
        
      

################################################################### Discovery #########

# To be fixed with GET
@route('/method/getResourceTypes/', method='POST')
@route('/method/getResourceTypes', method='POST')
def getResourceTypes():
    logger.info("Called")
    try:
        types = {"Types":[]}
        data = {"Type":"DFECluster","Attributes":{"Model":{"Description":"model","DataType":"string"},"Quantity":{"Description":"number of units","DataType":"int"},"Topology":{"Description":"Group or Array","DataType":"string"}}}
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
        global SHEPAPI 	
        
        if SHEPAPI == "":
           raise Exception("No SHEPARD compute node has been registered!")
           
        obj = { "IP": IP_ADDR, "PORT": PORT_ADDR }
        headers = {'content-type': 'application/json'}
        r = requests.post('http://'+SHEPAPI+'/method/getAvailableResources', headers=headers, data=json.dumps(obj))
        ret = r.json()       
        if ("error" in ret):
          raise Exception(ret['error']['message'])
        
        resources = ret["result"]
        
        global cluster_info
        
        i = 0
        for res in resources["Resources"]:
           res["ID"] = cluster_info["DFECluster"][i]["ID"] + res["ID"]
           res["Cost"] = cluster_info["DFECluster"][i]["Cost"]
           i = i + 1
                   
        return rest_write(resources)
    	             
    except Exception, msg:
        return rest_error(msg)
    
    logger.info("Completed")   
    return result    


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

@route('/method/registerSHEPARD/', method='POST')
@route('/method/registerSHEPARD', method='POST')
def registerSHEPARD():
    logger.info("Called")
    try:
       req = rest_read()
       verify_keys(['IP', 'PORT'], req)
          
       addr = req['IP'] + ":" + req['PORT']
       
       log("Registered SHEPARD COMPUTE: " + addr)
       global SHEPAPI
       SHEPAPI = addr

       rest_write({})
          
       return rest_write({})
       
    except Exception, msg:
        return rest_error(msg)
    logger.info("Completed!")
    
    
def registerIRM():
    logger.info("Called")
    CRS_URL = CONFIG.get('main', 'CRS_URL')
    print "Registering with CRS...", CRS_URL
#    print "ip:%s , port:%s, crs: %s" % (IP_ADDR, PORT_ADDR, )
    headers = {'content-type': 'application/json'}
    try:
       data = json.dumps(\
       {\
       "Manager":"IRM",\
       "Hostname":IP_ADDR,\
       "Port":PORT_ADDR\
       })
    except AttributeError:
    	logger.error("Failed to json.dumps into data")
   
    # add here a check if that flavor name exists already and in that case return the correspondent ID
    # without trying to create a new one as it will fail
    r = requests.post(CONFIG.get('main', 'CRS_URL')+'/method/addManager', data, headers=headers)

    logger.info("Completed!")
    
def getifip(ifn):
    '''
Provided network interface returns IP adress to bind on
'''
    import socket, fcntl, struct
    sck = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(sck.fileno(), 0x8915, struct.pack('256s', ifn[:15]))[20:24])
    #return '131.254.16.173'
    
def startAPI(IP_ADDR,PORT_ADDR):
    # check if irm already running
    command = "ps -fe | grep irm-shepard.py | grep python | grep -v grep"
    proccount = subprocess.check_output(command,shell=True).count('\n')
    proc = subprocess.check_output(command,shell=True)
    if proccount > 1:
        print "---Check if irm is already running. Connection error---"
        sys.exit(0)
    else:
        #Thread(target=registerIRM).start()
        
        #registerIRM()
        print "IRM API IP address:",IP_ADDR        
        API_HOST=run(host=IP_ADDR, port=PORT_ADDR)
    return IP_ADDR

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

    options, args = parser.parse_args()
    #print options, args
    if options.version:
        VERSION = "0.1"
        print VERSION
        sys.exit(1)
    
    try:
       INTERFACE = CONFIG.get('main', 'IRM_IF')
       global PORT_ADDR 
       PORT_ADDR = CONFIG.get('main', 'IRM_PORT')
       
       global SHEPAPI, cluster_info, IP_ADDR      

       SHEPAPI=""
       global cluster_info
       cluster_info = loadClusterInfo()
       IP_ADDR=getifip(INTERFACE)
       
       startAPI(IP_ADDR,PORT_ADDR)
    except Exception, e:
       e = sys.exc_info()[1]
       print "Error",e

if __name__ == '__main__':   
    main()
    
