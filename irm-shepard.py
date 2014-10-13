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
handler = handlers.TimedRotatingFileHandler("n-irm.log",when="H",interval=24,backupCount=0)
## Logging format
handler.setFormatter(formatter)

logger.addHandler(handler)

def getIP(url):
    logger.info("Called")
    address_regexp = re.compile ('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    try:
        result = address_regexp.search(url)
    except AttributeError:
    	print "N-Irm: [getIP] Failed to get IP. result variable could not search url. Possible url fault"
    	logger.error("url error caused result variable to have incorrect assignment")

    if result:
            return result.group()
    else:
            return None
    logger.info("Completed!")

#def createToken(os_api_url, tenantName, username, password):
     #logger.info("Called")
     #headers = {'content-type': 'application/json'}
     #data = json.dumps({"auth": {"tenantName": tenantName, "passwordCredentials": {"username": username, "password": password}}})
     #token_url = os_api_url+"/v2.0/tokens"
     ##print "token_url: "+token_url
     #r = requests.post(token_url, data, headers=headers)
     #try:
        #token_id = r.json()['access']['token']['id']
     #except AttributeError:
        #print "N-Irm: [createToken] Unable to use r variable with json. Fault with token_url, or data variables"
        #logger.error("Fault with token_url or data variable, caused r to be unusable with json")
     
     #if token_id:
            ##print token_id
            #return token_id
     #else:
            #return None
     #logger.info("Completed!")

#def getEndPoint(os_api_url, token_id):
     #logger.info("Called")
     #endpoints_url = os_api_url+"/v2.0/tokens/"+token_id+"/endpoints"
     #headers = {'X-Auth-Token': token_id}

     #if str(token_id) not in str(headers):
       #raise AttributeError("N-Irm: [getEndPoint] Failure to assign headers. Possibly incorrect token_id")
       #logger.error("Failed to assign headers. Possible fault in token_id")

     #r = requests.get(endpoints_url, headers=headers)
     #try:
       #endpoints = r.json()['endpoints']
     #except AttributeError:
       #print "N-Irm [getEndPoint] Failure to assign endpoints. Possibly incorrect endpoints_url or unable to acces endpoints"
       #logger.error("Failed to assign endpoints. Possible incorrect endpoints_url or unable to access endpoints")
    ## print endpoints
     #for majorkey in endpoints:
         #if majorkey['type'] == 'compute':
            #public_url = majorkey['publicURL']
     #if public_url:
            #print public_url
            #return public_url
     #else:
            #return None
     #logger.info("Completed!")


## get hosts from nova and return a list
#def getHosts():
     #logger.info("Called")
	### regex check that public url begins with http:// 
	### token id check that it is of the correct length [32]
	### general try except in the event of an unexpected error, recommending that 
	### they check the public url, as named urls may not have been resolved

     #headers = {'X-Auth-Token': token_id}
     ##headers = None
     ##print public_url
     ##print token_id
     #r = requests.get(public_url+'/os-hosts', headers=headers)
     
    ## print headers
    ## print "public url"
     #print public_url
    ## print "token id"
    ## print token_id
   
     #if str(token_id) not in str(headers):
       #raise AttributeError("N-Irm: [getHosts] Failure to assign headers. Possibly incorrect token_id")
       #logger.error("Failed to assign headers. Possible fault in token_id")
     
     #try:
     	#print r.json() 
     #except ValueError:
     	#print "N-Irm: [getHosts] r = requests.get failed. Possible error with public_url or hostname"
     	#logger.error("Error within public_url or hostname. ")

     #hosts = []
     #for majorkey in r.json()['hosts']:
          #if majorkey['service'] == 'compute':
              #hosts.append(majorkey['host_name'])
     #if hosts:
            #return hosts
     #else:
            #return None
     #logger.info("Completed!")



#def getHostDetails(hostname):
    #logger.info("Called")
    #headers = {'X-Auth-Token': token_id}
    ##headers = None       
    #if str(token_id) not in str(headers):
    	#raise AttributeError("N-Irm: [getHostDetails] Failure to assign headers. Possibly incorrect token_id")
    	#logger.error("Failed to assign headers. Possible fault in token_id")

    #r = requests.get(public_url+'/os-hosts/'+hostname, headers=headers)
    ##print r
    #try:
    	#hostDetails = r.json()
    #except ValueError:
    	#print "N-Irm: [getHostDetails] r = requests.get failed. Possible error with public_url or hostname"
    	#print ""
    	#logger.error("Error within public_url or hostname")
    ##print hostDetails    
    
    #if hostDetails:
       #return hostDetails
    #else:
       #return None
    #logger.info("Completed!")

def createListAvailableResources(option):
     # create response structure
     logger.info("Called")
     resources = {option:[]}   
     #h_list = getHosts()
     headers = {'content-type': 'application/json'}
     #data = {}
     r = requests.post('http://'+SHEPAPI+'/method/getLocalInfo', headers=headers, data=json.dumps({}))
     localInfo = r.json()
     print localInfo
     r = requests.post('http://'+SHEPAPI+'/method/getAvailableResources', headers=headers, data=json.dumps({}))
     freeInfo = r.json()
     print freeInfo
     ## loop through all hosts
     #for novah in h_list:
     for h in host_list['DFESet']:
       #if novah == h['host_name']:
		   #host_split = h.split()
		   # load values
           hostIP = localInfo['IP']
           hostName = localInfo['host_name']
           hostModel = h['Model']
           #hostQuantity = h['Quantity']
           costModel = h['Cost']['Model']
           costQuantity = h['Cost']['Quantity']
		   #costDisk = h['Cost']['Disk']
		   #frequency = h['frequency']
           location = h['location']
           CRSID = location+hostIP+"/DFE/"+hostName
           freeRes = freeInfo['result']
           #print hostName,costCores,costMemory,costDisk
           # get details from nova

           #hostDetails = getHostDetails(hostName)
           #nCores = 0
           #Memory = 0
           #total_cpu = 0
           #used_cpu = 0
           #total_mem = 0
           #used_mem = 0
           #total_disk = 0
           #used_disk = 0
						
		 ## load detail from nova reply
		 #if 'host' in hostDetails:
			 #for majorkey in hostDetails['host']:
	     #if majorkey['resource']['project'] == '(total)':
	         #total_mem = majorkey['resource']['memory_mb'] * int(CONFIG.get('overcommit', 'MEM_RATIO'))
	         #total_cpu = majorkey['resource']['cpu'] * int(CONFIG.get('overcommit', 'CPU_RATIO'))
	         #total_disk = majorkey['resource']['disk_gb'] * int(CONFIG.get('overcommit', 'DISK_RATIO'))
	     #if majorkey['resource']['project'] == '(used_now)':
	         #used_mem = majorkey['resource']['memory_mb']
	         #used_cpu = majorkey['resource']['cpu']
	         #used_disk = majorkey['resource']['disk_gb']
				 ## calculate available resources
				 #nCores = total_cpu - used_cpu
				 #Memory = int(total_mem - used_mem - 0.1 * total_mem)
				 #disk = total_disk - used_disk
			 ## build response
           data = {"ID":CRSID, "IP":hostIP, "Type":"DFE","Attributes":{"Model":hostModel,"Quantity":freeRes},"Cost":{"Model":costModel,"Quantity":costQuantity}}
           resources[option].append(data)
           print resources
     #r = json.dumps(resources)
     #if "{'Resources': []}" in resources:
         #raise AttributeError('N-Irm: [createListAvailableResources] resources variable is empty. Failure to append data variable')
         #logger.error("Failed to append 'data' variable. 'Resources' variable empty")

     
     logger.info("Completed!")

     if resources:
         return resources
     else:
         return None


# To be fixed with GET
@route('/method/getAvailableResources/', method='POST')
@route('/method/getAvailableResources', method='POST')
def getAvailableResources(): 
    logger.info("Called")

    try:    	
        if SHEPAPI == "":
           raise Exception("No SHEPARD Compute has been registered!")
           
        option = "Resources"   
        resources = createListAvailableResources(option) 
        r = {"result":resources}       

        result = json.dumps(r)
        print result
    	             
    except Exception, msg:
       response.status = 400
       e = str(msg)
       error = {"message":e,"code":response.status}
       return error
       logger.error(error)
    
    response.set_header('Content-Type', 'application/json')
    response.set_header('Accept', '*/*')
    response.set_header('Allow', 'POST, HEAD') 

    logger.info("Completed")   
    return result
    

#def createFlavor(name,vcpu,ram,disk):
    #logger.info("Called")
    #headers = {'content-type': 'application/json','X-Auth-Token': token_id}
    
    #if str(token_id) not in str(headers):
    	#raise AttributeError("N-Irm: [createFlavor] Failure to assign headers. Possibly incorrect token_id")
    	#logger.error("Failed to assign headers. Possible fault in token_id")
    
    #data = json.dumps({"flavor": {\
        #"name": name,\
        #"ram": ram,\
        #"vcpus": vcpu,\
        #"disk": disk,\
        #"id": name}})


        ## add here a check if that flavor name exists already and in that case return the correspondent ID
    ## without trying to create a new one as it will fail
    #r = requests.post(public_url+'/flavors', data, headers=headers)

    ##print r.json()
    #logger.info("Completed!")

#def deleteFlavor(ID):
    #logger.info("Called")
    #headers = {'X-Auth-Token': token_id}
    #if str(token_id) not in str(headers):
    	#raise AttributeError("N-Irm: [deleteFlavor] Failure to assign headers. Possibly incorrect token_id")
    	#logger.error("Failed to assign headers. Possible fault in token_id")

    #r = requests.delete(public_url+'/flavors/'+ID, headers=headers)
    #logger.info("Completed!")

#def cleanFlavors():
    #logger.info("Called")
    #headers = {'X-Auth-Token': token_id}
    #r = requests.get(public_url+'/flavors', headers=headers)

    #for flavor in r.json()['flavors']:
		#if "HARNESS" in flavor['name']:
			#deleteFlavor(flavor['id'])
			##print flavor

    #logger.info("Completed!")

def createRandomID(size):
    import binascii
    return binascii.b2a_hex(os.urandom(size))
    logger.info("Random ID generated")

def getInstanceStatus(ID):
    logger.info("Called")
    headers = {'X-Auth-Token': token_id}
    
    if str(token_id) not in str(headers):
    	raise AttributeError("N-Irm: [getInstanceStatus] Failure to assign headers. Possibly incorrect token_id")
    	logger.error("Failed to assign headers. Possible fault in token_id")
    
    r = requests.get(public_url+'/servers/'+ID, headers=headers)
    
    #print r.json()['server']['id']
    try:
    	status = r.json()['server']['status']
    except TypeError:
    	print "N-Irm: [getInstanceStatus] Fault in ID. Cannot access ['server'] ['status']"

    if status:
         return status
    else:
         return None
         
    logger.info("Completed!")


#def getNetworks():
    #logger.info("Called")
    #headers = {'X-Auth-Token': token_id}

    #if str(token_id) not in str(headers):
    	#raise AttributeError("N-Irm: [getNetworks]  Failure to assign headers. Possibly incorrect token_id")
    	#logger.error("Failed to assign headers. Possible fault in token_id")
    
    #r = requests.get(public_url+'/os-networks', headers=headers)
    ##print r.json()
    #networks = []
    #for net in r.json()['networks']:
         #networks.append(net['label'])

    #if len(networks) > 0:
         #return networks
    #else:
         #return None
    #logger.info("Completed!")

# To be fixed with GET
@route('/method/checkReservationInfo/<ID>', method='POST')
def getInstanceInfo(ID):
    logger.info("Called")
    headers = {'X-Auth-Token': token_id}
    if str(token_id) not in str(headers):
    	raise AttributeError("N-Irm: [getInstanceInfo] Failure to assign headers. Possibly incorrect token_id")
    	logger.error("Failed to assign headers. Possible fault in token_id")
    
    r = requests.get(public_url+'/servers/'+ID, headers=headers)

    response.set_header('Content-Type', 'application/json')
    response.set_header('Accept', '*/*')
    response.set_header('Allow', 'POST, HEAD')
    #print r.json()
    #print r.json()['server']['id']
    #status = r.json()['server']['status']
    if r:
         return r.json()
    else:
         return None
    logger.info("Completed!")


# To be fixed with GET
#@route('/method/verifyResources/<ID>', method='POST')
#def verifyResources(ID):
    ##headers = {'X-Auth-Token': token_id}
    ##r = requests.get(public_url+'/servers/'+ID, headers=headers)
    ##print r.json()['server']['id']
    ##status = getInstanceStatus(ID)
    #info = getInstanceInfo(ID)
    #status = info['server']['status']
    #IP = "100"
    #for private in info['server']['addresses']['private']:
        #if private['OS-EXT-IPS:type'] == "fixed":
            #IP = private['addr']
    ##status = r.json()['server']['status']
    #response.set_header('Content-Type', 'application/json')
    #response.set_header('Accept', '*/*')
    #response.set_header('Allow', 'POST, HEAD')
    #data = {"result":{"Ready":status,"addresses":IP}}
    #if data:
         #return data
    #else:
         #return None

# To be fixed with GET
@route('/method/verifyResources/', method='POST')
@route('/method/verifyResources', method='POST')
def verifyResources():
    logger.info("Called")
    try:
        req = json.load(request.body)
    except ValueError:
        print "N-Irm: [verifyResources] Attempting to load a non-existent payload, please enter desired payload"   
        print " "
        logger.error("Payload was empty. A payload must be present")
    reply = {"Reservations":[]}
   
   # print reply
    #network = getNetworks()[0]
    #print network
    try:
    	try:            
    	    for ID in req['Reservations']:
            	status = "false"                
                try:
                    while status == "false":
                        info = getInstanceInfo(ID)
                        osstatus = info['server']['status']
                        #print osstatus
                        if osstatus == "ACTIVE": status = "true"
                except TypeError:
                	print "N-Irm: [verifyResources] Payload present but fault in ID. Could be missing or incorrect."
                	print " "
                	logger.error("Fault in the payload's ID. Either missing or incorrect, must match an existent ID")
                IP = "100"
                # change to private to vmnet in field below
                for private in info['server']['addresses'][CONFIG.get('network', 'NET_ID')]:
                    if private['OS-EXT-IPS:type'] == CONFIG.get('network', 'IP_TYPE'):
                        IP = private['addr']
                #status = r.json()['server']['status']
                response.set_header('Content-Type', 'application/json')
                response.set_header('Accept', '*/*')
                response.set_header('Allow', 'POST, HEAD')
                data = {"ID":ID,"Ready":status,"Address":IP}
                reply["Reservations"].append(data)
            # When there is no ID, this case occurs    
            if ID in req['Reservations'] is None:
    	       raise UnboundLocalError('N-Irm: [verifyResources] Attempting to use ID variable before it has a value. Ensure payload has "<instanceID>"')
    	       logger.error("ID has not been assigned before being used. Ensure payload has a present and correct instance ID")
        except UnboundLocalError:
            raise UnboundLocalError("N-Irm: [verifyResources] Attempting to reference variable before it has been assigned. Payload may be missing. Or ID is missing or empty. Please check payload!")
            logger.error("Variable being referenced before payload or ID is assigned, possibly missing or empty. ")

        
        option = "AvailableResources"
        resources = createListAvailableResources(host_list,public_url,token_id,option)
        reply["Reservations"]
        reply.update(resources)
        result = {"result":reply}
        jsondata = json.dumps(result)
        return jsondata
    
    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        return error
        logger.error(error)
    logger.info("Completed!")

@route('/method/reserveResources/', method='POST')
@route('/method/reserveResources', method='POST')
def reserveResources():
    logger.info("Called")
    response.set_header('Content-Type', 'application/json')
    response.set_header('Accept', '*/*')
    response.set_header('Allow', 'POST, HEAD')
    try:
        # get the body request
      #  print request.body
        try:
            req = json.load(request.body)
        except ValueError:
        	print "N-Irm [reserveResources] Attempting to load a non-existent payload please enter desired payload"
        	logger.error("Payload was empty or incorrect. A payload must be present and correct")
        	print " "

        cleanFlavors()
        reply = {"Reservations":[]}
        # loop through all requested resources
        name = ""
        #print req
        for resource in req['Resources']:
           #print resource
           # load values
           IP = resource['IP']
           if 'Cores' in resource['Attributes']:
               vcpu = resource['Attributes']['Cores']
           else:
               vcpu = 0
           if 'Memory' in resource['Attributes']:
               memory = resource['Attributes']['Memory']
           else:
               memory = 0
           if 'Disk' in resource['Attributes']:
               disk = resource['Attributes']['Disk']
           else:
               disk = 0
           if 'Frequency' in resource['Attributes']:
               frequency = resource['Attributes']['Frequency']
           else:
               frequency = 0
           #if resource['imageRef']:
           image = resource['image']
           #else:
           #    imageRef = ''
           print IP,vcpu,memory,disk,frequency, image
           #count = resource['NumInstances']
           #count = 1
           #print "COUNT: ",count
           # get host_name from IP in the request
           hostName = ""
           h_list = getHosts()
           #print h_list
          # print IP
           for novah in h_list:
               #print host_list
               for h in host_list['Machine']:
                   #print novah, h
                   if novah == h['host_name']:
                       # load values
                       if h['IP'] == IP:
                          hostName = h['host_name']
                          # build host for availability_zone option to target specific host
                          host = "nova:"+hostName
                          name = "HARNESS-"+createRandomID(6)
                          # create ID for flavor creation
                          #tmpID = createRandomID(15)
                          #print tmpID
                          createFlavor(name,vcpu,memory,disk)
                          headers = {'content-type': 'application/json','X-Auth-Token': token_id}
                          # build body for nova api
                          # create instances up to the number in the request
                          #for i in xrange(0,count):
                          data = json.dumps({"server" : {\
                                      "name" : name,\
                                      "imageRef" : image, \
                                      #"imageRef" : "162bb278-76cf-4dd2-8560-e3367050d32a", \
                                      #"imageRef" : "3184a7b0-673e-4c17-9243-9241c914eec8",\
                                      #"imageRef" : "185982bc-5eab-4cde-8061-02d519dca5ef",\
                                      "flavorRef" : name,\
                                      "min_count": 1,\
                                      "max_count": 1,\
                                      "availability_zone":host}})
                          #print "Creating instance number "+str(i+1)+", name "+name
                          print "Creating instance "+name
                          r = requests.post(public_url+'/servers', data, headers=headers)
                          #print r.json()
                          try:
                          	ID = r.json()['server']['id']
                          except KeyError:
                          	print "N-Irm: [reserveResources] Error within payload, please check spelling"
                          logger.error("KeyError in payload, please check spelling of attributes")
                          #print getInstanceInfo(ID)
                          #print ID
                          #status = ""
                                  #while (status != "ACTIVE") and (status !="ERROR"):
                                  #    status = getInstanceStatus(ID)
                                  #    print "Status of "+name+" "+status
                          #instanceID = {"InfReservID":ID}
                          try:
                          	reply["Reservations"].append(ID)
                          except UnboundLocalError:
                          	print "N-Irm [reserveResources] Failed to append ID. As it has been referenced before assignment"
              	          logger.error("Attempting to append the ID when it has not been assigned yet")

                          # delete flavor
                          deleteFlavor(name)
        result = {"result":reply}
        jsondata = json.dumps(result)
        return jsondata

    except Exception.message, e:
        response.status = 400
        if name: deleteFlavor(name)
        error = {"message":e,"code":response.status}
        return error
        logger.error(error)

    logger.info("Completed!")

# To be fixed with DELETE
@route('/method/releaseResources/<ID>', method='POST')
def releaseResources(ID):
    logger.info("Called")
    headers = {'X-Auth-Token': token_id}
    #print headers
    #print token_id    
    if str(token_id) not in str(headers):
    	raise AttributeError("N-Irm: [releaseResources/<ID>] Failure to assign headers. Possibly incorrect token_id")
    	logger.error("Failed to assign headers. Possible fault in token_id")
   
    r = requests.delete(public_url+'/servers/'+ID, headers=headers)
    return r
    logger.info("Completed!")

# To be fixed with DELETE
@route('/method/releaseResources/', method='POST')
@route('/method/releaseResources', method='POST')
def releaseResources():
    logger.info("Called")
    headers = {'X-Auth-Token': token_id}
    try:
    	req = json.load(request.body)
    except ValueError:
    	print "N-Irm [releaseResources] Attempting to load a non-existent payload, please enter desired layout"
    	print " "
    	logger.error("Payload was empty or incorrect. A payload must be present and correct")
    try:
        try:
    	    for ID in req['Reservations']:    	        
                try:
    	    	    #forces it to break is incorrect ID
    	    	    info = getInstanceInfo(ID)
    	            osstatus = info['server']['status']
    	    	    #deletion of correct ID
                    r = requests.delete(public_url+'/servers/'+ID, headers=headers)
                except TypeError:
                    print " "
                    raise TypeError("N-Irm: [releaseResources] Payload present but fault in ID. Could be missing or incorrect.")
                    logger.error("Payload was incorrect. ID possibly missing or incorrect")
            # Thrown to enforce exception below
            if ID in req['Reservations'] is None:            	
                raise UnboundLocalError
        except UnboundLocalError:
            raise UnboundLocalError("N-Irm: [releaseResources] Payload may be missing. Or ID is missing or empty. Please check Payload!")
            logger.error("Fault with payload and ID. If payload is present, Id may be missing or empty")

            
    #return r
    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        return error
        logger.error(error)

    logger.info("Completed!")

@route('/method/calculateResourceCapacity/', method='POST')
@route('/method/calculateResourceCapacity', method='POST')
def calculateResourceCapacity():
    logger.info("Called")
    response.set_header('Content-Type', 'application/json')
    response.set_header('Accept', '*/*')
    response.set_header('Allow', 'POST, HEAD')
    try:          
        # get the body request
        try:
            req = json.load(request.body)
        except ValueError:
       	    print "N-Irm: [calculateResourceCapacity] Attempting to load a non-existent payload, please enter desired layout"
            print ""
            logger.error("Payload was empty or incorrect. A payload must be present and correct")


        # loop through all requested resources
        try:
            totCores = req['Resource']['Attributes']['Cores']
        except KeyError:
        	print "N-Irm [calculateResourceCapacity] 'Cores' cannot be found, please check spelling within payload"
        	logger.error("Cores could not be found within [Resource][Attributes]- Possible speeling error within payload")
        try:
            totMem = req['Resource']['Attributes']['Memory']
        except KeyError:
        	print "N-Irm [calculateResourceCapacity] 'Memory' cannot be found, please check spelling within payload"
          	logger.error("Memory could not be found within [Resource][Attributes]- Possible speeling error within payload")
        try:
            maxFreq = req['Resource']['Attributes']['Frequency']
        except KeyError:
            print "N-Irm [calculateResourceCapacity] 'Frequency' cannot be found, please check spelling within payload"
            logger.error("Frequency could not be found within [Resource][Attributes]- Possible speeling error within payload")
        try:
           totDisk = req['Resource']['Attributes']['Disk']
        except KeyError:
        	print "N-Irm [calculateResourceCapacity] 'Disk' cannot be found, please check spelling within payload"
        	logger.error("Disk could not be found within [Resource][Attributes]- Possible speeling error within payload")

        for majorkey in req['Reserve']:
           try: totCores = totCores - majorkey['Attributes']['Cores']
           except KeyError: 
              print "N-Irm [calculateResourceCapacity] failed to assign totCores in 'Reserve'" 
              logger.error("totCores could not be assigned within 'Reserve'")
              pass
           try: totMem = totMem - majorkey['Attributes']['Memory']
           except KeyError: 
              print "N-Irm [calculateResourceCapacity] failed to assign totMem in 'Reserve'" 
              logger.error("totMem could not be assigned within 'Reserve'")
              pass
           try: totDisk = totDisk - majorkey['Attributes']['Disk']
           except KeyError: 
              print "N-Irm [calculateResourceCapacity] failed to assign totDisk in 'Reserve'" 
              logger.error("totDisk could not be assigned within 'Reserve'")
              pass
           #try: 
           #    if maxFreq < majorkey['Attributes']['Frequency']:
           #        maxFreq = majorkey['Attributes']['Frequency']
           #except KeyError: pass
        for majorkey in req['Release']:
           try: totCores = totCores + majorkey['Attributes']['Cores']
           except KeyError: 
           	  print "N-Irm [calculateResourceCapacity] failed to assign totCores in 'Release'"
           	  logger.error("totCores could not be assigned within 'Release'")
           	  pass
           try: totMem = totMem + majorkey['Attributes']['Memory']
           except KeyError: 
           	  print "N-Irm [calculateResourceCapacity] failed to assign totMem in 'Release'"
           	  logger.error("totMem could not be assigned within 'Release'") 
           	  pass
           try: totDisk = totDisk + majorkey['Attributes']['Disk']
           except KeyError: 
           	  print "N-Irm [calculateResourceCapacity] failed to assign totMem in 'Release'" 
           	  logger.error("totMem could not be assigned within 'Release'")
           	  pass
           #try:
           #    if maxFreq < majorkey['Attributes']['Frequency']:
           #        maxFreq = majorkey['Attributes']['Frequency']
           #except KeyError: pass
        try:
            rType = req['Resource']['Type']
        except AttributeError:
        	print "Failed to assign Resource type to 'rtype'"
        	logger.error("Unable to assign Resource type to 'rtype'")
        #print totCores,maxFreq,totMem,totDisk

        reply = {"Resource":{"Type":rType,"Attributes":{"Cores":totCores,"Frequency":maxFreq,"Memory":totMem,"Disk":totDisk}}}
        result = {"result":reply}
        jsondata = json.dumps(result)
        return jsondata

    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        return error
        logger.error(error)   
    logger.info("Completed!")

@route('/method/calculateResourceAgg/', method='POST')
@route('/method/calculateResourceAgg', method='POST')
def calculateResourceAgg():
    response.set_header('Content-Type', 'application/json')
    response.set_header('Accept', '*/*')
    response.set_header('Allow', 'POST, HEAD')
    logger.info("Called")
    try:
        try:
            # get the body request
            req = json.load(request.body)
        except ValueError: 
        	print 'N-Irm: [calculateResourceAgg] Attempting to load a non-existent payload, please enter desired layout'
        	print ' '
        	logger.error("Payload was empty or incorrect. A payload must be present and correct")
        # loop through all requested resources
        totCores = 0
        totMem = 0
        maxFreq = 0
        totDisk = 0
        rType = req['Resources'][0]['Type']
        #rType = 'machine' 

        for majorkey in req['Resources']:
           try: totCores = totCores + majorkey['Attributes']['Cores']
           except KeyError:
              print "N-Irm [calculateResourceAgg] failed to assign totCores in 'Resources'. Possible payload spelling error"
              logger.error("Failure to assign totCores within 'Resources. Potential spelling error'") 
              raise KeyError
           try: totMem = totMem + majorkey['Attributes']['Memory']
           except KeyError: 
              print "N-Irm [calculateResourceAgg] failed to assign totMem in 'Resources'. Possible payload spelling error" 
              logger.error("Failure to assign totMem within 'Resources. Potential spelling error'")               
              raise KeyError
           try: totDisk = totDisk + majorkey['Attributes']['Disk']
           except KeyError: 
              print "N-Irm [calculateResourceAgg] failed to assign totDisk in 'Resources'. Possible payload spelling error" 
              logger.error("Failure to assign totDisk within 'Resources. Potential spelling error'")
              raise KeyError
           try:
               if maxFreq < majorkey['Attributes']['Frequency']:
                   maxFreq = majorkey['Attributes']['Frequency']
           except KeyError: pass
        #print totCores,maxFreq,totMem,totDisk

        reply = {"Type":rType,"Attributes":{"Cores":totCores,"Frequency":maxFreq,"Memory":totMem,"Disk":totDisk}}
        result = {"result":reply}
        
        jsondata = json.dumps(result)
        return jsondata
    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        return error
        logger.error(error)
    logger.info("Completed!")


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
    
