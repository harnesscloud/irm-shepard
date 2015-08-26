#!/usr/bin/env python

import deps
from hresman.metrics_view import MetricsView
from hresman.utils import post

class SHMetricsView(MetricsView):

    
    ###############################################  create reservation ############ 
    def _get_metrics(self, reservID, address, entry): 
       try:
          ret = post({ "ReservationID": reservID, "Address": address, "Entry": entry }, 
                       "getResourceValueStore", 12000, self.config['ORCH_IP'])
          
          return { "Metrics" : ret } 
       except:
          raise Exception("Cannot connect monitoring agent!")


MetricsView._class = SHMetricsView
          
                            
