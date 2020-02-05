import sys
import json
import splunk
import splunklib.client
import splunklib.results
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option
from splunklib.searchcommands.validators import Boolean
import splunk.mining.dcutils
import time
from datetime import datetime, timedelta
import re
from asx_lib import ASXLib


@Configuration(streaming=True, local=True)
class Executestory(GeneratingCommand):
    logger = splunk.mining.dcutils.getLogger()
    #story = Option(require=True)


    def generate(self):

        API_URL = 'https://content.splunkresearch.com'
        USER = 'admin'
        PASS = 'h3a2J90pFQoO'
        SPLUNK_INSTANCE = '172.31.7.199'
        asx_lib = ASXLib(USER, PASS, API_URL, SPLUNK_INSTANCE)
    
        x = asx_lib.get_analytics_story('credential_dumping')
        yield x
       
    
        

    def __init__(self):
        super(Executestory, self).__init__()


dispatch(Executestory, sys.argv, sys.stdin, sys.stdout, __name__)