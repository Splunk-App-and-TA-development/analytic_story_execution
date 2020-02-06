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
    story = Option(require=False)
    update = Option(require=False)


    def generate(self):

        # connect to splunk and start execution
        port = splunk.getDefault('port')
        service = splunklib.client.connect(token=self._metadata.searchinfo.session_key, port=port, owner="nobody",app="Splunk_Analytic_Story_Execution")
        self.logger.info("executestory.pym - starting run story - {0} ".format(self.update))

        API_URL = 'https://content.splunkresearch.com'
        # USER = 'admin'
        # PASS = 'h3a2J90pFQoO'
        # SPLUNK_INSTANCE = '172.31.7.199'
        asx_lib = ASXLib(service, API_URL)
        self.logger.info("executestory.pym - Start")

        if self.update == "true":
            x = asx_lib.list_analytics_stories()

    
        #x = asx_lib.get_analytics_story(self.story)
        self.logger.info("executestory.pym - COMPLETED")


        yield {
            '_time': time.time(),
            'sourcetype': "_json",
            '_raw': x,
            'status': "Saved Searches created in local"
        }

    def __init__(self):
        super(Executestory, self).__init__()


dispatch(Executestory, sys.argv, sys.stdin, sys.stdout, __name__)