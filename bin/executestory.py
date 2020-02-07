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
    now = Option(require=False)
    cron = Option(require=False)

    def generate(self):

        # connect to splunk and start execution
        port = splunk.getDefault('port')
        service = splunklib.client.connect(token=self._metadata.searchinfo.session_key, port=port, owner="nobody",app="Splunk_ASX")
        self.logger.info("executestory.py - starting ASX - {0} ".format(self.story))

        API_URL = 'https://content.splunkresearch.com'
        asx_lib = ASXLib(service, API_URL)

        #time attributes from time picker
        if hasattr(self.search_results_info, 'search_et') and hasattr(self.search_results_info, 'search_lt'):
            earliest_time = self.search_results_info.search_et
            latest_time = self.search_results_info.search_lt

        #Will move this to asxupdate.py
        if self.update == "true":
            story_list = asx_lib.list_analytics_stories()

        #Runnning the selected analytic story
        if self.now == "true":
            x = asx_lib.run_analytics_story(self.story, earliest_time, latest_time)

        #Schedule the selected analytic story if cron is selected
        if self.cron == "true":
            x = asx_lib.schedule_analytics_story(self.story, earliest_time, latest_time, self.cron)
           

        self.logger.info("executestory.py - completed ASX - {0} ".format(self.story))


        yield {
            '_time': time.time(),
            'sourcetype': "_json",
            '_raw': x
        }

    def __init__(self):
        super(Executestory, self).__init__()


dispatch(Executestory, sys.argv, sys.stdin, sys.stdout, __name__)
