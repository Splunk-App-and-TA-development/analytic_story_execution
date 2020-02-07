import sys
import splunk
import splunk.entity as entity
import splunklib.client
import splunklib.results
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, Boolean
import splunk.mining.dcutils
import splunk.Intersplunk as si
from asx_lib import ASXLib


@Configuration(streaming=True, local=True)
class ASXUpdate(GeneratingCommand):
    logger = splunk.mining.dcutils.getLogger()

    update_all = Option(doc='''
        **Syntax: update_all=<bool>
        **Description:** When `true`,retrives updates all analytics stories from the API.
        This process does take a while. Defaults to `false`.
        ''', name='update_all', default=False, validate=Boolean())

    story = Option(doc='''
        **Syntax:** **story=***<story name>*
        **Description:** Story to update.
        ''', name='story', require=True, default=None)

    def getURL(self):
        results, dummyresults, settings = si.getOrganizedResults()

        # list api_key
        ent = entity.getEntities('asx/conf/settings',namespace='Splunk_ASX', owner='nobody',sessionKey=settings['sessionKey'])

        # return first set of cred
        for value in ent.values():
            return value['api_url']

    def generate(self):
        # connect to splunk and start execution
        port = splunk.getDefault('port')
        service = splunklib.client.connect(token=self._metadata.searchinfo.session_key, port=port, owner="nobody",app="Splunk_ASX")
        API_URL = self.getURL()
        asx_lib = ASXLib(service, API_URL)
        self.logger.info("asx-update.py - start")

        if story:
            self.logger.info("asx-update.py - updating story {0}".format(self.story))
            asx_lib.get_analytics_story(self.story)
            
        if self.update_all:
            self.logger.info("asx-update.py - updating all stories")
        self.logger.info("asx-update.py - COMPLETED")

        #yield {
        #    '_time': time.time(),
        #    'sourcetype': "_json",
        #    '_raw': x,
        #    'status': "Saved Searches created in local"
        #}

    def __init__(self):
        super(ASXUpdate, self).__init__()


dispatch(ASXUpdate, sys.argv, sys.stdin, sys.stdout, __name__)
