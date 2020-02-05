
from classes.asx_lib import ASXLib

API_URL = 'https://content.splunkresearch.com'
USER = 'asx'
PASS = 'I-l1ke-Attack-Range!'
SPLUNK_INSTANCE = '52.10.192.118'


if __name__ == "__main__":

    asx_lib = ASXLib(USER, PASS, API_URL, SPLUNK_INSTANCE)
    #asx_lib.get_analytics_story('credential_dumping')
    #asx_lib.schedule_analytics_story('credential_dumping', '-60m', 'now', '*/10 * * * *')
    asx_lib.run_analytics_story('credential_dumping', '-60m', 'now')
