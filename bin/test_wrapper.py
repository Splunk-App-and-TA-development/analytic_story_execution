from asx_lib import ASXLib

API_URL = 'https://content.splunkresearch.com'
USER = 'admin'
PASS = 'h3a2J90pFQoO'
SPLUNK_INSTANCE = '172.31.7.199'


if __name__ == "__main__":

    asx_lib = ASXLib(USER, PASS, API_URL, SPLUNK_INSTANCE)
    print asx_lib
    x = asx_lib.get_analytics_story('credential_dumping')
    print type(x)
    #asx_lib.schedule_analytics_story('credential_dumping', '-60m', 'now', '*/10 * * * *')
    #asx_lib.run_analytics_story('credential_dumping', '-60m', 'now')
