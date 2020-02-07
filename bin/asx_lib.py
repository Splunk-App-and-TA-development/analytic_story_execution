import requests
import json
import splunk.mining.dcutils

class ASXLib:
    logger = splunk.mining.dcutils.getLogger()

    def __init__(self, service, api_url):
        self.service = service
        if api_url.endswith('/'):
            self.api_url = api_url[:-1]
        else:
            self.api_url = api_url

    def list_analytics_stories(self):
        url = self.api_url + '/stories/?community=false'
        response = self.__call_security_content_api(url)
        self.logger.info("asx_lib.py - listing stories - {0}\n".format(response))
        return response['stories']

   
    def get_analytics_story(self, name):
        self.story = name

        url = self.api_url + '/stories/' + name  + '?community=false'
        story = self.__call_security_content_api(url)

        detections = []
        macros = dict()

        for obj in story['detections']:
            self.logger.info("asx_lib.py - grabbing detection - {0}\n".format(json.dumps(obj['name'])))
            url = self.api_url + '/detections/' + obj['name'].lower().replace(' ', '_')  + '?community=false'
            detection = self.__call_security_content_api(url)
            if detection:
                detections.append(detection)
                for macro in detection['detect']['splunk']['correlation_rule']['macros']:
                    if not (macro in macros):
                        url = self.api_url + '/macros/' + macro  + '?community=false'
                        macro = self.__call_security_content_api(url)
                        macros[macro['name']] = macro

        self.__generate_standard_macros(self.service)
        for macro_name, macro in macros.items():
            self.__generate_macro(self.service, macro)

        for detection in detections:
            kwargs = self.__generate_detection(self.service, detection)

        return 0


    def schedule_analytics_story(self, name, earliest_time, latest_time, cron_schedule):
        search_name = []

        for search in self.service.saved_searches:
            if 'action.escu.analytic_story' in search:
                if search['action.escu.analytic_story'] == name:
                    mappings = json.loads(search['action.escu.mappings'])
                    if "mitre_technique_id" in mappings:
                        query = search['search'] + ' | collect index=asx marker="mitre_id=' + mappings["mitre_technique_id"][0] + '"'
                    else:
                        query = search['search'] + ' | collect index=asx '
                    kwargs =    {"disabled": "false",
                                "is_scheduled": True,
                                "cron_schedule": cron_schedule,
                                "dispatch.earliest_time": earliest_time,
                                "dispatch.latest_time": latest_time,
                                "search": query
                                }
                    search.update(**kwargs).refresh()
                    search_name.append(search['action.escu.full_search_name'])
                    
        return search_name


    def run_analytics_story(self, name, earliest_time, latest_time):
        search_name = []

        for search in self.service.saved_searches:
            if 'action.escu.analytic_story' in search:

                #Running Support, not sure if we want to index these results

                if name in search['action.escu.analytic_story']:
                    if search['action.escu.search_type'] == "support":
                        query = search['search'] + ' | collect index=asx '

                        kwargs = {  "disabled": False,
                                    "dispatch.earliest_time": earliest_time,
                                    "dispatch.latest_time": latest_time,
                                    "search": query}

                        search.update(**kwargs).refresh()
                        job = search.dispatch()
                        search_name.append(search['action.escu.full_search_name'])

                #Running Detections
                if name in search['action.escu.analytic_story']:
                    if search['action.escu.search_type'] == "detection":
        
                        mappings = json.loads(search['action.escu.mappings'])
                        if "mitre_technique_id" in mappings:
                            query = search['search'] + ' | collect index=asx marker="mitre_id=' + mappings["mitre_technique_id"][0] + '"'
                        else:
                            query = search['search'] + ' | collect index=asx '

                        self.logger.info("executestory.py - Search Name - {0} ".format(search['action.escu.full_search_name']))

                        kwargs = {  "disabled": False,
                                    "dispatch.earliest_time": earliest_time,
                                    "dispatch.latest_time": latest_time,
                                    "search": query}

                        search.update(**kwargs).refresh()
                        job = search.dispatch()
                        search_name.append(search['action.escu.full_search_name'])

        return search_name

    def __call_security_content_api(self, url):
        resp = requests.get(url)
        if resp.status_code != 200:
            # this is only temporary, needs to be fixed in API
            #raise requests.HTTPError('Error {} by calling {}'.format(resp.status_code, url))
            return 0
        else:
            # this is only temporary, needs to be fixed in API
            return resp.json()

    def __generate_macro(self, service, macro):
        service.post('properties/macros', __stanza=macro['name'])
        service.post('properties/macros/' + macro['name'], definition=macro['definition'], description=macro['description'])

    def __generate_standard_macros(self, service):
        service.post('properties/macros', __stanza="security_content_ctime(1)")
        service.post('properties/macros/security_content_ctime(1)', definition='convert timeformat="%m/%d/%Y %H:%M:%S" ctime($field$)', description='convert epoch time to string', args='field')

        service.post('properties/macros', __stanza="security_content_summariesonly")
        service.post('properties/macros/security_content_summariesonly', definition='summariesonly=true allow_old_summaries=true', description="search data models summaries only", args='field')

    def __generate_detection(self, service, detection):

        full_search_name = str("ESCU - " + detection['name'] + " - Rule")
        resp = service.saved_searches.list()

        # if there are detections with the same name, don't override
        if not any(x.name == full_search_name for x in resp):
            kwargs = {}
            kwargs.update({"action.escu": "0"})
            kwargs.update({"action.escu.enabled": "1"})
            kwargs.update({"description":  detection['description'] })
            kwargs.update({"action.escu.mappings":  json.dumps(detection['mappings']) })
            if 'data_models' in detection['data_metadata']:
                kwargs.update({"action.escu.data_models":  json.dumps(detection['data_metadata']['data_models']) })
            if 'eli5' in detection:
                kwargs.update({"action.escu.eli5":  detection['eli5'] })
            else:
                kwargs.update({"action.escu.eli5": 'none'})
            if 'how_to_implement' in detection:
                kwargs.update({"action.escu.how_to_implement":  detection['how_to_implement'] })
            else:
                kwargs.update({"action.escu.how_to_implement": "none"})
            if 'known_false_positives' in detection:
                kwargs.update({"action.escu.known_false_positives":  detection['known_false_positives'] })
            else:
                kwargs.update({"action.escu.known_false_positives": "None"})
            kwargs.update({"action.escu.creation_date":  detection['creation_date'] })
            kwargs.update({"action.escu.modification_date":  detection['modification_date'] })
            kwargs.update({"action.escu.confidence":  detection['confidence'] })
            kwargs.update({"action.escu.full_search_name": full_search_name })
            kwargs.update({"action.escu.search_type": "detection"})
            if 'asset_type' in detection:
                kwargs.update({"action.escu.asset_at_risk":  detection['asset_type'] })
            if 'entities' in detection:
                kwargs.update({"action.escu.fields_required":  json.dumps(detection['entities']) })
                kwargs.update({"action.escu.entities":  json.dumps(detection['entities']) })
            if 'providing_technologies' in detection['data_metadata']:
                kwargs.update({"action.escu.providing_technologies":  json.dumps(detection['data_metadata']['providing_technologies']) })
            kwargs.update({"action.escu.analytic_story":  self.story })

            if 'splunk' in detection['detect']:
                correlation_rule = detection['detect']['splunk']['correlation_rule']
            else:
                correlation_rule = detection['detect']['uba']['correlation_rule']

            if 'cron_schedule' in correlation_rule['schedule']:
                kwargs.update({"cron_schedule":  correlation_rule['schedule']['cron_schedule'] })
            if 'earliest_time' in correlation_rule['schedule']:
                kwargs.update({"dispatch.earliest_time":  correlation_rule['schedule']['earliest_time'] })
            if 'latest_time' in correlation_rule['schedule']:
                kwargs.update({"dispatch.latest_time":  correlation_rule['schedule']['latest_time'] })

            if correlation_rule:
                kwargs.update({"action.correlationsearch.enabled": "1"})
                kwargs.update({"action.correlationsearch.label":  detection['name'] })
                if 'notable' in correlation_rule:
                    kwargs.update({"action.notable": "1"})
                if 'nes_fields' in correlation_rule['notable']:
                    kwargs.update({"action.notable.param.nes_fields": correlation_rule['notable']['nes_fields'] })
                    kwargs.update({"action.notable.param.rule_description": correlation_rule['notable']['rule_description'] })
                    kwargs.update({"action.notable.param.rule_title": correlation_rule['notable']['rule_title'] })
                    kwargs.update({"action.notable.param.security_domain": detection['security_domain'] })
                    kwargs.update({"action.notable.param.severity": detection['confidence'] })
                if ('drilldown_name' in correlation_rule['notable']) and ('drilldown_search' in correlation_rule['notable']):
                    kwargs.update({"action.notable.param.drilldown_name":  correlation_rule['notable']['drilldown_name'] })
                    kwargs.update({"action.notable.param.drilldown_search": correlation_rule['notable']['drilldown_search'] })
                if 'risk' in correlation_rule:
                    kwargs.update({"action.risk": "1"})
                    kwargs.update({"action.risk.param._risk_object":  correlation_rule['risk']['risk_object'] })
                    kwargs.update({"action.risk.param._risk_object_type":  correlation_rule['risk']['risk_object_type'][0] })
                    kwargs.update({"action.risk.param._risk_score": correlation_rule['risk']['risk_score'] })
                    kwargs.update({"action.risk.param.verbose": "0"})
                if 'suppress' in correlation_rule:
                    kwargs.update({"alert.digest_mode": "1"})
                    kwargs.update({"alert.suppress": "1"})
                    kwargs.update({"alert.suppress.fields":  correlation_rule['suppress']['suppress_fields'] })
                    kwargs.update({"alert.suppress.period":  correlation_rule['suppress']['suppress_period'] })
            kwargs.update({"action.escu.earliest_time_offset": "3600"})
            kwargs.update({"action.escu.latest_time_offset": "86400"})
            kwargs.update({"disabled": "true"})
            kwargs.update({"schedule_window": "auto"})
            kwargs.update({"is_visible": "false"})


            if 'splunk' in detection['detect']:
                query = detection['detect']['splunk']['correlation_rule']['search']
                query = query.encode('ascii', 'ignore').decode('ascii')
            else:
                query = detection['detect']['uba']['correlation_rule']['search']
                query = query.encode('ascii', 'ignore').decode('ascii')
            search = kwargs['action.escu.full_search_name']
            search = search.encode('ascii', 'ignore').decode('ascii')

            savedsearch = service.saved_searches.create(search, query, **kwargs)
