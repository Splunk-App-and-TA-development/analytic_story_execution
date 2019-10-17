from splunklib.searchcommands import dispatch, StreamingCommand, Configuration
import sys
import json
import splunk
import splunklib.client
import splunklib.results
from splunklib.searchcommands.validators import Boolean
import splunk.mining.dcutils
import time
import re
from datetime import datetime, timedelta


@Configuration()
class Investigate(StreamingCommand):
    logger = splunk.mining.dcutils.getLogger()
    investigative_searches_to_run = []
    final_search = ""
    COLLECTION_NAME = "mp_detect_new"
    INVESTIGATIVE_COLLECTION_NAME = "investigative_collection_new"
    # story = "Malicious PowerShell"
    collection_results = {}

    def _investigative_searches(self, content):
        investigative_data = {}
        investigative_data['search_name'] = content['action.escu.full_search_name']
        investigative_data['search_description'] = content['description']
        investigative_data['search'] = content['search']
        investigative_data['entities'] = content['action.escu.entities']
        self.investigative_searches_to_run.append(investigative_data)
        return self.investigative_searches_to_run

    def _store_collections(self, collection, investigations_results):

        self.collection_results['investigations'] = investigations_results
        collection.data.insert(json.dumps(self.collection_results))
        self.logger.info("investigate.py - Append Investigate Collection: {0}".format(json.dumps(self.collection_results)))

    def _get_username(self, service):
        search = '| rest /services/authentication/current-context/context | fields + username'
        results = service.jobs.oneshot(search)
        username_results = splunklib.results.ResultsReader(results)
        username = next(iter(username_results))['username']
        return username

    def _process_job_results(self, job, job_results, search):
        investigation_results = []
        results={}       
        results['investigative_search_name'] = search
        # if there are results lets process them
        if job['resultCount'] > "0":

            for result in job_results:
                # add store detection results
                investigation_results.append(dict(result))
            results['investigation_results'] = investigation_results
            
        # else:
        #     self.logger.info(
        #         "investigate.py - search: {0} - HAD NO results".format(search))

        return results

    def _run_investigations(self, searches_to_run, service, earliest_time, latest_time):

        r = []

        for i in searches_to_run:
            search=i['search_name']
            for spl in i['searches']:
                kwargs = {"exec_mode": "normal", "earliest_time": earliest_time, "latest_time": latest_time + 1}
                spl =spl + "| head 1"
                #self.logger.info("investigate.py - TEST3: {0}".format((spl)))
                job = service.jobs.create(spl, **kwargs)
                
                while True:
                    job.refresh()
                    if job['isDone'] == "1":
                        #self.logger.info("investigate.py - C investigation search: {0}".format(spl))
                        break
                job_results = splunklib.results.ResultsReader(job.results())
                investigation_results = self._process_job_results(job, job_results, search)
            r.append(investigation_results)

        return r

        

    def _generate_investigation_objects(self, detected_entities):
        investigations = []

        # iterate through all the investigations
        for investigative_search in self.investigative_searches_to_run:
            # self.logger.info("investigate.py - {0} ".format(investigative_search['search_name']))

            i = dict()

            # get the data we need from the investigative search
            search_name = investigative_search['search_name']
            search = investigative_search['search']
            investigative_entities = json.loads(investigative_search['entities'])

            for investigative_entity_name in investigative_entities:
                # iterate through all the detection entities and grab their results
                #self.logger.info("investigate.py - {0} ".format(investigative_entity_name))
                i[investigative_entity_name] = []

                for e in sorted(detected_entities):
                
                    for detected_entity_name, detected_entity_value in sorted(e.items()):
                        if investigative_entity_name == detected_entity_name:
                            #self.logger.info("investigate.py - investigative_entity_name {2} | detected_entity_name {0} | detected_entity_value {1} ".format(detected_entity_name, detected_entity_value, investigative_entity_name))
                            for v in detected_entity_value['entity_results']:
                                i[investigative_entity_name].append(v)

            # self.logger.info("investigate.py {0} ||| object: {1}".format(search_name, json.dumps(i, indent=4)))
            searches = {}

            searches['searches'] = []
            searches['entities'] = []
            searches['values'] = []
            searches['search_name'] = investigative_search['search_name']
            searches['multiple_entities'] = False
            for entity_name, values in sorted(i.items()):
                modified_entity_name = "{" + entity_name + "}"
                for v in values:

                    # check if this is not our first entity and if is not in the list then we must update all our searches
                    if len(searches['entities']) > 0 and entity_name not in searches['entities']:
                        
                        updated_searches = []
                        searches['multiple_entities'] = True
                        # update all searches store
                        for s in searches['searches']:
                            
                            updated_search = s.replace(modified_entity_name, v)
                            updated_searches.append(updated_search)

                        searches['searches'] = updated_searches

                    searches['entities'].append(entity_name)
                    searches['values'].append(v)
                   
                    updated_search = search.replace(modified_entity_name, v)
                    searches['searches'].append(updated_search)

                    if searches['multiple_entities'] == True:
                        del searches['searches'][-1]
                    
            investigations.append(searches)
        #self.logger.info("investigate.py - FULL : {0}".format(json.dumps(investigations)))
        return investigations

    def _calculate_investigations(self, service, story):
        savedsearches = service.saved_searches

        for savedsearch in savedsearches:
            content = savedsearch.content
            if 'action.escu.analytic_story' in content:
                stories = str(content['action.escu.analytic_story']).strip('][').replace('"', '').split(', ')
                for s in stories:
                    if s == story and content['action.escu.search_type'] == 'investigative':
                        self.investigative_searches_to_run = self._investigative_searches(content)

    def _setup_kvstore(self, service):
        # grab investigations to execute
        collection_results = {}
        collection_results['investigations'] = []

        # testing investigation in KV store

        if self.INVESTIGATIVE_COLLECTION_NAME in service.kvstore:
            service.kvstore.delete(self.INVESTIGATIVE_COLLECTION_NAME)

        # Let's create it and then make sure it exists
        service.kvstore.create(self.INVESTIGATIVE_COLLECTION_NAME)
        investigate_collection = service.kvstore[self.INVESTIGATIVE_COLLECTION_NAME]

        return investigate_collection

    def stream(self, records):

        search_results = self.search_results_info
        port = splunk.getDefault('port')
        service = splunklib.client.connect(token=self._metadata.searchinfo.session_key, port=port, owner="nobody")

        collection = service.kvstore[self.COLLECTION_NAME]

        if self.COLLECTION_NAME in service.kvstore:
            self.logger.info("investigate.py - Detect Collection: {0}".format(self.COLLECTION_NAME))

        investigative_collection = self._setup_kvstore(service)
        detection_results = (collection.data.query())

        # for detection_result in detection_results:
        #     kv_key = (detection_result['_key'])

        # self.logger.info("investigate.py - key: {0}".format(kv_key))

        # investigations_results = {

        # }

        # collection.data.batch_save(kv_key, json.dumps(investigations_results))
        # self.logger.info("investigate.py - DONE UPDATING: {0}".format(self.COLLECTION_NAME))
        # test= {}

        # test = (collection.data.query())
        # self.logger.info("investigate.py - FINAL KV: {0}".format(json.dumps(test)))

        # yield test
    


        for record in records:
            record['executed_by'] = self._get_username(service)
            results = {}
            final_yield = []
            detection_result_count = record['detection_result_count']
            record['investigation_results'] = "null"

            if detection_result_count == "0":
                record['investigation_results'] = "null"

            if detection_result_count > "0": 

                if 'story' in record:
                                 
                    results['investigation_results'] = []               
                    self._calculate_investigations(service, record['story'])

                    #Running from the KV store 
                    for detection_result in detection_results:

                        for each_result in detection_result['detections']:

                            if each_result['detection_result_count'] > "0":
                            # check that we have a detected entity values before we move on to investigate
                
                                if each_result['entities'] != "null":
                                    investigations = self._generate_investigation_objects(each_result['entities'])

                                else:
                                    continue                                
                                # Execute investigation searches
                                earliest_time = each_result['first_detection_time']
                                earliest_time = int(time.mktime(time.strptime(earliest_time, '%Y-%m-%d %H:%M:%S')))
                                latest_time = each_result['last_detection_time']
                                latest_time = int(time.mktime(time.strptime(latest_time, '%Y-%m-%d %H:%M:%S')))
                                investigation_results = self._run_investigations(investigations, service, earliest_time,
                                                                                  latest_time)
                               
                                results['investigation_results'].append((investigation_results))


                                #BREAKING FOR TEST : TAKE NOTE. This loop will only work for the first detection result in KV store 
                                           

                        record['investigation_results'] = results

                else:
                    record['investigation_results'] = "no investigations for this story found"

            self.logger.info("investigate.py - FINAL -------------------")
            yield {

            '_time': time.time(),
            'sourcetype': "_json",
            'story': record['story'],
            'executed_by': record['executed_by'],
            'detection_result_count': record['detection_result_count'],
            'detection_search_name': record['detection_search_name'],
            'first_detection_time': record['first_detection_time'],
            'last_detection_time': record['last_detection_time'],
            'support_search_name': record['support_search_name'],
            'entities': record['entities'],
            'mappings': record['mappings'],
            'detection_results' : record['detection_results'],
            'investigation_results' : record['investigation_results']
                  }


if __name__ == "__main__":
    dispatch(Investigate, sys.argv, sys.stdin, sys.stdout, __name__)
