# Analytic Story Execution

## Benefit

Analysts can execute an Analytic Story end-to-end in their environments.

## Value
Security analysts gain use case relevant context and correlation when the event is generated


This application gives you the tools to execute an analytic story in Splunk. There are two custom commands in this app that will help you to detect and investigate scenarios in your dataset:

#1 Detect
	* Run all detection searches beloning in an analytic story and store resutls in a KV store

#2 Investigate
	* Run all investigative searches belonging to that analytic story


NOTE: 


There are some mandatory fields needed in your savedsearches.conf files to be able to leverage the Detect and Investigate binaries


MANDATORY FEILDS NEEDED BY THE CODE
#Example

	
[<stanza name>]
* Create a unique stanza name for each saved search that belongs to an analytic story
* Follow the stanza name with any number of the following settings.
* If you do not specify a setting, Splunk software uses the default.

action.escu.full_search_name = <string>
	* Full name of the search
	* required

action.escu.mappings = [json]
	* Framework mappings like CIS, Kill Chain, NIST, ATTACK

action.escu.analytic_story = <list>
	* List of analytic story the search belongs to

action.escu.search_type = [detection | investigative | support]
	* The type of this search
