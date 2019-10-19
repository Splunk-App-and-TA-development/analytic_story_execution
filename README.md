# Analytic Story Execution App (ASX)
![](static/appIconAlt_2x.png)

**Benefit:** Instead of running each search individually, analysts can use this app to execute an Analytic Story end-to-end in their environments. 

**Value:** Security analysts gain use-case relevant context and correlation when events are generated.

![](static/screenshot.png)

This application gives you the tools to make the execution of an Analytic Story in Splunk an automated process. It's as easy as selecting an Analytic Story and clicking "Submit!"

There are two custom commands in this app that will help you automatically detect and investigate scenarios in your dataset:

### Detect

```
detect story="Malicious Powershell" | `format_detection_results`
```

This runs all detection searches belonging to an Analytic Story and stores results in the KV store collection `detect_kvstore`. Also returns the following object for each detection search:

##### [Object Example](https://jsoneditoronline.org/?id=5527dddc593545baa60c5cfd4b10b2f0)

![](static/object_example.png)

### Investigate

`| investigate `

This runs all investigative searches related to the results of a detection in an Analytic Story. Note that `investigate` is a streaming command and can be executed after "Detect." 

For example: 

```
detect story="Malicious Powershell" 
| `format_detection_results` 
| investigate 
| mvexpand investigation_results 
| spath output=investigation_search_name input=investigation_results path=investigation_search_name 
| spath output=investigation_result input=investigation_results path=investigation_result{} | stats count values(investigation_result) as investigation_result by investigation_search_name
```

# Architectural Flow Diagram
![](static/architecture.png)
