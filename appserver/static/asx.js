require([
   'underscore',
   'jquery',
   'splunkjs/mvc',
   'splunkjs/mvc/searchmanager',
   '../app/Splunk_Analytic_Story_Execution/js/lib/tabs',
   'css!../app/Splunk_Analytic_Story_Execution/js/lib/tabs.css',
   'splunkjs/mvc/simplexml/ready!'
 ], function(_, $, mvc, SearchManager) {
    $('.all_results').html(_.template('<%- _("Detection Results").t() %>'));
    $('.all_entities').html(_.template('<%- _("Entities").t() %>'));
    $('.individual_entities').html(_.template('<%- _("Individual Entities").t() %>'));
    $('.chart').html(_.template('<%- _("Chart").t() %>'));
    $('.investigate').html(_.template('<%- _("Investigate Results").t() %>'));


    const tokenModel = mvc.Components.get('default');
    const submittedTokens = mvc.Components.get('submitted');

    
 });
