import splunk.admin as admin
import splunk.entity as en

CONF_FILE = 'asx'

class ConfigApp(admin.MConfigHandler):
  '''
  Set up supported arguments
  '''
  def setup(self):
    if self.requestedAction == admin.ACTION_EDIT:
      for arg in ['api_url']:
        self.supportedArgs.addOptArg(arg)
        
  '''
  Read the initial values of the parameters from the custom file myappsetup.conf
  and write them to the setup screen.
  If the app has never been set up, uses Splunk_Analytic_Story_Execution/default/asx.conf.
  If app has been set up, looks at local/asx.conf first, then looks at
  default/asx.conf only if there is no value for a field in local/asx.conf
  '''


  def handleList(self, confInfo):
    confDict = self.readConf(CONF_FILE)
    if None != confDict:
      for stanza, settings in confDict.items():
        for key, val in settings.items():
          if key in ['api_url'] and val in [None, '']:
            val = ''
          confInfo[stanza].append(key, val)
          
  '''
  After user clicks Save on setup page, take updated parameters,
  normalize them, and save them somewhere
  '''

  def handleEdit(self, confInfo):
    name = self.callerArgs.id
    args = self.callerArgs
    
    if self.callerArgs.data['api_url'][0] in [None, '']:
      self.callerArgs.data['api_url'][0] = ''  

    self.writeConf('asx', 'settings', self.callerArgs.data)
      
# initialize the handler
admin.init(ConfigApp, admin.CONTEXT_NONE)



