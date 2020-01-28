#!/usr/bin/python
import requests
import argparse
import json
import os
import base64
import tarfile
import sys
import splunklib.client as client


VERSION = 1 

def dump(obj):
    for attr in dir(obj):
        print "obj.%s = %s" % (attr, getattr(obj, attr))

def str2bool(v):
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')

def get_content(url):
    payload = ""
    headers = {'cache-control': 'no-cache'}
    response = requests.request("GET", url, data=payload, headers=headers)
    return response

def untar_data(data, output_path, update):
    data = base64.b64decode(data)

    tar_path = os.path.join(output_path,".latest.tar.gz")

    with open(tar_path, "w") as outfile:
        outfile.write(data)
        outfile.close()

    tar = tarfile.open(tar_path)
    members = tar.getmembers()

    for m in members:
        # strip src dir and replace with the output directory
        full_path = output_path + "/" + m.path.strip("src/")
        m.name = ""        
        if update:
            print "updating content files: {0}".format(full_path)
            tar.extract(m, path=full_path)
        else:
            print "fetched content file .. see source {1}.latest.tar.gz, not updating option was not set: {0}".format(full_path,output_path)
            continue 
    tar.close()
def bump_version(version, output_path, update):
    # trim v from v1.xxx
    v = version[1:]
    # full path to write to
    full_path = output_path + "/default/content-version.conf"
    if update:
        file = open(full_path, "w")
        file.write("[content-version]")
        file.write("\nversion = {0}\n".format(v))
        file.close()
        print "updated version to {1} under: {0}".format(full_path,v)

def reload_splunk(splunk_app, splunk_host, splunk_user, splunk_password):
    if splunk_app:
        splunkService = client.connect(host=splunk_host, port=8089, username=splunk_user, password=splunk_password, app=splunk_app)
    else:
        print("splunk app not passed")
        return False

    applications = splunkService.apps

    for app in applications:
        if app.name == splunk_app:
            try:
                app.reload()
                print(splunk_app + ' has been refreshed')
                return True
            except  EntityDeletedException:
                print('Application ' + splunk_app + ' does not exist.')
                return False

def send_message(version, splunk_host,splunk_user,splunk_password):
    splunkService = client.connect(host=splunk_host, port=8089, username=splunk_user, password=splunk_password)
    splunkService.post('/services/messages', name="Enterprise Security Content Update", value="ESCU was successfully updated to {0}".format(version), severity="info")



if __name__ == "__main__":
    # grab arguments
    parser = argparse.ArgumentParser(description="client for security content api""")
    parser.add_argument("-e", "--endpoint", required=False, default="https://g7jbilqdth.execute-api.us-west-2.amazonaws.com/api/", help="api endpoint url, defaults to: https://g7jbilqdth.execute-api.us-west-2.amazonaws.com/api/")
    parser.add_argument("-o", "--output", required=False, default=os.getcwd(), help="directory where to write the sources files to..example: /opt/splunk/etc/apps/DA-ESS-ContentUpdate/default")
    parser.add_argument("-u", "--update", type=str2bool, nargs='?', const=True, default=True, help="Updates/Overwrites content in present in output directory")
    parser.add_argument("-r", "--reload", type=str2bool, nargs='?', const=True, default=True, help="reloads app after deployment")
    parser.add_argument("--splunk_app", required=False, default="DA-ESS-ContentUpdate", help="the application name to reload, defaults to: DA-ESS-ContentUpdate")
    parser.add_argument("--splunk_host", required=False, default="127.0.0.1", help="the splunk host to run reload on, defaults to: 127.0.0.1 on port 8089")
    parser.add_argument("--splunk_user", required=False, default="admin", help="the splunk username that can run reload, defaults to: admin")
    parser.add_argument("--splunk_password", required=False, default="", help="the splunk password for the user that runs reload")
    parser.add_argument("-v", "--version", required=False, help="shows current cli version")

    # parse them
    args = parser.parse_args()
    endpoint = args.endpoint
    output_file = args.output
    ARG_VERSION = args.version    
    update = args.update
    splunk_host = args.splunk_host
    splunk_app = args.splunk_app
    splunk_user = args.splunk_user
    splunk_password = args.splunk_password
    print '''
                 __               __
   _____ ____   / /__  __ ____   / /__
  / ___// __ \ / // / / // __ \ / //_/
 (__  )/ /_/ // // /_/ // / / // ,<
/____// .___//_/ \__,_//_/ /_//_/|_|
     /_/                           _  __                                __                __
   _____ ___   _____ __  __ _____ (_)/ /_ __  __   _____ ____   ____   / /_ ___   ____   / /_
  / ___// _ \ / ___// / / // ___// // __// / / /  / ___// __ \ / __ \ / __// _ \ / __ \ / __/
 (__  )/  __// /__ / /_/ // /   / // /_ / /_/ /  / /__ / /_/ // / / // /_ /  __// / / // /_
/____/ \___/ \___/ \__,_//_/   /_/ \__/ \__, /   \___/ \____//_/ /_/ \__/ \___//_/ /_/ \__/
                                       /____/
'''
    if ARG_VERSION:
        print ("version: {0}".format(VERSION))
        sys.exit()

    if not os.path.isdir(output_file):
        print "output path provided is not a directory: {0}".format(output_file)
        parser.print_help()
        sys.exit(1)
    print "...init ..." 
    print "endpoint set to: ", endpoint
    print "output path set to: ", output_file
    print "checking for security content updates"
    raw_content = get_content(endpoint)
    content = json.loads(raw_content.text)
    print "grabbed latest release version: {0} released: {1}".format(content['name'],content['published_at'])
    untar_data(content['data'],output_file,update)
    bump_version(content['name'],output_file,update)
    print "extracted latest package to {0}".format(output_file)
    if args.reload:
        print "reloading splunk app: {0}".format(splunk_app)
        results = reload_splunk(splunk_app,splunk_host,splunk_user,splunk_password)
        if not results:
            print "failed to reload app {0}".format(splunk_app)

    send_message(content['name'],splunk_host, splunk_user, splunk_password)


##### NEED TO IMPLEMENT MESSAGE INTO SPLUNK THAT STATES CONTENT HAS BEEN UPDATED