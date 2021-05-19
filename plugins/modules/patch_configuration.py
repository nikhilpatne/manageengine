#!/usr/bin/env python

ANSIBLE_METADATA = {
    "metadata_version": "1.2",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = """
---
module: patch_configuration
short_description: Create and delete manageengine patch configuration
version_added: '1.0'
description:
    - "Create and delete manageengine patch configuration"
requirements: []
author:
    - Nikhil Patne (@nikhilpatne)
options:
    url:
        description:
            - URL or Host IP of manageengine instance.
        required: true
        type: str
    port:
        description:
            - TCP port on which manageengine instance is running.
        type: str
        default: 8020
    username:
        description:
            - Username to connect manageengine instance
        required: true
        type: str
    password:
        description:
            - Password to connect manageengine instance.
        required: true
        type: str
    ip_list:
        description:
            - List of IP addresses on which patching will perform.
        required: true
        type: list
    deployment_policy:
        description:
            - Deployment policy
        type: str
        choices: 
            - Force reboot excluding servers
            - Deploy during System start up/login
            - Download immediately and deploy during deployment window
            - Deploy security(Patch Tuesday) updates
            - Deploy during non-business hours(Wake computers and force shutdown)
            - Deploy during business hours(Do not reboot)
            - Allow user intervention(Skip deployment/reboot)
            - Deploy any time at the earliest
        default: 'Deploy any time at the earliest'
    configuration_name:
        description:
            - The name of the configuration.
        required: true
        type: str
    configuration_description:
        description:
            - Configuration description
        required: true
        type: str
    state:
        description:
            - Patch should create or delete
        type: str
        choices: ['present', 'absent']
        default: present
"""
EXAMPLES = """
# Create patch configuration
- name: create patch configuration
  patch_configuration:
    url: http://manageengine_host
    port: 8020
    username: admin
    password: admin
    ip_list: ["ip1","ip2"]
    deployment_policy: 'Deploy during business hours(Do not reboot)'
    configuration_name: 'MyConfiguration'
    configuration_description: 'My first configuration'
"""
import traceback,requests,json,base64
from requests.auth import HTTPBasicAuth 

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

resources = []
patches = []

def manageengine_auth(module,url, port, username, password):
    try:
        auth = HTTPBasicAuth(username, password)
        enc_password = base64.b64encode(password.encode("ascii")).decode("ascii")
        response = requests.get('http://'+url+':'+port+'/api/1.3/desktop/authentication?username='+username+'&password='+enc_password+'&auth_type=local_authentication', 
                auth = auth)
        response_content = json.loads(response.content.decode())
        token = response_content['message_response']['authentication']['auth_data']['auth_token']
        return token
    except Exception as e:
        module.fail_json(msg="Failed to get token {}".format(str(e)))


def getResources(module,token,url,port,ip_list):
    try:

        headers = {
                'Authorization' : token
            }

        response = requests.get('http://'+url+':'+port+'/api/1.3/patch/allsystems', headers=headers)
        response_content = json.loads(response.content.decode())
        for system in response_content['message_response']['allsystems']:
            if system['ip_address'] in ip_list:
                resources.append(system['resource_id'])
        return resources
    except Exception as e:
        module.fail_json(msg="Failed to get resource list {}".format(str(e)))


def getPatches(module,token,url,port):

    try:

        headers = {
                'Authorization' : token
            }

        response = requests.get('http://'+url+':'+port+'/api/1.3/patch/allpatches?patchstatusfilter=202', headers=headers)
        response_content = json.loads(response.content.decode())
        for patch in response_content['message_response']['allpatches']:
            if patch['update_name'] == "Security Updates":
                patches.append(patch['patch_id'])
        return patches
    except Exception as e:
        module.fail_json(msg="Failed to get patches {}".format(str(e)))


def getDeployments(module,token,url,port,deployment_policy):

    try:

        headers = {
                'Authorization' : token
            }

        response = requests.get('http://'+url+':'+port+'/api/1.3/patch/deploymentpolicies', headers=headers)
        response_content = json.loads(response.content.decode())
        for deployment in response_content['message_response']['deploymentpolicies']:
            if deployment['template_name'] == deployment_policy:
                return deployment['template_id']
    except Exception as e:
        module.fail_json(msg="Failed to get deployment policy {}".format(str(e)))


def setTargetData(module,token,url,port,resource_list):

    try:

        headers = {
                'Authorization' : token,
                'Content-Type' : 'application/patchConfig.v1+json',
                 'Accept': 'application/patchConfig.v1+json'

            }

        body = {
            "operation":  "INSTALL",
            "patchIDs":  [],
            "criteriaJSON":  {},
            "dcViewFilterID":  "",
            "resourceIDs": resource_list
        }     


        response = requests.post('http://'+url+':'+port+'/dcapi/patch/manualdeployment/patchConfig?autoPopulate=true&isOnlyApproved=false', headers=headers, data=json.dumps(body))
        response_content = json.loads(response.content.decode())
        if response_content:
            return response_content['targetData']
    except Exception as e:
        module.fail_json(msg="Failed to set targetData {}".format(str(e)))



def createConfiguration(module,token,url, port,configuration_name,configuration_description,deployment_policy_id,patch_list,targetData):

    try:

        headers = {
                'Authorization' : token,
                'Content-Type' : 'application/patchDeploy.v1+json',
            }

        body = {
           
    "collectionType":  1,
    "targetData": targetData,

    "refreshMinRetry":  1,
    "configType":  "computer",
    "configDetails":  [
                          {
                              "details":  [
                                              {
                                                  "patchIDs": patch_list
                                              }
                                          ],
                              "configName":  "PATCH_INSTALL"
                          }
                      ],
    "applyAtStartupLogon":  False,
    "continueDeployment":  False,
    "description": configuration_description,
    "logonStartupMinRetry":  1,
    "platform":  "windows",
    "label": configuration_name,
    "deploymentPolicyId": int(deployment_policy_id),
    "enableRetry":  True,
    "applyAtRefresh":  False,
    "noOfRetries":  2,
    "applyAlways":  False


   
            }     

        print("----------------------------------------------------------------------")
        response = requests.post('http://'+url+':'+port+'/dcapi/patch/manualdeployment', headers=headers, json=body)
        response_content = json.loads(response.content.decode())
        if response_content:
            return response_content
    except Exception as e:
        module.fail_json(msg="Failed to create patch configuration {}".format(str(e)))


    


def main():
    module = AnsibleModule(
        argument_spec=dict(
            url=dict(type="str", required=True),
            port=dict(type="str", default="8020"),
            username=dict(type="str", required=True),
            password=dict(type="str", default=None, no_log=True),
            ip_list = dict(type="list", required=True),
            deployment_policy=dict(type="str", default="Deploy any time at the earliest"),
            configuration_name=dict(type="str", required=True),
            configuration_description=dict(type="str", required=True),
            state=dict(type="str", choices=["present", "absent"], default="present"),
        ),
        supports_check_mode=True
    )

    url = module.params["url"]
    port = module.params["port"]
    username = module.params["username"]
    password = module.params["password"]
    ip_list = module.params["ip_list"]
    deployment_policy = module.params["deployment_policy"]
    configuration_name = module.params["configuration_name"]
    configuration_description = module.params["configuration_description"]
    state = module.params["state"]

    if state == "present":
        token = manageengine_auth(module,url, port, username, password)
        if token:
            resource_list = getResources(module,token,url, port,ip_list)
            if resource_list:
                patch_list = getPatches(module,token,url, port)
                if patch_list:
                    deployment_policy_id = getDeployments(module,token,url, port,deployment_policy)
                    if deployment_policy_id:
                        targetData = setTargetData(module,token,url, port,resource_list)
                        if targetData:
                            configuration_details = createConfiguration(module,token,url, port,configuration_name,configuration_description,deployment_policy_id,patch_list,targetData)


    module.exit_json(msg=configuration_details, changed=True)


if __name__ == "__main__":
    main()
