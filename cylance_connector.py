# --
# File: cylance_connector.py
#
# Copyright (c) 2018-2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
#
# --

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault as Vault

# Usage of the consts file is recommended
from cylance_consts import *
import os
import shutil
import jwt
import uuid
import requests
import json
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
from zipfile import ZipFile


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class CylanceConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(CylanceConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def _process_empty_reponse(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML resonse, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _download_file_to_vault(self, action_result, url, file_name):
        """ Download a file and add it to the vault """

        guid = uuid.uuid4()

        if hasattr(Vault, 'get_vault_tmp_dir'):
            local_dir = Vault.get_vault_tmp_dir()
        else:
            local_dir = '/vault/tmp'

        tmp_dir = local_dir + "/{}".format(guid)
        zip_path = "{}/{}".format(tmp_dir, file_name)

        try:
            os.makedirs(tmp_dir)
        except Exception as e:
            msg = "Unable to create temporary folder '{}': ".format(tmp_dir)
            return action_result.set_status(phantom.APP_ERROR, msg, e)

        try:
            r = requests.get(url)
        except:
            return action_result.set_status(phantom.APP_ERROR, "Error downloading file")

        with open(zip_path, 'wb') as f:
            f.write(r.content)
            f.close()

        zf = ZipFile(zip_path)
        ex_name = zf.namelist()[0]
        vault_path = "{}/{}".format(tmp_dir, ex_name)

        try:
            # All the zip files are encrypted with the password 'infected'
            zf.extractall(tmp_dir, pwd='infected')
        except:
            return action_result.set_status(phantom.APP_ERROR, "Error extracting zip file")

        vault_ret = Vault.add_attachment(vault_path, self.get_container_id(), file_name=ex_name)
        if vault_ret.get('succeeded'):
            action_result.set_status(phantom.APP_SUCCESS, "Transferred file")
            summary = {
                    phantom.APP_JSON_VAULT_ID: vault_ret[phantom.APP_JSON_HASH],
                    phantom.APP_JSON_NAME: ex_name,
                    phantom.APP_JSON_SIZE: vault_ret.get(phantom.APP_JSON_SIZE)}
            action_result.update_summary(summary)
            action_result.set_status(phantom.APP_SUCCESS, "Successfully added file to vault")
        else:
            action_result.set_status(phantom.APP_ERROR, "Error adding file to vault")

        shutil.rmtree(tmp_dir)

        return action_result.get_status()

    def _get_access_token(self, action_result):
        """
        An auth token is first generated using tenant's unique id, application's unique id, and application's secret
        A call to the /token endpoint is then made, using the auth token, to generate an access token with a timeout
        The code in _get_access_token() provided by Cylance and modified by Phantom
        """

        config = self.get_config()
        self.save_progress("Creating auth token")

        timeout = 1800  # 30 minutes from now
        now = datetime.utcnow()
        timeout_datetime = now + timedelta(seconds=timeout)
        epoch_time = int((now - datetime(1970, 1, 1)).total_seconds())
        epoch_timeout = int((timeout_datetime - datetime(1970, 1, 1)).total_seconds())
        jti_val = str(uuid.uuid4())

        tid_val = config[CYLANCE_JSON_TENANT_ID]
        app_id = config[CYLANCE_JSON_APPLICATION_ID]
        app_secret = config[CYLANCE_JSON_APPLICATION_SECRET]

        auth_url = self._base_url + "/auth/v2/token"
        claims = {
            "exp": epoch_timeout,
            "iat": epoch_time,
            "iss": "http://cylance.com",
            "sub": app_id,
            "tid": tid_val,
            "jti": jti_val
        }

        try:
            encoded = jwt.encode(claims, app_secret, algorithm='HS256')
        except:
            return (phantom.APP_ERROR, CYLANCE_AUTH_TOKEN_ERR)

        payload = { "auth_token": encoded }
        headers = { "Accept": "application/json", "Content-Type": "application/json" }

        self.save_progress("Creating access token")

        try:
            resp = requests.post(auth_url, headers=headers, json=payload)
            access_token = json.loads(resp.text)['access_token']
        except:
            return (phantom.APP_ERROR, CYLANCE_ACCESS_TOKEN_ERR)

        return (phantom.APP_SUCCESS, access_token)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, json=None, data=None, method="get"):

        config = self.get_config()

        ret_val, access_token = self._get_access_token(action_result)

        if (phantom.is_fail(ret_val)):
            return RetVal(action_result.set_status(phantom.APP_ERROR, access_token), None)

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = self._base_url + endpoint

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(access_token)
        }

        try:
            r = request_func(
                            url,
                            json=json,
                            data=data,
                            headers=headers,
                            verify=config.get('verify_server_cert', False),
                            params=params)
        except Exception as e:
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _get_additional_results(self, action_result, total_pages, url, params=None, json=None, headers=None):
        """ By default, results are limited to page 1 and 10 results per page.
            This function is used to iterate the additional pages if the user didn't specify to see a specific page """

        for curr_page in range(2, total_pages + 1):
            params['page'] = curr_page

            # make rest call
            ret_val, response = self._make_rest_call(url, action_result, params=params, json=json, headers=headers)

            if (phantom.is_fail(ret_val)):
                return action_result.get_status()

            # Add the response into the data section
            for item in response['page_items']:
                action_result.add_data(item)

    def _handle_test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Connecting to /users/v2 to test connectivity")
        # make rest call
        ret_val, response = self._make_rest_call('/users/v2', action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_endpoints(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Optional values should use the .get() function
        page = param.get('page')
        page_size = param.get('page_size')

        params = dict()
        if page:
            params['page'] = page
        if page_size:
            params['page_size'] = page_size

        url = '/devices/v2'

        # make rest call
        ret_val, response = self._make_rest_call(url, action_result, params=params, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        for item in response['page_items']:
            action_result.add_data(item)

        if not page and response['total_pages'] > 1:
            self._get_additional_results(action_result, response['total_pages'], url, params=params)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_endpoints'] = response['total_number_of_items']
        summary['total_pages'] = response['total_pages']

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_threats(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        unique_device_id = param['unique_device_id']
        page = param.get('page')
        page_size = param.get('page_size')

        params = dict()
        if page:
            params['page'] = page
        if page_size:
            params['page_size'] = page_size

        url = '/devices/v2/{}/threats'.format(unique_device_id)

        # make rest call
        ret_val, response = self._make_rest_call(url, action_result, params=params, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        for item in response['page_items']:
            action_result.add_data(item)

        if not page and response['total_pages'] > 1:
            self._get_additional_results(action_result, response['total_pages'], url, params=params)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_threats'] = response['total_number_of_items']
        summary['total_pages'] = response['total_pages']

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_system_info(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required values can be accessed directly
        unique_device_id = param['unique_device_id']

        # make rest call
        ret_val, response = self._make_rest_call('/devices/v2/{}'.format(unique_device_id), action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['is_safe'] = response['is_safe']

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_hunt_file(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        sha256_hash = param['hash']
        page = param.get('page')
        page_size = param.get('page_size')

        params = dict()
        if page:
            params['page'] = page
        if page_size:
            params['page_size'] = page_size

        url = '/threats/v2/{}/devices'.format(sha256_hash)

        # make rest call
        ret_val, response = self._make_rest_call(url, action_result, params=params, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        for item in response['page_items']:
            action_result.add_data(item)

        if not page and response['total_pages'] > 1:
            self._get_additional_results(action_result, response['total_pages'], url, params=params)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_items'] = response['total_number_of_items']

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_global_list(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        list_type_id = param.get('list_type_id')
        page = param.get('page')
        page_size = param.get('page_size')

        params = dict()
        if list_type_id == 'GlobalQuarantine':
            params['listTypeId'] = 0
        elif list_type_id == 'GlobalSafe':
            params['listTypeId'] = 1
        if page:
            params['page'] = page
        if page_size:
            params['page_size'] = page_size

        url = '/globallists/v2'

        # make rest call
        ret_val, response = self._make_rest_call(url, action_result, params=params, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        for item in response['page_items']:
            action_result.add_data(item)

        if not page and response['total_pages'] > 1:
            self._get_additional_results(action_result, response['total_pages'], url, params=params)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_items'] = response['total_number_of_items']

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_unblock_hash(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        sha256_hash = param['hash']
        list_type = param['list_type']

        request = {
            "sha256": sha256_hash,
            "list_type": list_type
        }

        # make rest call
        ret_val, response = self._make_rest_call('/globallists/v2', action_result, params=None, json=request, method='delete')

        if (phantom.is_fail(ret_val)):
            message = action_result.get_message()
            if "There's no entry for this threat" in message:
                return action_result.set_status(phantom.APP_SUCCESS, CYLANCE_UNBLOCK_HASH_ALREADY_UNBLOCKED_SUCC)
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, CYLANCE_UNBLOCK_HASH_SUCC)

    def _handle_block_hash(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        sha256_hash = param['hash']
        reason = param['reason']
        list_type = param['list_type']
        category = param.get('category', 'None')

        request = {
            "sha256": sha256_hash,
            "list_type": list_type,
            "category": category,
            "reason": reason
        }

        # make rest call
        ret_val, response = self._make_rest_call('/globallists/v2', action_result, json=request, method='post')

        if (phantom.is_fail(ret_val)):
            message = action_result.get_message()
            if "There's already an entry for this threat" in message:
                return action_result.set_status(phantom.APP_SUCCESS, CYLANCE_BLOCK_HASH_ALREADY_BLOCKED_SUCC)
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, CYLANCE_BLOCK_HASH_SUCC)

    def _handle_get_file(self, param):
        """ Get a file and download it to the vault. Cylance will give the URL """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        sha256_hash = param['hash']

        # make rest call
        ret_val, response = self._make_rest_call('/threats/v2/download/{}'.format(sha256_hash), action_result, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        url = response['url']
        file_name = '{}.zip'.format(sha256_hash)

        ret_val = self._download_file_to_vault(action_result, url, file_name)

        if phantom.is_fail(ret_val):
            msg = action_result.get_message()
            action_result.set_status(phantom.APP_ERROR, "Failed to add file to vault: {}".format(msg))
            return self.set_status(phantom.APP_ERROR)

        return self.set_status(phantom.APP_SUCCESS, "Successfully added file to vault")

    def _handle_get_file_info(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required values can be accessed directly
        sha256_hash = param['hash']

        # make rest call
        ret_val, response = self._make_rest_call('/threats/v2/{}'.format(sha256_hash), action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['classification'] = response['classification']

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_zones(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Optional values should use the .get() function
        page = param.get('page')
        page_size = param.get('page_size')

        params = dict()
        if page:
            params['page'] = page
        if page_size:
            params['page_size'] = page_size

        url = '/zones/v2'

        # make rest call
        ret_val, response = self._make_rest_call(url, action_result, params=params, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        for item in response['page_items']:
            action_result.add_data(item)

        if not page and response['total_pages'] > 1:
            self._get_additional_results(action_result, response['total_pages'], url, params=params)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_zones'] = response['total_number_of_items']

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_zone(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required values can be accessed directly
        unique_zone_id = param['unique_zone_id']
        name = param['name']
        policy_id = param['policy_id']
        criticality = param['criticality']

        request = {
            "name": name,
            "policy_id": policy_id,
            "criticality": criticality
        }

        # make rest call
        ret_val, response = self._make_rest_call('/zones/v2/{}'.format(unique_zone_id), action_result, json=request, method='put')

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, CYLANCE_UPDATE_ZONE_SUCC)

    def _handle_get_policies(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Optional values should use the .get() function
        page = param.get('page')
        page_size = param.get('page_size')

        params = dict()
        if page:
            params['page'] = page
        if page_size:
            params['page_size'] = page_size

        url = '/policies/v2'

        # make rest call
        ret_val, response = self._make_rest_call(url, action_result, params=params, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        for item in response['page_items']:
            action_result.add_data(item)

        if not page and response['total_pages'] > 1:
            self._get_additional_results(action_result, response['total_pages'], url, params=params)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_policies'] = response['total_number_of_items']

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'list_endpoints':
            ret_val = self._handle_list_endpoints(param)

        elif action_id == 'get_threats':
            ret_val = self._handle_get_threats(param)

        elif action_id == 'get_system_info':
            ret_val = self._handle_get_system_info(param)

        elif action_id == 'hunt_file':
            ret_val = self._handle_hunt_file(param)

        elif action_id == 'get_global_list':
            ret_val = self._handle_get_global_list(param)

        elif action_id == 'unblock_hash':
            ret_val = self._handle_unblock_hash(param)

        elif action_id == 'block_hash':
            ret_val = self._handle_block_hash(param)

        elif action_id == 'get_file':
            ret_val = self._handle_get_file(param)

        elif action_id == 'get_file_info':
            ret_val = self._handle_get_file_info(param)

        elif action_id == 'get_zones':
            ret_val = self._handle_get_zones(param)

        elif action_id == 'update_zone':
            ret_val = self._handle_update_zone(param)

        elif action_id == 'get_policies':
            ret_val = self._handle_get_policies(param)

        return ret_val

    def initialize(self):

        self._state = self.load_state()
        config = self.get_config()
        region_code = config[CYLANCE_JSON_REGION_CODE]

        region_codes = {
            "Asia-Pacific - North": "-apne1",
            "Asia-Pacific - Southeast": "-au",
            "Europe - Central": "-euc1",
            "Government": ".us",
            "North America": "",
            "South America": "-sae1"
        }

        region_code_formatted = region_codes.get(region_code)

        self._base_url = "https://protectapi{}.cylance.com".format(region_code_formatted)

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved accross actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print ("Accessing the Login page")
            r = requests.get(BaseConnector._get_phantom_base_url() + "login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = BaseConnector._get_phantom_base_url() + 'login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post(BaseConnector._get_phantom_base_url() + "login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = CylanceConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
