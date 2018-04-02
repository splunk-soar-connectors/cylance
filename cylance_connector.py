# --
# File: cylance_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2018
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
from cylance_consts import *
import jwt
import uuid
import requests
import json
from bs4 import BeautifulSoup
from datetime import datetime, timedelta


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

    def _get_access_token(self, action_result):
        """
        An auth token is first generated using tenant's unique id, application's unique id, and application's secret
        A call to the /token endpoint is then made, using the auth token, to generate an access token with a timeout
        The code in _get_access_token() provided by Cylance and modified by Phantom
        """

        config = self.get_config()
        self.save_progress("Retrieving access token")

        timeout = 1800  # 30 minutes from now
        now = datetime.utcnow()
        timeout_datetime = now + timedelta(seconds=timeout)
        epoch_time = int((now - datetime(1970, 1, 1)).total_seconds())
        epoch_timeout = int((timeout_datetime - datetime(1970, 1, 1)).total_seconds())
        jti_val = str(uuid.uuid4())

        tid_val = config[CYLANCE_JSON_TENANT_ID]
        app_id = config[CYLANCE_JSON_APPLICATION_ID]
        app_secret = config[CYLANCE_JSON_APPLICATION_SECRET]

        AUTH_URL = "https://protectapi.cylance.com/auth/v2/token"
        claims = {
            "exp": epoch_timeout,
            "iat": epoch_time,
            "iss": "http://cylance.com",
            "sub": app_id,
            "tid": tid_val,
            "jti": jti_val
        }

        try:
            auth_token = jwt.encode(claims, app_secret, algorithm='HS256')
        except Exception as e:
            return (phantom.APP_ERROR, e)

        payload = {"auth_token": auth_token}
        headers = { "Content-Type": "application/json", "Accept": "application/json" }

        try:
            resp = requests.post(AUTH_URL, headers=headers, data=json.dumps(payload))
            access_token = json.loads(resp.text)['access_token']
        except Exception as e:
            return (phantom.APP_ERROR, e)

        return (phantom.APP_SUCCESS, access_token)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get"):

        config = self.get_config()

        ret_val, access_token = self._get_access_token(action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = self._base_url + endpoint

        headers = headers.append({
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(access_token)
        })

        try:
            r = request_func(
                            url,
                            data=data,
                            headers=headers,
                            verify=config.get('verify_server_cert', False),
                            params=params)
        except Exception as e:
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        # self.save_progress("Connecting to endpoint")
        # make rest call
        ret_val, response = self._make_rest_call('/users/v2', action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_endpoints(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        """
        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        required_parameter = param['required_parameter']

        # Optional values should use the .get() function
        optional_parameter = param.get('optional_parameter', 'default_value')
        """

        """
        # make rest call
        ret_val, response = self._make_rest_call('/endpoint', action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        # action_result.add_data(response)
        """

        action_result.add_data({})

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['important_data'] = "value"

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        # return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message, in case of success we don't set the message, but use the summary
        return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

    def _handle_get_system_info(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        """
        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        required_parameter = param['required_parameter']

        # Optional values should use the .get() function
        optional_parameter = param.get('optional_parameter', 'default_value')
        """

        """
        # make rest call
        ret_val, response = self._make_rest_call('/endpoint', action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        # action_result.add_data(response)
        """

        action_result.add_data({})

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['important_data'] = "value"

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        # return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message, in case of success we don't set the message, but use the summary
        return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

    def _handle_hunt_file(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        """
        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        required_parameter = param['required_parameter']

        # Optional values should use the .get() function
        optional_parameter = param.get('optional_parameter', 'default_value')
        """

        """
        # make rest call
        ret_val, response = self._make_rest_call('/endpoint', action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        # action_result.add_data(response)
        """

        action_result.add_data({})

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['important_data'] = "value"

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        # return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message, in case of success we don't set the message, but use the summary
        return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

    def _handle_unblock_hash(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        """
        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        required_parameter = param['required_parameter']

        # Optional values should use the .get() function
        optional_parameter = param.get('optional_parameter', 'default_value')
        """

        """
        # make rest call
        ret_val, response = self._make_rest_call('/endpoint', action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        # action_result.add_data(response)
        """

        action_result.add_data({})

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['important_data'] = "value"

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        # return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message, in case of success we don't set the message, but use the summary
        return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

    def _handle_block_hash(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        """
        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        required_parameter = param['required_parameter']

        # Optional values should use the .get() function
        optional_parameter = param.get('optional_parameter', 'default_value')
        """

        """
        # make rest call
        ret_val, response = self._make_rest_call('/endpoint', action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        # action_result.add_data(response)
        """

        action_result.add_data({})

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['important_data'] = "value"

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        # return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message, in case of success we don't set the message, but use the summary
        return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

    def _handle_get_file(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        """
        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        required_parameter = param['required_parameter']

        # Optional values should use the .get() function
        optional_parameter = param.get('optional_parameter', 'default_value')
        """

        """
        # make rest call
        ret_val, response = self._make_rest_call('/endpoint', action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        # action_result.add_data(response)
        """

        action_result.add_data({})

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['important_data'] = "value"

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        # return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message, in case of success we don't set the message, but use the summary
        return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

    def _handle_get_file_info(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        """
        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        required_parameter = param['required_parameter']

        # Optional values should use the .get() function
        optional_parameter = param.get('optional_parameter', 'default_value')
        """

        """
        # make rest call
        ret_val, response = self._make_rest_call('/endpoint', action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        # action_result.add_data(response)
        """

        action_result.add_data({})

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['important_data'] = "value"

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        # return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message, in case of success we don't set the message, but use the summary
        return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'list_endpoints':
            ret_val = self._handle_list_endpoints(param)

        elif action_id == 'get_system_info':
            ret_val = self._handle_get_system_info(param)

        elif action_id == 'hunt_file':
            ret_val = self._handle_hunt_file(param)

        elif action_id == 'unblock_hash':
            ret_val = self._handle_unblock_hash(param)

        elif action_id == 'block_hash':
            ret_val = self._handle_block_hash(param)

        elif action_id == 'get_file':
            ret_val = self._handle_get_file(param)

        elif action_id == 'get_file_info':
            ret_val = self._handle_get_file_info(param)

        return ret_val

    def initialize(self):

        self._state = self.load_state()
        config = self.get_config()

        # Required values can be accessed directly
        region_code = config['CYLANCE_JSON_REGION_CODE']

        region_codes = {
            "Asia-Pacific - North": "-apne1",
            "Asia-Pacific - Southeast": "-au",
            "Europe - Central": "-euc1",
            "Government": "-us",
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
            r = requests.get("https://127.0.0.1/login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=False, data=data, headers=headers)
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
