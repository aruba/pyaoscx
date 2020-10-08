# (C) Copyright 2019-2020 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx import common_ops

import json
import logging
import base64
import os


def get_all_nae_scripts(params={}, **kwargs):
    """
    Perform a GET call to get a list or dictionary of all the Network Analytics Engine scripts on the device.

    :param params: Dictionary of optional parameters for the GET request
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: List (v1) or Dictionary (v10.04 or empty) containing all of the NAE scripts on the device
    """
    target_url = kwargs["url"] + "system/nae_scripts"
    response = kwargs["s"].get(target_url, params=params, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting dictionary of all NAE scripts on device failed with status code %d: %s"
              % (response.status_code, response.text))
        all_nae_scripts = {}
    else:
        if kwargs["url"].endswith("/v1/"):
            logging.info("SUCCESS: Getting list of all NAE scripts on device succeeded")
        else:
            # Else logic designed for v10.04 and later
            logging.info("SUCCESS: Getting dictionary of all NAE scripts on device succeeded")
        all_nae_scripts = response.json()

    return all_nae_scripts


def get_nae_script(nae_script, params={}, **kwargs):
    """
    Perform a GET call to get the details of a specific Network Analytics Engine script on the device.

    :param nae_script: String of name of the script that the function will return
    :param params: Dictionary of optional parameters for the GET request
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing the details of the specified NAE script on the device
    """
    target_url = kwargs["url"] + "system/nae_scripts/" + nae_script
    response = kwargs["s"].get(target_url, params=params, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting details of NAE script %s on device failed with status code %d: %s"
              % (nae_script, response.status_code, response.text))
        nae_script_details = {}
    else:
        logging.info("SUCCESS: Getting details of NAE script %s on device succeeded" % nae_script)
        nae_script_details = response.json()

    return nae_script_details


def get_nae_script_code(nae_script, params={}, **kwargs):
    """
    Perform a GET call to get the decoded Network Analytics Engine script from the device.

    :param nae_script: String of name of the script that the function will return
    :param params: Dictionary of optional parameters for the GET request
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: String of NAE script python code, decoded from base64
    """
    target_url = kwargs["url"] + "system/nae_scripts/" + nae_script
    response = kwargs["s"].get(target_url, params=params, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting NAE script %s python code on device failed with status code %d: %s"
                        % (nae_script, response.status_code, response.text))
        nae_script_code = ""
    else:
        logging.info("SUCCESS: Getting NAE script %s python code on device succeeded" % nae_script)
        nae_script_details = response.json()
        nae_script_code = base64.b64decode(nae_script_details['script'])

    return nae_script_code


def load_nae_script(script_name, script, is_base64=True, **kwargs):
    """
    Perform a POST call to upload a Network Analytics Engine script to the device. This function passes the script
    code as a parameter. By default, is_base64 is True and the script expects the base64 encoded text for the script.
    If is_base64 is set to false, the function will expect a block of python code for the NAE script.

    :param script_name: Alphanumeric String of the name of the script
    :param script: the base64 text or python code of the NAE script
    :param is_base64: Boolean to determine if the script parameter is already encoded in base64. If the set to True,
        the function will take in the script as is.  If set to False, the function will encode the script to base64.
        By default, this is True.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Boolean True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _load_nae_script_v1(script_name, script, is_base64, **kwargs)
    else:  # Updated else for when version is v10.04
        return _load_nae_script(script_name, script, is_base64, **kwargs)


def _load_nae_script_v1(script_name, script, is_base64, **kwargs):
    """
    Perform a POST call to upload a Network Analytics Engine script to the device. This function passes the script
    code as a parameter. By default, is_base64 is True and the script expects the base64 encoded text for the script.
    If is_base64 is set to false, the function will expect a block of python code for the NAE script.

    :param script_name: Alphanumeric String of the name of the script
    :param script: the base64 text or python code of the NAE script
    :param is_base64: Boolean to determine if the script parameter is already encoded in base64. If the set to True,
        the function will take in the script as is.  If set to False, the function will encode the script to base64.
        By default, this is True.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Boolean True if successful, False otherwise
    """
    script_list = get_all_nae_scripts(**kwargs)

    if "/rest/v1/system/nae_scripts/%s" % script_name not in script_list:
        script_data = {
            "name": script_name
            }

        if is_base64:
            script_data["script"] = script
        else:
            script_data["script"] = base64.b64encode(script)

        target_url = kwargs["url"] + "system/nae_scripts"
        post_data = json.dumps(script_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Uploading NAE script named '%s' failed with status code %d: %s"
                  % (script_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Uploading NAE script named '%s' succeeded" % script_name)
            return True
    else:
        logging.info("SUCCESS: Upload not needed; NAE Script named '%s' already exists on the system" % script_name)
        return True


def _load_nae_script(script_name, script, is_base64, **kwargs):
    """
    Perform a POST call to upload a Network Analytics Engine script to the device. This function passes the script
    code as a parameter. By default, is_base64 is True and the script expects the base64 encoded text for the script.
    If is_base64 is set to false, the function will expect a block of python code for the NAE script.

    :param script_name: Alphanumeric String of the name of the script
    :param script: the base64 text or python code of the NAE script
    :param is_base64: Boolean to determine if the script parameter is already encoded in base64. If the set to True,
        the function will take in the script as is.  If set to False, the function will encode the script to base64.
        By default, this is True.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Boolean True if successful, False otherwise
    """
    script_dict = get_all_nae_scripts(**kwargs)

    if script_name not in script_dict:
        script_data = {
            "expert_only": False,
            "name": script_name
            }

        if is_base64:
            script_data["script"] = script
        else:
            script_data["script"] = base64.b64encode(script)

        target_url = kwargs["url"] + "system/nae_scripts"
        post_data = json.dumps(script_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Uploading NAE script named '%s' failed with status code %d: %s"
                  % (script_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Uploading NAE script named '%s' succeeded" % script_name)
            return True
    else:
        logging.info("SUCCESS: Upload not needed; NAE Script named '%s' already exists on the system" % script_name)
        return True


def load_nae_script_from_file(script_name, path_and_filename, is_base64=False, **kwargs):
    """
    Retrieves a specified NAE script and uploads it to the device. This function will read the specified python file
    then perform a POST call to upload the script to the device. By default, is_base64 is False and the function expects
    to encoded the text in base64 prior to uploading.
    If is_base64 is set to True, the function will attempt to encode the python code prior to uploading.

    :param script_name: Alphanumeric String of the name of the script
    :param path_and_filename: Alphanumeric String of the path and filename to the NAE python script
    :param is_base64: Boolean to determine if the script parameter is already encoded in base64. If the set to True,
        the function will take in the script as is.  If set to False, the function will encode the script to base64.
        By default, this is True.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Boolean True if successful, False otherwise
    """
    with open(path_and_filename, 'rb') as py_file:
        py_file_data = py_file.read()

    if not is_base64:
        output_script = base64.b64encode(py_file_data)
        output_script = output_script.decode('utf-8')

    else:
        output_script = py_file_data

    return load_nae_script(script_name, output_script, is_base64=True, **kwargs)


def delete_nae_script(script_name, **kwargs):
    """
    Perform a DELETE call to remove a Network Analytics Engine script from the system.

    *Note that by removing a script, all associated agents of the script will be removed as well.
    :param script_name: Alphanumeric String of the name of the script
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Boolean True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        script_check = "/rest/v1/system/nae_scripts/%s" % script_name
    else:  # Updated else for when version is v10.04
        script_check = script_name

    all_scripts = get_all_nae_scripts(**kwargs)

    if script_check not in all_scripts:
        logging.info("SUCCESS: NAE Script deletion not needed; NAE Script named '%s' does NOT exist on the system"
                     % script_name)
        return True

    else:
        target_url = kwargs["url"] + "system/nae_scripts/%s" % script_name
        response = kwargs["s"].delete(target_url, verify=False)

        if not common_ops._response_ok(response, "DELETE"):
            logging.warning("FAIL: Deleting NAE script named '%s' failed with status code %d: %s"
                  % (script_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Deleting NAE script named '%s' succeeded" % script_name)
            return True


def get_all_nae_agents_of_script(script_name, params={}, **kwargs):
    """
    Perform a GET call to get a list or dictionary of Network Analytics Engine agents for the specified NAE script.

    :param script_name: Alphanumeric String of the name of the script
    :param params: Dictionary of optional parameters for the GET request
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: List (v1) or Dictionary (v10.04 or empty) containing all of the existing agents for the specified script.
    """
    target_url = kwargs["url"] + "system/nae_scripts/%s/nae_agents" % script_name
    response = kwargs["s"].get(target_url, params=params, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting list/dictionary of all NAE agents for NAE script named %s failed with "
                        "status code %d: %s" % (script_name, response.status_code, response.text))
        all_nae_agents = {}
    else:
        if kwargs["url"].endswith("/v1/"):
            logging.info("SUCCESS: Getting list of all NAE agents for script named %s on device succeeded"
                         % script_name)
        else:
            # Else logic designed for v10.04 and later
            logging.info("SUCCESS: Getting dictionary of all NAE agents for script named %s on device succeeded"
                         % script_name)
        all_nae_agents = response.json()

    return all_nae_agents


def get_nae_agent_details(script_name, agent_name, params={}, **kwargs):
    """
    Perform a GET call to get the details of a specific Network Analytics Engine agent on the device.

    :param script_name: Alphanumeric String of the name of the script
    :param agent_name: Alphanumeric String of the name of the agent that will have details returned
    :param params: Dictionary of optional parameters for the GET request
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing the details of the specified NAE script on the device
    """
    target_url = kwargs["url"] + "system/nae_scripts/%s/nae_agents/%s" % (script_name, agent_name)
    response = kwargs["s"].get(target_url, params=params, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting details of NAE agent %s for script %s on device failed with status code %d: %s"
              % (agent_name, script_name, response.status_code, response.text))
        nae_script_details = {}
    else:
        logging.info("SUCCESS: Getting details of NAE agent %s for script %s on device succeeded"
                     % (agent_name, script_name))
        nae_script_details = response.json()

    return nae_script_details


def create_nae_agent(script_name, agent_name, agent_parameters={}, disabled=False, **kwargs):
    """
    Perform a POST call to create a Network Analytics Engine agent for the specified script. This function will also
    take in the agent name, as well as a dictionary of parameters that are specific to the agent.

    *Note that upon initial check in, creating an NAE agent in v10.04 is not working.
    *Note that encrypted parameters are not currently supported in this function.
    :param script_name: Alphanumeric String of the name of the script
    :param agent_name: Alphanumeric String of the name of the agent
    :param agent_parameters: Dictionary of optional parameters for the agent. The key:value pairing is based on the
        agent parameter name and values to be passed in.  Any parameters not mentioned will be set to the default value
        for the given parameter, specified in the NAE script.
    :param disabled: Boolean to determine if the agent is disabled upon creation.  By default, disabled is False,
        implying that the agent will be enabled upon creation.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Boolean True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _create_nae_agent_v1(script_name, agent_name, agent_parameters, disabled, **kwargs)
    else:  # Updated else for when version is v10.04
        return _create_nae_agent(script_name, agent_name, agent_parameters, disabled, **kwargs)


def _create_nae_agent_v1(script_name, agent_name, agent_parameters, disabled, **kwargs):
    """
    Perform a POST call to create a Network Analytics Engine agent for the specified script. This function will also
    take in the agent name, as well as a dictionary of parameters that are specific to the agent.

    *Note that encrypted parameters are not currently supported in this function.
    :param script_name: Alphanumeric String of the name of the script
    :param agent_name: Alphanumeric String of the name of the agent
    :param agent_parameters: Dictionary of optional parameters for the agent. The key:value pairing is based on the
        agent parameter name and values to be passed in.  Any parameters not mentioned will be set to the default value
        for the given parameter, specified in the NAE script.
    :param disabled: Boolean to determine if the agent is disabled upon creation.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Boolean True if successful, False otherwise
    """
    agent_list = get_all_nae_agents_of_script(script_name, **kwargs)

    if "/rest/v1/system/nae_scripts/%s/nae_agents/%s" % (script_name, agent_name) not in agent_list:
        agent_data = {
            "disabled": disabled,
            "encrypted_parameters_values": {},
            "name": agent_name,
            "parameters_values": agent_parameters
        }

        target_url = kwargs["url"] + "system/nae_scripts/%s/nae_agents" % script_name
        post_data = json.dumps(agent_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Creating NAE agent named '%s' from script '%s' failed with status code %d: %s"
                  % (agent_name, script_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Creating NAE agent named '%s' from script '%s' succeeded"
                         % (agent_name, script_name))
            return True
    else:
        logging.info("SUCCESS: Agent creation not needed; NAE Agent named '%s' already exists on the system"
                     % agent_name)
        return True


def _create_nae_agent(script_name, agent_name, agent_parameters, disabled, **kwargs):
    """
    Perform a POST call to create a Network Analytics Engine agent for the specified script. This function will also
    take in the agent name, as well as a dictionary of parameters that are specific to the agent.

    *Note that encrypted parameters are not currently supported in this function.
    :param script_name: Alphanumeric String of the name of the script
    :param agent_name: Alphanumeric String of the name of the agent
    :param agent_parameters: Dictionary of optional parameters for the agent. The key:value pairing is based on the
        agent parameter name and values to be passed in.  Any parameters not mentioned will be set to the default value
        for the given parameter, specified in the NAE script.
    :param disabled: Boolean to determine if the agent is disabled upon creation.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Boolean True if successful, False otherwise
    """
    all_agents = get_all_nae_agents_of_script(script_name, **kwargs)

    if agent_name not in all_agents:
        agent_data = {
            "disabled": disabled,
            "encrypted_parameters_values": {},
            "name": agent_name,
            "parameters_values": agent_parameters
        }

        target_url = kwargs["url"] + "system/nae_scripts/%s/nae_agents" % script_name
        post_data = json.dumps(agent_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Creating NAE agent named '%s' from script '%s' failed with status code %d: %s"
                  % (agent_name, script_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Creating NAE agent named '%s' from script '%s' succeeded"
                         % (agent_name, script_name))
            return True
    else:
        logging.info("SUCCESS: Agent creation not needed; NAE Agent named '%s' already exists on the system"
                     % agent_name)
        return True


def update_nae_agent(script_name, agent_name, agent_parameters, disabled=False, **kwargs):
    """
    Perform a PUT call to update a specified Network Analytics Engine agent.  This function will take in a dictionary of
    parameters that are specific to the agent, as well as a boolean to update whether the agent is disabled or enabled.

    *Note that encrypted parameters are not currently supported in this function.
    :param script_name: Alphanumeric String of the name of the script
    :param agent_name: Alphanumeric String of the name of the agent
    :param agent_parameters: Dictionary of optional parameters for the agent.  The key:value pairing is based on the
        agent parameter name and values to be passed in.  Any parameters not mentioned will be set to the default value
        for the given parameter, specified in the NAE script.
    :param disabled: Boolean to determine if the agent is disabled upon updating.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Boolean True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _update_nae_agent_v1(script_name, agent_name, agent_parameters, disabled, **kwargs)
    else:  # Updated else for when version is v10.04
        return _update_nae_agent(script_name, agent_name, agent_parameters, disabled, **kwargs)


def _update_nae_agent_v1(script_name, agent_name, agent_parameters, disabled, **kwargs):
    """
    Perform a PUT call to update a specified Network Analytics Engine agent.  This function will take in a dictionary of
    parameters that are specific to the agent, as well as a boolean to update whether the agent is disabled or enabled.

    *Note that encrypted parameters are not currently supported in this function.
    :param script_name: Alphanumeric String of the name of the script
    :param agent_name: Alphanumeric String of the name of the agent
    :param agent_parameters: Dictionary of optional parameters for the agent.  The key:value pairing is based on the
        agent parameter name and values to be passed in.  Any parameters not mentioned will be set to the default value
        for the given parameter, specified in the NAE script.
    :param disabled: Boolean to determine if the agent is disabled upon updating.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Boolean True if successful, False otherwise
    """
    all_agents = get_all_nae_agents_of_script(script_name, **kwargs)
    all_agents_check = []
    # Create a new list with full uri stripped from agent list
    for agent in all_agents:
        all_agents_check.append(agent[(agent.rfind('/')+1):])

    if agent_name not in all_agents_check:
        logging.warning("FAIL: Updating NAE agent named '%s' failed. No agent with that name was found." % agent_name)
        return False
    else:
        current_agent_details = get_nae_agent_details(script_name, agent_name, **kwargs)
        new_parameters = {}
        # Create a new dictionary with keys stripped of full uri
        for parameter in current_agent_details['parameters_values']:
            key = parameter[(parameter.rfind('/')+1):]
            value = current_agent_details['parameters_values'][parameter]
            new_parameters[key] = value

        # Update the stripped dictionary with the key/value pairs passed in for the function
        new_parameters.update(agent_parameters)

        updated_agent_data = {
            "disabled": disabled,
            "encrypted_parameters_values": {},
            "parameters_values": new_parameters
        }

        target_url = kwargs["url"] + "system/nae_scripts/%s/nae_agents/%s" % (script_name, agent_name)
        put_data = json.dumps(updated_agent_data, sort_keys=True, indent=4)

        response = kwargs["s"].put(target_url, data=put_data, verify=False)

        if not common_ops._response_ok(response, "PUT"):
            logging.warning("FAIL: Updating NAE agent named '%s' from script '%s' failed with status code %d: %s"
                  % (agent_name, script_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Updating NAE agent named '%s' from script '%s' succeeded"
                         % (agent_name, script_name))
            return True


def _update_nae_agent(script_name, agent_name, agent_parameters, disabled, **kwargs):
    """
    Perform a PUT call to update a specified Network Analytics Engine agent.  This function will take in a dictionary of
    parameters that are specific to the agent, as well as a boolean to update whether the agent is disabled or enabled.

    *Note that encrypted parameters are not currently supported in this function.
    :param script_name: Alphanumeric String of the name of the script
    :param agent_name: Alphanumeric String of the name of the agent
    :param agent_parameters: Dictionary of optional parameters for the agent.  The key:value pairing is based on the
        agent parameter name and values to be passed in.  Any parameters not mentioned will be set to the default value
        for the given parameter, specified in the NAE script.
    :param disabled: Boolean to determine if the agent is disabled upon updating.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Boolean True if successful, False otherwise
    """
    all_agents = get_all_nae_agents_of_script(script_name, **kwargs)

    if agent_name not in all_agents:
        logging.warning("FAIL: Updating NAE agent named '%s' failed. No agent with that name was found." % agent_name)
        return False
    else:
        current_agent_details = get_nae_agent_details(script_name, agent_name, **kwargs)
        new_parameters = {}
        # Create a new dictionary with keys stripped of full uri
        for parameter in current_agent_details['parameters_values']:
            key = parameter[(parameter.rfind('/')+1):]
            value = current_agent_details['parameters_values'][parameter]
            new_parameters[key] = value

        # Update the stripped dictionary with the key/value pairs passed in for the function
        new_parameters.update(agent_parameters)

        updated_agent_data = {
            "disabled": disabled,
            "encrypted_parameters_values": {},
            "parameters_values": new_parameters
        }

        target_url = kwargs["url"] + "system/nae_scripts/%s/nae_agents/%s" % (script_name, agent_name)
        put_data = json.dumps(updated_agent_data, sort_keys=True, indent=4)

        response = kwargs["s"].put(target_url, data=put_data, verify=False)

        if not common_ops._response_ok(response, "PUT"):
            logging.warning("FAIL: Updating NAE agent named '%s' from script '%s' failed with status code %d: %s"
                  % (agent_name, script_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Updating NAE agent named '%s' from script '%s' succeeded"
                         % (agent_name, script_name))
            return True


def delete_nae_agent(script_name, agent_name, **kwargs):
    """
    Perform a DELETE call to remove a Network Analytics Engine agent for the specified script.

    :param script_name: Alphanumeric String of the name of the script
    :param agent_name: Alphanumeric String of the name of the agent
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Boolean True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        agent_check = "/rest/v1/system/nae_scripts/%s/nae_agents/%s" % (script_name, agent_name)
    else:  # Updated else for when version is v10.04
        agent_check = agent_name

    all_agents = get_all_nae_agents_of_script(script_name, **kwargs)

    if agent_check not in all_agents:
        logging.info("SUCCESS: Agent deletion not needed; NAE Agent named '%s' does NOT exist on the system"
                     % agent_name)
        return True

    else:
        target_url = kwargs["url"] + "system/nae_scripts/%s/nae_agents/%s" % (script_name, agent_name)
        response = kwargs["s"].delete(target_url, verify=False)

        if not common_ops._response_ok(response, "DELETE"):
            logging.warning("FAIL: Deleting NAE agent named '%s' based on script '%s' failed with status code %d: %s"
                  % (agent_name, script_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Deleting NAE agent named '%s' based on script '%s' succeeded"
                         % (agent_name, script_name))
            return True
