import requests
import json

from CTFd.utils import get_config  # type: ignore
from .logger import configure_logger

logger = configure_logger(__name__)

def query_challenges() -> list:
    """
    Query all challenges information and their instances running.

    :return list: list of challenges [{ . }, { . }]
    """
    cm_api_url = get_config("chall-manager:chall-manager_api_url")
    url = f"{cm_api_url}/challenges"

    logger.debug(f"Querying challenges from {url}")

    try:
        req = requests.get(url, headers=None, timeout=10) 
        result = req.json()
        result = result['data']
        logger.debug(f"Successfully queried challenges: {result}")
    except Exception as e:
        logger.error(f"Error querying challenges: {e}")
        raise Exception(f"ConnectionError: {e}")
    return result

def create_challenge(id: int, scenario: str, *args) -> requests.Response:
    """
    Create challenge on chall-manager
    
    :param id: id of challenge to create (e.g: 1)
    :param scenario: base64(zip(.)),
    
    :return Response: of chall-manager API
    """
    cm_api_url = get_config("chall-manager:chall-manager_api_url")
    url = f"{cm_api_url}/challenges/{str(id)}"

    headers = {
        "Content-Type": "application/json"
    }

    payload = {}

    if len(args) != 0:
        if type(args[0]) is not dict:
            logger.error(f"invalid argument, got {args[0]} for type {type(args[0])}, dict is expected")
            raise Exception(f"invalid argument, got {args[0]} for type {type(args[0])}, dict is expected")

        payload = args[0]
    
    print(f"args are: {args}")

    logger.debug(f"Creating challenge with id={id}")

    payload["zip64"] = scenario

    try:
        r = requests.post(url, data=json.dumps(payload), headers=headers)
        logger.debug(f"Received response: {r.status_code} {r.text}")
    except Exception as e:
        logger.error(f"Error creating challenge: {e}")
        raise Exception(f"An exception occurred while communicating with CM: {e}")
    else:
        if r.status_code != 201:
            logger.error(f"Error from chall-manager: {json.loads(r.text)}")
            raise Exception(f"Chall-manager returned an error: {json.loads(r.text)['message']}")
    
    return r

def delete_challenge(id: int) -> requests.Response:
    """
    Delete challenge and its instances running.
    Removed any dependant instances
    
    :param id* (int): 1

    :return Response: of chall-manager API
    """
    cm_api_url = get_config("chall-manager:chall-manager_api_url")
    url = f"{cm_api_url}/challenges/{id}"

    logger.debug(f"Deleting challenge with id={id}")

    try:
        r = requests.delete(url)
        logger.debug(f"Received response: {r.status_code} {r.text}")
    except Exception as e:
        logger.error(f"error deleting challenge: {e}")
        raise Exception(f"error deleting challenge: {e}")
    
    return r

def get_challenge(id: int) -> requests.Response:
    """
    Get challenge information and its instances running.
    
    :param id* (int): 1
    :return Response: of chall-manager API
    """
    cm_api_url = get_config("chall-manager:chall-manager_api_url")
    url = f"{cm_api_url}/challenges/{id}"

    logger.debug(f"Getting challenge information for id={id}")

    try:
        r = requests.get(url, timeout=30)
        logger.debug(f"Received response: {r.status_code} {r.text}")

    except Exception as e:
        logger.error(f"Error getting challenge: {e}")
        raise Exception(f"An exception occurred while communicating with CM: {e}")
    else:
        if r.status_code == 404:
            logger.info(f"Chall-manager could not find the challenge")
            raise Exception(f"Chall-manager could not find a challenge for this id")
        elif r.status_code != 200:
            logger.error(f"Error from chall-manager: {json.loads(r.text)}")
            raise Exception(f"Chall-manager returned an error: {json.loads(r.text)['message']}")
 
    return r

def update_challenge(id: int, *args) -> requests.Response:
    """
    Update challenge with information provided
    
    :param id*: 1 
    :param *args: additional configuration in dictionary format (e.g {'timeout': '600s', 'updateStrategy': 'update_in_place', 'until': '2024-07-10 15:00:00' })
    :return Response: of chall-manager API
    """
    cm_api_url = get_config("chall-manager:chall-manager_api_url")
    url = f"{cm_api_url}/challenges/{id}"

    headers = {
        "Content-Type": "application/json"
    }

    payload = {}

    if len(args) != 0:
        if type(args[0]) is not dict:
            logger.error("Invalid arguments provided for updating challenge")
            raise Exception(f"Error deleting challenge: {e}")

        payload = args[0]


    logger.debug(f"Updating challenge with id={id}")
    
    # attempt to set default payload if not provided
    if "timeout" not in payload:
        payload['timeout'] = 3600


    try:
        r = requests.put(url, data=json.dumps(payload), headers=headers)
        logger.debug(f"Received response: {r.status_code} {r.text}")
    except Exception as e:
        logger.error(f"Error updating challenge: {e}")
        raise Exception(f"An exception occurred while communicating with CM: {e}")
    else:
        if r.status_code != 204:
            logger.error(f"Error from chall-manager: {json.loads(r.text)}")
            raise Exception(f"Chall-manager returned an error: {json.loads(r.text)['message']}")
    return r
