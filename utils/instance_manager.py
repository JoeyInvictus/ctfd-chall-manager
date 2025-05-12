import requests
import json
from CTFd.utils import get_config  # type: ignore

from .logger import configure_logger
from .chall_manager_error import ChallManagerException

logger = configure_logger(__name__)

def create_instance(challengeId: int, userId: int, userEmail: str) -> requests.Response | Exception: 
    """
    Spins up a challenge instance, iif the challenge is registered and no instance is yet running.
    
    :param challengeId: id of challenge for the instance
    :param userId: id of source for the instance
    :param userEmail: str UPN of the requesting user
    :return Response: of chall-manager API
    :raise Exception:
    """

    cm_api_url = get_config("chall-manager:chall-manager_api_url")
    url = f"{cm_api_url}/instances/{challengeId}"

    payload = {
        "user_id": userId,
        "email": userEmail
    }

    headers = {
        "Content-Type": "application/json"
    }

    logger.debug(f"Creating instance for challengeId={challengeId}, userId={userId}")

    try:        
        r = requests.post(url, data=json.dumps(payload), headers=headers)
        logger.debug(f"Received response: {r.status_code} {r.text}")
    except Exception as e:
        logger.error(f"Error creating instance: {e}")
        raise Exception(f"An exception occurred while communicating with CM: {e}")
    else:
        # attempt to handle the error and communicate to the end user what is going wrong
        if r.status_code != 200:
            message = r.json()["message"]
            logger.error(f"{message}")
            raise ChallManagerException(message=message)
    return r

def delete_instance(challengeId: int , userId: int) -> requests.Response | Exception:
    """
    After completion, the challenge instance is no longer required. This spins down the instance and removes if from filesystem.
    
    :param challengeId: id of challenge for the instance
    :param userId: id of source for the instance
    :return Response: of chall-manager API
    :raise Exception:
    """

    cm_api_url = get_config("chall-manager:chall-manager_api_url")
    url = f"{cm_api_url}/instances/{challengeId}/{userId}"

    logger.debug(f"Deleting instance for challengeId={challengeId}, userId={userId}")

    try:        
        r = requests.delete(url)
        logger.debug(f"Received response: {r.status_code} {r.text}")
    except Exception as e:
        logger.error(f"Error deleting instance: {e}")
        raise Exception(f"An exception occurred while communicating with CM: {e}")
    else:
        if r.status_code != 200:
            logger.error(f"Error from chall-manager: {json.loads(r.text)}")
            raise Exception(f"Chall-manager returned an error: {json.loads(r.text)}")
 
    return r


def get_instance(challengeId: int, userId: int) -> requests.Response | Exception:
    """
    Once created, you can retrieve the instance information. If it has not been created yet, returns an error.
    
    :param challengeId: id of challenge for the instance
    :param userId: id of source for the instance
    :return Response: of chall-manager API
    :raise Exception:
    """

    cm_api_url = get_config("chall-manager:chall-manager_api_url")
    url = f"{cm_api_url}/instances/{challengeId}/{userId}"

    logger.debug(f"Getting instance information for challengeId={challengeId}, userId={userId}")

    try:        
        r = requests.get(url, timeout=10)
        logger.debug(f"Received response: {r.status_code} {r.text}")
    except Exception as e:
        logger.error(f"Error getting instance: {e}")
        raise Exception(f"An exception occurred while communicating with CM: {e}")
    else:
        if r.status_code == 404:
            # return nothing to end user. If its a 404 then the instance just does not exist (yet)
            pass
        elif r.status_code != 200:
            logger.info(f"No instance on chall-manager: {json.loads(r.text)}")
            raise Exception(f"Chall-manager returned an error: {json.loads(r.text)}")

    return r

def update_instance(challengeId: int, userId: int) -> requests.Response | Exception:
    """
    This will set the until date to the request time for the challenge timeout.
    
    :param challengeId: id of challenge for the instance
    :param userId: id of source for the instance
    :return Response: of chall-manager API
    :raise Exception:
    """

    cm_api_url = get_config("chall-manager:chall-manager_api_url")
    url = f"{cm_api_url}/instances/{challengeId}/{userId}"


    # extend with an hour by default
    payload = {
        "new_timeout": 3600
    }

    headers = {
        "Content-Type": "application/json"
    }

    logger.debug(f"Updating instance for challengeId={challengeId}, sourceId={userId}")

    try:        
        r = requests.put(url, data=json.dumps(payload), headers=headers)
        logger.debug(f"Received response: {r.status_code} {r.text}")
    except Exception as e:
        logger.error(f"Error updating instance: {e}")
        raise Exception(f"An exception occurred while communicating with CM: {e}")
    else:
        if r.status_code != 200:
            if r.json()["code"] == 2:
                message = r.json()["message"]
                logger.error(f"chall-manager return an error: {message}")
                raise ChallManagerException(message=message)
 
    return r

def query_instance(userId: int) -> list | Exception:
    """
    This will return a list with all instances that exists on chall-manager for the userId given.

    :param userId: id of source for the instance
    :return list: all instances for the userId (e.g [{userId:x, challengeId, y},..])
    """
    
    cm_api_url = get_config("chall-manager:chall-manager_api_url")
    url = f"{cm_api_url}/instances/user/{userId}"

    s = requests.Session()

    result = []

    logger.debug(f"Querying instances for sourceId={userId}")

    try:
        with s.get(url, headers=None, stream=True, timeout=10) as resp:
            for line in resp.iter_lines():
                if line:
                    res = line.decode("utf-8")
                    res = json.loads(res)
                    if "result" in res.keys():
                        result.append(res["result"])
        logger.debug(f"Successfully queried instances: {result}")
    except Exception as e:
        logger.error(f"ConnectionError: {e}")
        raise Exception(f"ConnectionError: {e}")

    return result
