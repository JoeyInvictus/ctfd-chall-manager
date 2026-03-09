"""
This module contains all functions to use Chall-Manager ChallengeStore group.
"""

import json

import requests

from CTFd.utils import get_config

from .chall_manager_error import ChallManagerException
from .logger import configure_logger

logger = configure_logger(__name__)
CM_API_TIMEOUT = get_config("chall-manager:chall-manager_api_timeout")
# pylint: disable=duplicate-code
# pylint detect duplicate-code between challenge_store and intance_manager
# This is false positive


def _get_cm_base_url():
    """
    Get the challenge manager base URL without /api/v1 suffix.
    Handles cases where config might already include /api/v1.
    """
    cm_api_url = get_config("chall-manager:chall-manager_api_url")
    # Remove trailing /api/v1 if present to avoid duplication
    if cm_api_url.endswith("/api/v1"):
        cm_api_url = cm_api_url[:-7]  # Remove "/api/v1"
    return cm_api_url


def query_challenges() -> list | ChallManagerException:
    """
    Query all challenges information and their instances running.

    :return list: list of challenges [{ . }, { . }]
    """
    cm_api_url = _get_cm_base_url()
    url = f"{cm_api_url}/api/v1/challenges"
    s = requests.Session()
    result = []

    logger.debug("querying challenges from %s", url)

    try:
<<<<<<< HEAD
        resp = s.get(url, headers=None, timeout=CM_API_TIMEOUT)
        resp.raise_for_status()
        res = resp.json()
        # terraform-challenge-manager wraps response in {status, message, data}
        # where data is an array of all challenges
        result = res.get("data", [])
        logger.debug("successfully queried challenges: %s", result)
=======
        req = requests.get(url, headers=None, timeout=10) 
        result = req.json()
        result = result['data']
        logger.debug(f"Successfully queried challenges: {result}")
>>>>>>> origin/main
    except Exception as e:
        logger.error("error querying challenges: %s", e)
        raise ChallManagerException(message="error querying challenges") from e

    return result


def create_challenge(
    challenge_id: int, **kwargs
) -> requests.Response | ChallManagerException:
    """
    Create challenge on chall-manager

    :param challenge_id: id of challenge to create (e.g: 1)
    :param **kwargs: additional configuration in dictionary format
    (e.g {'timeout': '600', 'updateStrategy': 'update_in_place', 'until': '2024-07-10 15:00:00'})

    :return Response: of chall-manager API
    """
    cm_api_url = _get_cm_base_url()
    url = f"{cm_api_url}/api/v1/challenges/{challenge_id}"
    headers = {"Content-Type": "application/json"}
    payload = kwargs

<<<<<<< HEAD
    logger.debug("creating challenge with id=%s", challenge_id)
=======
    headers = {
        "Content-Type": "application/json"
    }

    payload = {}

    if len(args) != 0:
        if type(args[0]) is not dict:
            logger.error(f"invalid argument, got {args[0]} for type {type(args[0])}, dict is expected")
            raise Exception(f"invalid argument, got {args[0]} for type {type(args[0])}, dict is expected")

        payload = args[0]

    logger.debug(f"Creating challenge with id={id}")

    payload["zip64"] = scenario
>>>>>>> origin/main

    try:
        r = requests.post(
            url, data=json.dumps(payload), headers=headers, timeout=CM_API_TIMEOUT
        )
        logger.debug("received response: %s %s", r.status_code, r.text)
    except Exception as e:
<<<<<<< HEAD
        logger.error("error creating challenge: %s", e)
        raise ChallManagerException(
            message="an exception occurred while communicating with CM"
        ) from e

    if r.status_code != 201:
        logger.error("error from chall-manager: %s", json.loads(r.text))
        raise ChallManagerException(
            message=f"Chall-manager returned an error: {json.loads(r.text)}"
        )

=======
        logger.error(f"Error creating challenge: {e}")
        raise Exception(f"An exception occurred while communicating with CM: {e}")
    else:
        if r.status_code != 201:
            logger.error(f"Error from chall-manager: {json.loads(r.text)}")
            raise Exception(f"Chall-manager returned an error: {json.loads(r.text)['message']}")
    
>>>>>>> origin/main
    return r


def delete_challenge(challenge_id: int) -> requests.Response | ChallManagerException:
    """
    Delete challenge and its instances running.
<<<<<<< HEAD

    :param challenge_id* (int): 1
=======
    Removed any dependant instances
    
    :param id* (int): 1
>>>>>>> origin/main

    :return Response: of chall-manager API
    """
    cm_api_url = _get_cm_base_url()
    url = f"{cm_api_url}/api/v1/challenges/{challenge_id}"

    logger.debug("deleting challenge with id=%s", challenge_id)

    try:
        r = requests.delete(url, timeout=CM_API_TIMEOUT)
        logger.debug("received response: %s %s", r.status_code, r.text)
    except Exception as e:
        logger.error("error deleting challenge: %s", e)
        raise ChallManagerException(message="error deleting challenge") from e

    return r


def get_challenge(challenge_id: int) -> requests.Response | ChallManagerException:
    """
    Get challenge information and its instances running.

    :param challenge_id* (int): 1
    :return Response: of chall-manager API
    """
    cm_api_url = _get_cm_base_url()
    url = f"{cm_api_url}/api/v1/challenges/{challenge_id}"

    logger.debug("getting challenge information for id=%s", challenge_id)

    try:
        r = requests.get(url, timeout=CM_API_TIMEOUT)
        logger.debug("recieved response: %s %s", r.status_code, r.text)
    except Exception as e:
<<<<<<< HEAD
        logger.error("error getting challenge: %s", e)
        raise ChallManagerException(
            message="an exception occurred while communicating with CM"
        ) from e

    if r.status_code != 200:
        # Try to parse as JSON, fallback to text if it fails (e.g., HTML 404 pages)
        try:
            error_data = json.loads(r.text)
            logger.error("error from chall-manager: %s", error_data)
            raise ChallManagerException(
                message=f"Chall-manager returned an error: {error_data}"
            )
        except json.JSONDecodeError:
            logger.error("error from chall-manager (status %s): %s", r.status_code, r.text[:200])
            raise ChallManagerException(
                message=f"Chall-manager returned status {r.status_code}"
            )

=======
        logger.error(f"Error getting challenge: {e}")
        raise Exception(f"An exception occurred while communicating with CM: {e}")
    else:
        if r.status_code == 404:
            logger.info(f"Chall-manager could not find the challenge")
            raise Exception(f"Chall-manager could not find a challenge for this id")
        elif r.status_code != 200:
            logger.error(f"Error from chall-manager: {json.loads(r.text)}")
            raise Exception(f"Chall-manager returned an error: {json.loads(r.text)['message']}")
 
>>>>>>> origin/main
    return r


def update_challenge(
    challenge_id: int, **kwargs
) -> requests.Response | ChallManagerException:
    """
    Update challenge with information provided

    :param challenge_id*: 1
    :param **kwargs: additional configuration in dictionary format
    (e.g {'timeout': '600s', 'updateStrategy': 'update_in_place', 'until': '2024-07-10 15:00:00' })
    :return Response: of chall-manager API
    """
    cm_api_url = _get_cm_base_url()
    url = f"{cm_api_url}/api/v1/challenges/{challenge_id}"
    headers = {"Content-Type": "application/json"}
    payload = kwargs

    logger.debug("updating challenge with id=%s", challenge_id)

    payload["updateMask"] = ",".join(
        k
        for k in ("timeout", "until", "additional", "min", "max", "scenario")
        if k in payload
    )

<<<<<<< HEAD
    logger.debug(
        "updating challenge %s with updateMask %s", challenge_id, payload["updateMask"]
    )
=======
    if len(args) != 0:
        if type(args[0]) is not dict:
            logger.error("Invalid arguments provided for updating challenge")
            raise Exception(f"Error deleting challenge: {e}")

        payload = args[0]

    logger.debug(f"Updating challenge with id={id}")
    
    # attempt to set default payload if not provided
    if "timeout" not in payload:
        payload['timeout'] = 3600
>>>>>>> origin/main

    try:
        r = requests.put(
            url, data=json.dumps(payload), headers=headers, timeout=CM_API_TIMEOUT
        )
        logger.debug("received response: %s %s", r.status_code, r.text)
    except Exception as e:
<<<<<<< HEAD
        logger.error("error updating challenge: %s", e)
        raise ChallManagerException(message="error while communicating with CM") from e

    if r.status_code != 204:
        logger.error("error from chall-manager: %s", json.loads(r.text))
        raise ChallManagerException(
            message=f"Chall-manager returned an error: {json.loads(r.text)}"
        )

=======
        logger.error(f"Error updating challenge: {e}")
        raise Exception(f"An exception occurred while communicating with CM: {e}")
    else:
        if r.status_code != 204:
            logger.error(f"Error from chall-manager: {json.loads(r.text)}")
            raise Exception(f"Chall-manager returned an error: {json.loads(r.text)['message']}")
>>>>>>> origin/main
    return r
