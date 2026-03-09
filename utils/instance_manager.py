"""
This module contains all functions to use Chall-Manager InstanceManager group.
"""

import json

import requests
from CTFd.cache import cache
from .chall_manager_error import (
    ChallManagerException,
)
from .logger import configure_logger
from CTFd.utils import get_config

logger = configure_logger(__name__)
CM_API_TIMEOUT = get_config("chall-manager:chall-manager_api_timeout")

# pylint: disable=duplicate-code
# pylint detect duplicate-code between challenge_store and intance_manager
# This is false positive


def create_instance(
    challenge_id: int, source_id: int, user_email: str = None
) -> dict | ChallManagerException:
    cm_api_url = get_config("chall-manager:chall-manager_api_url")
    url = f"{cm_api_url}/instances/{challenge_id}"
    cache_key = f"instance:{challenge_id}:{source_id}"

    payload = {"user_id": source_id}
    
    # Custom Invictus feature: include user email if provided
    if user_email:
        payload["email"] = user_email

    headers = {"Content-Type": "application/json"}

    logger.debug(
        "creating instance for challenge_id=%s, source_id=%s", challenge_id, source_id
    )

    try:
        # CREATING MUST BE A POST REQUEST
        r = requests.post(
            url, data=json.dumps(payload), headers=headers, timeout=CM_API_TIMEOUT
        )
        logger.debug("received response: %s, %s", r.status_code, r.text)
    except Exception as e:
        logger.error("error creating instance: %s", e)
        raise ChallManagerException(
            message="an exception occurred while communicating with CM"
        ) from e

    if r.status_code != 200:
        error_data = r.json()
        message = error_data.get("message", "Unknown error")
        logger.error("chall-manager returned an error: %s", message)
        raise ChallManagerException(message=message)

    result = r.json()
    instance_data = result.get("data", result)
    
    if not instance_data.get("locked"):
        cache.set(cache_key, instance_data, timeout=60)
        logger.debug("cached instance data")
    else:
        logger.debug("instance is locked (deploying), not caching")

    return instance_data


def delete_instance(challenge_id: int, source_id: int) -> dict | ChallManagerException:
    """
    After completion, the challenge instance is no longer required.
    This spins down the instance and removes if from filesystem.

    :param challenge_id: id of challenge for the instance
    :param source_id: id of source for the instance
    :return dict: JSON response of chall-manager API
    :raise ChallManagerException:
    """

    cm_api_url = get_config("chall-manager:chall-manager_api_url")
    url = f"{cm_api_url}/instances/{challenge_id}/{source_id}"
    cache_key = f"instance:{challenge_id}:{source_id}"

    logger.debug(
        "deleting instance for challenge_id=%s, source_id=%s", challenge_id, source_id
    )

    try:
        r = requests.delete(url, timeout=CM_API_TIMEOUT)
        logger.debug("received response: %s %s", r.status_code, r.text)
    except Exception as e:
        logger.error("error deleting instance: %s", e)
        raise ChallManagerException(
            message="an exception occurred while communicating with CM"
        ) from e

    if r.status_code != 200:
        data = r.json()
        logger.error("error from chall-manager: %s", data["message"])
        raise ChallManagerException(message=data["message"])

    # delete cache to prevent connectionInfo in front
    cached = cache.get(cache_key)
    if cached:
        logger.debug("delete cache informations for %s", cache_key)
        cache.delete(cache_key)

    return r.json()


def get_instance(challenge_id: int, source_id: int) -> dict | ChallManagerException:
    """
    Once created, you can retrieve the instance information.
    If it has not been created yet, returns an error.

    :param challenge_id: id of challenge for the instance
    :param source_id: id of source for the instance
    :return dict: JSON response of chall-manager API
    :raise ChallManagerException:
    """

    cm_api_url = get_config("chall-manager:chall-manager_api_url")
    url = f"{cm_api_url}/instances/{challenge_id}/{source_id}"
    cache_key = f"instance:{challenge_id}:{source_id}"

    cached = cache.get(cache_key)
    if cached:
        logger.debug("use cache informations for %s", cache_key)
        return cached

    logger.debug(
        "getting instance information for challenge_id=%s, source_id=%s",
        challenge_id,
        source_id,
    )

    try:
        r = requests.get(url, timeout=CM_API_TIMEOUT)
        logger.debug("received response: %s %s", r.status_code, r.text)
    except Exception as e:
        logger.error("error getting instance: %s", e)
        raise ChallManagerException(
            message="an exception occurred while communicating with CM"
        ) from e

    if r.status_code == 404:
        # 404 is normal - means no instance exists yet
        logger.info("no instance found for challenge_id=%s, source_id=%s", challenge_id, source_id)
        return {}  # Return empty dict, not an error
    
    if r.status_code != 200:
        # Other errors are real problems
        logger.error("error from chall-manager: %s", json.loads(r.text))
        raise ChallManagerException(
            message=f"Chall-Manager returned an error: {json.loads(r.text)}"
        )

    result = r.json()
    # terraform-challenge-manager wraps response in 'data' field
    if "data" in result and result["data"]:
        instance_data = result["data"]
        # Only cache if instance is NOT locked (not still deploying)
        # If locked, we want to fetch fresh data on next request
        if not instance_data.get("locked"):
            logger.debug("store result in cache for better performances")
            cache.set(cache_key, instance_data, timeout=60)
        else:
            logger.debug("instance is locked (deploying), not caching")
        return instance_data

    return result


def update_instance(challenge_id: int, source_id: int) -> dict | ChallManagerException:
    cm_api_url = get_config("chall-manager:chall-manager_api_url")
    url = f"{cm_api_url}/instances/{challenge_id}/{source_id}"
    cache_key = f"instance:{challenge_id}:{source_id}"

    payload = {"new_timeout": 3600}
    headers = {"Content-Type": "application/json"}

    logger.debug(
        "updating instance for challenge_id=%s, source_id=%s", challenge_id, source_id
    )

    try:
        r = requests.put(
            url, data=json.dumps(payload), headers=headers, timeout=CM_API_TIMEOUT
        )
        logger.debug("received response: %s %s", r.status_code, r.text)
    except Exception as e:
        logger.error("Error updating instance: %s", e)
        raise ChallManagerException(message="error while communicating with CM") from e

    # Handle rate-limiting or max renewals
    if r.status_code == 429:
        raise ChallManagerException(message="Instance renewal limit reached.")

    # Gracefully catch the 405 Method Not Allowed or any other errors
    if r.status_code != 200:
        error_msg = r.json().get("message", "Unknown error occurred.")
        logger.error("chall-manager returned an error: %s", error_msg)
        raise ChallManagerException(message=error_msg)

    # Invalidate cache to force fresh data on next GET request
    # This ensures the updated 'until' time is fetched immediately
    cached = cache.get(cache_key)
    if cached:
        logger.debug("invalidate cache for %s to fetch fresh data", cache_key)
        cache.delete(cache_key)

    result = r.json()
    instance_data = result.get("data", result)
    return instance_data


def query_instance(source_id: int) -> list | ChallManagerException:
    cm_api_url = get_config("chall-manager:chall-manager_api_url")
    url = f"{cm_api_url}/instances?sourceId={source_id}"

    logger.debug("querying instances for sourceId=%s", source_id)

    try:
        r = requests.get(url, timeout=CM_API_TIMEOUT)
        r.raise_for_status()
        
        data = r.json()
        # Handle the new v0.9.0 standard JSON response
        if isinstance(data, dict):
            result = data.get("data", [])
        elif isinstance(data, list):
            result = data
        else:
            result = []
            
        logger.debug("successfully queried instances: %s", len(result))
        return result
        
    except Exception as e:
        logger.error("connection error: %s", e)
        raise ChallManagerException(message="connection error") from e