import json
from datetime import timedelta, datetime

from flask import request
from flask_restx import Namespace, Resource, abort

from CTFd.utils import get_config  # type: ignore
from CTFd.utils import user as current_user  # type: ignore
from CTFd.utils.decorators import admins_only, authed_only  # type: ignore

from .models import DynamicIaCChallenge

from .utils.instance_manager import create_instance, delete_instance, get_instance, update_instance
from .utils.logger import configure_logger
from .utils.chall_manager_error import ChallManagerException
from .decorators import challenge_visible

import traceback
import logging
logger = configure_logger(__name__)
logger.setLevel(logging.DEBUG)

handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
logger.addHandler(handler)

admin_namespace = Namespace("ctfd-chall-manager-admin")
user_namespace = Namespace("ctfd-chall-manager-user")


@admin_namespace.errorhandler
@user_namespace.errorhandler
def handle_default(err):
    logger.error(f"Unexpected error: {err}")
    return {
        'success': False,
        'message': 'Unexpected things happened'
    }, 500


# region AdminInstance
# Resource to monitor all instances
@admin_namespace.route('/instance')
class AdminInstance(Resource):
    @staticmethod
    @admins_only
    def get():
        # retrieve all instances deployed by chall-manager
        challengeId = request.args.get("challengeId")
        sourceId = request.args.get("sourceId")

        adminId = str(current_user.get_current_user().id)
        logger.info(f"Admin {adminId} get instance info for challengeId: {challengeId}, sourceId: {sourceId}")

        try:
            logger.info(f"Getting instance for challengeId: {challengeId}, sourceId: {sourceId}")
            r = get_instance(challengeId, sourceId)
            logger.info(f"Instance retrieved successfully. {json.loads(r.text)}")
        except Exception as e:
            logger.error(f"Error while communicating with CM: {e}")
            return {'success': False, 'data': {
                'message': f"Error while communicating with CM : {e}",
            }}

        return {'success': True, 'data': json.loads(r.text)}
    
    @staticmethod
    @admins_only
    def post():
        data = request.get_json()
        # mandatory
        challengeId = data.get("challengeId")
        sourceId = data.get("sourceId")

        adminId = str(current_user.get_current_user().id)
        logger.info(f"Admin {adminId} request instance creation for challengeId: {challengeId}, sourceId: {sourceId}")


        try:
            logger.info(f"Creating instance for challengeId: {challengeId}, sourceId: {sourceId}")
            r = create_instance(challengeId, sourceId)
            logger.info(f"Instance for challengeId: {challengeId}, sourceId: {sourceId} created successfully.")

        except ChallManagerException as e:
            if "already exist" in e.message:
                return {'success': False, 'data': {
                    'message': f"instance already exist",
                }}
            return {'success': False, 'data': {
                    'message': f"{e.message}",
                }}

        except Exception as e:
            print(e)
            logger.error(f"Error while creating instance: {e}")
            return {'success': False, 'data': {
                'message': f"Error while communicating with CM : {e}",
            }}

        return {'success': True, 'data': json.loads(r.text)}

    @staticmethod
    @admins_only
    def patch():
        # mandatory
        data = request.get_json()
        challengeId = data.get("challengeId")
        sourceId = data.get("sourceId")

        adminId = str(current_user.get_current_user().id)
        logger.info(f"Admin {adminId} request instance update for challengeId: {challengeId}, sourceId: {sourceId}")

        try:
            logger.info(f"Updating instance for challengeId: {challengeId}, sourceId: {sourceId}")
            r = update_instance(challengeId, sourceId)
            logger.info(f"Instance for challengeId: {challengeId}, sourceId: {sourceId} updated successfully.")
        except Exception as e:
            logger.error(f"Error while updating instance (admin): {e}")
            return {'success': False, 'data': {
                'message': f"Error while communicating with CM : {e}",
            }}

        return {'success': True, 'data': json.loads(r.text)}

    @staticmethod
    @admins_only
    def delete():
        # mandatory
        data = request.get_json()
        challengeId = data.get("challengeId")
        sourceId = data.get("sourceId")

        adminId = str(current_user.get_current_user().id)
        logger.info(f"Admin {adminId} request instance delete for challengeId: {challengeId}, sourceId: {sourceId}")

        try:
            logger.info(f"Deleting instance for challengeId: {challengeId}, sourceId: {sourceId}")
            r = delete_instance(challengeId, sourceId)
            logger.info(f"Instance for challengeId: {challengeId}, sourceId: {sourceId} delete successfully.")

        except Exception as e:
            logger.error(f"Error while deleting instance: {e}")
            return {'success': False, 'data': {
                'message': f"Error while communicating with CM : {e}",
            }}

        return {'success': True, 'data': json.loads(r.text)}


from dateutil.parser import isoparse
# region UserInstance
# Resource to permit user to manage their instance
@user_namespace.route("/instance")
class UserInstance(Resource):
    @staticmethod
    @authed_only
    @challenge_visible
    def get():
        challengeId = request.args.get("challengeId")
        sourceId = str(current_user.get_current_user().id)
        logger.info(f"user {sourceId} request GET on challenge {challengeId}")

        if get_config("user_mode") == "teams":
            sourceId = str(current_user.get_current_user().team_id)

        if not challengeId or not sourceId:
            logger.warning("Missing argument: challengeId or sourceId")
            return {'success': False, 'data': {
                'message': "Missing argument: challengeId or sourceId"
            }}

        challenge = DynamicIaCChallenge.query.filter_by(id=challengeId).first()
        if challenge.shared:
            sourceId = 0

        # Initialize debug info for API response
        debug_info = []
        
        try:
            r = get_instance(challengeId, sourceId)
            result = json.loads(r.text)
            debug_info.append(f"Raw result from challenge manager: {result}")
        except Exception as e:
            debug_info.append(f"Error getting instance: {e}")
            return {'success': False, 'data': {
                'message': f"Error while communicating with CM: {e}",
                'debug': debug_info
            }}

        data = {}
        try:
            if result.get('status') == 'success' and 'data' in result and result['data']:
                debug_info.append(f"Challenge manager returned success with data")
                instance_data = result['data']
                debug_info.append(f"Instance data: {instance_data}")

                if 'connectionInfo' in instance_data:
                    data['connectionInfo'] = instance_data['connectionInfo']
                    debug_info.append(f"Added connectionInfo: {data['connectionInfo']}")

                if 'created_at' in instance_data:
                    debug_info.append(f"Found created_at: {instance_data['created_at']}")
                    try:
                        created_at = isoparse(instance_data['created_at'])
                        debug_info.append(f"Parsed created_at: {created_at}")
                        data['since'] = created_at.isoformat()
                        debug_info.append(f"Set since: {data['since']}")

                        challenge_timeout = 3600
                        if hasattr(challenge, 'alive') and challenge.alive:
                            challenge_timeout = challenge.alive
                            debug_info.append(f"Using challenge.alive: {challenge_timeout}")
                        elif hasattr(challenge, 'timeout') and challenge.timeout:
                            challenge_timeout = challenge.timeout
                            debug_info.append(f"Using challenge.timeout: {challenge_timeout}")
                        else:
                            debug_info.append(f"Using default timeout: {challenge_timeout}")

                        extra_time = int(instance_data.get('extra_time', 0))
                        debug_info.append(f"Extra time from instance: {extra_time}")

                        total_time = challenge_timeout + extra_time
                        debug_info.append(f"Total time: {total_time} seconds")

                        until_time = created_at + timedelta(seconds=total_time)
                        data['until'] = until_time.isoformat()
                        debug_info.append(f"Set until: {data['until']}")
                    except Exception as e:
                        debug_info.append(f"Error parsing created_at: {e}")
                        debug_info.append(f"Full traceback: {traceback.format_exc()}")
                        data['since'] = None
                        data['until'] = None

                if instance_data.get('connectionInfo') is None:
                    data['starting'] = "starting challenge..."
                    debug_info.append(f"No connectionInfo, set starting message")
            else:
                debug_info.append(f"Challenge manager returned error or no data: {result}")
                data = {}
        except Exception as e:
            debug_info.append(f"Error processing connection info: {e}")
            debug_info.append(f"Full traceback: {traceback.format_exc()}")
            data.setdefault('connectionInfo', None)

        debug_info.append(f"Final data being returned: {data}")
        return {'success': True, 'data': data, 'debug': debug_info}

    @staticmethod
    @authed_only
    @challenge_visible
    def post(): 
        data = request.get_json()
        # mandatory
        challengeId = data.get("challengeId")

        # check userMode of CTFd
        sourceId = str(current_user.get_current_user().id)
        userEmail = str(current_user.get_current_user().email)
        logger.info(f"user {sourceId} request instance creation of challenge {challengeId}")
        if get_config("user_mode") == "teams":
            sourceId = str(current_user.get_current_user().team_id)

        challenge = DynamicIaCChallenge.query.filter_by(id=challengeId).first()
        if challenge.shared:
            logger.warning(f"Unauthorized attempt to create sharing instance challengeId: {challengeId}, sourceId: {sourceId}")
            return {'success': False, 'data': {
                'message': "Unauthorized"
            }} 
        
        # check if sourceId can launch the instance

        try:
            logger.info(f"Creating instance for challengeId: {challengeId}, sourceId: {sourceId}")
            r = create_instance(challengeId, sourceId, userEmail)
            logger.info(f"Instance for challengeId: {challengeId}, sourceId: {sourceId} created successfully")

        except ChallManagerException as e:
            if "already exist" in e.message:
                return {'success': False, 'data': {
                    'message': f"instance already exist",
                }}
            return {'success': False, 'data': {
                'message': f"{e.message}",
            }}

        except Exception as e:
            print(e)
            logger.error(f"Error while creating instance: {e}")
            return {'success': False, 'data': {
                'message': f"Error while communicating with CM : {e}",
            }}

        # return only necessary values
        data = {}
        result = json.loads(r.text)

        try:
            if 'connectionInfo' in result['data'].keys():
                data['connectionInfo'] = result['data']['connectionInfo']
            
            # Calculate since and until from created_at
            if 'created_at' in result['data'].keys():
                from datetime import datetime, timedelta
                created_at = isoparse(result['data']['created_at'])
                data['since'] = created_at.isoformat()
                
                # Get challenge timeout (default 1 hour)
                challenge_timeout = 3600
                if hasattr(challenge, 'alive') and challenge.alive:
                    challenge_timeout = challenge.alive
                
                extra_time = int(result['data'].get('extra_time', 0))
                total_time = challenge_timeout + extra_time
                until_time = created_at + timedelta(seconds=total_time)
                data['until'] = until_time.isoformat()
            
            if result['data']['connectionInfo'] == None:
                data['starting'] = "starting challenge..."
        except Exception:
            data = {}

        return {'success': True, 'data': data}

    @staticmethod
    @authed_only
    @challenge_visible
    def patch():
        # mandatory
        data = request.get_json()
        challengeId = data.get("challengeId")

        # check userMode of CTFd
        sourceId = str(current_user.get_current_user().id)
        logger.info(f"user {sourceId} request instance update of challenge {challengeId}")
        if get_config("user_mode") == "teams":
            sourceId = str(current_user.get_current_user().team_id)

        challenge = DynamicIaCChallenge.query.filter_by(id=challengeId).first()
        if challenge.shared:
            logger.warning(f"Unauthorized attempt to patch sharing instance challengeId: {challengeId}, sourceId: {sourceId}")
            return {'success': False, 'data': {
                'message': "Unauthorized"
            }} 

        if not challengeId or not sourceId:
            logger.warning("Missing argument: challengeId or sourceId")
            return {'success': False, 'data': {
                'message': "Missing argument : challengeId or sourceId",
            }}

        try:
            logger.info(f"Updating instance for challengeId: {challengeId}, sourceId: {sourceId}")
            r = update_instance(challengeId, sourceId)
            logger.info(f"Instance for challengeId: {challengeId}, sourceId: {sourceId} updated successfully.")
        except ChallManagerException as e:
            return {'success': False, 'data': {\
                'message': f"{e.message}",
            }}

        except Exception as e:
            logger.error(f"Error while creating instance: {e}")
            return {'success': False, 'data': {
                'message': f"Error while communicating with CM : {e}",
            }}


        msg = "Your instance has been renewed !"
        a = json.loads(r.text)

        if challenge.until and challenge.timeout:
            if challenge.until  == a["until"]:
                msg = "You have renewed your instance, but it can't be renewed anymore !"

        return {'success': True, 'data': {
            'message': msg
        }}

    @staticmethod
    @authed_only
    @challenge_visible
    def delete():

        data = request.get_json()
        challengeId = data.get("challengeId")

        # check userMode of CTFd
        sourceId = str(current_user.get_current_user().id)
        logger.info(f"user {sourceId} requests instance destroy of challenge {challengeId}")
        if get_config("user_mode") == "teams":
            sourceId = str(current_user.get_current_user().team_id)

        challenge = DynamicIaCChallenge.query.filter_by(id=challengeId).first()
        if challenge.shared:
            logger.warning(f"Unauthorized attempt to delete shared instance, challengeId: {challengeId}, sourceId: {sourceId}")
            return {'success': False, 'data': {
                'message': "Unauthorized"
            }}

        try:

            logger.info(f"Deleting instance for challengeId: {challengeId}, sourceId: {sourceId}")
            r = delete_instance(challengeId, sourceId)
            logger.info(f"Instance for challengeId: {challengeId}, sourceId: {sourceId} deleted successfully.")
        except Exception as e:
            logger.error(f"Error while deleting instance: {e}")
            return {'success': False, 'data': {
                'message': f"Error while communicating with CM : {e}",
            }}


        return {'success': True, 'data': {}}

