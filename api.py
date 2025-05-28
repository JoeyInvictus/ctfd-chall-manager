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


# Configure logger for this module
logger = configure_logger(__name__)

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
            logger.debug(f"Getting instance for challengeId: {challengeId}, sourceId: {sourceId}")
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
            logger.debug(f"Creating instance for challengeId: {challengeId}, sourceId: {sourceId}")
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
            logger.debug(f"Updating instance for challengeId: {challengeId}, sourceId: {sourceId}")
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
            logger.debug(f"Deleting instance for challengeId: {challengeId}, sourceId: {sourceId}")
            r = delete_instance(challengeId, sourceId)
            logger.info(f"Instance for challengeId: {challengeId}, sourceId: {sourceId} delete successfully.")

        except Exception as e:
            logger.error(f"Error while deleting instance: {e}")
            return {'success': False, 'data': {
                'message': f"Error while communicating with CM : {e}",
            }}

        return {'success': True, 'data': json.loads(r.text)}


# region UserInstance
# Resource to permit user to manage their instance
@user_namespace.route("/instance")
class UserInstance(Resource):
    @staticmethod
    @authed_only
    @challenge_visible
    def get():
        # mandatory     
        challengeId = request.args.get("challengeId")

        # check userMode of CTFd
        sourceId = str(current_user.get_current_user().id)
        logger.info(f"user {sourceId} request GET on challenge {challengeId}")

        if get_config("user_mode") == "teams":
            sourceId = str(current_user.get_current_user().team_id)       

        if not challengeId or not sourceId:
            logger.warning("Missing argument: challengeId or sourceId")
            return {'success': False, 'data': {
                'message': "Missing argument : challengeId or sourceId",
            }}

        # if challenge is shared
        challenge = DynamicIaCChallenge.query.filter_by(id=challengeId).first()
        if challenge.shared:
            sourceId = 0

        try:
            logger.debug(f"Getting instance for challengeId: {challengeId}, sourceId: {sourceId}")
            r = get_instance(challengeId, sourceId)
            logger.info(f"Instance retrieved successfully. {json.loads(r.text)}")
        except Exception as e:
            logger.error(f"Error while getting instance: {e}")
            return {'success': False, 'data': {
                'message': f"Error while communicating with CM : {e}",
            }}

        # return only necessary values
        data = {}
        result = json.loads(r.text)
        try:
            if 'connectionInfo' in result['data'].keys():
                data['connectionInfo'] = result['data']['connectionInfo']

            # we moved this functionality to the front-end
            # establish the right ISO format
            # we assume the default for a lab is 3600
            if 'created_at' in result['data'].keys():
                created_at = datetime.fromisoformat(result['data']['created_at'])
                extra_time = int(result['data']['extra_time'] + 3600) #default 1 hour
                data['until'] = (created_at + timedelta(seconds=extra_time)).isoformat()
                data['since'] = created_at.isoformat()

            if result['data']['connectionInfo'] is None:
                data['starting'] = "starting challenge..."

        except Exception as e:
            logger.error(f"Error while returning connection info for challenge : {e}")
            data = []

        print(data)
        return {'success': True, 'data': data}

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
            logger.debug(f"Creating instance for challengeId: {challengeId}, sourceId: {sourceId}")
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

        if 'connectionInfo' in result.keys():
            data['connectionInfo'] = result['connectionInfo']

        if 'until' in result.keys():
            data['until'] = result['until']

        if 'since' in result.keys():
            data['since'] = result['since']

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
            logger.debug(f"Updating instance for challengeId: {challengeId}, sourceId: {sourceId}")
            r = update_instance(challengeId, sourceId)
            logger.info(f"Instance for challengeId: {challengeId}, sourceId: {sourceId} updated successfully.")
        except ChallManagerException as e:
            return {'success': False, 'data': {
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

            logger.debug(f"Deleting instance for challengeId: {challengeId}, sourceId: {sourceId}")
            r = delete_instance(challengeId, sourceId)
            logger.info(f"Instance for challengeId: {challengeId}, sourceId: {sourceId} deleted successfully.")
        except Exception as e:
            logger.error(f"Error while deleting instance: {e}")
            return {'success': False, 'data': {
                'message': f"Error while communicating with CM : {e}",
            }}


        return {'success': True, 'data': {}}

