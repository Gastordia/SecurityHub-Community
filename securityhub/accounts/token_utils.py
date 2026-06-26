import logging
import uuid
from django.utils import timezone
from django.db import transaction
from .models import CustomUser, UserToken
logger = logging.getLogger(__name__)


def generate_token(user, token_type='invitation'):
    """
    Generate a token (either invitation or password reset) for a user.

    Args:
        user (CustomUser): The user to generate a token for
        token_type (str): The type of token ('invitation' or 'password_reset')

    Returns:
        UserToken: The token object
    """
    with transaction.atomic():
        # Delete any existing tokens of the same type for this user
        UserToken.objects.filter(user=user, token_type=token_type).delete()

        # Create a new token
        token_obj = UserToken.objects.create(
            user=user,
            token_type=token_type
        )

        return token_obj


def validate_token(token_str):
    """
    Unified function to validate any type of token (invitation or password reset).

    Args:
        token_str (str): The token string to validate

    Returns:
        tuple: (is_valid, user, token_obj, message, token_type)
            - is_valid (bool): Whether the token is valid
            - user (CustomUser): The associated user, or None if invalid
            - token_obj (UserToken): The token object, or None if invalid
            - message (str): A message explaining the result
            - token_type (str): The type of token ('invitation' or 'password_reset')
    """
    if not token_str:
        return False, None, None, "No token provided.", None

    try:
        # Try parsing the token as UUID
        token_uuid = uuid.UUID(token_str)

        # Get the token object
        token_obj = UserToken.objects.get(token=token_uuid)
        token_type = token_obj.token_type

        # Check if the token is expired
        if timezone.now() > token_obj.expires_at:
            if token_type == 'invitation':
                message = "This invitation has expired."
            else:
                message = "This password reset link has expired."
            return False, None, token_obj, message, token_type

        # Check if the token is already used
        if token_obj.is_used:
            if token_type == 'invitation':
                message = "This invitation has already been used."
            else:
                message = "This password reset link has already been used."
            return False, None, token_obj, message, token_type

        # Verify that the user still exists and is valid
        user = token_obj.user
        if not user:
            return False, None, token_obj, "User associated with this token no longer exists.", token_type

        return True, user, token_obj, "Valid token.", token_type

    except ValueError:
        # Not a valid UUID
        return False, None, None, "Invalid token format.", None
    except UserToken.DoesNotExist:
        return False, None, None, "Invalid token.", None
    except Exception as e:
        logger.error(f"Error validating token: {str(e)}")
        return False, None, None, "An error occurred while validating the token.", None


def process_token(token_str, password):
    """
    Unified function to process any type of token (accept invitation or reset password).

    Args:
        token_str (str): The token string to process
        password (str): The new password to set

    Returns:
        tuple: (success, user, message, token_type)
            - success (bool): Whether the operation was successful
            - user (CustomUser): The user object if successful, None otherwise
            - message (str): A message explaining the result
            - token_type (str): The type of token that was processed
    """
    is_valid, user, token_obj, message, token_type = validate_token(token_str)

    if not is_valid:
        return False, None, message, token_type

    try:
        with transaction.atomic():
            # Set the user's password
            user.set_password(password)

            # For invitations, ensure the user is active
            if token_type == 'invitation':
                user.is_active = True

            user.save()

            # Delete the token
            token_obj.delete()

            if token_type == 'invitation':
                logger.info(f"Invitation accepted for user {user.email}")
                message = "Password set successfully."
            else:
                logger.info(f"Password reset completed for user {user.email}")
                message = "Password reset successfully."

            return True, user, message, token_type

    except Exception as e:
        error_msg = f"Error processing token: {str(e)}"
        logger.error(error_msg)
        return False, None, error_msg, token_type

