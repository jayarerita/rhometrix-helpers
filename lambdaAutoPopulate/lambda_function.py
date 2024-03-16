########### Template File for amplify Lambda Function API #################

### Start: Imports ###
## General Imports
import json, boto3, os, logging, base64, io
from datetime import datetime, timedelta
from decimal import Decimal
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
from uuid import uuid4, UUID
from PIL import Image
import traceback
import shortuuid # Useful for generating unique ids that are url safe

## Custom Imports

### End: Imports ###

### Start: Environment Variables ###
## General Environment Variables
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
## AWS specific Environment Variables
DYNAMO_GSINDEX_NAME = os.getenv("DYNAMO_GSINDEX_NAME", "gsi1")
AWS_REGION = os.getenv("REGION", "us-east-1")
S3_BUCKET = os.getenv("S3_BUCKET", "amplify-lambda-api-dev")
COGNITO_USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID", "us-east-1_123456789")
COGNITO_APP_CLIENT_ID = os.getenv("COGNITO_APP_CLIENT_ID", "123456789")
COGNITO_IDENTITY_POOL_ID = os.getenv("COGNITO_IDENTITY_POOL_ID", "us-east-1:123456789")
## Custom Environment Variables
STANDARD_QUERY_PARAMS = json.loads(os.getenv("STANDARD_QUERY_PARAMS", '[{"name":"omit","required":"false","type":"str"},{"name":"fields","required":"false","type":"str"}]')) # All routes are checked for these query parameters
DATETIME_FORMAT = os.getenv("DATETIME_FORMAT", "%Y-%m-%dT%H:%M:%S.%f")
PROTECTED_COMPANY_IDS = json.loads(os.getenv("PROTECTED_COMPANY_IDS", '["3PaScuC67HvrbmwgWsqpS7"]')) # These company ids cannot be deleted
COMPANY_TABLE = os.getenv("COMPANY_TABLE_NAME", "amplify-lambda-api-dev")
CONFIGURATION_TABLE = os.getenv("CONFIGURATION_TABLE_NAME", "amplify-lambda-api-dev")
USER_TABLE = os.getenv("USER_TABLE_NAME", "amplify-lambda-api-dev")
SUBSCRIPTIONPLAN_TABLE = os.getenv("SUBSCRIPTIONPLAN_TABLE_NAME", "amplify-lambda-api-dev")
### End: Environment Variables ###

### Start: Logger Setup ###
logger = logging.getLogger()
# Check environment variables for logging level
logging_level_str = os.getenv("LOGGING_LEVEL", "INFO")
if logging_level_str.lower() == "info":
    logging.getLogger().setLevel(logging.INFO) # need to define the log level per aws lambda documentation
elif logging_level_str.lower == "debug":
    logging.getLogger().setLevel(logging.DEBUG) # need to define the log level per aws lambda documentation
else:
    logging.getLogger().setLevel(logging.WARNING) # need to define the log level per aws lambda documentation

if os.getenv("LOGGER_STREAM_HANDLED", "False") == "True":
    # Set logger to print to console and format the message
    logger.addHandler(logging.StreamHandler())
    logger.handlers[0].setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%Y-%m-%d %H:%M:%S"))
### End: Logger Setup ###

### Start: Global Variables ###
## General Global Variables

## AWS specific Global Variables

COMPANYDB_RESOURCE = {
    "resource": boto3.resource("dynamodb", region_name=AWS_REGION),
    "table_name": COMPANY_TABLE,
    "gsindex_name": DYNAMO_GSINDEX_NAME,
    }

CONFIGDB_RESOURCE = {
    "resource": boto3.resource("dynamodb", region_name=AWS_REGION),
    "table_name": CONFIGURATION_TABLE,
    "gsindex_name": DYNAMO_GSINDEX_NAME,
    }

USERDB_RESOURCE = {
    "resource": boto3.resource("dynamodb", region_name=AWS_REGION),
    "table_name": USER_TABLE,
    "gsindex_name": DYNAMO_GSINDEX_NAME,
    }

SUBSCRIPTIONPLANDB_RESOURCE = {
    "resource": boto3.resource("dynamodb", region_name=AWS_REGION),
    "table_name": SUBSCRIPTIONPLAN_TABLE,
    "gsindex_name": DYNAMO_GSINDEX_NAME,
    }

S3_RESOURCE = {
    "resource": boto3.resource("s3", region_name=AWS_REGION),
    "bucket_name": S3_BUCKET,
    }
COGNITO_RESOURCE = {
    "resource": boto3.client('cognito-idp', region_name=AWS_REGION),
    "user_pool_id": COGNITO_USER_POOL_ID,
    "app_client_id": COGNITO_APP_CLIENT_ID,
    "identity_pool_id": COGNITO_IDENTITY_POOL_ID,
    }
## Custom Global Variables

### End: Global Variables ###

### Start: Classes ###
## General Classes
class DetailedError(Exception):
    """
    Custom error class for handling exceptions in the Lambda API.
    
    Attributes:
        error (str): The type of error that occurred.
        message (str): A brief description of the error.
        detail (str): Additional details about the error.

    Example Usage:
        raise DetailedError("auth-0001", "Incorrect username and password", "Ensure that the username and password included in the request are correct")
    """
    
    def __init__(self, error, message, detail, status_code=500):
        self.error = error
        self.message = message
        self.detail = detail
        self.status_code = status_code

## AWS specific Resource Classes
class DynamoDBClass:

    def __init__(self, lambda_dynamodb_resource):
        """
        Initializes an instance of MyClass with the given lambda_dynamodb_resource.

        Args:
            lambda_dynamodb_resource (dict): A dictionary containing the resource, table_name, and gsindex_name.

        Returns:
            None
        """
        self.resource = lambda_dynamodb_resource["resource"]
        self.table_name = lambda_dynamodb_resource["table_name"]
        self.gsindex_name = lambda_dynamodb_resource["gsindex_name"]
        self.table = self.resource.Table(self.table_name)
        if self.gsindex_name is not None and self.resource.Table(self.table_name).global_secondary_indexes is not None:
            self.gsindex = self.resource.Table(self.table_name).global_secondary_indexes[0]
        else:
            self.gsindex = None

    def correct_value_type(self, value):
        """
        Converts the given value to the correct type for DynamoDB.
        
        Args:
            value (any): The value to convert.
        
        Returns the converted value.
        """
        if isinstance(value, datetime):
            return value.strftime("%Y-%m-%dT%H:%M:%S.%f")
        if isinstance(value, Decimal):
            return float(value)
        if isinstance(value, UUID):
            return str(value)
        if isinstance(value, shortuuid.ShortUUID):
            return str(value)
        if value.lower() == "true":
            return True
        if value.lower() == "false":
            return False
        try:
            if int(value) == float(value):
                return int(value)
            else:
                return float(value)
        except:
            pass

        return value
    
    def construct_update_expression_and_values(self, update_expression_entries:dict):
        """
        Constructs the update expression and values for a DynamoDB update operation.

        Args:
            update_expression_entries (dict): A dictionary containing the update expression entries.

        Returns:
            tuple: A tuple containing the update expression and the corresponding values.

        Example:
            update_expression_entries = {"name": "John", "age": 30}
            update_expression, update_expression_values = construct_update_expression_and_values(update_expression_entries)
            print(update_expression)  # Output: "SET name = :name, age = :age"
            print(update_expression_values)  # Output: {":name": "John", ":age": 30}
        """
        update_expression = "SET "
        expression_attribute_values = {}
        expression_attribute_names = {}

        for i, (key, value) in enumerate(update_expression_entries.items()):
            # Skip the PK and SK if in the update expression entries
            if key == "PK" or key == "SK":
                continue
            placeholder = f':val{i}'
            name_placeholder = f'#name{i}'

            update_expression += f"{name_placeholder} = {placeholder}, "
            expression_attribute_values[placeholder] = value
            expression_attribute_names[name_placeholder] = key

        # Remove the trailing comma and space
        update_expression = update_expression.rstrip(', ')

        return update_expression, expression_attribute_values, expression_attribute_names
    
    def construct_filter_expression_entry(self, filter_expression, key:str, value:str):
        """
        Constructs a filter expression entry for the given key and value.
        
        Args:
            filter_expression (str): The filter expression to add the entry to.
            key (str): The key to add to the filter expression.
            value (str): The value to add to the filter expression.
        
        Returns the filter expression with the added entry.
        """
        # Convert the value to the correct type for DynamoDB
        value = self.correct_value_type(value)

        if filter_expression is None:
            filter_expression = Attr(key).eq(value)
        else:
            filter_expression = filter_expression & Attr(key).eq(value)
        return filter_expression
    
    def construct_date_filter_entry(self,key:str, filter_expression=None, start:str=None, end:str=None):
        """
        Constructs a filter expression entry for the given key and date range.

        Args:
            key (str): The key to add to the filter expression.
            filter_expression (str): The filter expression to add the entry to.
            start (str): The start of the date range.
            end (str): The end of the date range.

        Returns the filter expression with the added entry.
        """
        if start is None and end is None:
            logger.warn("Both start and end in a date filter are None")
            return filter_expression
        
        if filter_expression is None:
            if start is None:
                return Attr(key).lte(end)
            if end is None:
                return Attr(key).gte(start)
            return Attr(key).between(start, end)
        
        if start is None:
            return filter_expression & Attr(key).lte(end)
        if end is None:
            return filter_expression & Attr(key).gte(start)
        return filter_expression & Attr(key).between(start, end)

    def construct_filter_expression(self, filter_expression_entries:list, filter_expression=None):
        """
        Constructs a filter expression for the given filter expression entries.
        
        Args:
            filter_expression (str): The filter expression to add the entries to.
            filter_expression_entries (list): A list of dictionaries containing the key and value for each filter expression entry.
        
        Returns the filter expression with the added entries.
        """
        for filter_expression_entry in filter_expression_entries:
            filter_expression = self.construct_filter_expression_entry(filter_expression, filter_expression_entry["key"], filter_expression_entry["value"])
        
        filter_expression = self.construct_date_filter_entry("created", filter_expression, filter_expression_entries[0]["start"], filter_expression_entries[0]["end"])
        return filter_expression

    def create_item(self, item):
        """
        Create an item in the DynamoDB table
        
        Args:
            item (dict): The item to create in the DynamoDB table.
        """
        try:
            response = self.table.put_item(Item=item)
        except ClientError as e:
            logger.error(e.response["Error"]["Message"])
            raise DetailedError("dynamodb-0001", "Error creating item in DynamoDB table", e.response["Error"]["Message"])
        else:
            return True
        
    def search(self, key_condition_expression:str, expression_attribute_values,filter_expression:str=None, index_name:str=None):
        """
        Queries the DynamoDB table with the given key condition expression and expression attribute values.
        If a filter expression is provided, it is also applied to the query.
        If an index name is provided, the query is performed on that index.

        Args:
            key_condition_expression (str): The key condition expression to use in the query.
            expression_attribute_values (dict): The expression attribute values to use in the query.
            filter_expression (str): The filter expression to use in the query. Defaults to None.
            index_name (str): The index name to use in the query. Defaults to None.

        Returns the items matching the query criteria.
        """
        try:
            if filter_expression is None:
                response = self.table.query(
                    KeyConditionExpression=key_condition_expression,
                    ExpressionAttributeValues=expression_attribute_values,
                    IndexName=index_name
                )
            else:
                response = self.table.query(
                    KeyConditionExpression=key_condition_expression,
                    ExpressionAttributeValues=expression_attribute_values,
                    FilterExpression=filter_expression,
                    IndexName=index_name
                )
        except ClientError as e:
            logger.error(e.response["Error"]["Message"])
            raise DetailedError("dynamodb-0002", "Error searching DynamoDB table", e.response["Error"]["Message"])
        except Exception as e:
            logger.error(e)
            raise DetailedError("dynamodb-0003", "Error searching DynamoDB table", str(e))
        else:
            return response["Items"]
    
    def get_item_by_pk_and_sk(self, pk:str, sk:str):
        """
        Get an item from the DynamoDB table by its primary key.
        
        Args:
            pk (str): The parition key of the item to get.
            sk (str): The sort key of the item to get.
        
        Returns the item.
        """
        try:
            response = self.table.get_item(
                Key={
                    "PK": pk,
                    "SK": sk
                }
            )
        except ClientError as e:
            logger.error(e.response["Error"]["Message"])
            raise DetailedError("dynamodb-0004", "Error getting item from DynamoDB table", e.response["Error"]["Message"])
        else:
            return response["Item"]
    
    def delete_item_by_pk_and_sk(self, pk:str, sk:str):
        """
        Delete an item from the DynamoDB table by its primary key.
        
        Args:
            pk (str): The parition key of the item to delete.
            sk (str): The sort key of the item to delete.
        
        Returns True if the item was deleted successfully.
        """
        try:
            response = self.table.delete_item(
                Key={
                    "PK": pk,
                    "SK": sk
                }
            )
        except ClientError as e:
            logger.error(e.response["Error"]["Message"])
            raise DetailedError("dynamodb-0005", "Error deleting item from DynamoDB table", e.response["Error"]["Message"])
        else:
            return True
        
    def update_item(self, pk:str, sk:str, update_expression_entries:dict):
        """
        Update an item in the DynamoDB table.
        
        Args:
            pk (str): The partition key of the item to update.
            sk (str): The sort key of the item to update.
            update_expression_entries (dict): A dictionary containing the key and value for each update expression entry.
        Returns True if the item was updated successfully.
        """
        # Construct the db update expression
        update_expression, expression_attribute_values, expression_attribute_names = self.construct_update_expression_and_values(update_expression_entries)

        try:
            response = self.table.update_item(
                Key={
                    "PK": pk,
                    "SK": sk
                },
                UpdateExpression=update_expression,
                ExpressionAttributeValues=expression_attribute_values,
                ExpressionAttributeNames=expression_attribute_names
            )
        except ClientError as e:
            logger.error(e.response["Error"]["Message"])
            raise DetailedError("dynamodb-0006", "Error updating item in DynamoDB table", e.response["Error"]["Message"])
        else:
            return True

    def batch_delete(self, items:list):
        """
        Batch delete items from the DynamoDB table.
        
        Args:
            items (list): A list of dictionaries containing the primary key of each item to delete.
        
        Returns True if the items were deleted successfully.
        """
        with self.table.batch_writer() as batch:
            for item in items:
                batch.delete_item(
                    Key={
                        "PK": item["PK"],
                        "SK": item["SK"]
                    }
                )
        return True
        
class S3BucketClass:
    
    def __init__(self, lambda_s3_resource):
        self.resource = lambda_s3_resource["resource"]
        self.bucket_name = lambda_s3_resource["bucket_name"]
        self.bucket = self.resource.Bucket(self.bucket_name)

    def add_str_file(self, file_name:str, file_data:str):
        """
        Add a file in string format to the S3 bucket.
        
        Args:
            file_name (str): The name of the file to add.
            file_data (str): The data to add to the file.
        
        Returns True if the file was added successfully.
        """
        try:
            self.bucket.put_object(
                Key=file_name,
                Body=file_data
            )
        except ClientError as e:
            logger.error(e.response["Error"]["Message"])
            raise DetailedError("s3-0001", "Error adding file to S3 bucket", e.response["Error"]["Message"])
        else:
            return True
        
    def add_image(self, file_name:str, image_str):
        """
        Add an image to the S3 bucket.

        Args:
            file_name (str): The name of the file to be stored in the S3 bucket including extension.
            image_str (str): The base64 encoded string representation of the image.

        Returns:
            bool: True if the image is successfully added to the S3 bucket, False otherwise.
        """

        # Decode the image string
        image_data = base64.b64decode(image_str)
        image = Image.open(io.BytesIO(image_data))

        # Store the image in memory in byte format
        image_byte_arr = io.BytesIO()
        image.save(image_byte_arr, format=image.format)
        image_byte_arr.seek(0)

        # Upload the image to S3
        try:
            self.bucket.put_object(
                Key=file_name,
                Body=image_byte_arr,
                ContentType=f"image/{image.format.lower()}"
            )
        except ClientError as e:
            logger.error(e.response["Error"]["Message"])
            raise DetailedError("s3-0002", "Error adding image to S3 bucket", e.response["Error"]["Message"])
        else:
            return True
        
    def get_presigned_url(self, file_name:str, expiration:int=3600):
        """
        Get a presigned url for the given file name.
        
        Args:
            file_name (str): The name of the file to get the presigned url for.
            expiration (int): The expiration time of the presigned url in seconds. Defaults to 3600.
        
        Returns the presigned url.
        """
        try:
            response = self.resource.meta.client.generate_presigned_url(
                ClientMethod="get_object",
                Params={
                    "Bucket": self.bucket_name,
                    "Key": file_name
                },
                ExpiresIn=expiration
            )
        except ClientError as e:
            logger.error(e.response["Error"]["Message"])
            raise DetailedError("s3-0003", "Error getting presigned url from S3 bucket", e.response["Error"]["Message"])
        else:
            return response
        
class CognitoClass:

    def __init__(self, lambda_cognito_resource):
        """
        Initialize a Cognito Resource
        """
        self.resource = lambda_cognito_resource["resource"]
        self.user_pool_id = lambda_cognito_resource["user_pool_id"]
        self.app_client_id = lambda_cognito_resource["app_client_id"]
        self.identity_pool_id = lambda_cognito_resource["identity_pool_id"]
        #self.guest_user_pool_id = lambda_cognito_resource["guest_user_pool_id"]

    def get_user_by_username(self, username:str):
        """
        Get a user from Cognito using the given username.

        Args:
            username (str): The username of the user to get.

        Returns the user.

        Note: only use this for admin functions, otherwise use get_user_by_access_token
        """
        try:
            response = self.resource.admin_get_user(
                UserPoolId=self.user_pool_id,
                Username=username
            )
            return response
        except ClientError as e:
            logger.error(e.response["Error"]["Message"])
            raise DetailedError("cognito-0001", "Error getting user from Cognito", e.response["Error"]["Message"])
        except Exception as e:
            logger.error(e)
            raise DetailedError("cognito-0003", "Error getting user from Cognito", str(e))
        
    def list_groups_for_user(self, username:str):
        """
        List the groups the user belongs to.
        
        Args:
            username (str): The username of the user to get the groups for.
        
        Returns the groups the user belongs to. with the response syntax:
        {
            'Groups': [
                {
                    'GroupName': 'string',
                    'UserPoolId': 'string',
                    'Description': 'string',
                    'RoleArn': 'string',
                    'Precedence': 123,
                    'LastModifiedDate': datetime(2015, 1, 1),
                    'CreationDate': datetime(2015, 1, 1)
                },
            ],
            'NextToken': 'string'
        }
        """
        try:
            response = self.resource.admin_list_groups_for_user(
                UserPoolId=self.user_pool_id,
                Username=username
            )
            return response["Groups"]
        except ClientError as e:
            logger.error(e.response["Error"]["Message"])
            raise DetailedError("cognito-0004", "Error listing groups for user in Cognito", e.response["Error"]["Message"])
        except Exception as e:
            logger.error(e)
            raise DetailedError("cognito-0005", "Error listing groups for user in Cognito", str(e))
        
    def create_user(self, username:str, password:str, email:str, role:str, company_id:str, active:bool, nickname:str):
        """
        Create a user in Cognito.
        
        Args:
            username (str): The username of the user to create.
            password (str): The password of the user to create.
            email (str): The email of the user to create.
            role (str): The role of the user to create.
            company_id (str): The company id of the user to create.
            active (bool): Whether the user is active.
            nickname (str): The nickname of the user to create.
        
        Returns the user.
        """
        try:
            response = self.resource.admin_create_user(
                UserPoolId=self.user_pool_id,
                Username=username,
                TemporaryPassword=password,
                UserAttributes=[
                    {
                        'Name': 'email',
                        'Value': email
                    },
                    {
                        'Name': 'custom:role',
                        'Value': role
                    },
                    {
                        'Name': 'custom:company-id',
                        'Value': company_id
                    },
                    {
                        'Name': 'custom:active',
                        'Value': str(active)
                    },
                    {
                        'Name': 'nickname',
                        'Value': nickname
                    },
                    {
                        'Name': 'custom:created',
                        'Value': datetime.strftime(datetime.now(), DATETIME_FORMAT)
                    }
                ]
            )
            return response
        except ClientError as e:
            logger.error(e)
            if e.response["Error"]["Code"] == "UsernameExistsException":
                raise DetailedError("cognito-0009", "This username is already taken", e.__str__())
            raise DetailedError("cognito-0006", e.response["Error"]["Code"], e.__str__())
        except Exception as e:
            logger.error(e)
            raise DetailedError("cognito-0007", "Error creating user in Cognito", str(e))
        
    def add_user_to_group(self, username:str, group_name:str):
        """
        Add a user to a group in Cognito.
        
        Args:
            username (str): The username of the user to add to the group.
            group_name (str): The name of the group to add the user to.
        
        Returns True if the user was added to the group successfully.
        """
        try:
            response = self.resource.admin_add_user_to_group(
                UserPoolId=self.user_pool_id,
                Username=username,
                GroupName=group_name
            )
            return True
        except ClientError as e:
            logger.error(e.__str__())
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                raise DetailedError("cognito-0010", "This company group does not exist", e.__str__())
            raise DetailedError("cognito-00011", "Error adding user to group in Cognito", e.__str__())
        except Exception as e:
            logger.error(e)
            raise DetailedError("cognito-00012", "Error adding user to group in Cognito", str(e))
        
    def create_group(self, group_name:str, description:str, precedence:int):
        """
        Create a group in Cognito.
        
        Args:
            group_name (str): The name of the group to create.
            description (str): The description of the group to create.
            precedence (int): The precedence of the group to create.
        
        Returns the group.
        """
        try:
            response = self.resource.create_group(
                GroupName=group_name,
                UserPoolId=self.user_pool_id,
                Description=description,
                Precedence=precedence
            )
            return response
        except ClientError as e:
            logger.error(e.__str__())
            if e.response["Error"]["Code"] == "GroupExistsException":
                raise DetailedError("cognito-0018", "This companyId group already exists", e.__str__())
            raise DetailedError("cognito-0010", "Error creating group in Cognito", e.__str__())
        except Exception as e:
            logger.error(e)
            raise DetailedError("cognito-0011", "Error creating group in Cognito", str(e))
    
    def delete_user(self, username:str):
        """
        Delete a user from Cognito.
        
        Args:
            username (str): The username of the user to delete.
        
        Returns True if the user was deleted successfully.
        """
        try:
            response = self.resource.admin_delete_user(
                UserPoolId=self.user_pool_id,
                Username=username
            )
            return True
        except ClientError as e:
            logger.error(e.response["Error"]["Message"])
            raise DetailedError("cognito-0012", "Error deleting user from Cognito", e.response["Error"]["Message"])
        except Exception as e:
            logger.error(e)
            raise DetailedError("cognito-0013", "Error deleting user from Cognito", str(e))
        
    def list_group_users(self, group_name:str):
        """
        List the users in a group in Cognito.
        
        Args:
            group_name (str): The name of the group to list the users for.
        
        Returns the users in the group.
        """
        try:
            response = self.resource.list_users_in_group(
                UserPoolId=self.user_pool_id,
                GroupName=group_name
            )
            return response["Users"]
        except ClientError as e:
            logger.error(e.response["Error"]["Message"])
            raise DetailedError("cognito-0014", "Error listing users in group in Cognito", e.response["Error"]["Message"])
        except Exception as e:
            logger.error(e)
            raise DetailedError("cognito-0015", "Error listing users in group in Cognito", str(e))
    
        
class CognitoUserClass:
    def __init__(self, user: dict = None):
        """
        Initialize a Cognito User
        """
        self.lambda_cognito = CognitoClass(COGNITO_RESOURCE)
        # Allow the user to be initialized with either a request or a user dictionary
        
        if user is not None:
            self.user = user
            # Need to rename since the response from the list_users_in_group and get_user_by_access_token functions are different
            if "Attributes" in self.user:
                self.user["UserAttributes"] = self.user["Attributes"] 
        else:
            raise ValueError("Either a request or a user dictionary must be provided")
    
    @property
    def groups(self)->list:
        """
        Get the groups the user belongs to.
        
        Returns the groups the user belongs to.

        Note: only use this for admin functions
        """
        # Check if the user is an admin
        if self.role != "admin":
            raise DetailedError("cognito-0008", "User is not an admin", "User is not an admin")
        return self.lambda_cognito.list_groups_for_user(self.username)
    
    @property
    def role(self)->str:
        """
        Get the role of the user.
        
        Returns the role of the user.
        """
        role = ""
        for attribute in self.user["UserAttributes"]:
            if attribute["Name"] == "custom:role":
                role = attribute["Value"]
        return role
    
    @property
    def username(self)->str:
        """
        Get the username of the user.
        
        Returns the username of the user.
        """
        return self.user["Username"]
    
    @property
    def email(self)->str:
        """
        Get the email of the user.
        
        Returns the email of the user.
        """
        email = ""
        for attribute in self.user["UserAttributes"]:
            if attribute["Name"] == "email":
                email = attribute["Value"]
        return email
    
    @property
    def user_id(self)->str:
        """
        Get the user id of the user.
        
        Returns the user id of the user.
        """
        user_id = ""
        for attribute in self.user["UserAttributes"]:
            if attribute["Name"] == "sub":
                user_id = attribute["Value"]
        return user_id
    
    @property
    def is_verified(self)->bool:
        """
        Get whether the user is verified.
        
        Returns whether the user is verified.
        """
        is_verified = False
        for attribute in self.user["UserAttributes"]:
            if attribute["Name"] == "email_verified":
                is_verified = attribute["Value"] == "true"
        return is_verified
    
    @property
    def company_id(self)->str:
        """
        Get the company id of the user.
        
        Returns the company id of the user.
        """
        company_id = ""
        for attribute in self.user["UserAttributes"]:
            if attribute["Name"] == "custom:company-id":
                company_id = attribute["Value"]
        return company_id

    @property
    def active(self)->bool:
        """
        Get whether the user is active.
        
        Returns whether the user is active.
        """
        active = False
        for attribute in self.user["UserAttributes"]:
            if attribute["Name"] == "custom:active":
                active = attribute["Value"] == "true"
        return active
    
    @property
    def nickname(self)->str:
        """
        Get the nickname of the user.
        
        Returns the nickname of the user.
        """
        nickname = ""
        for attribute in self.user["UserAttributes"]:
            if attribute["Name"] == "nickname":
                nickname = attribute["Value"]
        return nickname
    
    @property
    def created(self)->datetime:
        """
        Get the date the user was created.
        
        Returns the date the user was created.
        """
        created = ""
        for attribute in self.user["UserAttributes"]:
            if attribute["Name"] == "custom:created":
                created = attribute["Value"]
        return datetime.strptime(created, DATETIME_FORMAT)
    
    @property
    def user_dict(self)->dict:
        """
        Get the user as a dictionary.
        
        Returns the user as a dictionary.
        """
        user_dict = {}
        user_dict["username"] = self.username
        user_dict["email"] = self.email
        user_dict["id"] = self.user_id
        user_dict["is_verified"] = self.is_verified
        user_dict["company_id"] = self.company_id
        user_dict["active"] = self.active
        user_dict["role"] = self.role
        user_dict["nickname"] = self.nickname
        user_dict["created"] = datetime.strftime(self.created, DATETIME_FORMAT)
        return user_dict
    
    def update_attribute(self, attribute_name:str, attribute_value:str):
        """
        Update a user attribute.
        
        Args:
            attribute_name (str): The name of the attribute to update.
            attribute_value (str): The value of the attribute to update.
        
        Returns True if the attribute was updated successfully.
        """
        try:
            response = self.lambda_cognito.resource.admin_update_user_attributes(
                UserPoolId=self.lambda_cognito.user_pool_id,
                Username=self.username,
                UserAttributes=[
                    {
                        'Name': attribute_name,
                        'Value': attribute_value
                    }
                ]
            )
            return True
        except ClientError as e:
            logger.error(e.response["Error"]["Message"])
            raise DetailedError("cognito-0016", "Error updating user attribute in Cognito", e.response["Error"]["Message"])
        except Exception as e:
            logger.error(e)
            raise DetailedError("cognito-0017", "Error updating user attribute in Cognito", str(e))
    
### End: Resource Classes ###

def clear_database():
    for resource in [COMPANYDB_RESOURCE, CONFIGDB_RESOURCE, USERDB_RESOURCE]:
        db = DynamoDBClass(resource)
        # Delete all items in the table except for those with companyId = "3PaScuC67HvrbmwgWsqpS7"
        items = db.table.scan()["Items"]
        # Batch delete the items
        with db.table.batch_writer() as batch:
            for item in items:
                batch.delete_item(
                    Key={
                        "companyId": item["companyId"],
                    }
                )

    # Just specify id for other tables
    for resource in []:
        db = DynamoDBClass(resource)
        # Delete all items in the table except for those with companyId = "3PaScuC67HvrbmwgWsqpS7"
        items = db.table.scan()["Items"]
        # Batch delete the items
        with db.table.batch_writer() as batch:
            for item in items:
                batch.delete_item(
                    Key={
                        "id": item["id"],
                    }
                )      
    return True

def populate_database():
    # Add some test data to the table
    # Create a company record
    # Add app settings for dev
    

    company_id = '86a5d624-da44-4cfc-b10c-98df3d15b51a'

    company_db = DynamoDBClass(COMPANYDB_RESOURCE)
    company_db.table.put_item(Item={
        '__typename': 'Company',
        'companyId': company_id,
        'name': 'Test Company',
        'address': '123 Main St.',
        'city': 'Test City',
        'state': 'Test State',
        'zip': '12345',
        'country': 'United States',
        'phone': '123-456-7890',
        'email': 'test@gmail.com',
        'website': 'https://www.test.com',
        'active': 'true',
        'createdAt': '2020-01-01T00:00:00.000Z',
        'updatedAt': '2020-01-01T00:00:00.000Z',
        'editGroups': ['sudo', f'{company_id}#admins'],
        'readGroups': ['sudo', f'{company_id}#admins', f'{company_id}#users']
    })

    company_db.table.put_item(Item={
        '__typename': 'Company',
        'companyId': 'c4165b1a-7213-4ca1-bbd6-f5140e7c89fb',
        'name': 'Test Company',
        'address': '123 Main St.',
        'city': 'Test City',
        'state': 'Test State',
        'zip': '12345',
        'country': 'United States',
        'phone': '123-456-7890',
        'email': 'test@gmail.com',
        'website': 'https://www.test.com',
        'active': 'true',
        'createdAt': '2020-01-01T00:00:00.000Z',
        'updatedAt': '2020-01-01T00:00:00.000Z',
        'editGroups': ['sudo', f'{company_id}#admins'],
        'readGroups': ['sudo', f'{company_id}#admins', f'{company_id}#users']
    })

    config_db = DynamoDBClass(CONFIGDB_RESOURCE)
    config_db.table.put_item(Item={
        'companyId': company_id,
        'createdAt': '2020-01-01T00:00:00.000Z',
        'updatedAt': '2020-01-01T00:00:00.000Z',
        '__typename': 'Configuration',
        'pressLabel': 'Press',
        'partLabel': 'Part',
        'inspectionLabel': 'Inspection',
        'purchaseOrderLabel': 'Purchase Order',
        'lineItemLabel': 'Line Item',
        'releaseLabel': 'Release',
        'cavityLabel': 'Cavity',
        'jobLabel': 'Job',
        'inspectionMethodLabel': 'Inspection Method',
        'externalPurchaseOrderReferenceLabel': 'External Purchase Order Reference',
        'internalPurchaseOrderReferenceLabel': 'Internal Purchase Order Reference',
        'defaultIntervalMinutes': '30',
        'startUpInspectionRequired': 'true',
        'noMeasureIsFail': 'true',
        'shotCountRequired': 'true',
        'pressAttributes': [{'id': '8c254701-7556-47d3-ab21-c34ce6ea0784','name': 'Tonnage', 'required': True}, {'id': 'e7bccd27-9db1-4e73-9b51-35f8b2f2c771', 'name': 'Brand', 'required': False}],
        'partAttributes': [{'id': 'e89fda61-7ef7-403b-966c-c830545d09f3','name': 'Color', 'required': True}, {'id': 'e7bccd27-9db1-4e73-9b51-35f8b2f2c771','name': 'Material', 'required': False}],
        'jobReportShowCavities': 'true',
        'jobReportShowTimeSeries': 'true',
        'jobReportShowDistribution': 'true',
        'jobReportShowDataTable': 'true',
        'jobReportShowStatistics': 'true',
        'scrapCauses': [{'name': 'Uknown', 'description': 'Unknown cause of scrap'}],
        'editGroups': ['sudo', f'{company_id}#admins'],
        'readGroups': ['sudo', f'{company_id}#admins', f'{company_id}#users']
    })

    config_db.table.put_item(Item={
        'companyId': 'c4165b1a-7213-4ca1-bbd6-f5140e7c89fb',
        'createdAt': '2020-01-01T00:00:00.000Z',
        'updatedAt': '2020-01-01T00:00:00.000Z',
        '__typename': 'Configuration',
        'pressLabel': 'Press',
        'partLabel': 'Part',
        'inspectionLabel': 'Inspection',
        'purchaseOrderLabel': 'Purchase Order',
        'lineItemLabel': 'Line Item',
        'releaseLabel': 'Release',
        'cavityLabel': 'Cavity',
        'jobLabel': 'Job',
        'inspectionMethodLabel': 'Inspection Method',
        'externalPurchaseOrderReferenceLabel': 'External Purchase Order Reference',
        'internalPurchaseOrderReferenceLabel': 'Internal Purchase Order Reference',
        'defaultIntervalMinutes': '30',
        'startUpInspectionRequired': 'true',
        'noMeasureIsFail': 'true',
        'shotCountRequired': 'true',
        'pressAttributes': [{'id': '8c254701-7556-47d3-ab21-c34ce6ea0784','name': 'Tonnage', 'required': True}, {'id': 'e7bccd27-9db1-4e73-9b51-35f8b2f2c771', 'name': 'Brand', 'required': False}],
        'partAttributes': [{'id': 'e89fda61-7ef7-403b-966c-c830545d09f3','name': 'Color', 'required': True}, {'id': 'e7bccd27-9db1-4e73-9b51-35f8b2f2c771','name': 'Material', 'required': False}],
        'jobReportShowCavities': 'true',
        'jobReportShowTimeSeries': 'true',
        'jobReportShowDistribution': 'true',
        'jobReportShowDataTable': 'true',
        'jobReportShowStatistics': 'true',
        'scrapCauses': [{'name': 'Uknown', 'description': 'Unknown cause of scrap'}],
        'editGroups': ['sudo', f'{company_id}#admins'],
        'readGroups': ['sudo', f'{company_id}#admins', f'{company_id}#users']
    })

    user_db = DynamoDBClass(USERDB_RESOURCE)
    user_db.table.put_item(Item={
        '__typename': 'User',
        'id': 'e0f36f6f-2b57-4b1e-931b-474863aca4ce',
        'companyId': company_id,
        'email': 'jake@latticeoperations.com',
        'role': 'admin',
        'active': True,
        'name': 'Adam Admin',
        'username': 'devadmin',
        'createdAt': '2024-03-06T12:12:12.123Z',
        'updatedAt': '2024-03-06T12:12:12.123Z',
        'editGroups': ['sudo', f'{company_id}#admins'],
        'readGroups': ['sudo', f'{company_id}#admins', f'{company_id}#users']
    })

    user_db.table.put_item(Item={
        '__typename': 'User',
        'id': '6e41d675-0e9b-4674-b55b-3213582c06d4',
        'companyId': "c4165b1a-7213-4ca1-bbd6-f5140e7c89fb",
        'email': 'jake@latticeoperations.com',
        'role': 'admin',
        'active': True,
        'name': 'Sammy Sudo',
        'username': 'devsudo',
        'createdAt': '2020-01-01T00:00:00.000Z',
        'updatedAt': '2020-01-01T00:00:00.000Z',
        'editGroups': ['sudo'],
        'readGroups': ['sudo']
    })

    subscriptionPlan_db = DynamoDBClass(SUBSCRIPTIONPLANDB_RESOURCE)

    subscriptionPlan_db.table.put_item(Item={
        '__typename': 'SubscriptionPlan',
        'id': 'a7cadd32-ecec-4ee2-a65f-4b1a3d2419d9',
        'name': 'Demo',
        'description': 'Demo subscription plan',
        'price': 0,
        'intervalDays': 30,
        'updateNotes': 'Initial version',
        'active': True,
        'createdAt': '2020-01-01T00:00:00.000Z',
        'updatedAt': '2020-01-01T00:00:00.000Z',
        'adminUsers': 1,
        'supervisorUsers': 0,
        'inspectorUsers': 0,
    })

    subscriptionPlan_db.table.put_item(Item={
        '__typename': 'SubscriptionPlan',
        'id': 'a7cadd32-ecec-4ee2-a65f-4b1a3d241964',
        'name': 'Starter',
        'description': 'Basic resources for a small company. Includes 1 Admin, 1 Supervisor, 3 Inspectors',
        'price': 0,
        'intervalDays': 30,
        'updateNotes': 'Initial version',
        'active': True,
        'createdAt': '2020-01-01T00:00:00.000Z',
        'updatedAt': '2020-01-01T00:00:00.000Z',
        'adminUsers': 1,
        'supervisorUsers': 1,
        'inspectorUsers': 3,
    })

### Start: Lambda Function Handler ###       

def lambda_handler(event, context):

    global logger
    global S3_RESOURCE
    global COGNITO_RESOURCE
    global COMPANYDB_RESOURCE
    global CONFIGDB_RESOURCE
    global USERDB_RESOURCE
    global SUBSCRIPTIONPLANDB_RESOURCE

    # Run the populattion function
    populate_database()

    return {
        "statusCode": 200,
        "body": json.dumps({
            "message": "Lambda function executed successfully"
        })
    }

### End: Lambda Function Handler ###