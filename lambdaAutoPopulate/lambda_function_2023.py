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
DYNAMODB_TABLE = os.getenv("DYNAMODB_TABLE", "amplify-lambda-api-dev")
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
DYNAMODB_RESOURCE = {
    "resource": boto3.resource("dynamodb", region_name=AWS_REGION),
    "table_name": DYNAMODB_TABLE,
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
    db = DynamoDBClass(DYNAMODB_RESOURCE)
    # Delete all items in the table except for those with companyId = "3PaScuC67HvrbmwgWsqpS7"
    items = db.table.scan()["Items"]
    # Batch delete the items
    with db.table.batch_writer() as batch:
        for item in items:
            batch.delete_item(
                Key={
                    "PK": item["PK"],
                    "SK": item["SK"]
                }
            )
    return True

def dev_delete_database():
    db = DynamoDBClass(DYNAMODB_RESOURCE)
    # Delete all items in the table except for those with companyId = "3PaScuC67HvrbmwgWsqpS7"
    items = db.table.scan()["Items"]
    items_to_delete = []
    for item in items:
        # check if the item has a companyId attribute
        if "companyId" not in item:
            continue
        if item["companyId"] in PROTECTED_COMPANY_IDS:
            continue
        if item["PK"] == "APP_SETTINGS":
            continue
        items_to_delete.append(item)
    # Batch delete the items
    with db.table.batch_writer() as batch:
        for item in items_to_delete:
            batch.delete_item(
                Key={
                    "PK": item["PK"],
                    "SK": item["SK"]
                }
            )
    return True

def populate_app_settings():
    db = DynamoDBClass(DYNAMODB_RESOURCE)
    db.table.put_item(Item={
        'PK': 'APP_SETTINGS',
        'SK': 'DIMENSION_TYPE#ACTIVE#pass-fail',
        'name': 'pass-fail',
        'active': 'true',
        'description': 'pass-fail',
        'created': '2020-01-01T00:00:00.000',
        'updated': '2020-01-01T00:00:00.000',
        'updateNote': 'Length'
    })
    db.table.put_item(Item={
        'PK': 'APP_SETTINGS',
        'SK': 'DIMENSION_TYPE#ACTIVE#bounded',
        'name': 'bounded',
        'active': 'true',
        'description': 'bounded',
        'created': '2020-01-01T00:00:00.000',
        'updated': '2020-01-01T00:00:00.000',
        'updateNote': 'Length'
    })
    db.table.put_item(Item={
        'PK': 'APP_SETTINGS',
        'SK': 'DIMENSION_TYPE#ACTIVE#max',
        'name': 'max',
        'active': 'true',
        'description': 'max',
        'created': '2020-01-01T00:00:00.000',
        'updated': '2020-01-01T00:00:00.000',
        'updateNote': 'Length'
    })
    db.table.put_item(Item={
        'PK': 'APP_SETTINGS',
        'SK': 'DIMENSION_TYPE#ACTIVE#min',
        'name': 'min',
        'active': 'true',
        'description': 'min',
        'created': '2020-01-01T00:00:00.000',
        'updated': '2020-01-01T00:00:00.000',
        'updateNote': 'Length'
    })

    db.table.put_item(Item={
        'PK': 'APP_SETTINGS',
        'SK': 'USER_ROLE#ACTIVE#admin',
        'name': 'admin',
        'active': 'true',
        'description': 'admin',
        'created': '2020-01-01T00:00:00.000',
        'updated': '2020-01-01T00:00:00.000',
        'updateNote': 'new'
    })
    db.table.put_item(Item={
        'PK': 'APP_SETTINGS',
        'SK': 'USER_ROLE#ACTIVE#supervisor',
        'name': 'supervisor',
        'active': 'true',
        'description': 'supervisor',
        'created': '2020-01-01T00:00:00.000',
        'updated': '2020-01-01T00:00:00.000',
        'updateNote': 'new'
    })
    db.table.put_item(Item={
        'PK': 'APP_SETTINGS',
        'SK': 'USER_ROLE#ACTIVE#inspector',
        'name': 'inspector',
        'active': 'true',
        'description': 'inspector',
        'created': '2020-01-01T00:00:00.000',
        'updated': '2020-01-01T00:00:00.000',
        'updateNote': 'new'
    })

    db.table.put_item(Item={
        'PK': 'APP_SETTINGS',
        'SK': 'JOB_STATUS#ACTIVE#unassigned',
        'name': 'unassigned',
        'active': 'true',
        'description': 'unassigned',
        'created': '2020-01-01T00:00:00.000',
        'updated': '2020-01-01T00:00:00.000',
        'updateNote': 'new'
    })
    db.table.put_item(Item={
        'PK': 'APP_SETTINGS',
        'SK': 'JOB_STATUS#ACTIVE#pending',
        'name': 'pending',
        'active': 'true',
        'description': 'pending',
        'created': '2020-01-01T00:00:00.000',
        'updated': '2020-01-01T00:00:00.000',
        'updateNote': 'new'
    })
    db.table.put_item(Item={
        'PK': 'APP_SETTINGS',
        'SK': 'JOB_STATUS#ACTIVE#running',
        'name': 'running',
        'active': 'true',
        'description': 'running',
        'created': '2020-01-01T00:00:00.000',
        'updated': '2020-01-01T00:00:00.000',
        'updateNote': 'new'
    })
    db.table.put_item(Item={
        'PK': 'APP_SETTINGS',
        'SK': 'JOB_STATUS#ACTIVE#paused',
        'name': 'paused',
        'active': 'true',
        'description': 'paused',
        'created': '2020-01-01T00:00:00.000',
        'updated': '2020-01-01T00:00:00.000',
        'updateNote': 'new'
    })
    db.table.put_item(Item={
        'PK': 'APP_SETTINGS',
        'SK': 'JOB_STATUS#ACTIVE#closed',
        'name': 'closed',
        'active': 'true',
        'description': 'closed',
        'created': '2020-01-01T00:00:00.000',
        'updated': '2020-01-01T00:00:00.000',
        'updateNote': 'Running'
    })
    db.table.put_item(Item={
        'PK': 'APP_SETTINGS',
        'SK': 'JOB_STATUS#INACTIVE#inactive',
        'name': 'inactive',
        'active': 'false',
        'description': 'inactive',
        'created': '2020-01-01T00:00:00.000',
        'updated': '2020-01-01T00:00:00.000',
        'updateNote': 'new'
    })

    db.table.put_item(Item={
        'PK': 'APP_SETTINGS',
        'SK': 'SCRAP_DISPOSITION#ACTIVE#rework',
        'name': 'Rework',
        'active': 'true',
        'description': 'Rework the part to be good',
        'created': '2020-01-01T00:00:00.000',
        'updated': '2020-01-01T00:00:00.000',
        'updateNote': 'new'
    })
    db.table.put_item(Item={
        'PK': 'APP_SETTINGS',
        'SK': 'PRESS_STATUS#ACTIVE#running',
        'name': 'running',
        'active': 'true',
        'description': 'running',
        'created': '2020-01-01T00:00:00.000',
        'updated': '2020-01-01T00:00:00.000',
        'updateNote': 'new'
    })
    db.table.put_item(Item={
        'PK': 'APP_SETTINGS',
        'SK': 'PRESS_STATUS#ACTIVE#idle',
        'name': 'idle',
        'active': 'true',
        'description': 'idle',
        'created': '2020-01-01T00:00:00.000',
        'updated': '2020-01-01T00:00:00.000',
        'updateNote': 'new'
    })
    db.table.put_item(Item={
        'PK': 'APP_SETTINGS',
        'SK': 'PRESS_STATUS#ACTIVE#maintenance',
        'name': 'maintenance',
        'active': 'true',
        'description': 'maintenance',
        'created': '2020-01-01T00:00:00.000',
        'updated': '2020-01-01T00:00:00.000',
        'updateNote': 'new'
    })

def delete_app_settings():
    db = DynamoDBClass(DYNAMODB_RESOURCE)
    # Delete all items in the table except for those with companyId = "3PaScuC67HvrbmwgWsqpS7"
    items = db.table.scan()["Items"]
    items_to_delete = []
    for item in items:
        if item["PK"] == "APP_SETTINGS":
            items_to_delete.append(item)
    # Batch delete the items
    with db.table.batch_writer() as batch:
        for item in items_to_delete:
            batch.delete_item(
                Key={
                    "PK": item["PK"],
                    "SK": item["SK"]
                }
            )
    return True

def reset_app_settings():
    delete_app_settings()
    populate_app_settings()
    return True

def populate_new_demo_company(company_id:str):
    db = DynamoDBClass(DYNAMODB_RESOURCE)
    db.table.put_item(Item={
        'PK': f'COMPANY#{company_id}',
        'SK': 'COMPANY',
        'id': f'{company_id}',
        'name': 'Test Company',
        'address': '123 Main St.',
        'city': 'Test City',
        'state': 'Test State',
        'zip': '12345',
        'country': 'United States',
        'phone': '123-456-7890',
        'email': 'test@gmail.com',
        'website': 'www.test.com',
        'logo': f'COMPANY#{company_id}/company/logo.png',
        'created': '2020-01-01T00:00:00.000Z'
    })

    db.table.put_item(Item={
        'PK': f'COMPANY#{company_id}',
        'SK': 'CONFIGURATION',
        'companyId': f'{company_id}',
        'id': '54Qop7s2A6edN28gTrHR79',
        'created': '2020-01-01T00:00:00.000Z',
        'updated': '2020-01-01T00:00:00.000Z',
        'pressLabel': 'Press',
        'partLabel': 'Part',
        'jobLabel': 'Job',
        'inspectionLabel': 'Inspection',
        'purchaseOrderLabel': 'Purchase Order',
        'lineItemLabel': 'Line Item',
        'releaseLabel': 'Release',
        'cavityLabel': 'Cavity',
        'inspectionMethodLabel': 'Inspection Method',
        'externalPurchaseOrderReferenceLabel': 'External Purchase Order Reference',
        'internalPurchaseOrderReferenceLabel': 'Internal Purchase Order Reference',
        'startUpInspectionRequired': 'true',
        'noMeasureIsFail': 'true',
        'requireShotCount': 'true',
        'pressAttributes': [{'name': 'attribute1', 'required': True}, {'name': 'attribute2', 'required': False}],
        'defaultIntervalMinutes': '30'
    })

    # part_names = ["75-R0123-1", "ER4-8367", "E64561-0", "TRAIL-02"]
    # part_familiies = {}
    # for part_name in part_names:
    #     part_familiies[part_name] = []
    #     for i in range(5):
    #         part_familiies[part_name].append(shortuuid.uuid())

    # for part_name in part_names:
    #     for i, id in enumerate(part_familiies[part_name]):
    #         part = {
    #             'PK': 'PART#COMPANY#' + company_id,
    #             'SK': '',
    #             'companyId': '3Fwa2RJvVn7HXSdfiBL3i2',
    #             'id': '',
    #             'name': part_name,
    #             'revision': '',
    #             'akaName': '',
    #             'cavities': 4,
    #             'intervalMinutes': 30,
    #             'previousId': '',
    #             'latest': False,
    #             'description': 'Turboencabulator with twisted opposites poles',
    #             'active': True,
    #             'created': (datetime.now()-timedelta(days=1)).isoformat(),
    #             'updated': datetime.now().isoformat(),
    #             'updateNote': 'This part has been updated.',
    #             'dimensions': [{"name":"string", "akaName":"string", "type":"string", "nominal":"string", "upper":"string", "lower":"string", "unit":"string", "updated":"2020-01-01T00:00:00.000Z", "updatedNote":"string", "notes":"string"}],
    #         }
    #         # Create dummy parts in the same format as the part above
    #         # Generate a random uuid for the part id
    #         part['id'] = id
    #         # Generate a random uuid for the previousId or use the last part id
    #         if i > 0:
    #             part['previousId'] = part_familiies[part_name][i-1]
    #         else:
    #             part['previousId'] = None

    #         if i == len(part_familiies[part_name]) - 1:
    #             part['latest'] = True

    #         # Generate a random revision for the part
    #         part['revision'] = str(i)

    #         part["SK"] = 'COMPANY#' + company_id + '#LATEST#FALSE#ACTIVE#TRUE#NAME#' + part['name'].upper().replace(" ", "_") + '#REVISION#' + part['revision'] + '#PART#' + part['id']
    #         if i == len(part_familiies[part_name]) - 1:
    #             part["SK"] = part["SK"].replace("#LATEST#FALSE", "#LATEST#TRUE")

    #         # Generate 3 dimensions for the part
    #         dimensions = []
    #         types = ["bounded", "max", "min", "limits", "pass-fail"]
    #         for j, type_ in enumerate(types):
    #             dimension = {"name":"Dimension " + str(j), "akaName":"Balloon " + str(j), "type":type_, "nominal": 1.0, "upper":1.5, "lower":0.6, "unit":"in", "updated":datetime.now().isoformat(), "updatedNote":"Updated Note " + str(j), "notes":"Measure with calipers", "measureMethod":"calipers"}
    #             for key, value in dimension.items():
    #                 if key == 'nominal' or key == 'upper' or key == 'lower':
    #                     if value:
    #                         dimension[key] = Decimal(str(value))
    #             dimensions.append(dimension)
    #             if dimension['type'] == 'pass-fail':
    #                 dimension['nominal'] = None
    #                 dimension['upper'] = None
    #                 dimension['lower'] = None
    #                 dimension['unit'] = None
    #                 dimension['measureMethod'] = "Visual"
    #                 dimension["notes"] = "Visual inspection"

    #         part['dimensions'] = dimensions

    #         # Put the part in the database
    #         db.table.put_item(Item=part)

    return True

    

def populate_database():
    db = DynamoDBClass(DYNAMODB_RESOURCE)
    # Add some test data to the table
    # Create a company record
    # Add app settings for dev
    

    company_id = '3Fwa2RJvVn7HXSdfiBL3i2'
    part_names = ["75-R0123-1", "ER4-8367", "E64561-0", "TRAIL-02"]
    part_familiies = {}
    for part_name in part_names:
        part_familiies[part_name] = []
        for i in range(5):
            part_familiies[part_name].append(shortuuid.uuid())

    for part_name in part_names:
        for i, id in enumerate(part_familiies[part_name]):
            part = {
                'PK': 'PART#COMPANY#' + company_id,
                'SK': '',
                'companyId': '3Fwa2RJvVn7HXSdfiBL3i2',
                'id': '',
                'name': part_name,
                'revision': '',
                'akaName': '',
                'cavities': 4,
                'intervalMinutes': 30,
                'previousId': '',
                'latest': False,
                'description': 'Turboencabulator with twisted opposites poles',
                'active': True,
                'created': (datetime.now()-timedelta(days=1)).isoformat(),
                'updated': datetime.now().isoformat(),
                'updateNote': 'This part has been updated.',
                'dimensions': [{"name":"string", "akaName":"string", "type":"string", "nominal":"string", "upper":"string", "lower":"string", "unit":"string", "updated":"2020-01-01T00:00:00.000Z", "updatedNote":"string", "notes":"string"}],
            }
            # Create dummy parts in the same format as the part above
            # Generate a random uuid for the part id
            part['id'] = id
            # Generate a random uuid for the previousId or use the last part id
            if i > 0:
                part['previousId'] = part_familiies[part_name][i-1]
            else:
                part['previousId'] = None

            if i == len(part_familiies[part_name]) - 1:
                part['latest'] = True

            # Generate a random revision for the part
            part['revision'] = str(i)

            part["SK"] = 'COMPANY#' + company_id + '#LATEST#FALSE#ACTIVE#TRUE#NAME#' + part['name'].upper().replace(" ", "_") + '#REVISION#' + part['revision'] + '#PART#' + part['id']
            if i == len(part_familiies[part_name]) - 1:
                part["SK"] = part["SK"].replace("#LATEST#FALSE", "#LATEST#TRUE")

            # Generate 3 dimensions for the part
            dimensions = []
            types = ["bounded", "max", "min", "limits", "pass-fail"]
            for j, type_ in enumerate(types):
                dimension = {"name":"Dimension " + str(j), "akaName":"Balloon " + str(j), "type":type_, "nominal": 1.0, "upper":1.5, "lower":0.6, "unit":"in", "updated":datetime.now().isoformat(), "updatedNote":"Updated Note " + str(j), "notes":"Measure with calipers", "measureMethod":"calipers"}
                for key, value in dimension.items():
                    if key == 'nominal' or key == 'upper' or key == 'lower':
                        if value:
                            dimension[key] = Decimal(str(value))
                dimensions.append(dimension)
                if dimension['type'] == 'pass-fail':
                    dimension['nominal'] = None
                    dimension['upper'] = None
                    dimension['lower'] = None
                    dimension['unit'] = None
                    dimension['measureMethod'] = "Visual"
                    dimension["notes"] = "Visual inspection"

            part['dimensions'] = dimensions

            # Put the part in the database
            db.table.put_item(Item=part)

    ## TODO add data for companyId 3PaScuC67HvrbmwgWsqpS7 to be used for demo purposes
    

	#### Start: Autogenerated Dev Data ####
    db.table.put_item(Item={
        'PK': 'COMPANY#3Fwa2RJvVn7HXSdfiBL3i2',
        'SK': 'COMPANY',
        'id': '3Fwa2RJvVn7HXSdfiBL3i2',
        'name': 'Test Company',
        'address': '123 Main St.',
        'city': 'Test City',
        'state': 'Test State',
        'zip': '12345',
        'country': 'United States',
        'phone': '123-456-7890',
        'email': 'test@gmail.com',
        'website': 'www.test.com',
        'logo': 'COMPANY#3Fwa2RJvVn7HXSdfiBL3i2/company/logo.png',
        'created': '2020-01-01T00:00:00.000Z'
    })
    db.table.put_item(Item={
        'PK': 'SUBSCRIPTION#3Fwa2RJvVn7HXSdfiBL3i2',
        'SK': 'COMPANY#3Fwa2RJvVn7HXSdfiBL3i2#SUBSCRIPTION#J9EkjgCCkAA6pnc7EzJrA5',
        'companyId': '3Fwa2RJvVn7HXSdfiBL3i2',
        'id': 'J9EkjgCCkAA6pnc7EzJrA5',
        'planId': 'kiznqXhxTVvWdNZQoDmuPn',
        'status': 'active',
        'startDate': '2020-01-01T00:00:00.000Z',
        'endDate': '2020-01-01T00:00:00.000Z',
        'created': '2020-01-01T00:00:00.000Z',
        'updated': '2020-01-01T00:00:00.000Z',
        'updateNote': 'Subscription extended.'
    })

    db.table.put_item(Item={
        'PK': 'COMPANY#3Fwa2RJvVn7HXSdfiBL3i2',
        'SK': 'CONFIGURATION',
        'companyId': '3Fwa2RJvVn7HXSdfiBL3i2',
        'id': '54Qop7s2A6edN28gTrHR79',
        'created': '2020-01-01T00:00:00.000Z',
        'updated': '2020-01-01T00:00:00.000Z',
        'pressLabel': 'Press',
        'partLabel': 'Part',
        'jobLabel': 'Job',
        'inspectionLabel': 'Inspection',
        'purchaseOrderLabel': 'Purchase Order',
        'lineItemLabel': 'Line Item',
        'releaseLabel': 'Release',
        'cavityLabel': 'Cavity',
        'inspectionMethodLabel': 'Inspection Method',
        'externalPurchaseOrderReferenceLabel': 'External Purchase Order Reference',
        'internalPurchaseOrderReferenceLabel': 'Internal Purchase Order Reference',
        'startUpInspectionRequired': 'true',
        'noMeasureIsFail': 'true',
        'requireShotCount': 'true',
        'pressAttributes': [{'name': 'attribute1', 'required': True}, {'name': 'attribute2', 'required': False}],
        'defaultIntervalMinutes': '30'
    })
    db.table.put_item(Item={
        'PK': 'JOB#COMPANY#3Fwa2RJvVn7HXSdfiBL3i2',
        'SK': 'COMPANY#3Fwa2RJvVn7HXSdfiBL3i2#PART#VJ63LEx4vMiFpJyVTYDMWX#JOB#9nJb2nEmAjvHsiEns2atHv',
        'companyId': '3Fwa2RJvVn7HXSdfiBL3i2',
        'id': 'mNXe7HGWvzxdQU9rXcsmr7',
        'partId': 'VJ63LEx4vMiFpJyVTYDMWX',
        'part': {'PK': 'PART#COMPANY#3Fwa2RJvVn7HXSdfiBL3i2', 'SK': 'COMPANY#3Fwa2RJvVn7HXSdfiBL3i2#LATEST#TRUE#ACTIVE#TRUE#NAME#Part_1#REVISION#A#PART#VJ63LEx4vMiFpJyVTYDMWX', 'companyId': '3Fwa2RJvVn7HXSdfiBL3i2', 'id': 'VJ63LEx4vMiFpJyVTYDMWX', 'name': 'Part 1', 'revision': 'A', 'akaName': 'Part 1', 'cavities': '1', 'intervalMinutes': '30', 'previousId': '3Fwa2RJvVn7HXSdfiBL3i2', 'latest': 'true', 'description': 'Part 1', 'active': 'true', 'created': '2020-01-01T00:00:00.000Z', 'updated': '2020-01-01T00:00:00.000Z', 'updateNote': 'Part 1', 'dimensions': [{'name': 'string', 'akaName': 'string', 'type': 'string', 'nominal': 'string', 'upper': 'string', 'lower': 'string', 'unit': 'string', 'updated': '2020-01-01T00:00:00.000Z', 'updatedNote': 'string', 'notes': 'string'}]},
        'pressId': '9nJb2nEmAjvHsiEns2atHv',
        'releaseIds': ['a2Pr4WY4GkV4YUoDw4iiYA', 'a2Pr4WY4GkV4YUoDw4iiYA'],
        'intervalMinutes': '30',
        'status': 'running',
        'created': '2020-01-01T00:00:00.000Z',
        'updated': '2020-01-01T00:00:00.000Z',
        'notes': [{'userId': 'string', 'nickname': 'string', 'note': 'string', 'created': '2020-01-01T00:00:00.000Z'}],
        'quantity': '100'
    })
    db.table.put_item(Item={
        'PK': 'PRESS#COMPANY#3Fwa2RJvVn7HXSdfiBL3i2',
        'SK': 'COMPANY#3Fwa2RJvVn7HXSdfiBL3i2#PRESS#ACTIVE#True#ID#CAFnNaB9r2Aw6fPYDB2kRa',
        'companyId': '3Fwa2RJvVn7HXSdfiBL3i2',
        'id': 'CAFnNaB9r2Aw6fPYDB2kRa',
        'name': 'Press 1',
        'description': 'Press 1',
        'active': 'true',
        'status': 'running',
        'notes': [{'userId': 'string', 'nickname': 'string', 'note': 'string', 'created': '2020-01-01T00:00:00.000Z'}],
        'created': '2020-01-01T00:00:00.000Z',
        'attributes': [{'name': 'string', 'value': 'string'}]
    })
    db.table.put_item(Item={
        'PK': 'PART#COMPANY#3Fwa2RJvVn7HXSdfiBL3i2',
        'SK': 'COMPANY#3Fwa2RJvVn7HXSdfiBL3i2#LATEST#TRUE#ACTIVE#TRUE#NAME#Part_1#REVISION#A#PART#VJ63LEx4vMiFpJyVTYDMWX',
        'companyId': '3Fwa2RJvVn7HXSdfiBL3i2',
        'id': 'VJ63LEx4vMiFpJyVTYDMWX',
        'name': 'Part 1',
        'revision': 'A',
        'akaName': 'Part 1',
        'cavities': '1',
        'intervalMinutes': '30',
        'previousId': '3Fwa2RJvVn7HXSdfiBL3i2',
        'latest': 'true',
        'description': 'Part 1',
        'active': 'true',
        'created': '2020-01-01T00:00:00.000Z',
        'updated': '2020-01-01T00:00:00.000Z',
        'updateNote': 'Part 1',
        'dimensions': [{'name': 'string', 'akaName': 'string', 'type': 'string', 'nominal': 'string', 'upper': 'string', 'lower': 'string', 'unit': 'string', 'updated': '2020-01-01T00:00:00.000Z', 'updatedNote': 'string', 'notes': 'string'}]
    })
    db.table.put_item(Item={
        'PK': 'DIMENSION#COMPANY#3Fwa2RJvVn7HXSdfiBL3i2',
        'SK': 'COMPANY#3Fwa2RJvVn7HXSdfiBL3i2#LATEST#TRUE#ACTIVE#TRUE#DIMENSION#LsJ3ChzQgnHNB3QF2TvJxK',
        'companyId': '3Fwa2RJvVn7HXSdfiBL3i2',
        'id': 'LsJ3ChzQgnHNB3QF2TvJxK',
        'partIds': ['VJ63LEx4vMiFpJyVTYDMWX'],
        'name': 'Length',
        'previousId': 'koWuD5G29DqrLWecGzCxgS',
        'latest': 'true',
        'type': 'bounded',
        'nominal': '1.0',
        'max': '1.02',
        'min': '0.98',
        'active': 'true',
        'created': '2020-01-01T00:00:00.000Z',
        'updated': '2020-01-01T00:00:00.000Z',
        'updateNote': 'Part 1'
    })
    db.table.put_item(Item={
        'PK': 'INSPECTION#COMPANY#3Fwa2RJvVn7HXSdfiBL3i2',
        'SK': 'COMPANY#3Fwa2RJvVn7HXSdfiBL3i2#PART#VJ63LEx4vMiFpJyVTYDMWX#JOB#LsJ3ChzQgnHNB3QF2TvJxK#DUE#2020-01-01T00_00_00#INSPECTION#PJXidn8K4CRjxmioASY7Qg',
        'companyId': '3Fwa2RJvVn7HXSdfiBL3i2',
        'id': 'PJXidn8K4CRjxmioASY7Qg',
        'partId': 'VJ63LEx4vMiFpJyVTYDMWX',
        'pressId': 'VJ63LEx4vMiFpJyVTYDMWX',
        'jobId': 'LsJ3ChzQgnHNB3QF2TvJxK',
        'userId': 'LsJ3ChzQgnHNB3QF2TvJxK',
        'due': '2020-01-01T00:00:00.000Z',
        'created': '2020-01-01T00:00:00.000Z',
        'updated': '2020-01-01T00:00:00.000Z',
        'updateNote': 'Part 1',
        'measurements': [{'dimensionName': 'string', 'value': '1.0', 'cavity': 1}],
        'measurementNotes': [{'dimensionName': 'string', 'note': '1.0'}]
    })
    db.table.put_item(Item={
        'PK': 'SCRAP#COMPANY#3Fwa2RJvVn7HXSdfiBL3i2',
        'SK': 'COMPANY#3Fwa2RJvVn7HXSdfiBL3i2#PART_NAME#Part_1#JOB#mNXe7HGWvzxdQU9rXcsmr7#SCRAP#DqMVckzTn6DtPmWBb7F5LK',
        'companyId': '3Fwa2RJvVn7HXSdfiBL3i2',
        'disposition': 'Scrap',
        'user': 'User 1',
        'userId': '3Fwa2RJvVn7HXSdfiBL3i2',
        'part': 'Part 1',
        'notes': 'Notes 1',
        'images': ['https://www.example.com/image1.jpg', 'https://www.example.com/image2.jpg']
    })
    db.table.put_item(Item={
        'PK': 'CUSTOMER#COMPANY#3Fwa2RJvVn7HXSdfiBL3i2',
        'SK': 'COMPANY#3Fwa2RJvVn7HXSdfiBL3i2#NAME#Customer_1#ID#aLw4VdwF3t3FtSsEEhhaof',
        'companyId': '3Fwa2RJvVn7HXSdfiBL3i2',
        'id': 'aLw4VdwF3t3FtSsEEhhaof',
        'name': 'Customer 1',
        'address': '123 Main St.',
        'city': 'Anytown',
        'state': 'Anytown',
        'zip': '12345',
        'country': 'USA',
        'phone': '123-456-7890',
        'email': 'customer@customer1.com',
        'created': '2020-01-01T00:00:00.000Z',
        'updated': '2020-01-01T00:00:00.000Z'
    })
    db.table.put_item(Item={
        'PK': 'PO#COMPANY#3Fwa2RJvVn7HXSdfiBL3i2',
        'SK': 'COMPANY#3Fwa2RJvVn7HXSdfiBL3i2#OPEN#CUSTOMER#Customer_1#aLw4VdwF3t3FtSsEEhhaof#PO#3nV9NjicmTFuseLnPBfhix',
        'companyId': '3Fwa2RJvVn7HXSdfiBL3i2',
        'id': '3nV9NjicmTFuseLnPBfhix',
        'lineItemIds': ['Urc8hX9p7bFW4eC4ZaPB6j'],
        'status': 'open',
        'created': '2020-01-01T00:00:00.000Z',
        'updated': '2020-01-01T00:00:00.000Z',
        'externalReference': 'EXT12345',
        'internalReference': 'INT12345',
        'customerId': 'aLw4VdwF3t3FtSsEEhhaof',
        'notes': 'These are the notes.'
    })
    db.table.put_item(Item={
        'PK': 'LINE_ITEM#COMPANY#3Fwa2RJvVn7HXSdfiBL3i2',
        'SK': 'COMPANY#3Fwa2RJvVn7HXSdfiBL3i2#PART_NAME#PART_1#PO#3nV9NjicmTFuseLnPBfhix#LINE_ITEM#Urc8hX9p7bFW4eC4ZaPB6j',
        'companyId': '3Fwa2RJvVn7HXSdfiBL3i2',
        'id': 'Urc8hX9p7bFW4eC4ZaPB6j',
        'partId': 'VJ63LEx4vMiFpJyVTYDMWX',
        'partName': 'Part 1',
        'purchaseOrderId': '3nV9NjicmTFuseLnPBfhix',
        'quantity': '1.0',
        'created': '2020-01-01T00:00:00.000Z',
        'updated': '2020-01-01T00:00:00.000Z',
        'releaseIds': ['b85fYsYsw9RhbySiqyqf3f']
    })
    db.table.put_item(Item={
        'PK': 'RELEASE#COMPANY#3Fwa2RJvVn7HXSdfiBL3i2',
        'SK': 'COMPANY#3Fwa2RJvVn7HXSdfiBL3i2#PART_NAME#Part_1#CUSTOMER#aLw4VdwF3t3FtSsEEhhaof#PO#3nV9NjicmTFuseLnPBfhix#LINE_ITEM#Urc8hX9p7bFW4eC4ZaPB6j#RELEASE#b85fYsYsw9RhbySiqyqf3f#DUE#2024-02-01',
        'companyId': '3Fwa2RJvVn7HXSdfiBL3i2',
        'id': 'b85fYsYsw9RhbySiqyqf3f',
        'lineItemId': 'Urc8hX9p7bFW4eC4ZaPB6j',
        'puchaseOrderId': '3nV9NjicmTFuseLnPBfhix',
        'partId': 'VJ63LEx4vMiFpJyVTYDMWX',
        'partName': 'Part 1',
        'quantity': '1.0',
        'due': '2020-01-01T00:00:00.000Z',
        'jobId': '8rWBuNivBE6QQVtTXCnk5d',
        'created': '2020-01-01T00:00:00.000Z',
        'updated': '2020-01-01T00:00:00.000Z'
    })






    #### End: Autogenerated Dev Data ####

### Start: Lambda Function Handler ###       

def lambda_handler(event, context):

    global logger
    global DYNAMODB_RESOURCE
    global S3_RESOURCE
    global COGNITO_RESOURCE
    # Run the delete function
    clear_database()

    # Run the dev delete function
    #dev_delete_database()

    # Populate new company
    populate_new_demo_company(company_id="3PaScuC67HvrbmwgWsqpS7")

    # Reset the app settings
    #reset_app_settings()

    # Populate app_settings
    populate_app_settings()

    # Run the populattion function
    populate_database()

    return {
        "statusCode": 200,
        "body": json.dumps({
            "message": "Lambda function executed successfully"
        })
    }

### End: Lambda Function Handler ###