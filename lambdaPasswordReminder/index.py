# Create a lambda function to run at the start of every day and check all users in the user pool
# If a user has UserStatus as "FORCE_CHANGE_PASSWORD" and they hvae not logged in for 3 days send them a reminder email
# You can use the UserLastModifiedDate attribute to check when the user last logged in
# The email should contain the following message:
# "For security reasons our temporary passwords are only good for 7 days. Please login and change your password by <insert day 7 days from their modifed data> or your account will be locked
# and you will have to contact support to unlock it"
# The email should be sent from the address "no-reply@rhometrix.com" and the subject should be "Account Reminder"
# You can use the boto3 library to send the email and to check the user status with the admin_get_user function

# Example of the user object returned by the admin_get_user function
'''
{
    "Username": "janedoe",
    "UserAttributes": [
        {
            "Name": "sub",
            "Value": "b7622ff5-1001-4bcd-a017-5a1dadbb4d2c"
        },
        {
            "Name": "email_verified",
            "Value": "true"
        },
        {
            "Name": "custom:createdAt",
            "Value": "2024-03-15T20:08:51.309014Z"
        },
        {
            "Name": "name",
            "Value": "janedoe"
        },
        {
            "Name": "custom:companyId",
            "Value": "8da2d624-da44-445c-b10c-17cf3d66b51a"
        },
        {
            "Name": "custom:active",
            "Value": "True"
        },
        {
            "Name": "custom:role",
            "Value": "inspector"
        },
        {
            "Name": "email",
            "Value": "jake@latticeoperations.com"
        }
    ],
    "UserCreateDate": "2024-03-15T16:08:51.382000-04:00",
    "UserLastModifiedDate": "2024-03-15T16:08:51.382000-04:00",
    "Enabled": true,
    "UserStatus": "FORCE_CHANGE_PASSWORD"
}
'''