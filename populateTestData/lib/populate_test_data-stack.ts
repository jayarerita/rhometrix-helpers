import * as cdk from "aws-cdk-lib";
import { Construct } from "constructs";
import * as fs from "fs";
import { NodejsFunction, OutputFormat } from "aws-cdk-lib/aws-lambda-nodejs";
import { Runtime } from "aws-cdk-lib/aws-lambda";
import { Effect } from "aws-cdk-lib/aws-iam";
import { PolicyStatement } from "aws-cdk-lib/aws-iam";
import { LogGroup, RetentionDays } from "aws-cdk-lib/aws-logs";
import { HostedZone } from "aws-cdk-lib/aws-route53";
import { Certificate } from "aws-cdk-lib/aws-certificatemanager";
import {
  RestApi,
  LambdaIntegration,
  ApiKey,
  UsagePlan,
} from "aws-cdk-lib/aws-apigateway";
import { ApiGateway } from "aws-cdk-lib/aws-route53-targets";
import { ARecord, RecordTarget } from "aws-cdk-lib/aws-route53";

// import * as sqs from 'aws-cdk-lib/aws-sqs';

export class PopulateTestDataStack extends cdk.Stack {
  constructor(
    scope: Construct,
    id: string,
    envName: string,
    props?: cdk.StackProps
  ) {
    super(scope, id, props);

    const envVars = JSON.parse(
      fs.readFileSync(`./env-vars-${envName}.json`, "utf-8")
    );

    // Log out the environment variables
    console.log("Environment Variables  ", envVars);

    const RhometrixPopTestData = new NodejsFunction(
      this,
      `RhometrixPopTestData${envName}`,
      {
        runtime: Runtime.NODEJS_20_X,
        entry: "lambda/src.ts",
        description: "Populate Test Data Lambda",
        timeout: cdk.Duration.seconds(30),
        environment: envVars,
        bundling: {
          format: OutputFormat.ESM,
        },
      }
    );

    RhometrixPopTestData.addToRolePolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: [
          "dynamodb:DescribeTable",
          "dynamodb:Query",
          "dynamodb:Scan",
          "dynamodb:GetItem",
          "dynamodb:BatchGetItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem",
          "dynamodb:BatchWriteItem",
        ],
        resources: [
          cdk.Fn.sub(
            "arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/${TableName}",
            {
              TableName: envVars.RHOMETRIX_USER_TABLE_NAME,
            }
          ),
          cdk.Fn.sub(
            "arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/${TableName}",
            {
              TableName: envVars.RHOMETRIX_COMMENT_TABLE_NAME,
            }
          ),
          cdk.Fn.sub(
            "arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/${TableName}",
            {
              TableName: envVars.RHOMETRIX_MEASUREMENT_TABLE_NAME,
            }
          ),
          cdk.Fn.sub(
            "arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/${TableName}",
            {
              TableName: envVars.RHOMETRIX_INSPECTION_TABLE_NAME,
            }
          ),
          cdk.Fn.sub(
            "arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/${TableName}",
            {
              TableName: envVars.RHOMETRIX_RELEASE_TABLE_NAME,
            }
          ),
          cdk.Fn.sub(
            "arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/${TableName}",
            {
              TableName: envVars.RHOMETRIX_JOB_TABLE_NAME,
            }
          ),
          cdk.Fn.sub(
            "arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/${TableName}",
            {
              TableName: envVars.RHOMETRIX_LINEITEM_TABLE_NAME,
            }
          ),
          cdk.Fn.sub(
            "arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/${TableName}",
            {
              TableName: envVars.RHOMETRIX_PURCHASEORDER_TABLE_NAME,
            }
          ),
          cdk.Fn.sub(
            "arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/${TableName}",
            {
              TableName: envVars.RHOMETRIX_CUSTOMER_TABLE_NAME,
            }
          ),
          cdk.Fn.sub(
            "arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/${TableName}",
            {
              TableName: envVars.RHOMETRIX_PRESS_TABLE_NAME,
            }
          ),
          cdk.Fn.sub(
            "arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/${TableName}",
            {
              TableName: envVars.RHOMETRIX_CONFIGURATION_TABLE_NAME,
            }
          ),
          cdk.Fn.sub(
            "arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/${TableName}",
            {
              TableName: envVars.RHOMETRIX_COMPANY_TABLE_NAME,
            }
          ),
        ],
      })
    );

    // Add a log group for the Lambda function
    const RhometrixPopTestDataLogGroup = new LogGroup(
      this,
      `RhometrixPopTestData${envName}LogGroup`,
      {
        logGroupName: `/aws/lambda/${RhometrixPopTestData.functionName}`,
        retention: RetentionDays.ONE_WEEK,
      }
    );

    // Define a new Route53 alias record for the API Gateway
    const zone = HostedZone.fromLookup(this, "Zone", {
      domainName: envVars.HOSTED_ZONE_NAME,
    });

    // Get certificate by arn
    const certificate = Certificate.fromCertificateArn(
      this,
      "Certificate",
      envVars.CERTIFICATE_ARN
    );

    // Create an API Gateway REST API connected to the lambda function
    const api = new RestApi(this, "RhometrixPopTestData", {
      restApiName: "Rhometrix Populate Test Data API",
      description:
        "This API is used to manage test data in the Rhometrix DynamoDB tables",
      domainName: {
        domainName: envVars.DOMAIN_NAME,
        certificate: certificate,
      },
    });

    // Create an API Key
    const apiKey = new ApiKey(this, "ApiKey", {
      apiKeyName: "RhometrixApiKey",
      description: "API Key for Rhometrix Test Data API",
      enabled: true,
    });

    // Create a Usage Plan
    const usagePlan = new UsagePlan(this, "UsagePlan", {
      name: "RhometrixUsagePlan",
      description: "Usage plan for Rhometrix Test Data API",
      apiStages: [
        {
          api: api,
          stage: api.deploymentStage,
        },
      ],
    });

    // Add the API Key to the Usage Plan
    usagePlan.addApiKey(apiKey);

    // Output the API Key
    new cdk.CfnOutput(this, "ApiKeyOutput", {
      value: apiKey.keyId,
      description: "The API Key for Rhometrix Test Data API",
    });

    // Add the Lambda function as an API Gateway integration on the /stripe-webhook path for POST requests
    const integration = new LambdaIntegration(RhometrixPopTestData);
    const resourcePath = envVars.POPULATE_ROUTE.replace("/", "");
    const resource = api.root.addResource(resourcePath);
    resource.addMethod("GET", integration, {
      apiKeyRequired: true,
    });

    // Create the Route53 target for the API Gateway
    const apiGatewayTarget = new ApiGateway(api);

    // Create a Route53 A record for the API Gateway
    const apiGatewayAliasRecord = new ARecord(this, "ApiGatewayAliasRecord", {
      zone: zone,
      recordName: envVars.DOMAIN_NAME,
      target: RecordTarget.fromAlias(apiGatewayTarget),
    });
  }
}
