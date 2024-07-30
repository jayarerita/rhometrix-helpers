import { APIGatewayProxyEvent } from "aws-lambda";
import { unmarshall, marshall } from "@aws-sdk/util-dynamodb";
import {
  DynamoDBClient,
  BatchWriteItemCommand,
  BatchWriteItemCommandInput,
  DeleteItemCommand,
  DeleteItemCommandInput,
  PutItemCommand,
  PutItemCommandInput,
} from "@aws-sdk/client-dynamodb";

import type { CompanyInfo } from "./types";
import { getEnvVar } from "./utils";

const dbClient = new DynamoDBClient({ region: process.env.REGION });

const putItem = async (tableName: string, item: any) => {
  const input: PutItemCommandInput = {
    TableName: tableName,
    Item: marshall(item),
  };

  return dbClient.send(new PutItemCommand(input));
};

const createCompany = async () => {
  const companyId = getEnvVar("COMPANY_ID");
  const company: CompanyInfo = {
    companyId: companyId,
    endOfPeriod: new Date(),
    name: "Test Company",
    address: "23 Wallaby Way",
    address2: "",
    city: "Sydney",
    state: "Texas",
    zip: "12345",
    country: "United States",
    phone: "123-456-7890",
    website: "www.testcompany.com",
    email: "jake@latticeoperations.com",
    billingCustomerId: "123",
    editGroups: [`${companyId}#admins`],
    readGroups: ["sudo", `${companyId}#users`],
    active: true,
    __typename: "Company",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  const RHOMETRIX_COMPANY_TABLE_NAME = getEnvVar(
    "RHOMETRIX_COMPANY_TABLE_NAME"
  );

  await putItem(RHOMETRIX_COMPANY_TABLE_NAME, company);
  console.log("Company created for companyId: ", companyId);
};

const createConfiguration = async () => {
  const companyId = getEnvVar("COMPANY_ID");

  const configuration = {
    companyId: companyId,
    pressLabel: "Press",
    partLabel: "Part",
    inspectionLabel: "Inspection",
    purchaseOrderLabel: "Purchase Order",
    lineItemLabel: "Line Item",
    releaseLabel: "Release",
    cavityLabel: "Cavity",
    jobLabel: "Job",
    inspectionMethodLabel: "Inspection Method",
    externalPurchaseOrderReferenceLabel: "External Reference",
    internalPurchaseOrderReferenceLabel: "Internal Reference",
    externalJobReferenceLabel: "External Reference",
    internalJobReferenceLabel: "Internal Reference",
    defaultIntervalMinutes: "60",
    startUpInspectionRequired: false,
    noMeasureIsFail: false,
    shotCountRequired: false,
    pressAttributes: null,
    partAttributes: null,
    jobReportShowCavities: true,
    jobReportShowTimeSeries: true,
    jobReportShowDistribution: true,
    jobReportShowDataTable: true,
    jobReportShowStatistics: true,
    jobReportShowScrap: true,
    jobReportShowRuntime: true,
    jobReportShowCustomerInfo: true,
    jobReportShowReleases: true,
    dashboardShowPoId: true,
    scrapCauses: [
      {
        name: "Unknown",
        description: "Unknown cause of scrap",
      },
    ],
    editGroups: [`${companyId}#admins`],
    readGroups: ["sudo", `${companyId}#users`],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    __typename: "Configuration",
  };

  const RHOMETRIX_CONFIGURATION_TABLE_NAME = getEnvVar(
    "RHOMETRIX_CONFIGURATION_TABLE_NAME"
  );

  await putItem(RHOMETRIX_CONFIGURATION_TABLE_NAME, configuration);
  console.log("Configuration created for companyId: ", companyId);
};

const createAdminUser = async () => {
  const companyId = getEnvVar("COMPANY_ID");

  const userItem = {
    id: getEnvVar("ADMIN_USER_ID"),
    companyId: companyId,
    active: true,
    role: "admin",
    name: "Test Admin",
    email: getEnvVar("ADMIN_USER_EMAIL"),
    username: "testadmin",
    readGroups: [`${companyId}#users`],
    editGroups: [`${companyId}#admins`],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    __typename: "User",
  };
  const RHOMETRIX_USER_TABLE_NAME = getEnvVar("RHOMETRIX_USER_TABLE_NAME");
  await putItem(RHOMETRIX_USER_TABLE_NAME, userItem);
  console.log("Admin user created for companyId: ", companyId);
};

const populateTestData = async () => {
  await createCompany();
  await createConfiguration();
  await createAdminUser();
};

const deleteCompany = async () => {
  const companyId = getEnvVar("COMPANY_ID");
  const RHOMETRIX_COMPANY_TABLE_NAME = getEnvVar(
    "RHOMETRIX_COMPANY_TABLE_NAME"
  );

  const deleteCompanyInput: DeleteItemCommandInput = {
    TableName: RHOMETRIX_COMPANY_TABLE_NAME,
    Key: {
      companyId: { S: companyId },
    },
  };

  await dbClient.send(new DeleteItemCommand(deleteCompanyInput));
  console.log("Company deleted for companyId: ", companyId);
};

const deleteConfiguration = async () => {
  const companyId = getEnvVar("COMPANY_ID");
  const RHOMETRIX_CONFIGURATION_TABLE_NAME = getEnvVar(
    "RHOMETRIX_CONFIGURATION_TABLE_NAME"
  );

  const deleteConfigurationInput: DeleteItemCommandInput = {
    TableName: RHOMETRIX_CONFIGURATION_TABLE_NAME,
    Key: {
      companyId: { S: companyId },
    },
  };

  await dbClient.send(new DeleteItemCommand(deleteConfigurationInput));

  console.log("Configuration deleted for companyId: ", companyId);
};

const deleteAllTableItems = async (tableName: string) => {
  const items = await dbClient.send(
    new BatchWriteItemCommand({
      RequestItems: {
        [tableName]: [
          {
            DeleteRequest: {
              Key: {
                companyId: { S: getEnvVar("COMPANY_ID") },
              },
            },
          },
        ],
      },
    })
  );

  console.log(`Deleted ${items.UnprocessedItems} items from ${tableName}`);
};

const clearTestData = async () => {
  await deleteCompany();
  await deleteConfiguration();
  await deleteAllTableItems(getEnvVar("RHOMETRIX_PRESS_TABLE_NAME"));
  await deleteAllTableItems(getEnvVar("RHOMETRIX_CUSTOMER_TABLE_NAME"));
  await deleteAllTableItems(getEnvVar("RHOMETRIX_PURCHASEORDER_TABLE_NAME"));
  await deleteAllTableItems(getEnvVar("RHOMETRIX_LINEITEM_TABLE_NAME"));
  await deleteAllTableItems(getEnvVar("RHOMETRIX_JOB_TABLE_NAME"));
  await deleteAllTableItems(getEnvVar("RHOMETRIX_RELEASE_TABLE_NAME"));
  await deleteAllTableItems(getEnvVar("RHOMETRIX_INSPECTION_TABLE_NAME"));
  await deleteAllTableItems(getEnvVar("RHOMETRIX_MEASUREMENT_TABLE_NAME"));
  await deleteAllTableItems(getEnvVar("RHOMETRIX_COMMENT_TABLE_NAME"));
  await deleteAllTableItems(getEnvVar("RHOMETRIX_USER_TABLE_NAME"));
  console.log("Test data cleared");
};

export const handler = async (request: APIGatewayProxyEvent) => {
  try {
    const str = JSON.stringify(request);
    console.log(`Received request: ${str}`);
    await clearTestData();
    await populateTestData();
  } catch (err: any) {
    console.error(err);
    return {
      statusCode: 500,
      body: JSON.stringify(`Internal Server Error: ${err.message}`),
    };
  }

  const response = {
    statusCode: 200,
    body: JSON.stringify({ received: true }),
  };
  return response;
};
