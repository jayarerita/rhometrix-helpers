#!/usr/bin/env node
import "source-map-support/register";
import * as cdk from "aws-cdk-lib";
import { PopulateTestDataStack } from "../lib/populate_test_data-stack";

const app = new cdk.App();
new PopulateTestDataStack(app, "PopulateTestDataStack", "test", {
  env: { account: "975050172558", region: "us-east-1" },
  description: "Rhometrix Populate Test Data Stack",
});
