// Feature 8: Guardian Management
// This Lambda creates a new guardian for the authenticated user
// and stores the guardian details in DynamoDB.

import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, PutCommand } from "@aws-sdk/lib-dynamodb";
import crypto from "crypto";

const client = new DynamoDBClient({});
const docClient = DynamoDBDocumentClient.from(client);

const GUARDIANS_TABLE_NAME = process.env.GUARDIANS_TABLE_NAME;

export const handler = async (event) => {
  try {
    console.log("Received event:", JSON.stringify(event, null, 2));

    const body = typeof event.body === "string"
      ? JSON.parse(event.body)
      : event.body || event;

    const guardianName = body.guardianName;
    const guardianPhone = body.guardianPhone;

    // Feature 8: Guardian Management
    // Store guardian email so Feature 9 can send email alerts later.
    const guardianEmail = body.guardianEmail || body.email || "";

    const relationship = body.relationship || "Family member";
    const isPrimary = body.isPrimary ?? true;

    // Feature 8: Guardian Management
    // Validate the required guardian details before saving the guardian.
    if (!guardianName || !guardianPhone) {
      return {
        statusCode: 400,
        headers: corsHeaders(),
        body: JSON.stringify({
          message: "guardianName and guardianPhone are required"
        })
      };
    }

    /*
      Feature 1: User Authentication

      When connected to API Gateway + Cognito,
      the userId is taken from the authenticated user's JWT claims.

      For manual testing, userId can also be sent in the request body.
    */
    const claims =
      event.requestContext?.authorizer?.claims ||
      event.requestContext?.authorizer?.jwt?.claims ||
      {};

    const userId = claims.sub || body.userId;
    const userEmail = claims.email || body.userEmail || "unknown";

    // Feature 1: User Authentication
    // Reject the request if no authenticated userId exists.
    if (!userId) {
      return {
        statusCode: 401,
        headers: corsHeaders(),
        body: JSON.stringify({
          message: "Missing authenticated userId"
        })
      };
    }

    const now = new Date().toISOString();

    // Feature 8: Guardian Management
    // Build the guardian record that will be saved in DynamoDB.
    const item = {
      guardianId: crypto.randomUUID(),
      userId,
      userEmail,
      guardianName,
      guardianPhone,

      // Feature 9: Guardian Alerts
      // These fields are used later by the alert Lambda to send email alerts.
      guardianEmail,
      email: guardianEmail,

      relationship,
      isPrimary,
      createdAt: now,
      updatedAt: now
    };

    // Feature 8: Guardian Management
    // Save the new guardian in the Guardians table.
    await docClient.send(new PutCommand({
      TableName: GUARDIANS_TABLE_NAME,
      Item: item
    }));

    return {
      statusCode: 201,
      headers: corsHeaders(),
      body: JSON.stringify({
        message: "Guardian created successfully",
        guardian: item
      })
    };

  } catch (error) {
    console.error("Error creating guardian:", error);

    return {
      statusCode: 500,
      headers: corsHeaders(),
      body: JSON.stringify({
        message: "Failed to create guardian",
        error: error.message
      })
    };
  }
};

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Allow-Methods": "OPTIONS,POST,GET"
  };
}