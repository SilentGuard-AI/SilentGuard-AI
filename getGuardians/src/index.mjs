// Feature 8: Guardian Management
// This Lambda fetches all guardians that belong to the authenticated user.
// It is used by the frontend to display the user's guardian list.

import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, QueryCommand } from "@aws-sdk/lib-dynamodb";

const client = new DynamoDBClient({});
const docClient = DynamoDBDocumentClient.from(client);

const GUARDIANS_TABLE_NAME = process.env.GUARDIANS_TABLE_NAME;
const USER_ID_INDEX_NAME = process.env.USER_ID_INDEX_NAME || "userId-index";

export const handler = async (event) => {
  try {
    console.log("Received event:", JSON.stringify(event, null, 2));
    console.log("GUARDIANS_TABLE_NAME:", GUARDIANS_TABLE_NAME);
    console.log("USER_ID_INDEX_NAME:", USER_ID_INDEX_NAME);

    const body = typeof event.body === "string"
      ? JSON.parse(event.body || "{}")
      : event.body || {};

    /*
      Feature 1: User Authentication

      When this Lambda is connected to API Gateway + Cognito,
      the userId should be taken from the authenticated user's JWT claims.

      For manual testing, userId can also be sent directly in the event,
      request body, or query string parameters.
    */
    const claims =
      event.requestContext?.authorizer?.claims ||
      event.requestContext?.authorizer?.jwt?.claims ||
      {};

    const userId =
      claims.sub ||
      event.userId ||
      body.userId ||
      event.queryStringParameters?.userId;

    if (!userId) {
      return {
        statusCode: 401,
        headers: corsHeaders(),
        body: JSON.stringify({
          message: "Missing authenticated userId"
        })
      };
    }

    /*
      Feature 8: Guardian Management

      Query the Guardians table by userId in order to return only the
      guardians that belong to the current authenticated user.
    */
   
    const result = await docClient.send(new QueryCommand({
      TableName: GUARDIANS_TABLE_NAME,
      IndexName: USER_ID_INDEX_NAME,
      KeyConditionExpression: "userId = :userId",
      ExpressionAttributeValues: {
        ":userId": userId
      }
    }));

    const guardians = result.Items || [];

    return {
      statusCode: 200,
      headers: corsHeaders(),
      body: JSON.stringify({
        message: "Guardians fetched successfully",
        count: guardians.length,
        guardians
      })
    };

  } catch (error) {
    console.error("Error fetching guardians:", error);

    return {
      statusCode: 500,
      headers: corsHeaders(),
      body: JSON.stringify({
        message: "Failed to fetch guardians",
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