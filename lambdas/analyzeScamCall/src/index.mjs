// Feature 5: Call Transcript Analysis
// Feature 6: Scam Risk Classification
// Feature 7: Risk Event Storage
// Feature 9: Guardian Alerts
// Feature 10: Call History
// Feature 12: Disconnect Call
// This Lambda processes a call/contact event, analyzes the transcript,
// saves the risk event, sends guardian alerts, and optionally disconnects the call.

import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  PutCommand,
  QueryCommand,
  ScanCommand
} from "@aws-sdk/lib-dynamodb";

import {
  SNSClient,
  PublishCommand
} from "@aws-sdk/client-sns";

import {
  SESClient,
  SendEmailCommand
} from "@aws-sdk/client-ses";

import {
  ConnectClient,
  GetContactAttributesCommand,
  StopContactCommand,
  DescribeContactCommand
} from "@aws-sdk/client-connect";

async function describeConnectContact(instanceId, contactId) {
  if (!instanceId || !contactId) {
    console.log("Missing instanceId/contactId. Cannot describe contact.", {
      instanceId,
      contactId
    });
    return {};
  }

  try {
    const response = await connectClient.send(
      new DescribeContactCommand({
        InstanceId: instanceId,
        ContactId: contactId
      })
    );

    console.log("DescribeContact:", JSON.stringify(response.Contact, null, 2));

    return response.Contact || {};
  } catch (error) {
    console.log("DescribeContact failed:", error);
    return {};
  }
}

const REGION = process.env.AWS_REGION || "us-east-1";

const CALL_RECORDS_TABLE =
  process.env.CALL_RECORDS_TABLE || "SilentGuardCallRecords";

const GUARDIANS_TABLE =
  process.env.GUARDIANS_TABLE || "AISilentGuardGuardians";

const GUARDIANS_USER_ID_INDEX =
  process.env.GUARDIANS_USER_ID_INDEX || "userId-index";

const USERS_TABLE =
  process.env.USERS_TABLE || "AISilentGuardUsers";

const CONNECT_INSTANCE_ID =
  process.env.CONNECT_INSTANCE_ID || "";

const ENABLE_DISCONNECT =
  process.env.ENABLE_DISCONNECT === "true";

// For testing, 25 means one strong keyword can trigger SMS/email.
// Later you can raise this to 70.
const ALERT_SCORE_THRESHOLD =
  Number(process.env.ALERT_SCORE_THRESHOLD || 25);

// Feature 9: Guardian Alerts
// Email alerts are sent with Amazon SES.
// The source email must be verified in SES.
// Example environment variable: ALERT_FROM_EMAIL=no-reply@your-domain.com
const ALERT_FROM_EMAIL =
  process.env.ALERT_FROM_EMAIL || "";

const ALERT_REPLY_TO_EMAIL =
  process.env.ALERT_REPLY_TO_EMAIL || ALERT_FROM_EMAIL;

const dynamoClient = new DynamoDBClient({ region: REGION });
const docClient = DynamoDBDocumentClient.from(dynamoClient);

const snsClient = new SNSClient({ region: REGION });
const sesClient = new SESClient({ region: REGION });
const connectClient = new ConnectClient({ region: REGION });

const scamSignals = [
  {
    keyword: "verification code",
    score: 25,
    reason: "Caller asked for a verification code"
  },
  {
    keyword: "bank account",
    score: 25,
    reason: "Caller mentioned bank account details"
  },
  {
    keyword: "urgent",
    score: 15,
    reason: "Caller used urgency pressure"
  },
  {
    keyword: "police",
    score: 20,
    reason: "Caller claimed to be from the police"
  },
  {
    keyword: "transfer money",
    score: 30,
    reason: "Caller asked to transfer money"
  },
  {
    keyword: "do not tell anyone",
    score: 25,
    reason: "Caller asked the victim to keep it secret"
  },
  {
    keyword: "gift card",
    score: 30,
    reason: "Caller asked for gift card payment"
  },
  {
    keyword: "password",
    score: 25,
    reason: "Caller asked for a password"
  },
  {
    keyword: "credit card",
    score: 25,
    reason: "Caller mentioned credit card details"
  },
  {
    keyword: "otp",
    score: 25,
    reason: "Caller asked for OTP code"
  },
  {
    keyword: "pin security code",
    score: 25,
    reason: "Caller asked for PIN security code"
  }
];

function normalizeInstanceId(value) {
  if (!value) return "";

  // If someone accidentally puts the full ARN, take only the ID.
  if (value.includes("/")) {
    return value.split("/").pop();
  }

  return value;
}

function findValueByKey(obj, targetKeys) {
  if (!obj || typeof obj !== "object") return undefined;

  const wanted = targetKeys.map(k => k.toLowerCase());

  for (const [key, value] of Object.entries(obj)) {
    if (wanted.includes(key.toLowerCase())) {
      return value;
    }

    if (value && typeof value === "object") {
      const found = findValueByKey(value, targetKeys);
      if (found !== undefined) return found;
    }
  }

  return undefined;
}

function extractContactId(event) {
  const directContactId =
    event.contactId ||
    event.ContactId ||
    event.detail?.contactId ||
    event.detail?.ContactId ||
    findValueByKey(event, ["contactId", "ContactId"]);

  if (directContactId) {
    return directContactId;
  }

  const contactArn =
    event.contactArn ||
    event.ContactArn ||
    event.detail?.contactArn ||
    event.detail?.ContactArn ||
    findValueByKey(event, ["contactArn", "ContactArn"]);

  if (contactArn && String(contactArn).includes("/contact/")) {
    return String(contactArn).split("/contact/").pop();
  }

  return undefined;
}

function extractInstanceId(event) {
  if (CONNECT_INSTANCE_ID) {
    return normalizeInstanceId(CONNECT_INSTANCE_ID);
  }

  const instanceArn =
    event.instanceArn ||
    event.InstanceArn ||
    event.detail?.instanceArn ||
    event.detail?.InstanceArn ||
    findValueByKey(event, ["instanceArn", "InstanceArn"]);

  return normalizeInstanceId(instanceArn);
}

// Feature 5: Call Transcript Analysis
// Extract the call transcript or matched scam text from the event.
function extractTranscript(event) {
  const transcript =
    event.transcript ||
    event.Transcript ||
    event.detail?.transcript ||
    event.detail?.Transcript ||
    event.detail?.matchedText ||
    event.detail?.MatchedText ||
    event.detail?.matched_text ||
    findValueByKey(event, [
      "transcript",
      "Transcript",
      "matchedText",
      "MatchedText",
      "matched_text"
    ]);

  if (transcript) {
    return String(transcript);
  }

  // Fallback: search the whole event for keywords
  const eventText = JSON.stringify(event).toLowerCase();

  const matchedKeywords = scamSignals
    .filter(signal => eventText.includes(signal.keyword.toLowerCase()))
    .map(signal => signal.keyword);

  if (matchedKeywords.length > 0) {
    return matchedKeywords.join(" ");
  }

  return JSON.stringify(event.detail || event);
}

// Feature 6: Scam Risk Classification
// Calculate a risk score and risk level according to scam-related keywords.
function calculateRisk(transcript) {
  let riskScore = 0;
  const detectedSignals = [];
  const lowerTranscript = transcript.toLowerCase();

  for (const signal of scamSignals) {
    if (lowerTranscript.includes(signal.keyword.toLowerCase())) {
      riskScore += signal.score;
      detectedSignals.push(signal);
    }
  }

  riskScore = Math.min(riskScore, 100);

  let riskLevel = "LOW";

  if (riskScore >= 70) {
    riskLevel = "HIGH";
  } else if (riskScore >= 31) {
    riskLevel = "MEDIUM";
  }

  return {
    riskScore,
    riskLevel,
    detectedSignals
  };
}

async function getContactAttributes(instanceId, contactId) {
  if (!instanceId || !contactId) {
    console.log("Missing instanceId/contactId. Cannot get contact attributes.", {
      instanceId,
      contactId
    });
    return {};
  }

  try {
    const response = await connectClient.send(
      new GetContactAttributesCommand({
        InstanceId: instanceId,
        InitialContactId: contactId
      })
    );

    return response.Attributes || {};
  } catch (error) {
    console.log("GetContactAttributes failed:", error);
    return {};
  }
}

// Feature 8: Guardian Management
// Load all active guardians of the protected user before sending alerts.
async function getGuardiansForUser(userId) {
  const response = await docClient.send(
    new QueryCommand({
      TableName: GUARDIANS_TABLE,
      IndexName: GUARDIANS_USER_ID_INDEX,
      KeyConditionExpression: "userId = :userId",
      ExpressionAttributeValues: {
        ":userId": userId
      }
    })
  );

  const guardians = response.Items || [];

  // Accept active guardians, and also guardians without status for MVP data.
  return guardians.filter(g => !g.status || g.status === "active");
}

// Feature 7: Risk Event Storage
// Save the analyzed call/risk event in DynamoDB so it can appear in history.
async function saveCallRecord(item) {
  await docClient.send(
    new PutCommand({
      TableName: CALL_RECORDS_TABLE,
      Item: item
    })
  );
}

// Feature 9: Guardian Alerts
// Send SMS alerts to all active guardians that have a phone number.
async function sendSmsToGuardians(item) {
  const guardians = await getGuardiansForUser(item.userId);

  if (guardians.length === 0) {
    console.log("No guardians found for userId:", item.userId);
    return {
      sentCount: 0,
      guardiansCount: 0
    };
  }

  let sentCount = 0;
  const alreadySent = new Set();

  for (const guardian of guardians) {
    const phoneNumber =
      guardian.guardianPhone ||
      guardian.PhoneNumber ||
      guardian.phoneNumber ||
      guardian.phone;

    if (!phoneNumber) {
      console.log("Guardian missing phone number:", guardian);
      continue;
    }

    // Avoid sending duplicate SMS to same number
    if (alreadySent.has(phoneNumber)) {
      console.log("Skipping duplicate guardian phone:", phoneNumber);
      continue;
    }

    const snsResponse = await snsClient.send(
      new PublishCommand({
        PhoneNumber: phoneNumber,
        Message: "SilentGuard alert. Please check on the protected user.",
        MessageAttributes: {
          "AWS.SNS.SMS.SMSType": {
            DataType: "String",
            StringValue: "Transactional"
          }
        }
      })
    );

    console.log("SNS publish response:", {
      guardianId: guardian.guardianId,
      phoneNumber,
      messageId: snsResponse.MessageId
    });

    alreadySent.add(phoneNumber);
    sentCount++;

    console.log("SMS sent:", {
      guardianId: guardian.guardianId,
      phoneNumber
    });
  }

  return {
    sentCount,
    guardiansCount: guardians.length
  };
}

// Feature 9: Guardian Alerts
// Send email alerts to all active guardians that have an email address.
// This uses Amazon SES, so ALERT_FROM_EMAIL must be verified in SES.
async function sendEmailToGuardians(item) {
  if (!ALERT_FROM_EMAIL) {
    console.log("ALERT_FROM_EMAIL is not configured. Skipping email alerts.");
    return {
      sentCount: 0,
      guardiansCount: 0,
      skipped: "ALERT_FROM_EMAIL is not configured"
    };
  }

  const guardians = await getGuardiansForUser(item.userId);

  if (guardians.length === 0) {
    console.log("No guardians found for userId:", item.userId);
    return {
      sentCount: 0,
      guardiansCount: 0
    };
  }

  const subject = `SilentGuard Alert - ${item.riskLevel} Risk Call Detected`;

  const detectedSignalsText =
    item.detectedSignals.length > 0
      ? item.detectedSignals
          .map(s => `- ${s.keyword}: ${s.reason}`)
          .join("\n")
      : "No specific signals were listed.";

  const bodyText = [
    "SilentGuard Alert",
    "",
    "A suspicious call was detected for a protected user.",
    "",
    `Risk level: ${item.riskLevel}`,
    `Risk score: ${item.riskScore}`,
    `User ID: ${item.userId}`,
    `Contact ID: ${item.contactId}`,
    "",
    "Detected signals:",
    detectedSignalsText,
    "",
    "Please check on the protected user as soon as possible."
  ].join("\n");

  let sentCount = 0;
  const alreadySent = new Set();

  for (const guardian of guardians) {
    const emailAddress =
      guardian.guardianEmail ||
      guardian.email ||
      guardian.Email ||
      guardian.guardian_email;

    if (!emailAddress) {
      console.log("Guardian missing email address:", {
        guardianId: guardian.guardianId
      });
      continue;
    }

    const normalizedEmail = String(emailAddress).trim().toLowerCase();

    if (alreadySent.has(normalizedEmail)) {
      console.log("Skipping duplicate guardian email:", normalizedEmail);
      continue;
    }

    const sesResponse = await sesClient.send(
      new SendEmailCommand({
        Source: ALERT_FROM_EMAIL,
        Destination: {
          ToAddresses: [normalizedEmail]
        },
        ReplyToAddresses: ALERT_REPLY_TO_EMAIL ? [ALERT_REPLY_TO_EMAIL] : [],
        Message: {
          Subject: {
            Data: subject,
            Charset: "UTF-8"
          },
          Body: {
            Text: {
              Data: bodyText,
              Charset: "UTF-8"
            }
          }
        }
      })
    );

    console.log("SES send email response:", {
      guardianId: guardian.guardianId,
      emailAddress: normalizedEmail,
      messageId: sesResponse.MessageId
    });

    alreadySent.add(normalizedEmail);
    sentCount++;
  }

  return {
    sentCount,
    guardiansCount: guardians.length
  };
}

// Feature 12: Disconnect Call
// Disconnect the Amazon Connect contact when disconnect mode is enabled
// and the call risk passes the configured threshold.
async function disconnectContactIfEnabled(instanceId, contactId, shouldAlert) {
  if (!ENABLE_DISCONNECT) {
    console.log("ENABLE_DISCONNECT=false. Skipping disconnect.");
    return false;
  }

  if (!shouldAlert) {
    console.log("Risk below threshold. Skipping disconnect.");
    return false;
  }

  if (!instanceId || !contactId) {
    console.log("Missing instanceId/contactId. Cannot disconnect.", {
      instanceId,
      contactId
    });
    return false;
  }

  await connectClient.send(
    new StopContactCommand({
      InstanceId: instanceId,
      ContactId: contactId
    })
  );

  console.log("Contact disconnected:", {
    instanceId,
    contactId
  });

  return true;
}
function normalizePhoneNumber(value) {
  if (!value) return "";

  return String(value)
    .replace(/[^\d+]/g, "")
    .trim();
}

async function findProtectedUserByConnectNumber(connectNumber) {
  const normalizedConnectNumber = normalizePhoneNumber(connectNumber);

  if (!normalizedConnectNumber) {
    console.log("Missing resolved Connect number. Cannot find protected user.");
    return null;
  }

  const response = await docClient.send(
    new ScanCommand({
      TableName: USERS_TABLE,
      FilterExpression: "#connectNumber = :connectNumber",
      ExpressionAttributeNames: {
        "#connectNumber": "connectNumber"
      },
      ExpressionAttributeValues: {
        ":connectNumber": normalizedConnectNumber
      }
    })
  );

  const matches = (response.Items || []).filter(
    user => user.monitoringEnabled !== false
  );

  if (matches.length === 0) {
    console.log("No protected user found for Connect number:", normalizedConnectNumber);
    return null;
  }

  if (matches.length > 1) {
    console.log("ERROR: Multiple protected users found with the same Connect number. Skipping guardian alerts.", {
      connectNumber: normalizedConnectNumber,
      userIds: matches.map(user => user.userId)
    });

    return null;
  }

  console.log("Protected user found for Connect number:", {
    connectNumber: normalizedConnectNumber,
    userId: matches[0].userId
  });

  return matches[0];
}

// Main Lambda handler
// Processes the event, analyzes risk, stores the result, and sends alerts.
export const handler = async (event) => {
  console.log("Received event:", JSON.stringify(event, null, 2));

  const contactId = extractContactId(event);
  const instanceId = extractInstanceId(event);

  const attributes = await getContactAttributes(instanceId, contactId);

  console.log("Contact attributes:", JSON.stringify(attributes, null, 2));

  const describedContact = await describeConnectContact(instanceId, contactId);

  const resolvedConnectNumber =
    describedContact.SystemEndpoint?.Address ||
    attributes.connectNumber ||
    attributes.protectedConnectNumber ||
    "";
  
  console.log("Resolved Connect number:", resolvedConnectNumber);
  

const protectedUser =
  await findProtectedUserByConnectNumber(resolvedConnectNumber);

  const userId =
    attributes.userId ||
    event.userId ||
    event.detail?.userId ||
    event.detail?.elderlyUserId ||
    protectedUser?.userId;

  const connectAgentLogin =
    attributes.connectAgentLogin ||
    event.connectAgentLogin ||
    event.detail?.connectAgentLogin ||
    protectedUser?.connectAgentLogin ||
    "unknown";

  if (!userId) {
    console.log("Missing userId. Guardian alerts will be skipped, but disconnect can still run.", {
      contactId,
      instanceId,
      attributes
    });
  }
    
  const effectiveUserId = userId || "unknown-user";

  const transcript = extractTranscript(event);

  let {
    riskScore,
    riskLevel,
    detectedSignals
  } = calculateRisk(transcript);
  
  const isRealtimeScamRuleMatch =
    event.source === "aws.connect" &&
    event["detail-type"] === "Contact Lens Realtime Rules Matched" &&
    event.detail?.ruleName === "AISilentGuardScamRisk";
  
  if (isRealtimeScamRuleMatch && riskScore < ALERT_SCORE_THRESHOLD) {
    riskScore = ALERT_SCORE_THRESHOLD;
    riskLevel = "MEDIUM";
    detectedSignals = [
      {
        keyword: "AISilentGuardScamRisk",
        score: ALERT_SCORE_THRESHOLD,
        reason: "Contact Lens real-time scam-risk rule matched"
      }
    ];
  }
  
  const shouldAlert =
    riskScore >= ALERT_SCORE_THRESHOLD || isRealtimeScamRuleMatch;
  const item = {
    callId: contactId || crypto.randomUUID(),
    contactId: contactId || "N/A",
    instanceId: instanceId || "N/A",

    userId: effectiveUserId,
    elderlyUserId: effectiveUserId,
    connectAgentLogin,

    transcript,
    riskScore,
    riskLevel,
    detectedSignals,
    shouldAlert,

    eventSource: event.source || "manual-test",
    eventDetailType: event["detail-type"] || "manual-test",
    createdAt: new Date().toISOString()
  };

  console.log("Prepared call record:", JSON.stringify(item, null, 2));

  let smsResult = {
    sentCount: 0,
    guardiansCount: 0
  };

  let emailResult = {
    sentCount: 0,
    guardiansCount: 0
  };

  let disconnected = false;

  if (shouldAlert) {
    // Feature 12: Disconnect Call
    // Automatically disconnect the call when the risk score passes the threshold.
    disconnected = await disconnectContactIfEnabled(
      instanceId,
      contactId,
      shouldAlert
    );
  
    if (userId) {
      // Feature 9: Guardian Alerts
      // Send both SMS and email alerts to active guardians.
      smsResult = await sendSmsToGuardians(item);
      emailResult = await sendEmailToGuardians(item);
    } else {
      console.log("Skipping guardian alerts because userId is missing.");
    }

    item.smsResult = smsResult;
    item.emailResult = emailResult;
    item.guardianNotified =
      smsResult.sentCount > 0 || emailResult.sentCount > 0;
    item.action = item.guardianNotified ? "alert_sent" : "alert_failed";

    // Feature 7: Risk Event Storage
    // Save the final alert status so the dashboard/history can show what happened.
    await saveCallRecord(item);
  } else {
    item.smsResult = smsResult;
    item.emailResult = emailResult;
    item.guardianNotified = false;
    item.action = "none";

    // Feature 7: Risk Event Storage
    // Save the final no-alert status for low-risk calls.
    await saveCallRecord(item);

    console.log("Risk below alert threshold. No SMS/email/disconnect.", {
      riskScore,
      ALERT_SCORE_THRESHOLD
    });
  }

  return {
    statusCode: 200,
    body: JSON.stringify({
      message: "SilentGuard event processed",
      userId,
      connectAgentLogin,
      contactId,
      riskScore,
      riskLevel,
      detectedSignals,
      shouldAlert,
      smsResult,
      emailResult,
      disconnected
    })
  };
};