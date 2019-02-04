// Help function to generate an IAM policy
var generatePolicy = function(principalId, effect, resource, authData) {
  console.log(`principal id ${principalId}`);

  // Required output:
  var authResponse = {};
  authResponse.principalId = principalId;
  if (effect && resource) {
    var policyDocument = {};
    policyDocument.Version = "2012-10-17"; // default version
    policyDocument.Statement = [];
    var statementOne = {};
    statementOne.Action = "execute-api:Invoke"; // default action
    statementOne.Effect = effect;
    statementOne.Resource = resource;
    policyDocument.Statement[0] = statementOne;
    authResponse.policyDocument = policyDocument;
  }
  // Optional output with custom properties of the String, Number or Boolean type.
  authResponse.context = {
    userid: authData.id,
    usertype: authData.type
  };
  return authResponse;
};

var generateAllow = function(principalId, resource, authData) {
  return generatePolicy(principalId, "Allow", resource, authData);
};

var generateDeny = function(principalId, resource) {
  return generatePolicy(principalId, "Deny", resource);
};

const jwt = require("jsonwebtoken");
const variables = require("./variables");
exports.handler = function(event, context, callback) {
  console.log("Received event:", JSON.stringify(event, null, 2));

  // A simple REQUEST authorizer example to demonstrate how to use request
  // parameters to allow or deny a request. In this example, a request is
  // authorized if the client-supplied HeaderAuth1 header, QueryString1 query parameter,
  // stage variable of StageVar1 and the accountId in the request context all match
  // specified values of 'headerValue1', 'queryValue1', 'stageValue1', and
  // '123456789012', respectively.

  // Retrieve request parameters from the Lambda function input:
  var headers = event.headers;
  console.log("headers: \n", headers);

  const token = headers.Authorization;
  const tokenVerified = jwt.verify(token, variables.jwtSecret);
  console.log("verified token: ", tokenVerified);

  // var queryStringParameters = event.queryStringParameters;
  // var pathParameters = event.pathParameters;
  // var stageVariables = event.stageVariables;
  // var requestContext = event.requestContext;

  // Parse the input for the parameter values
  var tmp = event.methodArn.split(":");
  var apiGatewayArnTmp = tmp[5].split("/");
  // var awsAccountId = tmp[4];
  // var region = tmp[3];
  // var restApiId = apiGatewayArnTmp[0];
  var stage = apiGatewayArnTmp[1];
  // var method = apiGatewayArnTmp[2];
  var resource = "/"; // root resource
  if (apiGatewayArnTmp[3]) {
    resource += apiGatewayArnTmp[3];
  }
  console.log("stage: ", stage);
  console.log("resource: ", resource);

  // Perform authorization to return the Allow policy for correct parameters and
  // the 'Unauthorized' error, otherwise.
  var authResponse = {};
  var condition = {};
  condition.IpAddress = {};

  if (headers.Authorization !== "") {
    callback(
      null,
      generateAllow(
        `${tokenVerified.usertype}|${tokenVerified.userid}`,
        event.methodArn,
        tokenVerified
      )
    );
  } else {
    callback("Unauthorized");
  }
};
