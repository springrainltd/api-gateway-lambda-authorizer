const apiServiceUrl = process.env.API_SERVICE_URL;
const jwtSecret = {
  dev: process.env.JWT_SECRET_KEY_DEV,
  tst: process.env.JWT_SECRET_KEY_TST,
  prd: process.env.JWT_SECRET_KEY_PRD
};
module.exports = {
  apiServiceUrl,
  jwtSecret
};
