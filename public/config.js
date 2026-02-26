require("dotenv").config();

function required(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required env var: ${name}`);
  return v;
}

module.exports = {
  region: required("GENESYS_REGION"),
  clientId: required("GENESYS_CLIENT_ID"),
  redirectUri: required("REDIRECT_URI"),
  callNumber: required("CALL_NUMBER"),
  port: Number(process.env.PORT || 3000),
  cookieSecret: required("COOKIE_SECRET"),
};
