local state_to_authorization = "state_to_authorization:"
local code_to_authorization = "code_to_authorization:"
local access_to_authorization = "access_to_authorization:"
local refresh_to_authorization = "refresh_to_authorization:"

local id_to_authorization = KEYS[1]
local id_to_correlations = KEYS[2]

local authorization = ARGV[1]
local authorization_id = ARGV[2]
local stateTtl = tonumber(ARGV[3])
local codeTtl = tonumber(ARGV[4])
local accessTokenTtl = tonumber(ARGV[5])
local refreshTokenTtl = tonumber(ARGV[6])
local authorizationTtl = tonumber(ARGV[7])
local correlationsTtl = tonumber(ARGV[8])

local function setCorrelationKeys(key)
  if string.find(key, state_to_authorization, 1) ~= nil then
    redis.call("setex", key, stateTtl, authorization_id)
    redis.call("sadd", id_to_correlations, key)
    redis.log(redis.LOG_WARNING, "set state_to_authorization" .. key)
  end
  if string.find(key, code_to_authorization, 1) ~= nil then
    redis.call("setex", key, codeTtl, authorization_id)
    redis.call("sadd", id_to_correlations, key)
    redis.log(redis.LOG_WARNING, "set code_to_authorization" .. key)
  end
  if string.find(key, access_to_authorization, 1) ~= nil then
    redis.call("setex", key, accessTokenTtl, authorization_id)
    redis.call("sadd", id_to_correlations, key)
    redis.log(redis.LOG_WARNING, "set access_to_authorization" .. key)
  end
  if string.find(key, refresh_to_authorization, 1) ~= nil then
    redis.call("setex", key, refreshTokenTtl, authorization_id)
    redis.call("sadd", id_to_correlations, key)
    redis.log(redis.LOG_WARNING, "set refresh_to_authorization" .. key)
  end
end

redis.call("setex", id_to_authorization, authorizationTtl, authorization)

for k, v in pairs(KEYS) do
  setCorrelationKeys(v)
end

redis.call("expire", id_to_correlations, correlationsTtl)