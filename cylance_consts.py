# File: cylance_consts.py
# Copyright (c) 2018-2020 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
# --

CYLANCE_JSON_USERNAME = "username"
CYLANCE_JSON_PASSWORD = "password"
CYLANCE_JSON_REGION_CODE = "region_code"

CYLANCE_JSON_TENANT_ID = "tenant_id"
CYLANCE_JSON_APPLICATION_ID = "application_id"
CYLANCE_JSON_APPLICATION_SECRET = "application_secret"

CYLANCE_AUTH_TOKEN_ERR = "Could not generate an auth token"
CYLANCE_ACCESS_TOKEN_ERR = "Could not generate an access token"

CYLANCE_BLOCK_HASH_SUCC = "Successfully blocked hash"
CYLANCE_UNBLOCK_HASH_SUCC = "Successfully unblocked hash"
CYLANCE_BLOCK_HASH_ALREADY_BLOCKED_SUCC = "Hash is already blocked"
CYLANCE_UNBLOCK_HASH_ALREADY_UNBLOCKED_SUCC = "Hash is already unblocked"
CYLANCE_UPDATE_ZONE_SUCC = "Successfully updated zone"
CYLANCE_ERR_INVALID_PARAM = "Please provide non-zero positive integer in {param}"
CYLANCE_ERR_HOSTNAME_DOESNT_EXIST = "please check for hostname"

DEFAULT_MAX_RESULTS = 200
