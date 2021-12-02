[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2018-2021 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
### Troubleshooting Connection Issues

**Error - Could not generate an access token**

If you see this error be sure to synchronize the time on your Phantom host machine. Cylance uses a
time-based authorization and will deny API requests if the clock on your Splunk Phantom server has
drifted. For example, the following command can be used to update your system time:

sudo ntpdate -u ntp.ubuntu.com

### JWT

This app uses the python-jwt module, which is licensed under the MIT License, Copyright (c) 2015
José Padilla.  
PyJWT is a Python library which allows you to encode and decode JSON Web Tokens (JWT). JWT is an
open, industry-standard (RFC 7519) for representing claims securely between two parties.
