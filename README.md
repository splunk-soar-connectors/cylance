[comment]: # "Auto-generated SOAR connector documentation"
# CylancePROTECT

Publisher: Splunk  
Connector Version: 2\.0\.2  
Product Vendor: Cylance  
Product Name: CylancePROTECT  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.9\.39220  

This app supports the various investigative, containment, and corrective actions on CylancePROTECT

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


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a CylancePROTECT asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**tenant\_id** |  required  | string | Tenant unique identifier
**application\_id** |  required  | string | Application unique identifier
**application\_secret** |  required  | password | Application secret to sign the auth token with
**region\_code** |  required  | string | Location where your organization's servers belong

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using the supplied configuration  
[list endpoints](#action-list-endpoints) - List all the endpoints/sensors configured on the device  
[list threats](#action-list-threats) - Get a list of threats on the specific device  
[get system info](#action-get-system-info) - Get information about an endpoint  
[hunt file](#action-hunt-file) - Hunt a file on the network using the hash  
[get global list](#action-get-global-list) - Retrieve the hashes for the given type of list  
[unblock hash](#action-unblock-hash) - Unblock a file hash  
[block hash](#action-block-hash) - Block a file hash  
[get file](#action-get-file) - Download a file to the vault  
[get file info](#action-get-file-info) - Get information about a file  
[update zone](#action-update-zone) - Update the details of a zone  
[list policies](#action-list-policies) - Get a list of tenant policies  
[list zones](#action-list-zones) - Get a list of tenant zones  

## action: 'test connectivity'
Validate the asset configuration for connectivity using the supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'list endpoints'
List all the endpoints/sensors configured on the device

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** |  optional  | Number of results to fetch | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.data\.\*\.agent\_version | string | 
action\_result\.data\.\*\.date\_first\_registered | string | 
action\_result\.data\.\*\.date\_offline | string | 
action\_result\.data\.\*\.id | string |  `cylance device id` 
action\_result\.data\.\*\.ip\_addresses | string |  `ip` 
action\_result\.data\.\*\.mac\_addresses | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.os\_kernel\_version | string | 
action\_result\.data\.\*\.policy\.id | string |  `cylance policy id` 
action\_result\.data\.\*\.policy\.name | string | 
action\_result\.data\.\*\.products\.\*\.name | string | 
action\_result\.data\.\*\.products\.\*\.status | string | 
action\_result\.data\.\*\.products\.\*\.version | string | 
action\_result\.data\.\*\.state | string | 
action\_result\.summary\.num\_endpoints | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list threats'
Get a list of threats on the specific device

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**unique\_device\_id** |  required  | ID of the device to fetch threats | string |  `cylance device id` 
**limit** |  optional  | Number of results to fetch | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.unique\_device\_id | string |  `cylance device id` 
action\_result\.data\.\*\.classification | string | 
action\_result\.data\.\*\.cylance\_score | numeric | 
action\_result\.data\.\*\.date\_found | string | 
action\_result\.data\.\*\.file\_path | string |  `file name` 
action\_result\.data\.\*\.file\_status | string | 
action\_result\.data\.\*\.name | string |  `file name` 
action\_result\.data\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.sub\_classification | string | 
action\_result\.summary\.num\_threats | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get system info'
Get information about an endpoint

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**unique\_device\_id** |  required  | ID of the device to get info | string |  `cylance device id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.unique\_device\_id | string |  `cylance device id` 
action\_result\.data\.\*\.agent\_version | string | 
action\_result\.data\.\*\.background\_detection | boolean | 
action\_result\.data\.\*\.date\_first\_registered | string | 
action\_result\.data\.\*\.date\_last\_modified | string | 
action\_result\.data\.\*\.date\_offline | string | 
action\_result\.data\.\*\.distinguished\_name | string | 
action\_result\.data\.\*\.host\_name | string | 
action\_result\.data\.\*\.id | string |  `cylance device id` 
action\_result\.data\.\*\.ip\_addresses | string |  `ip` 
action\_result\.data\.\*\.is\_safe | boolean | 
action\_result\.data\.\*\.last\_logged\_in\_user | string | 
action\_result\.data\.\*\.mac\_addresses | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.os\_kernel\_version | string | 
action\_result\.data\.\*\.os\_version | string | 
action\_result\.data\.\*\.policy\.id | string |  `cylance policy id` 
action\_result\.data\.\*\.policy\.name | string | 
action\_result\.data\.\*\.products\.\*\.name | string | 
action\_result\.data\.\*\.products\.\*\.status | string | 
action\_result\.data\.\*\.products\.\*\.version | string | 
action\_result\.data\.\*\.state | string | 
action\_result\.data\.\*\.update\_available | boolean | 
action\_result\.data\.\*\.update\_type | string | 
action\_result\.summary\.id | string |  `cylance device id` 
action\_result\.summary\.is\_safe | boolean | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'hunt file'
Hunt a file on the network using the hash

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | SHA256 hash of the file to hunt | string |  `sha256` 
**limit** |  optional  | Number of results to fetch | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.hash | string |  `sha256` 
action\_result\.parameter\.limit | numeric | 
action\_result\.data\.\*\.agent\_version | string | 
action\_result\.data\.\*\.date\_found | string | 
action\_result\.data\.\*\.file\_path | string | 
action\_result\.data\.\*\.file\_status | string | 
action\_result\.data\.\*\.id | string |  `cylance device id` 
action\_result\.data\.\*\.ip\_addresses | string |  `ip` 
action\_result\.data\.\*\.mac\_addresses | string |  `mac address` 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.policy\_id | string |  `cylance policy id` 
action\_result\.data\.\*\.state | string | 
action\_result\.summary\.num\_items | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get global list'
Retrieve the hashes for the given type of list

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**list\_type\_id** |  required  | List type of which the threat belongs to | string | 
**limit** |  optional  | Number of results to fetch | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.list\_type\_id | string | 
action\_result\.data\.\*\.added | string | 
action\_result\.data\.\*\.added\_by | string | 
action\_result\.data\.\*\.av\_industry | string | 
action\_result\.data\.\*\.category | string | 
action\_result\.data\.\*\.classification | string | 
action\_result\.data\.\*\.cylance\_score | numeric | 
action\_result\.data\.\*\.list\_type | string | 
action\_result\.data\.\*\.md5 | string |  `md5` 
action\_result\.data\.\*\.name | string |  `file name` 
action\_result\.data\.\*\.reason | string | 
action\_result\.data\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.sub\_classification | string | 
action\_result\.summary\.num\_items | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'unblock hash'
Unblock a file hash

Type: **correct**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | SHA256 hash for the threat | string |  `sha256` 
**list\_type** |  required  | List type to which the threat belongs | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.hash | string |  `sha256` 
action\_result\.parameter\.list\_type | string | 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'block hash'
Block a file hash

Type: **contain**  
Read only: **False**

Action parameter 'category' is required only if the list\_type value is GlobalSafe\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | SHA256 hash for the threat | string |  `sha256` 
**reason** |  required  | Reason why the file was added to the list | string | 
**list\_type** |  required  | List type to which the threat belongs | string | 
**category** |  optional  | Category for GlobalSafe list type | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.category | string | 
action\_result\.parameter\.hash | string |  `sha256` 
action\_result\.parameter\.list\_type | string | 
action\_result\.parameter\.reason | string | 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get file'
Download a file to the vault

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | SHA256 hash of file to download | string |  `sha256` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.hash | string |  `sha256` 
action\_result\.data | string | 
action\_result\.summary\.name | string |  `sha256` 
action\_result\.summary\.size | numeric | 
action\_result\.summary\.vault\_id | string |  `sha1`  `vault id` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get file info'
Get information about a file

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | SHA256 hash of file | string |  `sha256` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.hash | string |  `sha256` 
action\_result\.data\.\*\.auto\_run | boolean | 
action\_result\.data\.\*\.av\_industry | string | 
action\_result\.data\.\*\.cert\_issuer | string | 
action\_result\.data\.\*\.cert\_publisher | string | 
action\_result\.data\.\*\.cert\_timestamp | string | 
action\_result\.data\.\*\.classification | string | 
action\_result\.data\.\*\.cylance\_score | numeric | 
action\_result\.data\.\*\.detected\_by | string | 
action\_result\.data\.\*\.file\_size | numeric | 
action\_result\.data\.\*\.global\_quarantined | boolean | 
action\_result\.data\.\*\.md5 | string |  `md5` 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.running | boolean | 
action\_result\.data\.\*\.safelisted | boolean | 
action\_result\.data\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.signed | boolean | 
action\_result\.data\.\*\.sub\_classification | string | 
action\_result\.data\.\*\.unique\_to\_cylance | boolean | 
action\_result\.summary\.classification | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update zone'
Update the details of a zone

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**unique\_zone\_id** |  required  | Zone ID to update info of | string |  `cylance zone id` 
**name** |  required  | Name of the zone to be updated | string |  `cylance zone name` 
**policy\_id** |  required  | Unique ID of the policy to be assigned to the zone | string |  `cylance policy id` 
**criticality** |  required  | Criticality of the zone to be updated | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.criticality | string | 
action\_result\.parameter\.name | string |  `cylance zone name` 
action\_result\.parameter\.policy\_id | string |  `cylance policy id` 
action\_result\.parameter\.unique\_zone\_id | string |  `cylance zone id` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list policies'
Get a list of tenant policies

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** |  optional  | Number of results to fetch | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.data\.\*\.date\_added | string | 
action\_result\.data\.\*\.date\_modified | string | 
action\_result\.data\.\*\.device\_count | numeric | 
action\_result\.data\.\*\.id | string |  `cylance policy id` 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.zone\_count | numeric | 
action\_result\.summary\.num\_policies | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list zones'
Get a list of tenant zones

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** |  optional  | Number of results to fetch | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.data\.\*\.criticality | string | 
action\_result\.data\.\*\.date\_created | string | 
action\_result\.data\.\*\.date\_modified | string | 
action\_result\.data\.\*\.id | string |  `cylance zone id` 
action\_result\.data\.\*\.name | string |  `cylance zone name` 
action\_result\.data\.\*\.policy\_id | string |  `cylance policy id` 
action\_result\.data\.\*\.update\_type | string | 
action\_result\.data\.\*\.zone\_rule\_id | string | 
action\_result\.summary\.num\_zones | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 