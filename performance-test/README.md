
### Contains
* This folder contains performance Test script of below API endpoint categories.
    01. Create Identities in MOSIP Identity System (Setup)
    02. S03 User downloads MOSIP National ID credential (Preparation)
    03. S01 User accessing Inji Web portal landing page (Execution)
	04. S02 User choosing an issuer and landing on credential types screen (Execution)
	05. S03 User downloads MOSIP National ID credential (Execution)

* Open source Tools used,
    1. [Apache JMeter](https://jmeter.apache.org/)

### How to run performance scripts using Apache JMeter tool
* Download Apache JMeter from https://jmeter.apache.org/download_jmeter.cgi
* Download scripts for the required module.
* Start JMeter by running the jmeter.bat file for Windows or jmeter file for Unix. 
* Validate the scripts for one user.
* Execute a dry run for 10 min.
* Execute performance run with various loads in order to achieve targeted NFR's.

### Setup points for Execution

* We need some jar files which needs to be added in lib folder of jmeter, PFA dependency links for your reference : 

   * jmeter-plugins-manager-1.10.jar
      *<!-- https://mvnrepository.com/artifact/kg.apc/jmeter-plugins-manager -->
<dependency>
    <groupId>kg.apc</groupId>
    <artifactId>jmeter-plugins-manager</artifactId>
    <version>1.10</version>
</dependency>

   * jmeter-plugins-synthesis-2.2.jar
      * <!-- https://mvnrepository.com/artifact/kg.apc/jmeter-plugins-synthesis -->
<dependency>
    <groupId>kg.apc</groupId>
    <artifactId>jmeter-plugins-synthesis</artifactId>
    <version>2.2</version>
</dependency>


* eSignet-default properties: Update the value for the properties according to the execution setup. Perform the execution for eSignet api's with redis setup. So check for the redis setup accordingly. 
	
	* Enabling redis cache of eSignet application.
		*spring.cache.type=redis
		*spring.redis.host=redis-master-0.redis-headless.redis.svc.cluster.local
		*spring.redis.port=6379
		*management.health.redis.enabled=false
	
	* Increasing the expire time to 24 hours for field mosip.esignet.cache.expire-in-seconds
		*'clientdetails' : 86400
		*'authcodegenerated': 86400
		*'authtokens': 86400
		
* id-authentication-default.properties: Update the value for the properties according to the execution setup. 	
		*mosip.ida.kyc.token.expire.time.adjustment.seconds=86400

### Execution points for eSignet Authentication API's

*InjiWeb_Test_Script.jmx
	
	* Create Identities in MOSIP Identity System (Setup) : This thread contains the authorization api's for regproc and idrepo from which the auth token will be generated. There is set of 4 api's generate RID, generate UIN, add identity and add VID. From here we will get the VID which can be further used as individual id. These 4 api's are present in the loop controller where we can define the number of samples for creating identities in which "addIdentitySetup" is used as a variable. 
	
	* S03 User downloads MOSIP National ID credential (Preparation) : This thread generates authcode-token for the download of National ID department PDF. The number of testdata created is depended upon the TPS planned for test execution. The testdata created is non-reusable and expires after 24 hours.
	  
	  *Procedure to calculate number of authcodegenerated token values.
		* Considering load of 100 TPS volume : As per the request page, 40% Load will be consumed by User downloads MOSIP National ID credential Scenario which is equivalent to 40 TPS. 
		* User downloads MOSIP National ID credential Scenario consists following 5 endpoints.
			*/issuers
			*/issuers/<issuerId>
			*/issuers/<issuerId>/credentialTypes
			*/get-token/<issuerid>
			*/issuers/<issuerId>/credential/download
		* Each point url will consume 8 TPS ( 40 TPS / 5 requests).
		* If we are executing test only for one hour then number of testdata will be as follows
			* Total Number of testdata = TPS value X 3600(number of seconds in one hour)
									   = 8 X 3600
								       = 28800
		* After calculating number of testdata. provide random number of threads in threadgroup (Assuming thread numbers equal to 4 for the sake of calculation),  calculate number of iterations as follows
			* Number of iterations = Total testdata required / Number of users
								   = 28800 / 4
								   = 7200
			
	* S01 User accessing Inji Web portal landing page (Execution) :
		* S01 T01 Issuers : This thread executes issuer endpoint.
		
	* S02 User choosing an issuer and landing on credential types screen (Execution):
		* S02 T01 Issuers : This thread executes issuer endpoint.
		* S02 T02 Issuer Id : This thread executes eSignet issuer endpoint.
		* S02 T03 Credential Types : This thread executes credential type endpoint.
	
	* S03 User downloads MOSIP National ID credential (Execution):
		* S03 T01 Issuers : This thread executes issuer endpoint.
		* S03 T02 Issuer Id : This thread executes eSignet issuer endpoint.
		* S03 T03 Credential Types : This thread executes credential type endpoint.
		* S03 T04 Get Token : This thread connects to eSignet /token endpoint with the authorization code.
		* S03 T05 Download File : This thread downloads National ID department PDF file.
 	
### Downloading Plugin manager jar file for the purpose installing other JMeter specific plugins

* Download JMeter plugin manager from below url links.
	*https://jmeter-plugins.org/get/

* After downloading the jar file place it in below folder path.
	*lib/ext

* Please refer to following link to download JMeter jars.
	https://mosip.atlassian.net/wiki/spaces/PT/pages/1227751491/Steps+to+set+up+the+local+system#PluginManager
		
### Designing the workload model for performance test execution
* Calculation of number of users depending on Transactions per second (TPS) provided by client

* Applying little's law
	* Users = TPS * (SLA of transaction + think time + pacing)
	* TPS --> Transaction per second.
	
* For the realistic approach we can keep (Think time + Pacing) = 1 second for API testing
	* Calculating number of users for 10 TPS
		* Users= 10 X (SLA of transaction + 1)
		       = 10 X (1 + 1)
			   = 20
			   
### Usage of Constant Throughput timer to control Hits/sec from JMeter
* In order to control hits/ minute in JMeter, it is better to use Timer called Constant Throughput Timer.

* If we are performing load test with 10TPS as hits / sec in one thread group. Then we need to provide value hits / minute as in Constant Throughput Timer
	* Value = 10 X 60
			= 600

* Dropdown option in Constant Throughput Timer
	* Calculate Throughput based on as = All active threads in current thread group
		* If we are performing load test with 10TPS as hits / sec in one thread group. Then we need to provide value hits / minute as in Constant Throughput Timer
	 			Value = 10 X 60
					  = 600
		  
	* Calculate Throughput based on as = this thread
		* If we are performing scalability testing we need to calculate throughput for 10 TPS as 
          Value = (10 * 60 )/(Number of users)
