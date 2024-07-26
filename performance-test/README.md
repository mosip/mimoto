
### Contains
* This folder contains performance Test script of below API endpoint categories.
    01. Create Identities in MOSIP Authentication System (Setup)
    02. S01 User accessing Inji Web portal landing page (Execution)
    03. S02 User choosing an issuer and landing on credential types screen (Execution)
	04. S03 User downloads MOSIP National ID credential (Preparation)
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


### Execution points for eSignet Authentication API's

*InjiWeb_Test_Script.jmx.jmx
	
	* Create Identities in MOSIP Authentication System (Setup) : This thread contains the authorization api's for regproc and idrepo from which the auth token will be generated. There is set of 4 api's generate RID, generate UIN, add identity and add VID. From here we will get the VID which can be further used as individual id. These 4 api's are present in the loop controller where we can define the number of samples for creating identities in which "addIdentitySetup" is used as a variable. 
	
	* S01 User accessing Inji Web portal landing page (Execution) :
		* S01 T01 Issuers : This thread executes issuer endpoint.
		
	* S02 User choosing an issuer and landing on credential types screen (Execution):
		* S02 T01 Issuers : This thread executes issuer endpoint.
		* S02 T02 Issuer Id : This thread executes eSignet issuer endpoint.
		* S02 T03 Credential Types : This thread executes credential type endpoint.
		
	* S03 User downloads MOSIP National ID credential (Preparation) : This thread generates authcode-token for the download of National ID department PDF.
	
	* S03 User downloads MOSIP National ID credential (Execution):
		* S03 T01 Issuers : This thread executes issuer endpoint.
		* S03 T02 Issuer Id : This thread executes eSignet issuer endpoint.
		* S03 T03 Credential Types : This thread executes credential type endpoint.
		* S03 T09 Get Token : This thread fetches token from eSignet cache and generates access token.
		* S03 T10 Download File : This thread downloads National ID department PDF file.
 	
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