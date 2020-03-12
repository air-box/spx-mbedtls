#################
AirBox Components
#################

When you use AirBox, regardless of whether the cloud or the edge where your application is deployed is compromised or not, you get complete security gurantees for your AirBox-inside app. 

AirBox-inside app has superior security and at the same time, a minimal impact of performance (latency, scalability) compared to any existing confidential computing solution.

This document outlines the various components you need to have a complete and working AirBox-inside app.

Here is the diagram of an AirBox inside-app with all components tied together.


Creating an AirBox-inside app
#############################

An AirBox-inside app typically takes a form of one or more containers deployed in the cloud or at the edge, but is not limited to it. AirBox can support any virtualization and any infrastructure as long as it provides TEE support in the processors like Intel SGX, ARM TrustZone, AMD SEV, etc.

To create AirBox-inside app, you can use AirBox SDK (for new apps), AirBox runtime (for unmodified existing apps).

* AirBox SDK is a set of libraries and APIs that developers can easily use in the applications.
	- AirBox ETX: Execution extensions that get embedded in app containers which then, automatically remotely attests itself at every launch.
	- AirBox STX: Storage extensions that the app container(s) use to store or access any secure state in untrusted storage.
	- AirBox SPX: Secure protocol extensions that get embedded in standard end to end encryption protocol libraries used in the app container(s) to secure its communication over the Internet.

* AirBox runtime is a set of containers the provide a complete OS ABI to run unmodified apps.
	- Uses all the secure extensions underneath its hood.
	- Supports complete or debloated set of ABI for smaller footprint.

* AirBox backend is a security orchestrator service for AirBox inside apps. 
	- gets deployed alongside the app in the cloud, edge, on-prem or at AirBox cloud
	- houses credentials for all AirBox extensions
	- implements a security dashboard to provide easy access & insights from fine-grained security monitoring data for AirBox-inside apps


Optimizing AirBox-inside app
############################

The two conflicting goals in optimizing an AirBox-inside app: security and performance. 

To help, AirBox has developed a unique approach and tool (mander) that help them choose appropriate portions of app to run using AirBox.

Mander analyzes your app, your workload characteristics, your security and performance requirements. 

It then creates multiple partitions of your app that run inside and outside TEE in form of a list of different options and associated trade-offs.

Trade-off are in simple to understand metrics such as security, performance ratios and cost ratios (changes in the code). 

AirBox being designed at low level provides full flexibility to run any of those partitions in form of customized AirBox SDK or runtime or a combination of both.

##########
AirBox API
##########

Here we list core set of low level AirBox extension APIs that affords AirBox its flexibility, security and low overhead on performance. 

Typically this would be too low-level for most cloud, edge app developers. However, it abstracts all the TEE-specific complexity and easese system level integration of AirBox extensions in to standard libraries, tools and workflows that developers are accustomed to use e.g., Docker containers, sealed volumes, OpenSSL, etc.



Both AirBox SDK, AirBox runtime and AirBox backend use this common set of APIs.


Core API
########

* Execution extension API 
	- The low level C API that abstracts handling of TEE-specific attestation qoute handling for applications explicitly in code or sideloaded into a container.

.. code-block:: C

   abx_status abx_etx_attest(char* qoute)
   abx_status abx_etx_check(char* qoute)

* Sealed storage extension API 
	- The low level C API that abstracts storage operations from TEE-specific sealing key use to store/access content using another data store interface or file system.

.. code-block:: C

   abx_status abx_efx_get(char *key, char *value)
   abx_status abx_efx_put(char *key, int key_len, char *value, int *value_len)
   abx_status abx_efx_getkeys(char* keys, int key_length)

* Secure protocol extension API 
	- The low level C API that abstracts handling of protocol-agnostic functions needed to integrated attestation in a end to end encryption protocol like TLS.

.. code-block:: C

   abx_status abx_spx_detect(char *msg)
   abx_status abx_spx_relay(char *msg, session_id)
   abx_status abx_spx_bind(char* ephemeral_key, session_id)
   abx_status abx_spx_forward(char *msg, session_id)
   abx_status abx_spx_resume(char* state)
   abx_status abx_spx_grant(char *session_id)

Example Workflow
################


