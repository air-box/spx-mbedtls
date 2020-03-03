******************************
Problem w/ existing approaches
******************************

The problem with existing confidential computing solutions is that they are so much focussed on data in use protection that their design leaves a critical hole that compromises its core value i.e., protection from adversary with root previleges. 

The core reason for the design flaw stems from their assumption that data at rest and data in motion is guaranteed to be protected using existing solutions (like disk encryption) and protocols (like end to end encryption using TLS) which is simply not true. With the threat model addressed in confidential computing, those gurantees are not sound because the design of those solutions make trust related assumptions. 

For example, TLS is guaranteed to be end to end secure only and only if ends are guaranteed to be secure. TLS grantees are hinged on the binding created between end hosts and a network connection between them over which only data encrypted with negotiated keys is sent after integrity and authenticity of ends is established using CA certificates. However, in confidential computing the security of end host relies on the hardware TEE (typically unenforceable evidence used in remote attestation) where as TLS still relies on CA certificates. There is NO SECURE BINDING between TLS & TEE.

This exposes a critical flow as an advanced adversary can easily compromise a communication channel being established between a TEE and end users or cloud/edge users through privileged man in the middle attacks like TOCTTU and Cuckoo. Thus, exposing the encrypted data sent/received over connection at the very lease. This alone exposes all end user and cloud/edge user credentials which then can easily lead to other attacks. In fact, it becomes easily possible to impersonate and leaking of private key material and encrypted data storage. 

