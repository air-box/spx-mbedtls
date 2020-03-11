*****************
AirBox Components
*****************

This document provides a high level technical overview of the security problems and AirBox’s solution approach that is fit for cloud and edge 

Terminology:
############

Cloud/Edge apps: The application deployed in the cloud or at the edge. Typically, in form of containers which intends to use AirBox. These apps include the AirBox security extension modules. 

Developers: Individuals or teams who are developing cloud apps. These folks are intended users of AirBox SDK to integrate into their MEC apps. 

DevSecOps: Individuals or teams responsible to deploy those cloud apps while ensuring their security. These folks are intended user of AirBox service.

End User: End users are the end consumers/customers of the cloud apps. They are the folks who get impacted due to performance overheads or face difficulty complex security . 

AirBox SDK: 

AirBox Service: AirBox service is the part of AirBox offerings which runs at the same cloud or edge infrastructure (for performance) but cloud reside elsewhere (for better security). Sometimes, it may become part of cloud app (as component of a pod deployment model in kubernetes or in case of on-premise AirBox deployment) or is a stand-alone service (if using AirBox operated subscription service).




