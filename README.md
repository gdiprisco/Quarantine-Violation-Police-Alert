# Quarantine-Violation-Police-Alert
This project proposes a system to prevent violations of the quarantine during the SARS-CoV-2 pandemic. A citizen (infected or not) can be quarantined; this system helps the police authority in monitoring them during the isolation.
The system is based on the DP3T protocol and uses its infrastructure. Our idea adds some new information to DP3T in order to achieve the new goals trying not to violate the security and the privacy of DP3T.  

## The aim
The goal is preventing the violation quarantine without revealing the identity of the person (unless it is necessary to punish an illegal action). The aim is achieved adding to the data that the app backend of DP3T knows normally, some extra anonymous data. The only personal information is owned by a backend server belonging to a police authority and it is used only to punish a citizen that is not respecting the rules.  

## The hardware
A special BLE Beacon is installed in the house of the quarantined person (this detail will be discussed further) and it is established a continuous exchange of messages between the app backend and what we will call SmartBeacon. The smartphone is like a proxy in this context and needs to be near to the SmartBeacon in order to have a successful communication. The messages exchanged between the SmartBeacon and the smartphone and then between the smartphone and the app backend does not contain personal info. If the exchange is successful it is assumed that the person is respecting the quarantine; if something goes wrong, the police authority is informed and can decide what measure should be taken.  

## Privacy
The info used in the system are not owned by a unique actor in order to prevent an abuse of the data. The app backend only knows anonymous data (the identifier of the SmartBeacon and a seed associated to a person) and cannot derive some other information, especially sensitive data. The police authority backend server owns some personal info of the person that already knows in a normal situation (names and surnames, home addresses etc.).


## Details
All details and the instructions about how to run the code in Quarantine Violation Police Alert - White Paper.pdf
