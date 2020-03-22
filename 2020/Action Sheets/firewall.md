### Action sheet for the edge firewall
PAN-OS 8.0 admin guide: https://docs.paloaltonetworks.com/content/dam/techdocs/en_US/pdf/pan-os/8-0/pan-os-admin/pan-os-admin.pdf

*IMPORTANT*: PaloAlto is like Juniper. Don't forget to `commit` after making changes!

* Remove extra admins
* Disable management from external network
* Disable HTTP and Telnet
* Enable security on all zones
* EXPORT FIREWALL CONFIG

* Check for admin accounts, change passwords!
    * `show mgt-config users`, `delete mgt-config users <user>`, `set mgt-config users <user> password`
* Check security policies
    * `show running security-policy`
    * Docs: https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000ClaCCAS
* Check port forwarding rules
    * `show running nat-policy`

#### Nice-to-know references

* Creating DNAT'd service: https://docs.paloaltonetworks.com/pan-os/8-1/pan-os-admin/networking/nat/nat-configuration-examples/destination-nat-with-port-translation-example
