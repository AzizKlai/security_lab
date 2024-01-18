# SecureNetAuth

### objective
This project aims to implement a robust security infrastructure with authentication via OpenLDAP, SSH, Apache, OpenVPN, and the integration of network services with DNS, as well as authentication with Kerberos. 

## content
### [Part 1: Authentication with OpenLDAP, SSH, Apache and OpenVPN](./document/security project.pdf)  
 Establish a secure authentication framework using OpenLDAP, SSH, Apache, and OpenVPN. Configure OpenLDAP, authenticate users with Apache and SSH, and integrate OpenVPN with OpenLDAP. Rigorously test to ensure effectiveness.
### [Part 2: Network Service Management with DNS](./documents/security project.pdf)  
 Efficiently manage network services by configuring a Bind DNS server for domain resolution associated with OpenLDAP, Apache, and OpenVPN. Thoroughly test and validate the DNS setup.
### [Part 3: Authentication with Kerberos](./documents/security project.pdf)  
 Introducing Kerberos authentication to enhance the security framework. We will install and configure a Kerberos server, adding principals and password policies for users. Additionally, we will choose a service to configure for Kerberos authentication.
## Technologies 

| Technology              | Description                                                                                                              |
|-------------------------|--------------------------------------------------------------------------------------------------------------------------|
| OpenLDAP  <div>  <img src="https://assets.zabbix.com/img/brands/openldap.png" alt="OpenLDAP Logo" height="80">  </div>              | Configured for user and group management, providing a centralized authentication source.  |
| SSH    <div>  <img src="https://upload.wikimedia.org/wikipedia/commons/0/00/Unofficial_SSH_Logo.svg" alt="SSH Logo" height="80">  </div>                 | Utilized for secure remote access with authentication linked to OpenLDAP.                  |
| Apache   <div>  <img src="https://cdn.icon-icons.com/icons2/2699/PNG/512/apache_logo_icon_168630.png" alt="Apache Logo" height="80">  </div>               | Configured with OpenLDAP authentication for secure web services.                   |
| OpenVPN   <div>  <img src="https://m.media-amazon.com/images/I/41CRKpBzyBL.png" alt="OpenVPN Logo" height="80">  </div>              | Implemented with OpenLDAP integration for secure virtual private network access.   |
| DNS     <div>  <img src="https://w7.pngwing.com/pngs/628/668/png-transparent-computer-icons-domain-name-system-share-icon-dns-sinkhole-computer-network-logo-share-icon-thumbnail.png" alt="DNS Logo" height="80">  </div>                | Used to resolve domain names associated with OpenLDAP, Apache, and OpenVPN servers.       |
| Kerberos  <div>  <img src="https://www.fortinet.com/content/fortinet-com/en_us/resources/cyberglossary/kerberos-authentication/_jcr_content/par/c05_container_copy_c/par/c28_image.img.jpg/1643741826059.jpg" alt="KERBEROS Logo" height="80">  </div>              | Installed and configured as an advanced authentication protocol.                 |


---
#### Authors : 
 [@AzizKlai](https://www.github.com/AzizKlai)   [@HeniYangui](https://www.github.com/hunyan-io)  [@FirasMiladi](https://github.com/miladifiras01)   [@SofienAzzabli](https://github.com/sofienazzabi2)
 
 

