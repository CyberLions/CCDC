## Setting up Splunk Universal Forwarders

https://youtu.be/rs6q28xUd-o?si=cni81Pj9h75v5qQs 

### Indexer 

Gui 

- After login, select forwarding and receiving (under DATA section) 

- Select “add new” next to configure receiving 

- Specify port it will listen on (ex 9997) 

CLI 

- `./splunk enable listen PORT#`

- Can also edit config file manually 

### Forwarder 

- Login to splunk and browse to universal forwarder download page 

- Download correct version or copy the wget command 

- In linux where splunk forwarder should go: 

    - Put in opt dir 

        - `sudo tar xvzf splunkforwarder-Linux-x86_64.tgz -C /opt` 

    - `cd /opt/splunkforwarder/bin` 

    - `./splunk start –accept-license` 

    - Setup admin account 

    - `sudo ./splunk enable boot-start –user splunker` 

    - Configure forwarder to send data to indexer 

        - `./splunk add forward-server INDEXIPADDRESS:LISTENINGPORT` 

        - Login with admiin account 

    - Tell it which data to send 

        - `./splunk add monitor –auth admin:password /opt/log/www1` 

            - Ex was for an apache web server 