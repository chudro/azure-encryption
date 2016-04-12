# Azure Encryption

This document provides details on the steps it takes to setup Encryption in DataStax Enterprise.  It provides instructions for:

1. Internode Encryption
1. Client to Cluster Encryption
1. Opscenter to Cluster Encryption

# Assumptions
The cluster that this document references is a 3 DC installation with 4 nodes in each DC. This is also assuming you are working with DSE 4.8.  This should be the same with all versions of 4.X.  

### Here are the instructions:
# Client/Node to Node Encryption

The starting point for setting up encryption will be Node to Node, followed by Client to Node. 

First, choose a node to setup the keystore and truststore that will be distributed to all of the nodes.  On that node, here are the steps to first setup the node, keystore and truststore.  All of this assumes you are running Ubuntu 14.04.

## Step 1 - Ubuntu and OpenSSL

Make sure you are running the proper Ubuntu and OpenSSL versions.  This is the case for both the nodes, and especially, Opscenter.

### 1. Determine Ubuntu OS:

```
# lsb_release -a
```
General Output:

```
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 14.04.3 LTS
Release:	14.04
Codename:	trusty
```

### 2. Determine OpenSSL version:

```
# python -c "import OpenSSL; print OpenSSL.__version__"
```

General Output:

0.13

To upgrade openssl to 0.15:

```
# sudo apt-get install python-pip
# sudo apt-get install libffi-dev
# sudo apt-get install build-essential libssl-dev libffi-dev python-dev
# sudo pip install --upgrade pyOpenSSL
# sudo pip -v list | grep pyOpen
```

## Step 2 - Create Keystore and Truststore

On the node that will be eventually used to identify the cluster when setting up Opscenter, run the following commands for each node as follows.  This assumes you have three DC’s (east_us, central_us, west_us), and 4 nodes in each (e.g. dc1vm0, dc1vm1, dc1vm2, dc1vm3, dc2vm0, etc.).  I placed this in a executable shell file.

The first key generation commands assume the following entries.  Please adjust to your needs:

* CN=<dcname>
* OU=<org unit name>
* O=<org name>
* C=<country>

Also, assuming the password is “cassandra”.

Perform this in the ssl directory, if you wish to create this directory.  There are also default settings that can be used. Then generate the keystore.

```
# mkdir /etc/dse/cassandra/ssl
# cd /etc/dse/cassandra/ssl

# keytool -genkey -keyalg RSA -alias dc1vm0 -keystore .keystore -storepass cassandra -keypass cassandra -dname "CN=dc1vm0, OU=SSL-verification-cluster, O=Datastax, C=US"
# keytool -genkey -keyalg RSA -alias dc1vm1 -keystore .keystore -storepass cassandra -keypass cassandra -dname "CN=dc1vm1, OU=SSL-verification-cluster, O=Microsoft, C=US"
# keytool -genkey -keyalg RSA -alias dc1vm2 -keystore .keystore -storepass cassandra -keypass cassandra -dname "CN=dc1vm2, OU=SSL-verification-cluster, O=Microsoft, C=US"
# keytool -genkey -keyalg RSA -alias dc1vm3 -keystore .keystore -storepass cassandra -keypass cassandra -dname "CN=dc1vm3, OU=SSL-verification-cluster, O=Microsoft, C=US"
# keytool -genkey -keyalg RSA -alias dc2vm0 -keystore .keystore -storepass cassandra -keypass cassandra -dname "CN=dc2vm0, OU=SSL-verification-cluster, O=Microsoft, C=US"
# keytool -genkey -keyalg RSA -alias dc2vm1 -keystore .keystore -storepass cassandra -keypass cassandra -dname "CN=dc2vm1, OU=SSL-verification-cluster, O=Microsoft, C=US"
# keytool -genkey -keyalg RSA -alias dc2vm2 -keystore .keystore -storepass cassandra -keypass cassandra -dname "CN=dc2vm2, OU=SSL-verification-cluster, O=Microsoft, C=US"
# keytool -genkey -keyalg RSA -alias dc2vm3 -keystore .keystore -storepass cassandra -keypass cassandra -dname "CN=dc2vm3, OU=SSL-verification-cluster, O=Microsoft, C=US"
# keytool -genkey -keyalg RSA -alias dc3vm0 -keystore .keystore -storepass cassandra -keypass cassandra -dname "CN=dc3vm0, OU=SSL-verification-cluster, O=Microsoft, C=US"
# keytool -genkey -keyalg RSA -alias dc3vm1 -keystore .keystore -storepass cassandra -keypass cassandra -dname "CN=dc3vm1, OU=SSL-verification-cluster, O=Microsoft, C=US"
# keytool -genkey -keyalg RSA -alias dc3vm2 -keystore .keystore -storepass cassandra -keypass cassandra -dname "CN=dc3vm2, OU=SSL-verification-cluster, O=Microsoft, C=US"
# keytool -genkey -keyalg RSA -alias dc3vm3 -keystore .keystore -storepass cassandra -keypass cassandra -dname "CN=dc3vm3, OU=SSL-verification-cluster, O=Microsoft, C=US"
```

Now create the certificate:

```
# keytool -export -alias dc1vm0 -file dc1vm0.cer -keystore .keystore -storepass cassandra -keypass cassandra
# keytool -export -alias dc1vm1 -file dc1vm1.cer -keystore .keystore -storepass cassandra -keypass cassandra
# keytool -export -alias dc1vm2 -file dc1vm2.cer -keystore .keystore -storepass cassandra -keypass cassandra
# keytool -export -alias dc1vm3 -file dc1vm3.cer -keystore .keystore -storepass cassandra -keypass cassandra
# keytool -export -alias dc2vm0 -file dc2vm0.cer -keystore .keystore -storepass cassandra -keypass cassandra
# keytool -export -alias dc2vm1 -file dc2vm1.cer -keystore .keystore -storepass cassandra -keypass cassandra
# keytool -export -alias dc2vm2 -file dc2vm2.cer -keystore .keystore -storepass cassandra -keypass cassandra
# keytool -export -alias dc2vm3 -file dc2vm3.cer -keystore .keystore -storepass cassandra -keypass cassandra
# keytool -export -alias dc3vm0 -file dc3vm0.cer -keystore .keystore -storepass cassandra -keypass cassandra
# keytool -export -alias dc3vm1 -file dc3vm1.cer -keystore .keystore -storepass cassandra -keypass cassandra
# keytool -export -alias dc3vm2 -file dc3vm2.cer -keystore .keystore -storepass cassandra -keypass cassandra
# keytool -export -alias dc3vm3 -file dc3vm3.cer -keystore .keystore -storepass cassandra -keypass cassandra
```

import certificate to truststore:

```
# keytool -import -v -trustcacerts -alias dc1vm0 -file dc1vm0.cer -keystore .truststore
# keytool -import -v -trustcacerts -alias dc1vm1 -file dc1vm1.cer -keystore .truststore
# keytool -import -v -trustcacerts -alias dc1vm2 -file dc1vm2.cer -keystore .truststore
# keytool -import -v -trustcacerts -alias dc1vm3 -file dc1vm3.cer -keystore .truststore
# keytool -import -v -trustcacerts -alias dc2vm0 -file dc2vm0.cer -keystore .truststore
# keytool -import -v -trustcacerts -alias dc2vm1 -file dc2vm1.cer -keystore .truststore
# keytool -import -v -trustcacerts -alias dc2vm2 -file dc2vm2.cer -keystore .truststore
# keytool -import -v -trustcacerts -alias dc2vm3 -file dc2vm3.cer -keystore .truststore
# keytool -import -v -trustcacerts -alias dc3vm0 -file dc3vm0.cer -keystore .truststore
# keytool -import -v -trustcacerts -alias dc3vm1 -file dc3vm1.cer -keystore .truststore
# keytool -import -v -trustcacerts -alias dc3vm2 -file dc3vm2.cer -keystore .truststore
# keytool -import -v -trustcacerts -alias dc3vm3 -file dc3vm3.cer -keystore .truststore
```

## Step 3 - Copy Keystore and Truststore to all nodes

Now, take the keystore and truststore and distribute to all nodes.

```
# scp .*store dse@dc1vm0:/etc/dse/cassandra/ssl
# scp .*store dse@dc1vm1:/etc/dse/cassandra/ssl
# scp .*store dse@dc1vm2:/etc/dse/cassandra/ssl
# scp .*store dse@dc1vm3:/etc/dse/cassandra/ssl
# scp .*store dse@dc2vm0:/etc/dse/cassandra/ssl
etc.
```

## Step 4 - Edit cassandra.yaml on all nodes

Modify the cassandra.yaml file to enable ssl certification. All modifications are in bold.

First modify the client encryption section as follows.  

```
client_encryption_options:
  enabled: true
  require_client_auth: true
  keystore: /etc/dse/cassandra/ssl/.keystore
  truststore: /etc/dse/cassandra/ssl/.truststore
  algorithm: SunX509
  cipher_suites: [TLS_RSA_WITH_AES_128_CBC_SHA]
  truststore_password: cassandra
  keystore_password: cassandra
  protocol: TLS
  store_type: JKS

server_encryption_options:
  require_client_auth: true
  keystore: /etc/dse/cassandra/ssl/.keystore
  internode_encryption: all
  truststore: /etc/dse/cassandra/ssl/.truststore
  algorithm: SunX509
  cipher_suites: [TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_256_CBC_SHA, TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA]
  truststore_password: cassandra
  keystore_password: cassandra
  protocol: TLS
  store_type: JKS  
```

## Step 5 - Restart DSE on all nodes

Restart DSE on all nodes, after DSE has been stopped:

```
# sudo dse cassandra restart
```

## Step 6 - Create Certificate and Key for Client to Node encryption

The following commands will create the required certificate and key on a node to allow access to the CQL CLI (cqlsh).

```
# cd /etc/dse/cassandra/ssl
# keytool -importkeystore -srckeystore .keystore -destkeystore dc1vm0.p12 -deststoretype PKCS12 -srcstorepass cassandra -deststorepass cassandra
# openssl pkcs12 -in dc1vm0.p12 -nokeys -out dc1vm0.cer.pem -passin pass:cassandra
# openssl pkcs12 -in dc1vm0.p12 -nodes -nocerts -out dc1vm0.key.pem -passin pass:cassandra
```

## Step 7 - Setup cqlshrc

Make sure there is a directory under your $HOME directory, called “.cassandra”.

```
# cd $HOME
# mkdir .cassandra
# cd ~/.cassandra
# vi cqlshrc
```

Enter the following into the file, then save it:

```
[connection]
hostname = dc1vm0vm.region.app.azure.com
port = 9042

[tracing]
max_trace_wait = 20.0

[ssl]
validate = false
userkey = /etc/dse/cassandra/ssl/dc1vm0.key.pem
usercert = /etc/dse/cassandra/ssl/dc1vm0.cer.pem
```


## Step 8 - Test cqlsh

To run cqlsh with ssl turned on:

```
# cqlsh --ssl 
```


# Opscenter to Cluster Encryption

## Step 1 - Setup opscenter key and certificate

First, setup the opscenter key and certificate on the node where you created the Keystore and Truststore.

```
# cd /etc/dse/cassandra/ssl
# keytool -importkeystore -srckeystore .keystore -destkeystore opscenter_user1.p12 -deststoretype PKCS12
# openssl pkcs12 -in opscenter_user1.p12 -out opscenter_user1.pem –nodes

# sudo keytool -genkey -alias opscenter -keyalg RSA -keystore opscenter.keystore
# sudo keytool -import -v -trustcacerts -alias dc1vm0 -file dc1vm0.cer -keystore opscenter.keystore
# sudo keytool -export -alias opscenter -file opscenter.cer -keystore opscenter.keystore
# sudo keytool -import -v -trustcacerts -alias opscenter -file opscenter.cer -keystore .truststore
# sudo keytool -importkeystore -srckeystore opscenter.keystore -destkeystore opscenter.p12 -deststoretype PKCS12 -srcalias opscenter -deststorepass cassandra -destkeypass cassandra
# sudo openssl pkcs12 -in opscenter.p12  -nokeys -out opscenter.pem
# sudo openssl pkcs12 -in opscenter.p12  -nodes -nocerts -out opscenter.key
```

Next, copy the resulting cert/key file to the Opscenter node:

```
# scp opscenter_user1.pem dse@10.0.1.5:/usr/share/opscenter/ssl
```

## Step 2 - Setup agentKeyStore and distribute

Now create the agentKeyStore that will be used by the agents on all nodes:

```
# cd /usr/share/opscenter
# bin/setup.py
```

The resulting files will be created in the /usr/share/opscenter/ssl directory.  Copy the agentKeyStore to all nodes as follows:

```
# cd /usr/share/opscenter/ssl
# scp agentKeyStore dse@10.1.1.5:/var/lib/datastax-agent/ssl/
# scp agentKeyStore dse@10.1.1.6:/var/lib/datastax-agent/ssl/
etc.
```

## Step 3 - Setup agents on all nodes

You now need to establish ssl for the agents on all of the nodes. Make sure to stop the agent right before or after you are done editing the file. Run these commands on each of the nodes:

```
# cd /var/lib/datastax-agent/conf
# vi address.yaml
```

Make the following modifications:

```
stomp_interface: 10.0.1.5
use_ssl: 1
ssl_keystore: /etc/dse/cassandra/ssl/.keystore
monitored_ssl_keystore: /etc/dse/cassandra/ssl/.keystore
ssl_keystore_password: cassandra
monitored_ssl_keystore_password: cassandra
```

## Step 4 - Setup Opscenter

Now, the <Cluster Name>.conf file must be setup.  If the cluster name (from the cassandra.yaml file on any of the nodes) is “Test Cluster”, then the name of the file should contain an underscore replacing the space.

```
# cd /etc/opscenter/clusters/
# vi Test_Cluster.conf
```

Add the following entries into the file:

```
[agent_config]
production = 1

[cassandra_metrics]
ignored_keyspaces = system, system_traces, system_auth, dse_auth

[agents]
api_port = 61621
backup_staging_dir = /tmp
ssl_keystore: /etc/dse/cassandra/ssl/.keystore
ssl_keystore_password: cassandra

[cassandra]
seed_hosts = 10.1.1.5
ssl_ca_certs: /usr/share/opscenter/ssl/opscenter_user1.pem
ssl_client_pem = /usr/share/opscenter/ssl/opscenter.pem
ssl_client_key = /usr/share/opscenter/ssl/opscenter.key
ssl_validate = True
```

## Step 5 - Start Opscenter

Now (re)start Opscenter:

```
# sudo service opscenterd start
```

--or--

```
# sudo service opscenterd restart
```

## Step 6 - Register the cluster in Opscenter

Finally, register the cluster to Opscenter:

Web Browser:
```
https://your.azure.opscenter.instance:8443/opscenter/login.html?timeout=1
login: admin
password: admin
```

Now go to SETTINGSCluster Connections

Her are the entries:

```
Enter at least one host / IP in the cluster (newline delimited)
10.1.1.5

JMX Port: 7199
Native Transport Port: 9042

Check the box for: Client to node encryption is enabled on my cluster

CA Certificate File Path: /usr/share/opscenter/ssl/opscenter_user1.pem

Keystore File Path: /etc/dse/cassandra/ssl/.keystore

Keystore Password: cassandra
```

Click on Save Cluster.



NOTES

The following are notable items to check out:

https://support.datastax.com/hc/en-us/articles/204226129-Receiving-error-Caused-by-java-lang-IllegalArgumentException-Cannot-support-TLS-RSA-WITH-AES-256-CBC-SHA-with-currently-installed-providers-on-DSE-startup-after-setting-up-client-to-node-encryption

http://docs.datastax.com/en/opscenter/5.2/opsc/configure/opscEnableSSLpkg.html

http://docs.datastax.com/en/cassandra/2.1/cassandra/security/secureSSLCertificates_t.html
