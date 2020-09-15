# multi-tor-evalution
Evaluate replica selection under multi-tor setup on AWS

# Environment setup

## DPDK installation in local and AWS settings

### Local setup

#### MLNX_OFED driver
OFED driver is the prerequisite of DPDK installtion as we rely on mlx5 pmd driver for DPDK. 

```
sudo su
wget http://www.mellanox.com/downloads/ofed/MLNX_OFED-5.0-2.1.8.0/MLNX_OFED_LINUX-5.0-2.1.8.0-ubuntu18.04-x86_64.tgz .
tar -xvf MLNX_OFED_LINUX-5.0-2.1.8.0-ubuntu18.04-x86_64.tgz
sudo ./mlnxofedinstall --upstream-libs
/etc/init.d/openibd restart
```

#### DPDK download and instllation
We borrowed a script from BESS project and have our own strip-off version keeping functions we need.

```  
python build.py
```

#### Environment setup
```
sh dpdk_setup_local.sh
```

### AWS setup

#### DPDK download and instllation
We borrowed a script from BESS project and have our own strip-off version keeping functions we need.

```  
python build.py
```
#### Environment setup
```
sh dpdk_setup_aws.sh
```