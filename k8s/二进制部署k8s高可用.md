[TOC]

## 一、前置知识点

### 1、生产环境可部署Kubernetes集群的两种方式

目前生产部署Kubernetes集群主要有两种方式：

- kubeadm

Kubeadm是一个K8s部署工具，提供kubeadm init和kubeadm join，用于快速部署Kubernetes集群。

官方地址：https://kubernetes.io/docs/reference/setup-tools/kubeadm/kubeadm/

- 二进制包

从github下载发行版的二进制包，手动部署每个组件，组成Kubernetes集群。

Kubeadm降低部署门槛，但屏蔽了很多细节，遇到问题很难排查。如果想更容易可控，推荐使用二进制包部署Kubernetes集群，虽然手动部署麻烦点，期间可以学习很多工作原理，也利于后期维护。

### 2、安装要求

在开始之前，部署Kubernetes集群机器需要满足以下几个条件：

- 一台或多台机器，操作系统 CentOS7.x-86_x64
- 硬件配置：2GB或更多RAM，2个CPU或更多CPU，硬盘30GB或更多
- 集群中所有机器之间网络互通
- 可以访问外网，需要拉取镜像，如果服务器不能上网，需要提前下载镜像并导入节点
- 禁止swap分区

### 3、 准备环境

软件环境：

| 软件       | 版本      |
| ---------- | --------- |
| system     | centos7.7 |
| docker     | 19-ce     |
| kubernetes | 1.18      |

服务部署规划：

|    角色     | ip                              |                             组件                             | hostname    |
| :---------: | :------------------------------ | :----------------------------------------------------------: | ----------- |
| k8s-master1 | 172.16.2.231                    | kube-apiserver，kube-controller-manager，kube-scheduler，etcd | k8s-master1 |
| k8s-master2 | 172.16.2.232                    | kube-apiserver，kube-controller-manager，kube-scheduler，etcd | k8s-master2 |
| k8s-master3 | 172.16.2.233                    | kube-apiserver，kube-controller-manager，kube-scheduler，etcd | k8s-master3 |
|  k8s-node1  | 172.16.2.237                    |                 kubelet，kube-proxy，docker                  | k8s-node1   |
|  k8s-node2  | 172.16.2.238                    |                 kubelet，kube-proxy，docker                  | k8s-node2   |
| LB(master)  | 172.16.2.234，172.16.2.230(VIP) |                           nginx L4                           |             |
| LB(backup)  | 172.16.2.235                    |                           nginx L4                           |             |

### 4、 操作系统初始化配置

```shell
# 修改主机名
hostnamectl set-hostname <hostname>

#关闭selinux
setenforce 0  # 临时
sed -i 's/enforcing/disabled/' /etc/selinux/config  # 永久

# 关闭防火墙
systemctl stop firewalld
systemctl disable firewalld

# 关闭swap
swapoff -a  # 临时
sed -ri 's/.*swap.*/#&/' /etc/fstab    # 永久

# 将桥接的IPv4流量传递到iptables的链
cat > /etc/sysctl.d/k8s.conf << EOF
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
EOF
sysctl --system  # 生效

# 添加host文件
cat >> /etc/hosts << EOF
172.16.2.231 k8s-master1
172.16.2.232 k8s-master2
172.16.2.233 k8s-master3
172.16.2.237 k8s-node1
172.16.2.238 k8s-node2
EOF

# 时间同步
yum install ntp -y
cat /etc/ntp.conf

driftfile  /var/lib/ntp/drift
pidfile   /var/run/ntpd.pid
logfile /var/log/ntp.log
restrict    default kod nomodify notrap nopeer noquery
restrict -6 default kod nomodify notrap nopeer noquery
restrict 127.0.0.1
server 127.127.1.0
fudge  127.127.1.0 stratum 10
server ntp.aliyun.com iburst minpoll 4 maxpoll 10
restrict ntp.aliyun.com nomodify notrap nopeer noquery

```

## 二、部署Etcd集群

Etcd 是一个分布式键值存储系统，Kubernetes使用Etcd进行数据存储，所以先准备一个Etcd数据库，为解决Etcd单点故障，应采用集群方式部署，这里使用3台组建集群，可容忍1台机器故障，当然，你也可以使用5台组建集群，可容忍2台机器故障。

| 角色   | ip           | hostname    |
| ------ | ------------ | ----------- |
| etcd-1 | 172.16.2.231 | k8s-master1 |
| etcd-2 | 172.16.2.232 | k8s-master2 |
| etcd-3 | 172.16.2.233 | k8s-master3 |

### 1、安装cfssl

cfssl是一个开源的证书管理工具，使用json文件生成证书，我用Master1节点来做etcd的证书签发。

```shell
wget https://pkg.cfssl.org/R1.2/cfssl_linux-amd64
wget https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64
wget https://pkg.cfssl.org/R1.2/cfssl-certinfo_linux-amd64
chmod +x cfssl_linux-amd64 cfssljson_linux-amd64 cfssl-certinfo_linux-amd64
mv cfssl_linux-amd64 /usr/local/bin/cfssl
mv cfssljson_linux-amd64 /usr/local/bin/cfssljson
mv cfssl-certinfo_linux-amd64 /usr/bin/cfssl-certinfo
```

### 2、生成etcd证书

#### 自签CA

```shell
mkdir -p  /opt/TLS/{etcd,k8s}

cd /opt/TLS/etcd

#10年有效期
cat > ca-config.json << EOF
{
  "signing": {
    "default": {
      "expiry": "87600h"
    },
    "profiles": {
      "etcd": {
         "expiry": "87600h",
         "usages": [
            "signing",
            "key encipherment",
            "server auth",
            "client auth"
        ]
      }
    }
  }
}
EOF

cat > ca-csr.json << EOF
{
    "CN": "etcd CA",
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "L": "WuHan",
            "ST": "WuHan"
        }
    ]
}
EOF

#生成证书
cfssl gencert -initca ca-csr.json | cfssljson -bare ca -
	ca-key.pem
	ca.pem

```

#### 使用自签CA证书颁发etcd https证书

```shell
#创建证书申请文件
cat > server-csr.json << EOF
{
    "CN": "etcd",
    "hosts": [
    "172.16.2.231",
    "172.16.2.232",
    "172.16.2.233"
    ],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "L": "WuHan",
            "ST": "WuHan"
        }
    ]
}
EOF
#所有的etcd节点ip都需要加上，也可以预留ip方便后面扩容etcd

#生成证书
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=etcd server-csr.json | cfssljson -bare server
    server-key.pem
    server.pem
```

### 3、部署etcd

etcd二进制文件下载地址：https://github.com/etcd-io/etcd/releases/download/v3.4.9/etcd-v3.4.9-linux-amd64.tar.gz



```shell
#三台节点都需要执行
mkdir /data/etcd/  -p

#下面在etcd-1服务器执行-------------------------
mkdir /data/etcd/{ssl,data,bin,cfg}

[root@k8s-master1 ~]# cd /data/etcd  && ls
bin  cfg  data  etcd-v3.4.9-linux-amd64.tar.gz  ssl

#解压 etcd-v3.4.9-linux-amd64.tar.gz
tar xvf etcd-v3.4.9-linux-amd64.tar.gz
mv etcd-v3.4.9-linux-amd64/{etcd,etcdctl} /data/etcd/bin/

# 修改etcd config文件
cat > /data/etcd/cfg/etcd.conf << EOF
#[Member]
ETCD_NAME="etcd-1" #当前节点名字，唯一
ETCD_DATA_DIR="/data/etcd/data" #数据目录
ETCD_LISTEN_PEER_URLS="https://172.16.2.231:2380" #当前节点ip，集群通信监听地址
ETCD_LISTEN_CLIENT_URLS="https://172.16.2.231:2379" #当前节点ip，客户端访问监听地址
#[Clustering]
ETCD_INITIAL_ADVERTISE_PEER_URLS="https://172.16.2.231:2380" #当前节点ip，集群通告地址
ETCD_ADVERTISE_CLIENT_URLS="https://172.16.2.231:2379" #当前节点ip，客户端通告地址
ETCD_INITIAL_CLUSTER="etcd-1=https://172.16.2.231:2380,etcd-2=https://172.16.2.232:2380,etcd-3=https://172.16.2.233:2380" #集群节点地址
ETCD_INITIAL_CLUSTER_TOKEN="etcd-cluster" #集群Token
ETCD_INITIAL_CLUSTER_STATE="new" #加入集群的当前状态，new是新集群，existing表示加入已有集群
EOF



#证书拷贝
cp /opt/TLS/etcd/ca*pem /opt/TLS/etcd/server*pem /data/etcd/ssl/

#使用systemd管理etcd

cat  /usr/lib/systemd/system/etcd.service 
[Unit]
Description=Etcd Server
After=network.target
After=network-online.target
Wants=network-online.target
[Service]
Type=notify
EnvironmentFile=/data/etcd/cfg/etcd.conf
ExecStart=/data/etcd/bin/etcd \
--cert-file=/data/etcd/ssl/server.pem \
--key-file=/data/etcd/ssl/server-key.pem \
--peer-cert-file=/data/etcd/ssl/server.pem \
--peer-key-file=/data/etcd/ssl/server-key.pem \
--trusted-ca-file=/data/etcd/ssl/ca.pem \
--peer-trusted-ca-file=/data/etcd/ssl/ca.pem \
--logger=zap
Restart=on-failure
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target



```

##### 将etcd-1配置拷贝到etcd-2，etcd-3并修改

```shell
scp -r /data/etcd/ root@172.16.2.232:/data/etcd/
scp /usr/lib/systemd/system/etcd.service root@172.16.2.232:/usr/lib/systemd/system/
scp -r /data/etcd/ root@172.16.2.233:/data/etcd/
scp /usr/lib/systemd/system/etcd.service root@172.16.2.233:/usr/lib/systemd/system/

#分别修改etcd-2和etcd-3的配置
[root@k8s-master2 etcd]# cat /data/etcd/cfg/etcd.conf  
#[Member]
ETCD_NAME="etcd-2"
ETCD_DATA_DIR="/data/etcd/data"
ETCD_LISTEN_PEER_URLS="https://172.16.2.232:2380"
ETCD_LISTEN_CLIENT_URLS="https://172.16.2.232:2379"
#[Clustering]
ETCD_INITIAL_ADVERTISE_PEER_URLS="https://172.16.2.232:2380"
ETCD_ADVERTISE_CLIENT_URLS="https://172.16.2.232:2379"
ETCD_INITIAL_CLUSTER="etcd-1=https://172.16.2.231:2380,etcd-2=https://172.16.2.232:2380,etcd-3=https://172.16.2.233:2380"
ETCD_INITIAL_CLUSTER_TOKEN="etcd-cluster"
ETCD_INITIAL_CLUSTER_STATE="new"

[root@k8s-master3 etcd]# cat /data/etcd/cfg/etcd.conf  
#[Member]
ETCD_NAME="etcd-3"
ETCD_DATA_DIR="/data/etcd/data"
ETCD_LISTEN_PEER_URLS="https://172.16.2.233:2380"
ETCD_LISTEN_CLIENT_URLS="https://172.16.2.233:2379"
#[Clustering]
ETCD_INITIAL_ADVERTISE_PEER_URLS="https://172.16.2.233:2380"
ETCD_ADVERTISE_CLIENT_URLS="https://172.16.2.233:2379"
ETCD_INITIAL_CLUSTER="etcd-1=https://172.16.2.231:2380,etcd-2=https://172.16.2.232:2380,etcd-3=https://172.16.2.233:2380"
ETCD_INITIAL_CLUSTER_TOKEN="etcd-cluster"
ETCD_INITIAL_CLUSTER_STATE="new"

```

##### 三台etcd节点设置为开机启动

```shell
#三节点都需要执行
systemctl daemon-reload
systemctl start etcd
systemctl enable etcd

#查看etcd集群状态
ETCDCTL_API=3 /data/etcd/bin/etcdctl --cacert=/data/etcd/ssl/ca.pem --cert=/data/etcd/ssl/server.pem --key=/data/etcd/ssl/server-key.pem --endpoints="https://172.16.2.231:2379,https://172.16.2.232:2379,https://172.16.2.233:2379" endpoint health

[root@k8s-master3 etcd]# ETCDCTL_API=3 /data/etcd/bin/etcdctl --cacert=/data/etcd/ssl/ca.pem --cert=/data/etcd/ssl/server.pem --key=/data/etcd/ssl/server-key.pem --endpoints="https://172.16.2.231:2379,https://172.16.2.232:2379,https://172.16.2.233:2379" endpoint health
https://172.16.2.233:2379 is healthy: successfully committed proposal: took = 17.151424ms
https://172.16.2.232:2379 is healthy: successfully committed proposal: took = 17.974727ms
https://172.16.2.231:2379 is healthy: successfully committed proposal: took = 18.892283ms

```

## 三、部署docker(所有的master和node都需要执行)

### 1、添加docker的yum源

```shell
yum-config-manager --add-repo http://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo
yum makecache fast 
```

### 2、安装docker并配置

```shell
yum install -y yum-utils device-mapper-persistent-data lvm2 #相关工具
yum list docker-ce.x86_64 --showduplicates | sort -r # 查看docker版本
yum install -y docker-ce-19.03.9-3.el7 # 安装docker



# 修改daemon配置文件/etc/docker/daemon.json来使用加速器
mkdir -p /etc/docker
cat > /etc/docker/daemon.json << EOF
    {
      "registry-mirrors": ["https://0s3r40ws.mirror.aliyuncs.com"],
      "live-restore": true # 重启dockerd不影响运行容器
    }
EOF
  
# 开机自启动  
systemctl daemon-reload
systemctl restart docker
systemctl enable docker
```

## 四、部署k8s的master和node

### 1、自签kubernetes的CA证书

证书签发是在k8s-master1服务器上，既172.16.2.231服务器上面

```shell
cat > ca-config.json << EOF
{
  "signing": {
    "default": {
      "expiry": "87600h"
    },
    "profiles": {
      "kubernetes": {
         "expiry": "87600h",
         "usages": [
            "signing",
            "key encipherment",
            "server auth",
            "client auth"
        ]
      }
    }
  }
}
EOF
# 创建CA证书申请请求文件(csr)的json配置文件
cat > ca-csr.json << EOF
{
    "CN": "kubernetes",
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "L": "HuBei",
            "ST": "WuHan",
            "O": "k8s",
            "OU": "System"
        }
    ]
}
EOF
#生成ca证书
[root@k8s-master1 k8s]# cfssl gencert -initca ca-csr.json | cfssljson -bare kubernetes-ca -
2020/06/30 11:33:21 [INFO] generating a new CA key and certificate from CSR
2020/06/30 11:33:21 [INFO] generate received request
2020/06/30 11:33:21 [INFO] received CSR
2020/06/30 11:33:21 [INFO] generating key: rsa-2048
2020/06/30 11:33:22 [INFO] encoded CSR
2020/06/30 11:33:22 [INFO] signed certificate with serial number 557300048648264508068553032951865374930382033709
[root@k8s-master1 k8s]# ls
ca-config.json  ca-csr.json  kubernetes-ca.csr  kubernetes-ca-key.pem  kubernetes-ca.pem
[root@k8s-master1 k8s]# pwd
/opt/TLS/k8s
```

### 2、使用自签的kubernetes CA签发kube-apiserver https证书

```shell
# 创建证书申请请求文件(csr)的json配置文件
cat > server-csr.json << EOF
{
    "CN": "kubernetes",
    "hosts": [
      "10.96.0.1",
      "127.0.0.1",
      "172.16.2.230",
      "172.16.2.231",
      "172.16.2.232",
      "172.16.2.233",
      "172.16.2.234",
      "172.16.2.235",
      "172.16.2.236",
      "172.16.2.237",
      "kubernetes",
      "kubernetes.default",
      "kubernetes.default.svc",
      "kubernetes.default.svc.cluster",
      "kubernetes.default.svc.cluster.local"
    ],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "L": "HuBei",
            "ST": "WuHan",
            "O": "k8s",
            "OU": "System"
        }
    ]
}
EOF

#如果为后期做集群扩展，可以预先在上面的请求文件hosts中加入冗余ip。否者以后扩容集群，添加apiserver主机，需要重新做证书，替换之前所有的。

#使用自签ca颁发apiserver-server证书
cfssl gencert -ca=kubernetes-ca.pem  -ca-key=kubernetes-ca-key.pem  -config=ca-config.json -profile=kubernetes server-csr.json  |cfssljson  -bare apiserver
2020/06/30 14:55:44 [INFO] generate received request
2020/06/30 14:55:44 [INFO] received CSR
2020/06/30 14:55:44 [INFO] generating key: rsa-2048
2020/06/30 14:55:45 [INFO] encoded CSR
2020/06/30 14:55:45 [INFO] signed certificate with serial number 171910205443906277398963937825679076758153992347
2020/06/30 14:55:45 [WARNING] This certificate lacks a "hosts" field. This makes it unsuitable for
websites. For more information see the Baseline Requirements for the Issuance and Management
of Publicly-Trusted Certificates, v.1.1.6, from the CA/Browser Forum (https://cabforum.org);
specifically, section 10.2.3 ("Information Requirements").
[root@k8s-master1 k8s]# ls
apiserver.csr      apiserver.pem   ca-csr.json        kubernetes-ca-key.pem  server-csr.json
apiserver-key.pem  ca-config.json  kubernetes-ca.csr  kubernetes-ca.pem

```

3、部署apiserver

```shell
# 下载地址： https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG/CHANGELOG-1.18.md#v1183
# 解压二进制包

# mkdir -p /data/kubernetes/{bin,cfg,ssl,logs} 
# tar zxvf kubernetes-server-linux-amd64.tar.gz
[root@k8s-master1 ~]# tree kubernetes
kubernetes
├── addons
├── kubernetes-src.tar.gz
├── LICENSES
└── server
    └── bin
        ├── apiextensions-apiserver
        ├── kubeadm  
        ├── kube-apiserver  需要
        ├── kube-apiserver.docker_tag
        ├── kube-apiserver.tar    kube-apiserver.tar选择kubeadm安装的镜像文件
        ├── kube-controller-manager 需要 
        ├── kube-controller-manager.docker_tag
        ├── kube-controller-manager.tar kube-controller-manager.tar选择kubeadm安装的镜像文件
        ├── kubectl 需要
        ├── kubelet 需要
        ├── kube-proxy 需要
        ├── kube-proxy.docker_tag
        ├── kube-proxy.tar  kube-proxy.tar选择kubeadm安装的镜像文件
        ├── kube-scheduler 需要
        ├── kube-scheduler.docker_tag
        ├── kube-scheduler.tar  kube-scheduler.tar选择kubeadm安装的镜像文件
        └── mounter
# cd kubernetes/server/bin
# cp kube-apiserver kube-scheduler kube-controller-manager /data/kubernetes/bin
# cp kubectl /usr/bin/

# 创建kube-apiserver启动配置文件

# cat  /data/kubernetes/cfg/kube-apiserver.conf 
KUBE_APISERVER_OPTS="--logtostderr=false \
--v=2 \
--log-dir=/data/kubernetes/logs \
--etcd-servers=https://172.16.2.231:2379,https://172.16.2.232:2379,https://172.16.2.233:2379 \
--bind-address=172.16.2.231 \
--secure-port=6443 \
--advertise-address=172.16.2.231 \
--allow-privileged=true \
--service-cluster-ip-range=10.96.0.0/16 \
--enable-admission-plugins=NamespaceLifecycle,LimitRanger,ServiceAccount,ResourceQuota,NodeRestriction \
--authorization-mode=RBAC,Node \
--enable-bootstrap-token-auth=true \
--token-auth-file=/data/kubernetes/cfg/token.csv \
--service-node-port-range=22222-33333 \
--kubelet-client-certificate=/data/kubernetes/ssl/apiserver.pem \
--kubelet-client-key=/data/kubernetes/ssl/apiserver-key.pem \
--tls-cert-file=/data/kubernetes/ssl/apiserver.pem  \
--tls-private-key-file=/data/kubernetes/ssl/apiserver-key.pem \
--client-ca-file=/data/kubernetes/ssl/kubernetes-ca.pem \
--service-account-key-file=/data/kubernetes/ssl/kubernetes-ca-key.pem \
--etcd-cafile=/data/etcd/ssl/kubernetes-ca.pem \
--etcd-certfile=/data/etcd/ssl/apiserver.pem \
--etcd-keyfile=/data/etcd/ssl/apiserver-key.pem \
--audit-log-maxage=30 \
--audit-log-maxbackup=3 \
--audit-log-maxsize=100 \
--audit-log-path=/data/kubernetes/logs/k8s-audit.log"
--------------------------------------------------------

–logtostderr：启用日志
—v：日志等级
–log-dir：日志目录
–bind-address： 监听地址，当前主机ip
–etcd-servers：etcd集群地址
–bind-address：监听地址
–secure-port：https安全端口
–advertise-address：集群通告地址，当前主机ip
–allow-privileged：启用授权
–service-cluster-ip-range：svc虚拟IP地址段
–enable-admission-plugins：准入控制模块
–authorization-mode：认证授权，启用RBAC授权和节点自管理
–enable-bootstrap-token-auth：启用TLS bootstrap机制
–token-auth-file：bootstrap token文件
–service-node-port-range：Service nodeport类型默认分配端口范围
–kubelet-client-xxx：apiserver访问kubelet客户端证书
–tls-xxx-file：apiserver https证书
–etcd-xxxfile：连接Etcd集群证书
–audit-log-xxx：审计日志

# 拷贝上面生成的证书到安装目录
cp /opt/TLS/k8s/kubernetes-ca*pem /opt/TLS/k8s/apiserver*pem /data/kubernetes/ssl/

# 创建api-server的systemd管理文件
cat  /usr/lib/systemd/system/kube-apiserver.service
[Unit]
Description=Kubernetes API Server
Documentation=https://github.com/kubernetes/kubernetes
[Service]
EnvironmentFile=/data/kubernetes/cfg/kube-apiserver.conf
ExecStart=/data/kubernetes/bin/kube-apiserver \$KUBE_APISERVER_OPTS
Restart=on-failure
[Install]
WantedBy=multi-user.target

# 启用 TLS Bootstrapping 机制
TLS Bootstraping：Master apiserver启用TLS认证后，Node节点kubelet和kube-proxy要与kube-apiserver进行通信，必须使用CA签发的有效证书才可以，当Node节点很多时，这种客户端证书颁发需要大量工作，同样也会增加集群扩展复杂度。为了简化流程，Kubernetes引入了TLS bootstraping机制来自动颁发客户端证书，kubelet会以一个低权限用户自动向apiserver申请证书，kubelet的证书由apiserver动态签署。所以强烈建议在Node上使用这种方式，目前主要用于kubelet，kube-proxy还是由我们统一颁发一个证书。

TLS bootstraping 工作流程：
![1](C:\Users\Administrator\Desktop\1.png)

#创建上面的token文件(格式：token，用户名，UID，用户组):
[root@k8s-master1 k8s]# head -c 16 /dev/urandom | od -An -t x | tr -d ' '
0726a539607d2df4162ed4ef388fbb11
# cat > /data/kubernetes/cfg/token.csv << EOF
0726a539607d2df4162ed4ef388fbb11,kubelet-bootstrap,10001,"system:node-bootstrapper"
EOF

#授权kubelet-bootstrap用户允许请求证书 

# kubectl create clusterrolebinding kubelet-bootstrap --clusterrole=system:node-bootstrapper --user=kubelet-bootstrap

```

### 3、 部署kube-controller-manager

```shell
# 创建kube-ccontroller-manager启动文件

cat  /data/kubernetes/cfg/kube-controller-manager.conf 
KUBE_CONTROLLER_MANAGER_OPTS="--logtostderr=false \
--v=2 \
--log-dir=/data/kubernetes/logs \
--leader-elect=true \
--master=127.0.0.1:8080 \
--bind-address=127.0.0.1 \
--allocate-node-cidrs=true \
--cluster-cidr=10.244.0.0/16 \
--service-cluster-ip-range=10.96.0.0/16 \
--cluster-signing-cert-file=/data/kubernetes/ssl/kubernetes-ca.pem \
--cluster-signing-key-file=/data/kubernetes/ssl/kubernetes-ca-key.pem  \
--root-ca-file=/data/kubernetes/ssl/kubernetes-ca.pem \
--service-account-private-key-file=/data/kubernetes/ssl/kubernetes-ca-key.pem \
--experimental-cluster-signing-duration=87600h0m0s"

–master：通过本地非安全本地端口8080连接apiserver
–leader-elect：当该组件启动多个时，自动选举（HA）
–cluster-signing-cert-file/–cluster-signing-key-file：自动为kubelet颁发证书的CA，与apiserver保持一致


# 创建kube-ccontroller-manager的systemd管理文件
cat > /usr/lib/systemd/system/kube-controller-manager.service << EOF
[Unit]
Description=Kubernetes Controller Manager
Documentation=https://github.com/kubernetes/kubernetes
[Service]
EnvironmentFile=/data/kubernetes/cfg/kube-controller-manager.conf
ExecStart=/data/kubernetes/bin/kube-controller-manager \$KUBE_CONTROLLER_MANAGER_OPTS
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
```

4、部署kube-scheduler

```shell
# cat  /data/kubernetes/cfg/kube-scheduler.conf
KUBE_SCHEDULER_OPTS="--logtostderr=false \
--v=2 \
--log-dir=/data/kubernetes/logs \
--leader-elect \
--master=127.0.0.1:8080 \
--bind-address=127.0.0.1"

–master：通过本地非安全本地端口8080连接apiserver
–leader-elect：当该组件启动多个时，自动选举（HA）

# 创建kube-scheduler的systemd管理文件
cat > /usr/lib/systemd/system/kube-scheduler.service << EOF
[Unit]
Description=Kubernetes Scheduler
Documentation=https://github.com/kubernetes/kubernetes
[Service]
EnvironmentFile=/data/kubernetes/cfg/kube-scheduler.conf
ExecStart=/data/kubernetes/bin/kube-scheduler \$KUBE_SCHEDULER_OPTS
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF

# ----------------------------------------------------------------
#  启动并设置开机启动
systemctl daemon-reload
systemctl start kube-scheduler
systemctl enable kube-scheduler

systemctl daemon-reload
systemctl start kube-controller-manager
systemctl enable kube-controller-manager

systemctl daemon-reload
systemctl start kube-apiserver
systemctl enable kube-apiserver

# 查看集群状态
[root@k8s-master1 k8s]# kubectl get cs
NAME                 STATUS    MESSAGE             ERROR
scheduler            Healthy   ok                  
controller-manager   Healthy   ok                  
etcd-1               Healthy   {"health":"true"}   
etcd-2               Healthy   {"health":"true"}   
etcd-0               Healthy   {"health":"true"}   

# 说明kubernetes的master组件已经启动正常

```

### 4、部署node

下面操作也是在k8s-master1操作部署kube-proxy和kubelet用来管理集群。

####  4.1、部署kubelet

```shell

cat  /data/kubernetes/cfg/kubelet.conf 
KUBELET_OPTS="--logtostderr=false \
--v=2 \
--log-dir=/data/kubernetes/logs \
--hostname-override=k8s-master1 \
--network-plugin=cni \
--kubeconfig=/data/kubernetes/cfg/kubelet.kubeconfig \
--bootstrap-kubeconfig=/data/kubernetes/cfg/bootstrap.kubeconfig \
--config=/data/kubernetes/cfg/kubelet-config.yml \
--cert-dir=/data/kubernetes/ssl \
--pod-infra-container-image=registry.cn-hangzhou.aliyuncs.com/bigfcat/pause-amd64:3.0"

–hostname-override：显示名称，集群中唯一
–network-plugin：启用CNI
–kubeconfig：空路径，会自动生成，后面用于连接apiserver
–bootstrap-kubeconfig：首次启动向apiserver申请证书
–config：配置参数文件
–cert-dir：kubelet证书生成目录
–pod-infra-container-image：管理Pod网络容器的镜像
172.16.2.81:5000/pause-amd64:3.0镜像文件因为下载太慢，所以下载了后推送到私有仓库的

# 配置参数文件
cat > /data/kubernetes/cfg/kubelet-config.yml << EOF
kind: KubeletConfiguration
apiVersion: kubelet.config.k8s.io/v1beta1
address: 0.0.0.0
port: 10250
readOnlyPort: 10255
cgroupDriver: cgroupfs
clusterDNS:
- 10.96.0.2
clusterDomain: cluster.local 
failSwapOn: false
authentication:
  anonymous:
    enabled: false
  webhook:
    cacheTTL: 2m0s
    enabled: true
  x509:
    clientCAFile: /data/kubernetes/ssl/kubernetes-ca.pem 
authorization:
  mode: Webhook
  webhook:
    cacheAuthorizedTTL: 5m0s
    cacheUnauthorizedTTL: 30s
evictionHard:
  imagefs.available: 15%
  memory.available: 100Mi
  nodefs.available: 10%
  nodefs.inodesFree: 5%
maxOpenFiles: 1000000
maxPods: 110
EOF

# 生成bootstrap.kubeconfig文件，下面命令会在当前目录下面生成一个bootstrap.kubeconfig文件

[root@k8s-master1 k8s]# KUBE_APISERVER="https://192.168.31.71:6443" # apiserver 172.16.2.231:6443,后面做高可用会替换为vip的ip地址

[root@k8s-master1 k8s]# TOKEN="0726a539607d2df4162ed4ef388fbb11" # 与/data/kubernetes/cfg/token.csv里保持一致

[root@k8s-master1 k8s]# kubectl config set-cluster kubernetes --certificate-authority=/data/kubernetes/ssl/kubernetes-ca.pem --embed-certs=true --server=${KUBE_APISERVER} --kubeconfig=bootstrap.kubeconfig

[root@k8s-master1 k8s]# kubectl config set-credentials "kubelet-bootstrap" --token=${TOKEN} --kubeconfig=bootstrap.kubeconfig

[root@k8s-master1 k8s]# kubectl config set-context default --cluster=kubernetes --user="kubelet-bootstrap" --kubeconfig=bootstrap.kubeconfig

[root@k8s-master1 k8s]# kubectl config use-context default --kubeconfig=bootstrap.kubeconfig
#拷贝生成的bootstrap.kubeconfig配置到上面kubelet的配置中指定的路径去：
[root@k8s-master1 k8s]# cp bootstrap.kubeconfig /data/kubernetes/cfg

# 创建kubelet的systemd管理文件
# cat > /usr/lib/systemd/system/kubelet.service << EOF
[Unit]
Description=Kubernetes Kubelet
After=docker.service
[Service]
EnvironmentFile=/data/kubernetes/cfg/kubelet.conf
ExecStart=/data/kubernetes/bin/kubelet \$KUBELET_OPTS
Restart=on-failure
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
EOF

# 设置开机启动
systemctl daemon-reload
systemctl start kubelet
systemctl enable kubelet

# 批准kubelet证书申请并加入集群
# 查看kubelet证书请求
[root@k8s-master1 k8s]# kubectl get csr
NAME                                                   AGE    SIGNERNAME                                    REQUESTOR           CONDITION
node-csr-uCEGPOIiDdlLODKts8J658HrFq9CZ--K6M4G7bjhk8A   6m3s   kubernetes.io/kube-apiserver-client-kubelet   kubelet-bootstrap   Pending

# 批准申请
[root@k8s-master1 k8s]# kubectl certificate approve node-csr-uCEGPOIiDdlLODKts8J658HrFq9CZ--K6M4G7bjhk8A

# 查看节点
[root@k8s-master1 k8s]# kubectl get node
NAME         STATUS     ROLES    AGE   VERSION
k8s-master1   NotReady   <none>   7s    v1.18.3
```

#### 4.2、部署kube-proxy

```shell

从kubernetes的下载解压目录拷贝
# cd kubernetes/server/bin
# cp kubelet kube-proxy /data/kubernetes/bin

# 创建kube-proxy启动配置文件
cat /data/kubernetes/cfg/kube-proxy.conf
KUBE_PROXY_OPTS="--logtostderr=false \
--v=2 \
--log-dir=/data/kubernetes/logs \
--config=/data/kubernetes/cfg/kube-proxy-config.yml"


# 配置kube-proxy启动是指定的参数文件
cat > /data/kubernetes/cfg/kube-proxy-config.yml << EOF
kind: KubeProxyConfiguration
apiVersion: kubeproxy.config.k8s.io/v1alpha1
bindAddress: 0.0.0.0
metricsBindAddress: 0.0.0.0:10249
clientConnection:
  kubeconfig: /data/kubernetes/cfg/kube-proxy.kubeconfig
hostnameOverride: k8s-master1
clusterCIDR: 10.244.0.0/16
mode: ipvs
EOF


# 生成kube-proxy.kubeconfig文件，创建证书请求文件
cd /opt/TLS/k8s
cat > kube-proxy-csr.json << EOF
{
  "CN": "system:kube-proxy",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "L": "HuBei",
      "ST": "WuHan",
      "O": "k8s",
      "OU": "System"
    }
  ]
}
EOF

[root@k8s-master1 k8s]# cfssl gencert -ca=kubernetes-ca.pem -ca-key=kubernetes-ca-key.pem -config=ca-config.json -profile=kubernetes kube-proxy-csr.json | cfssljson -bare kube-proxy

#生成kubeconfig文件：

[root@k8s-master1 k8s]# KUBE_APISERVER="https://172.16.2.231:6443" # 做高可用后面会替换为vip地址

[root@k8s-master1 k8s]#kubectl config set-cluster kubernetes --certificate-authority=/data/kubernetes/ssl/kubernetes-ca.pem --embed-certs=true --server=${KUBE_APISERVER} --kubeconfig=kube-proxy.kubeconfig
[root@k8s-master1 k8s]#kubectl config set-credentials kube-proxy --client-certificate=./kube-proxy.pem --client-key=./kube-proxy-key.pem --embed-certs=true --kubeconfig=kube-proxy.kubeconfig
[root@k8s-master1 k8s]#kubectl config set-context default --cluster=kubernetes --user=kube-proxy --kubeconfig=kube-proxy.kubeconfig
[root@k8s-master1 k8s]#kubectl config use-context default --kubeconfig=kube-proxy.kubeconfig

#会在当前目录下面创建一个kube-proxy.kubeconfig文件，拷贝到上面按kube-proxy启动配置文件里面指定的目录
[root@k8s-master1 k8s]# cp kube-proxy.kubeconfig /data/kubernetes/cfg/

#创建kube-proxy的systemd管理文件
[root@k8s-master1 k8s]# cat /usr/lib/systemd/system/kube-proxy.service
[Unit]
Description=Kubernetes Proxy
After=network.target
[Service]
EnvironmentFile=/data/kubernetes/cfg/kube-proxy.conf
ExecStart=/data/kubernetes/bin/kube-proxy $KUBE_PROXY_OPTS
Restart=on-failure
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target

# 开机自动启动
systemctl daemon-reload
systemctl start kube-proxy
systemctl enable kube-proxy
```

### 5、部署网络插件CNI

下载CNI二进制文件：https://github.com/containernetworking/plugins/releases/download/v0.8.6/cni-plugins-linux-amd64-v0.8.6.tgz

```shell
# mkdir /opt/cni/bin
# tar zxvf cni-plugins-linux-amd64-v0.8.6.tgz -C /opt/cni/bin

# 部署CNI网络：
# yum install -y wget
# wget https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel.yml
# 修改flannel默认镜像下载地址：
sed -i -r "s#quay.io/coreos/flannel:.*-amd64#lizhenliang/flannel:v0.12.0-amd64#g" kube-flannel.yml

kubectl apply -f kube-flannel.yml

#  授权apiserver访问kubelet
cat > apiserver-to-kubelet-rbac.yaml << EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  annotations:
    rbac.authorization.kubernetes.io/autoupdate: "true"
  labels:
    kubernetes.io/bootstrapping: rbac-defaults
  name: system:kube-apiserver-to-kubelet
rules:
  - apiGroups:
      - ""
    resources:
      - nodes/proxy
      - nodes/stats
      - nodes/log
      - nodes/spec
      - nodes/metrics
      - pods/log
    verbs:
      - "*"
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: system:kube-apiserver
  namespace: ""
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:kube-apiserver-to-kubelet
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: User
    name: kubernetes
EOF
# kubectl apply -f apiserver-to-kubelet-rbac.yaml

```

### 6、添加k8s-node1(172.16.2.237)作为work node到集群

下面操作是在k8s-node1(172.16.2.237)上面操作：

```shell
# 1.拷贝已部署好的Node相关文件到新节点
scp -r root@172.16.2.231:/data/kubernetes /data/
scp -r root@172.16.2.231:/usr/lib/systemd/system/{kubelet,kube-proxy}.service /usr/lib/systemd/system/
scp -r root@172.16.2.231:/opt/cni/ /opt/
scp root@172.16.2.231:/data/kubernetes/ssl/kubernetes-ca.pem /data/kubernetes/ssl

#2.修改主机名
sed -i "@hostname-override=k8s-master1@hostname-override=k8s-node1@" /data/kubernetes/cfg/kubelet.conf
sed -i "@hostnameOverride: k8s-master1@hostnameOverride: k8s-node1@" /data/kubernetes/cfg/kube-proxy-config.yml

#3.删除kubelet证书和kubeconfig文件,每个节点的文件不一样，需要删除重新生成
rm /data/kubernetes/cfg/kubelet.kubeconfig 
rm -f /data/kubernetes/ssl/kubelet*

#4.开机启动
systemctl daemon-reload
systemctl start kubelet
systemctl enable kubelet
systemctl start kube-proxy
systemctl enable kube-proxy
#5.在k8s-master1上批准新Node kubelet证书申请
[root@k8s-master1 k8s]# kubectl get csr
NAME                                                   AGE   SIGNERNAME                                    REQUESTOR           CONDITION
node-csr-4zTjsaVSrhuyhIGqsefxzVoZDCNKei-aE2jyTP81Uro   89s   kubernetes.io/kube-apiserver-client-kubelet   kubelet-bootstrap   Pending

[root@k8s-master1 k8s]# kubectl certificate approve node-csr-4zTjsaVSrhuyhIGqsefxzVoZDCNKei-aE2jyTP81Uro
# 查看集群状态
[root@k8s-master1 k8s]# kubectl get node
NAME         STATUS     ROLES    AGE   VERSION
k8s-master   Ready      <none>   65m   v1.18.3
k8s-node1    Ready      <none>   12m   v1.18.3
```

### 7、部署CoreDNS

CoreDNS用于集群内部Service名称解析

下载coreDNS启动文件：https://raw.githubusercontent.com/BigFCat/WorkTools/master/k8s/coredns.yaml

```shell
# kubectl apply -f coredns.yaml
[root@k8s-master1 ~]#  kubectl get pods -n default
NAME                       READY   STATUS    RESTARTS   AGE
coredns-5ffbfd976d-7whkr   1/1     Running   2          12m


# DNS解析测试(新版本的busybox可能会解释失败)
kubectl run -it --rm dns-test --image=busybox:1.28.4 sh
```



## 五、扩展为高可用及集群

### 1、添加master

将172.16.2.232，172.16.2.233作为master加入到集群，使用nginx(172.16.2.234,172.16.2.235)作为LB，使用keepalived做nginx的高可用。

```shell
#1、部署docker环境172.16.2.232和172.16.2.232都需要部署。

#2、添加master(172.16.2.232操作)
mkdir /data
scp -r root@172.16.2.231:/data/kubernetes /data/
scp -r root@172.16.2.231:/usr/lib/systemd/system/kube* /usr/lib/systemd/system/
scp -r root@172.16.2.231:/opt/cni/ /opt/
scp -r root@172.16.2.231:/usr/bin/kubectl /usr/bin/
# 删除kubelet证书和kubeconfig文件：
rm -f /data/kubernetes/cfg/kubelet.kubeconfig
rm -f /data/kubernetes/ssl/kubelet*
# 修改apiserver、kubelet和kube-proxy配置文件为本机IP和本机主机名
# cat /data/kubernetes/cfg/kube-apiserver.conf
.....
--bind-address=172.16.2.232 \
--secure-port=6443 \
--advertise-address=172.16.2.232 \
......

# cat /data/kubernetes/cfg/kubelet.conf
.....
--hostname-override=k8s-master1 \
.....

# cat /data/kubernetes/cfg/kube-proxy-config.yml
......
hostnameOverride: k8s-master1
......

#3、开机自启动
systemctl daemon-reload
systemctl start kube-apiserver
systemctl start kube-controller-manager
systemctl start kube-scheduler
systemctl start kubelet
systemctl start kube-proxy
systemctl enable kube-apiserver
systemctl enable kube-controller-manager
systemctl enable kube-scheduler
systemctl enable kubelet
systemctl enable kube-proxy

#4、通过kubelet证书申请
[root@k8s-master1 k8s]# kubectl get csr
NAME                                                   AGE   SIGNERNAME                                    REQUESTOR           CONDITION
node-csr-4zTjsaVSrhuyhIGqsefxzVoZDCNKei-aE2jyTP81Uro   89s   kubernetes.io/kube-apiserver-client-kubelet   kubelet-bootstrap   Pending

[root@k8s-master1 k8s]# kubectl certificate approve node-csr-4zTjsaVSrhuyhIGqsefxzVoZDCNKei-aE2jyTP81Uro

#5、添加172.16.2.233作为master，操作如上面的1-4步骤


# 查看集群状态
[root@k8s-master1 kubernetes]#  kubectl get node
NAME          STATUS   ROLES    AGE     VERSION
k8s-master1   Ready    <none>   4d20h   v1.18.3
k8s-master2   Ready    <none>   3d17h   v1.18.3
k8s-master3   Ready    <none>   3d17h   v1.18.3
k8s-node1     Ready    <none>   3d23h   v1.18.3
```

### 2、部署nginx负载均衡(vip：172.16.2.230)

```shell
# 172.16.2.234(主)和172.16.2.235(备)都需要执行nginx和keepalived安装
yum install nginx keepalived -y
#nginx配置主备都一样
cat > /etc/nginx/nginx.conf << "EOF"
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

include /usr/share/nginx/modules/*.conf;

events {
    worker_connections 1024;
}

# 四层负载均衡，为两台Master apiserver组件提供负载均衡
stream {

    log_format  main  '$remote_addr $upstream_addr - [$time_local] $status $upstream_bytes_sent';

    access_log  /var/log/nginx/k8s-access.log  main;

    upstream k8s-apiserver {
       server 172.16.2.231:6443;   # Master1 APISERVER IP:PORT
       server 172.16.2.232:6443;   # Master2 APISERVER IP:PORT
       server 172.16.2.233:6443;   # Master2 APISERVER IP:PORT
    }
    
    server {
       listen 6443;
       proxy_pass k8s-apiserver;
    }
}

http {
    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    sendfile            on;
    tcp_nopush          on;
    tcp_nodelay         on;
    keepalive_timeout   65;
    types_hash_max_size 2048;

    include             /etc/nginx/mime.types;
    default_type        application/octet-stream;

    server {
        listen       80 default_server;
        server_name  _;

        location / {
        }
    }
}
EOF

#nginx状态检测脚本(主备都需要添加)
cat > /etc/keepalived/check_nginx.sh  << "EOF"
#!/bin/bash
count=$(ps -ef |grep nginx |egrep -cv "grep|$$")

if [ "$count" -eq 0 ];then
    exit 1
else
    exit 0
fi
EOF

chmod +x /etc/keepalived/check_nginx.sh


# keepalived配置文件(主配置)
cat > /etc/keepalived/keepalived.conf << EOF
global_defs {
   notification_email {
     acassen@firewall.loc
     failover@firewall.loc
     sysadmin@firewall.loc
   }
   notification_email_from Alexandre.Cassen@firewall.loc
   smtp_server 127.0.0.1
   smtp_connect_timeout 30
   router_id NGINX_MASTER
}
vrrp_script check_nginx {
    script "/etc/keepalived/check_nginx.sh"
}
vrrp_instance VI_1 {
    state MASTER
    interface ens192
    virtual_router_id 51 # VRRP 路由 ID实例，每个实例是唯一的
    priority 100    # 优先级，备服务器设置 90
    advert_int 1    # 指定VRRP 心跳包通告间隔时间，默认1秒
    authentication {
        auth_type PASS
        auth_pass 1111
    }
    # 虚拟IP
    virtual_ipaddress {
        172.16.2.230/24
    }
    track_script {
        check_nginx
    }
}
EOF

# keepalived配置文件(备配置)
cat > /etc/keepalived/keepalived.conf << EOF
global_defs {
   notification_email {
     acassen@firewall.loc
     failover@firewall.loc
     sysadmin@firewall.loc
   }
   notification_email_from Alexandre.Cassen@firewall.loc
   smtp_server 127.0.0.1
   smtp_connect_timeout 30
   router_id NGINX_BACKUP
}
vrrp_script check_nginx {
    script "/etc/keepalived/check_nginx.sh"
}
vrrp_instance VI_1 {
    state BACKUP
    interface ens192
    virtual_router_id 51 # VRRP 路由 ID实例，每个实例是唯一的
    priority 90
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass 1111
    }
    virtual_ipaddress {
        172.16.2.230/24
    }
    track_script {
        check_nginx
    }
}
EOF

# 开机启动
systemctl daemon-reload
systemctl start nginx
systemctl start keepalived
systemctl enable nginx
systemctl enable keepalived

#测试负载均衡效果

#curl -k https://172.16.2.230:6443/version
#curl -k https://172.16.2.234:6443/version
#curl -k https://172.16.2.235:6443/version
{
  "major": "1",
  "minor": "18",
  "gitVersion": "v1.18.3",
  "gitCommit": "2e7996e3e2712684bc73f0dec0200d64eec7fe40",
  "gitTreeState": "clean",
  "buildDate": "2020-05-20T12:43:34Z",
  "goVersion": "go1.13.9",
  "compiler": "gc",
  "platform": "linux/amd64"
}

 #修改所有Worker Node连接LB VIP

虽然我们增加了k8s-master2、k8s-master3和负载均衡器，但是我们是从单Master架构扩容的，也就是说目前所有的Node组件连接都还是k8s-master1，如果不改为连接VIP走负载均衡器，那么master还是单点故障。
因此接下来就是要改所有Node组件配置文件，由原来172.16.2.231修改为172.16.2.230（VIP）：在上述所有Worker Node执行：

sed -i 's#172.16.2.231:6443#172.16.2.230:6443#' /data/kubernetes/cfg/*
systemctl restart kubelet
systemctl restart kube-proxy

```

# 六、使用kubeadm部署的k8s备份etcd数据

### 备份：

```shell
docker run -it --rm  \
-v /data/backup:/backup  \
-v /etc/kubernetes/pki/etcd:/etc/kubernetes/pki/etcd \
--env ETCDCTL_API=3  \
b2756210eeab  \
/bin/sh -c "etcdctl --endpoints=https://172.16.2.77:2379 \
--cacert=/etc/kubernetes/pki/etcd/ca.crt  \
--key=/etc/kubernetes/pki/etcd/healthcheck-client.key \
--cert=/etc/kubernetes/pki/etcd/healthcheck-client.crt \
snapshot save /backup/etcd-snapshot.db"
```

/data/backup:/backup # /data/backup宿主机目录；/backup容器目录

—env ETCDCTL_API=3  # etcd指定版本

-v /etc/kubernetes/pki/etcd  #etcd的证书文件目录

/data/backup:/backup # /data/backup宿主机目录；/backup容器目录

—env ETCDCTL_API=3  # etcd指定版本

-v /etc/kubernetes/pki/etcd  #etcd的证书文件目录

-v b2756210eeab  #  imageID registry.cn-hangzhou.aliyuncs.com/google_containers/etcd                      3.3.15-0 

### 恢复

```shell
# 查看备份文件：
etcdctl snapshot status /backup/etcd-snapshot.db --write-out=table


```



# 错误日志处理：

```
https://jimmysong.io/kubernetes-handbook/appendix/issues.html

# 解决k8s"failed to set bridge addr: "cni0" already has an IP address different from 10.244.1.1/24"
https://blog.csdn.net/Wuli_SmBug/article/details/104712653


首先我们重新配置k8s的flannel文件，可以参考其他环境的文件配置，也可以重新安装插件生成，会在/run下面生成flannel文件夹，下面包含网络配置环境变量

查看出错节点cni0的网卡配置，发现cni0的这个网卡地址是10.244.2.1，明显与报错中的10.244.1.1不一致

我们可以将其改为10.244.1.1，也可将这个错误的网卡删掉，它会自己重建，这里采用删除重生的方法，首先停用网络，然后删除配置

    ifconfig cni0 down    
    ip link delete cnif
   
# coredns 日志报错：failed to list *v1.Endpoints: Get https://10.96.0.1:443/api/v1/endpoints?limit=500&resourceVersion=0: dial tcp 10.96.0.1:443: connect: no route to host
```



# 错误日志处理：

```shell
https://jimmysong.io/kubernetes-handbook/appendix/issues.html

# 解决k8s"failed to set bridge addr: "cni0" already has an IP address different from 10.244.1.1/24"
https://blog.csdn.net/Wuli_SmBug/article/details/104712653


首先我们重新配置k8s的flannel文件，可以参考其他环境的文件配置，也可以重新安装插件生成，会在/run下面生成flannel文件夹，下面包含网络配置环境变量

查看出错节点cni0的网卡配置，发现cni0的这个网卡地址是10.244.2.1，明显与报错中的10.244.1.1不一致

我们可以将其改为10.244.1.1，也可将这个错误的网卡删掉，它会自己重建，这里采用删除重生的方法，首先停用网络，然后删除配置

    ifconfig cni0 down    
    ip link delete cnif
   
# coredns 日志报错：failed to list *v1.Endpoints: Get https://10.96.0.1:443/api/v1/endpoints?limit=500&resourceVersion=0: dial tcp 10.96.0.1:443: connect: no route to host
```

