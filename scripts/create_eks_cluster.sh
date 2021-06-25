#!/bin/bash

###############################################################################
# This script uses cloud-init/userdata to configure the EKS worker nodes      #
# during boot time with the customizations required for Calico/VPP DPDK based #
# deployments and then it creates an EKS cluster consisting of a managed      #
# nodegroup with 2 worker nodes.                                              #
#                                                                             #
# The following customizations are done on EKS worker nodes:                  #
#   1. configure 512 2MB hugepages                                            #
#   2. enable unsafe_noiommu_mode                                             #
#   3. download, build, install and load ENAv2 compatible igb_uio driver      #
#   4. download, build, install and load ENAv2 compatible vfio-pci driver     #
###############################################################################


###############################################################################
#                           CONFIG PARAMS                                     #
###############################################################################
### Config params; replace with appropriate values
CLUSTER_NAME=				# cluster name (MANDATORY)
REGION=					# cluster region (MANDATORY)
NODEGROUP_NAME=$CLUSTER_NAME-nodegroup	# managed nodegroup name
LT_NAME=$CLUSTER_NAME-lt		# EC2 launch template name
KEYNAME=				# keypair name for ssh access to worker nodes
SSH_SECURITY_GROUP_NAME="$CLUSTER_NAME-ssh-allow"
SSH_ALLOW_CIDR="0.0.0.0/0"		# source IP from which ssh access is allowed
INSTANCE_TYPE=m5.large			# EC2 instance type
INSTANCE_NUM=2				# Number of instances in cluster
## Calico/VPP deployment yaml; could be url or local file
CALICO_VPP_YAML=https://raw.githubusercontent.com/projectcalico/vpp-dataplane/master/yaml/generated/calico-vpp-eks-dpdk.yaml
#CALICO_VPP_YAML=<full path>/calico-vpp-eks-dpdk.yaml
## init_eks.sh script location; could be url or local file
INIT_EKS_SCRIPT=https://raw.githubusercontent.com/projectcalico/vpp-dataplane/master/scripts/init_eks.sh
#INIT_EKS_SCRIPT=<full path>/init_eks.sh
###############################################################################

usage ()
{
	echo
	echo "Either execute the script after filling in the CONFIG PARAMS section in the"
	echo "script or execute the script with command-line options as follows:"
	echo
	echo "    bash $0  <cluster name>  -r <region name>  [-k <keyname>]"
	echo "    [-t <instance type>]  [-n <number of instances>]  [-f <calico/vpp config yaml file>]"
	echo
	echo "Mandatory options are \"cluster name\" and \"region name\"."
	exit 1
}

### Parse the command line
if [ "$1" != "" ]; then
	CLUSTER_NAME=$1
	shift
	while getopts ":r:k:t:n:f:" flag
	do
	        case "${flag}" in
	                r) REGION=${OPTARG};;
	                k) KEYNAME=${OPTARG};;
	                t) INSTANCE_TYPE=${OPTARG};;
	                n) INSTANCE_NUM=${OPTARG};;
	                f) CALICO_VPP_YAML=${OPTARG};;
	               \?) echo "Invalid option : -${OPTARG}"; usage;;
	                :) echo "Option -${OPTARG} requires an argument"; usage;;
	        esac
	done
	NODEGROUP_NAME=$CLUSTER_NAME-nodegroup
	LT_NAME=$CLUSTER_NAME-lt
	SSH_SECURITY_GROUP_NAME="$CLUSTER_NAME-ssh-allow"
fi

### Check for mandatory options
if [ "$CLUSTER_NAME" = "" -o "$REGION" = "" ]; then
	echo "Please provide \"cluster name\" and \"region name\"."
	echo
	usage
	exit 1
fi

#### Basic sanity checks
# Save pain of tons of unnecessary errors and wasted time since EKS cluster
# creation takes an awfully long time (>20 mins)

### check for OS type; only macos and linux
OS_TYPE=`uname`
echo; echo "OS_TYPE=$OS_TYPE"
if [ "$OS_TYPE" = "Darwin" ]; then
	BASE64_COMMAND="base64"
elif [ "$OS_TYPE" = "Linux" ]; then
	# On Linux, by default base64 wraps the lines to 76 column width
	# which causes launch template creation to fail. "--wrap=0" disables it.
	BASE64_COMMAND="base64 --wrap=0"
else
        echo
        echo "ERROR: OS_TYPE=$OS_TYPE not supported"
        exit 1
fi
echo "BASE64_COMMAND=$BASE64_COMMAND"


### Make sure we have aws cli version 2
which aws
if [ $? -ne 0 ]; then
	echo "You do not have aws cli installed. Please install aws cli version 2."
	exit 1
fi
AWSCLI_VERSION=`aws --version | awk '{print $1}' | awk -F/ '{print $2}'`
AWSCLI_VERSION_MAJ=`aws --version | awk '{print $1}' | awk -F/ '{print $2}' | awk -F. '{print $1}'`
if [ "$AWSCLI_VERSION_MAJ" -ne "2" ]; then
	echo "You have aws cli version $AWSCLI_VERSION. Please install aws cli version 2."
	exit 1
fi

### Make sure we have eksctl version >= 0.51.0; this is the version recommended by aws
which eksctl
if [ $? -ne 0 ]; then
	echo "You do not have eksctl installed. Please install eksctl version >= 0.51.0"
	exit 1
fi
EKSCTL_VERSION=`eksctl version`
#EKSCTL_VERSION_MAJ=`eksctl version | awk -F. '{print $1}'`
EKSCTL_VERSION_MIN=`eksctl version | awk -F. '{print $2}'`
if [  $EKSCTL_VERSION_MIN -lt 51 ]; then
	echo "You have eksctl version $EKSCTL_VERSION. Please install eksctl version >= 0.51.0"
	exit 1
fi

### Make sure we have kubectl
which kubectl
if [ $? -ne 0 ]; then
	echo "You do not have kubectl installed. Please install kubectl."
	exit 1
fi


### Create a temporary dir
TMP_DIR=`mktemp -d`
CUR_DIR=`pwd`
cd $TMP_DIR

### Get the Calico/VPP deployment yaml using wget or curl or whatever
# local file or url
if [ -f "$CALICO_VPP_YAML" ]; then
	cp $CALICO_VPP_YAML ./calico_vpp_deployment.yaml
else # url
	# try wget first
	echo "Trying wget..."
	wget $CALICO_VPP_YAML -O ./calico_vpp_deployment.yaml
	if [ $? -ne 0 ]; then
		# and then try curl
		echo
		echo "Trying curl..."
		curl $CALICO_VPP_YAML -o ./calico_vpp_deployment.yaml --fail
		if [ $? -ne 0 ]; then
			echo
			echo "ERROR: could not download \"$CALICO_VPP_YAML\""
			cd $CUR_DIR; rm -rf $TMP_DIR; exit 1
		fi
	fi
fi

### Get the INIT_EKS_SCRIPT using wget or curl or whatever. It does the
# following customizations on EKS worker nodes:
#   1. configure 512 2MB hugepages 
#   2. enable unsafe_noiommu_mode 
#   3. download, build, install and load ENAv2 compatible igb_uio driver
#   4. download, build, install and load ENAv2 compatible vfio-pci driver

# local file or url
if [ -f "$INIT_EKS_SCRIPT" ]; then
	cp $INIT_EKS_SCRIPT ./init_eks.sh
else # url
	# try wget first
	echo "Trying wget..."
	wget $INIT_EKS_SCRIPT -O ./init_eks.sh
	if [ $? -ne 0 ]; then
		# and then try curl
		echo
		echo "Trying curl..."
		curl $INIT_EKS_SCRIPT -o ./init_eks.sh --fail
		if [ $? -ne 0 ]; then
			echo
			echo "ERROR: could not download \"$INIT_EKS_SCRIPT\""
			cd $CUR_DIR; rm -rf $TMP_DIR; exit 1
		fi
	fi
fi

echo
echo "Here's the \"init_eks.sh\" script which will go into cloud-init/userdata of the EKS"
echo "worker nodes and it does the following customizations on the EKS worker nodes:"
echo "  1. configure 512 2MB hugepages"
echo "  2. enable unsafe_noiommu_mode"
echo "  3. download, build, install and load ENAv2 compatible igb_uio driver"
echo "  4. download, build, install and load ENAv2 compatible vfio-pci driver"
echo
cat ./init_eks.sh

# enclose in MIME format
INIT_EKS_SCRIPT_CONTENT=`cat ./init_eks.sh`
cat << highly_unlikely_that_this_will_be_in_the_init_eks.sh_script > ./mimed_init_eks.sh
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="==MYBOUNDARY=="

--==MYBOUNDARY==
Content-Type: text/x-shellscript; charset="us-ascii"

$INIT_EKS_SCRIPT_CONTENT

--==MYBOUNDARY==--
highly_unlikely_that_this_will_be_in_the_init_eks.sh_script

# base64 encode it
USERDATA=`$BASE64_COMMAND < ./mimed_init_eks.sh`


### Create cluster without nodegroup
echo; echo
echo "Creating cluster $CLUSTER_NAME..."
echo "NOTE: It will write the config in ~/.kube/eksctl/clusters/$CLUSTER_NAME"
echo "Please execute \"export KUBECONFIG=~/.kube/eksctl/clusters/$CLUSTER_NAME\" before executing kubectl commands on this cluster"
echo
eksctl create cluster --name=$CLUSTER_NAME --without-nodegroup --auto-kubeconfig
if [ $? -ne 0 ]; then
	echo
	echo "ERROR: Failed to create cluster. Refer to the error logs above."
	cd $CUR_DIR; rm -rf $TMP_DIR; exit 1
fi
export KUBECONFIG=~/.kube/eksctl/clusters/$CLUSTER_NAME

### Delete aws-node
echo; echo
echo "Deleting aws-node..."
kubectl delete daemonset -n kube-system aws-node

### Grab the clusterSecurityGroup and VpcId
CLUSTER_SECURITY_GROUP_ID=`aws eks describe-cluster --name $CLUSTER_NAME --output text | grep RESOURCESVPCCONFIG | awk '{print $2}'`
if [ "$CLUSTER_SECURITY_GROUP_ID" = "" ]; then
	echo "ERROR: Missing clusterSecurityGroup. Exiting..."
	cd $CUR_DIR; rm -rf $TMP_DIR; exit 1
fi
LT_SECURITY_GROUP_IDS="\"$CLUSTER_SECURITY_GROUP_ID\""

VPC_ID=`aws eks describe-cluster --name $CLUSTER_NAME --output text | grep RESOURCESVPCCONFIG | awk '{print $5}'`
if [ "$VPC_ID" = "" ]; then
	echo "ERROR: Missing cluster VPC ID. Exiting..."
	cd $CUR_DIR; rm -rf $TMP_DIR; exit 1
fi

### Create security group to allow ssh access
if [ "$KEYNAME" != "" ]; then
	echo
	echo "Creating security group to allow incoming ssh connections..."
	SSH_SECURITY_GROUP_ID=`aws ec2 create-security-group --description "Allow incoming ssh connections" --group-name $SSH_SECURITY_GROUP_NAME --vpc-id $VPC_ID --output text`
	aws ec2 authorize-security-group-ingress --group-id $SSH_SECURITY_GROUP_ID --protocol tcp --port 22 --cidr $SSH_ALLOW_CIDR
	LT_SECURITY_GROUP_IDS="\"$SSH_SECURITY_GROUP_ID\", \"$CLUSTER_SECURITY_GROUP_ID\""
fi

### Deploy Calico/VPP CNI
echo; echo
echo "Deploying calico/VPP CNI..."
echo
kubectl apply -f ./calico_vpp_deployment.yaml


### Launch template file in JSON
cat << EOF > ./lt.json
{
  "LaunchTemplateData": {
    "InstanceType": "$INSTANCE_TYPE",
    "KeyName": "$KEYNAME",
    "UserData": "$USERDATA",
    "SecurityGroupIds": [$LT_SECURITY_GROUP_IDS]
  }
}
EOF

### Create EC2 launch template
echo
echo "Creating EC2 launch template..."
aws ec2 create-launch-template --launch-template-name $LT_NAME --output text --cli-input-json file://./lt.json 1>./lt_output.log 2>./lt_error.log
if [ $? -ne 0 ]; then
	cat ./lt_error.log
	echo "ERROR: Could not create EC2 launch template. Refer to error logs above."
	cd $CUR_DIR; rm -rf $TMP_DIR; exit 1
fi
cat ./lt_output.log
echo
LT_ID=`cat ./lt_output.log | awk '{print $6}'`
echo "Launch Template ID : $LT_ID"
echo
cat ./lt.json


### yaml to create EKS managed nodegroup with launch template
cat << EOF >> ./nodegroup.yaml
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig
metadata:
  name: $CLUSTER_NAME
  region: $REGION
managedNodeGroups:
- name: $NODEGROUP_NAME
  desiredCapacity: $INSTANCE_NUM
  labels: {role: worker}
  launchTemplate:
    id: $LT_ID
EOF

### Create nodegroup
echo; echo
echo "Creating managed nodegroup $NODEGROUP_NAME..."
echo
eksctl create nodegroup -f ./nodegroup.yaml
if [ $? -ne 0 ]; then
	echo; echo "ERROR: Failed to create nodegroup. Refer to error logs above."
else
	echo; echo "SUCCESS: Cluster created!!!"
fi

### Print the CONFIG PARAMS for reference
echo; echo
echo "Please note the following for reference:"
echo "    CLUSTER_NAME=$CLUSTER_NAME"
echo "    REGION=$REGION"
echo "    NODEGROUP_NAME=$NODEGROUP_NAME"
echo "    LAUNCH TEMPLATE NAME=$LT_NAME"
echo "    KEYNAME=$KEYNAME"
echo "    SSH_SECURITY_GROUP_NAME=$SSH_SECURITY_GROUP_NAME"
echo "    SSH_SECURITY_GROUP_ID=$SSH_SECURITY_GROUP_ID"
echo "    SSH_ALLOW_CIDR=$SSH_ALLOW_CIDR"
echo "    VPC_ID=$VPC_ID"
echo "    CLUSTER_SECURITY_GROUP_ID=$CLUSTER_SECURITY_GROUP_ID"
echo "    INSTANCE_TYPE=$INSTANCE_TYPE"
echo "    INSTANCE_NUM=$INSTANCE_NUM"
echo "    CALICO_VPP_YAML=$CALICO_VPP_YAML"
echo "    INIT_EKS_SCRIPT=$INIT_EKS_SCRIPT"
echo "    KUBECONFIG=~/.kube/eksctl/clusters/$CLUSTER_NAME"
echo
echo "Do not forget to execute \"export KUBECONFIG=~/.kube/eksctl/clusters/$CLUSTER_NAME\""
echo "before executing kubectl commands on this cluster."

### Delete the TMP_DIR
cd $CUR_DIR; rm -rf $TMP_DIR

### Create cleanup_eks_cluster.sh so one can cleanup cluster resources easily
echo
echo "Once you are done with the cluster, you may want to cleanup the resources:"
echo "   eksctl delete nodegroup --region=$REGION --cluster=$CLUSTER_NAME --name=$NODEGROUP_NAME"
echo "   aws ec2 delete-launch-template --launch-template-name $LT_NAME"
echo "   eksctl delete cluster --region=$REGION --name=$CLUSTER_NAME"
if [ "$KEYNAME" != "" ]; then
	DELETE_SECURITY_GROUP="aws ec2 delete-security-group --group-id $SSH_SECURITY_GROUP_ID"
	echo "   $DELETE_SECURITY_GROUP"
fi
#echo "   aws ec2 delete-vpc --vpc-id $VPC_ID"
echo
echo "These commands are saved in \"./cleanup_eks_cluster.sh\" script in $CUR_DIR and you"
echo "can just execute the script to do the cleanup."
cat << EOF > ./cleanup_eks_cluster.sh
#!/bin/bash
eksctl delete nodegroup --region=$REGION --cluster=$CLUSTER_NAME --name=$NODEGROUP_NAME
aws ec2 delete-launch-template --launch-template-name $LT_NAME
eksctl delete cluster --region=$REGION --name=$CLUSTER_NAME
$DELETE_SECURITY_GROUP
EOF

### Done
exit 0
