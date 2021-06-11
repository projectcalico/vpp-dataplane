#!/bin/bash

###############################################################################
# This is a convenience wrapper script which uses cloud-init/userdata to      #
# configure the EKS worker nodes during boot time with the customizations     #
# required for Calico/VPP DPDK based deployments and then it creates an EKS   #
# cluster consisting of a managed nodegroup with 2 m5.large worker nodes.     #
#                                                                             #
# The following customizations are done on EKS worker nodes:                  #
#   1. 512 2MB hugepages configured                                           #
#   2. unsafe_noiommu_mode is enabled                                         #
#   3. download, build, install and load ENAv2 compatible igb_uio driver      #
#   4. download, build, install and load ENAv2 compatible vfio-pci driver     #
###############################################################################


##############################################################################
#                           CONFIG PARAMS                                    #
##############################################################################
### Config params; replace with appropriate values
CLUSTER_NAME=				# cluster name (MANDATORY)
REGION=					# cluster region (MANDATORY)
NODEGROUP_NAME=$CLUSTER_NAME-nodegroup	# managed nodegroup name
LT_NAME=$CLUSTER_NAME-lt		# EC2 launch template name
KEYNAME=				# keypair name for ssh access to worker nodes (MANDATORY)
SSH_SECURITY_GROUP_NAME="$CLUSTER_NAME-ssh-allow"
SSH_ALLOW_CIDR="0.0.0.0/0"		# source IP from which ssh access is allowed
INSTANCE_TYPE=m5.large			# EC2 instance type
INSTANCE_NUM=2				# Number of instances in cluster
### Calico/VPP deployment yaml
CALICO_VPP_YAML=https://raw.githubusercontent.com/projectcalico/vpp-dataplane/master/yaml/generated/calico-vpp-eks-dpdk.yaml
#CALICO_VPP_YAML=./calico-vpp-eks-dpdk.yaml
##############################################################################

usage ()
{
	echo
	echo "Either execute the script after filling in the CONFIG PARAMS section in the"
	echo "script or execute the script with command-line options as follows:"
	echo
	echo "    $0 <cluster name> -r <region name> -k <keyname> [-t <instance type>]"
	echo "    [-n <number of instances>] [-f <calico/vpp config yaml file>]"
	echo
	echo "Mandatory options are \"cluster name\", \"region name\" and \"keyname\"."
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
if [ "$CLUSTER_NAME" = "" -o "$REGION" = "" -o "$KEYNAME" = "" ]; then
	echo "Please provide \"cluster name\", \"region name\" and \"keyname\"."
	echo
	usage
	exit 1
fi

### Basic sanity checks; save pain of tons of unnecessary errors and wasted time
# Make sure we have aws cli version 2
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

# Make sure we have eksctl version >= 0.51.0; this is the version recommended by aws
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

# Make sure we have kubectl
which kubectl
if [ $? -ne 0 ]; then
	echo "You do not have kubectl installed. Please install kubectl."
	exit 1
fi


### Create a temporary dir
TMP_DIR=`mktemp -d`
CUR_DIR=`pwd`
cd $TMP_DIR


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
CLUSTER_SECURITY_GROUP_ID=`aws eks describe-cluster --name $CLUSTER_NAME | grep RESOURCESVPCCONFIG | awk '{print $2}'`
if [ "$CLUSTER_SECURITY_GROUP_ID" = "" ]; then
	echo "ERROR: Missing clusterSecurityGroup. Exiting..."
	cd $CUR_DIR; rm -rf $TMP_DIR; exit 1
fi
VPC_ID=`aws eks describe-cluster --name $CLUSTER_NAME | grep RESOURCESVPCCONFIG | awk '{print $5}'`
if [ "$VPC_ID" = "" ]; then
	echo "ERROR: Missing cluster VPC ID. Exiting..."
	cd $CUR_DIR; rm -rf $TMP_DIR; exit 1
fi

### Create security group to allow ssh access
echo
echo "Creating security group to allow incoming ssh connections..."
SSH_SECURITY_GROUP_ID=`aws ec2 create-security-group --description "Allow incoming ssh connections" --group-name $SSH_SECURITY_GROUP_NAME --vpc-id $VPC_ID`
aws ec2 authorize-security-group-ingress --group-id $SSH_SECURITY_GROUP_ID --protocol tcp --port 22 --cidr $SSH_ALLOW_CIDR


### Launch template file in JSON
cat << EOF >> ./lt.json
{
  "LaunchTemplateData": {
    "EbsOptimized": false,
    "InstanceType": "$INSTANCE_TYPE",
    "KeyName": "$KEYNAME",
    "UserData": "TUlNRS1WZXJzaW9uOiAxLjAKQ29udGVudC1UeXBlOiBtdWx0aXBhcnQvbWl4ZWQ7IGJvdW5kYXJ5PSI9PU1ZQk9VTkRBUlk9PSIKCi0tPT1NWUJPVU5EQVJZPT0KQ29udGVudC1UeXBlOiB0ZXh0L3gtc2hlbGxzY3JpcHQ7IGNoYXJzZXQ9InVzLWFzY2lpIgoKIyEvYmluL2Jhc2gKCiMgVGhpcyBzY3JpcHRzIGJ1aWxkcyBhbmQgaW5zZXJ0IHRoZSBkcGRrIGlnYl91aW8ga2VybmVsIG1vZHVsZXMgaW4gYW4KIyBBbWF6b24gQU1JLiBJZiBydW4gYXQgYm9vdCB0aW1lLCB0aGlzIGVuYWJsZXMgcnVubmluZyBjYWxpY28tdnBwIHdpdGgKIyB0aGUgRFBESyB1cGxpbmsgZHJpdmVyIGluIEVLUy4KCndoaWxlICgoICIkIyIgKSkgOyBkbwogICAgZXZhbCAkMQogICAgc2hpZnQKZG9uZQoKRFBES19WRVJTSU9OPSR7RFBES19WRVJTSU9OOj12MjAuMTF9CkhVR0VQQUdFUz0ke0hVR0VQQUdFUzo9NTEyfQpCVUlMRF9ESVI9L3RtcC9idWlsZApJR0JfVUlPX1BBVEg9L2xpYi9tb2R1bGVzLyQodW5hbWUgLXIpL2tlcm5lbC9kcml2ZXJzL3Vpby9pZ2JfdWlvLmtvCgpidWlsZF9hbmRfaW5zdGFsbF9pZ2JfdWlvICgpCnsKCWlmIFsgLWYgJElHQl9VSU9fUEFUSCBdOyB0aGVuCgkJZWNobyAiQWxyZWFkeSBidWlsdCIKCQlyZXR1cm4KCWZpCgoJc3VkbyB5dW0gaW5zdGFsbCAteSBnaXQgcHl0aG9uMyBnY2MgbWFrZSBrZXJuZWwtZGV2ZWwtJCh1bmFtZSAtcikKCXN1ZG8gcGlwMyBpbnN0YWxsIG1lc29uIHB5ZWxmdG9vbHMgbmluamEKCglta2RpciAkQlVJTERfRElSICYmIGNkICRCVUlMRF9ESVIKCglnaXQgY2xvbmUgaHR0cDovL2RwZGsub3JnL2dpdC9kcGRrCgljZCBkcGRrICYmIGdpdCBjaGVja291dCAke0RQREtfVkVSU0lPTn0gJiYgY2QgLi4KCWdpdCBjbG9uZSBodHRwOi8vZHBkay5vcmcvZ2l0L2RwZGsta21vZHMKCWNwIC1yIC4vZHBkay1rbW9kcy9saW51eC9pZ2JfdWlvIC4vZHBkay9rZXJuZWwvbGludXgvCgoJIyMjIyMjIyMjIyBQQVRDSElORyBEUERLICMjIyMjIyMjIyMKCglzZWQgLWkgInMvc3ViZGlycyA9IFxbJ2tuaSdcXS9zdWJkaXJzID0gXFsnaWdiX3VpbydcXS9nIiAuL2RwZGsva2VybmVsL2xpbnV4L21lc29uLmJ1aWxkCgoJY2F0IDw8IEVPRiB8IHRlZSAuL2RwZGsva2VybmVsL2xpbnV4L2lnYl91aW8vbWVzb24uYnVpbGQKIyBTUERYLUxpY2Vuc2UtSWRlbnRpZmllcjogQlNELTMtQ2xhdXNlCiMgQ29weXJpZ2h0KGMpIDIwMTcgSW50ZWwgQ29ycG9yYXRpb24KCm1rZmlsZSA9IGN1c3RvbV90YXJnZXQoJ2lnYl91aW9fbWFrZWZpbGUnLAogICAgICAgIG91dHB1dDogJ01ha2VmaWxlJywKICAgICAgICBjb21tYW5kOiBbJ3RvdWNoJywgJ0BPVVRQVVRAJ10pCgpjdXN0b21fdGFyZ2V0KCdpZ2JfdWlvJywKICAgICAgICBpbnB1dDogWydpZ2JfdWlvLmMnLCAnS2J1aWxkJ10sCiAgICAgICAgb3V0cHV0OiAnaWdiX3Vpby5rbycsCiAgICAgICAgY29tbWFuZDogWydtYWtlJywgJy1DJywgZ2V0X29wdGlvbigna2VybmVsX2RpcicpICsgJy9idWlsZCcsCiAgICAgICAgICAgICAgICAnTT0nICsgbWVzb24uY3VycmVudF9idWlsZF9kaXIoKSwKICAgICAgICAgICAgICAgICdzcmM9JyArIG1lc29uLmN1cnJlbnRfc291cmNlX2RpcigpLAogICAgICAgICAgICAgICAgJ0VYVFJBX0NGTEFHUz0tSScgKyBtZXNvbi5jdXJyZW50X3NvdXJjZV9kaXIoKSArCiAgICAgICAgICAgICAgICAgICAgICAgICcvLi4vLi4vLi4vbGliL2xpYnJ0ZV9lYWwvaW5jbHVkZScsCiAgICAgICAgICAgICAgICAnbW9kdWxlcyddLAogICAgICAgIGRlcGVuZHM6IG1rZmlsZSwKICAgICAgICBpbnN0YWxsOiB0cnVlLAogICAgICAgIGluc3RhbGxfZGlyOiBnZXRfb3B0aW9uKCdrZXJuZWxfZGlyJykgKyAnL2V4dHJhL2RwZGsnLAogICAgICAgIGJ1aWxkX2J5X2RlZmF1bHQ6IGdldF9vcHRpb24oJ2VuYWJsZV9rbW9kcycpKQpFT0YKCglzZWQgLWkgInMvc3ViZGlyKCdsaWInKS9lbmFibGVkX2xpYnMgPSBbXSAjc3ViZGlyKCdsaWInKS9nIiAuL2RwZGsvbWVzb24uYnVpbGQKCXNlZCAtaSAicy9zdWJkaXIoJ2RyaXZlcnMnKS8jc3ViZGlyKCdkcml2ZXJzJykvZyIgLi9kcGRrL21lc29uLmJ1aWxkCglzZWQgLWkgInMvc3ViZGlyKCd1c2VydG9vbHMnKS8jc3ViZGlyKCd1c2VydG9vbHMnKS9nIiAuL2RwZGsvbWVzb24uYnVpbGQKCXNlZCAtaSAicy9zdWJkaXIoJ2FwcCcpLyNzdWJkaXIoJ2FwcCcpL2ciIC4vZHBkay9tZXNvbi5idWlsZAoJc2VkIC1pICJzL3N1YmRpcignZG9jJykvI3N1YmRpcignZG9jJykvZyIgLi9kcGRrL21lc29uLmJ1aWxkCglzZWQgLWkgInMvc3ViZGlyKCdleGFtcGxlcycpLyNzdWJkaXIoJ2V4YW1wbGVzJykvZyIgLi9kcGRrL21lc29uLmJ1aWxkCglzZWQgLWkgInMvaW5zdGFsbF9zdWJkaXIoJ2V4YW1wbGVzJywvI2luc3RhbGxfc3ViZGlyKCdleGFtcGxlcycsL2ciIC4vZHBkay9tZXNvbi5idWlsZAoJc2VkIC1pICJzQGluc3RhbGxfZGlyOiBnZXRfb3B0aW9uKCdkYXRhZGlyJylAI2luc3RhbGxfZGlyOiBnZXRfb3B0aW9uKCdkYXRhZGlyJylAZyIgLi9kcGRrL21lc29uLmJ1aWxkCglzZWQgLWkgInMvZXhjbHVkZV9maWxlczogJ21lc29uLmJ1aWxkJykvI2V4Y2x1ZGVfZmlsZXM6ICdtZXNvbi5idWlsZCcpL2ciIC4vZHBkay9tZXNvbi5idWlsZAoKCSMjIyMjIyMjIyMgUEFUQ0hJTkcgRFBESyAjIyMjIyMjIyMjCgoJY2QgLi9kcGRrCgltZXNvbiBidWlsZCAtRGVuYWJsZV9rbW9kcz10cnVlIC1Ea2VybmVsX2Rpcj0vbGliL21vZHVsZXMvJCh1bmFtZSAtcikvCgluaW5qYSAtQyBidWlsZAoKCXN1ZG8gbXYgLi9idWlsZC9rZXJuZWwvbGludXgvaWdiX3Vpby9pZ2JfdWlvLmtvICR7SUdCX1VJT19QQVRIfQoJc3VkbyBjaG93biByb290OnJvb3QgJHtJR0JfVUlPX1BBVEh9Cn0KCmNvbmZpZ3VyZV9kcGRrX2ludGVycnVwdF9tb2RlX3N1cHBvcnQgKCkKewoJIyBkb3dubG9hZCBhbmQgYnVpbGQgYW5kIGluc3RhbGwgdGhlIHZmaW8tcGNpIGRyaXZlciB3aXRoIHdjIHN1cHBvcnQKCSMgZm9yIEVOQXYyCgljZCAkQlVJTERfRElSCglnaXQgY2xvbmUgaHR0cHM6Ly9naXRodWIuY29tL2Ftem4vYW16bi1kcml2ZXJzLmdpdAoJY2QgYW16bi1kcml2ZXJzL3VzZXJzcGFjZS9kcGRrL2VuYXYyLXZmaW8tcGF0Y2gKCS4vZ2V0LXZmaW8td2l0aC13Yy5zaAoKCSMgTk9URTogdXNlIHN1ZG8gd2hlbi9pZiBydW5uaW5nIHRoZSBzY3JpcHQgbWFudWFsbHkKCSMgbG9hZCB0aGUgZHJpdmVyCgltb2Rwcm9iZSB2ZmlvLXBjaQoKCSMgZW5hYmxlIHVuc2FmZV9ub2lvbW11X21vZGUKCWVjaG8gMSA+IC9zeXMvbW9kdWxlL3ZmaW8vcGFyYW1ldGVycy9lbmFibGVfdW5zYWZlX25vaW9tbXVfbW9kZQoKCSMgcGVyc2lzdCB0aGUgY2hhbmdlcyBhY3Jvc3MgcmVib290cwoJY2F0IDw8IEVPRiA+PiAvZXRjL3JjLmQvcmMubG9jYWwKbW9kcHJvYmUgdmZpby1wY2kKZWNobyAxID4gL3N5cy9tb2R1bGUvdmZpby9wYXJhbWV0ZXJzL2VuYWJsZV91bnNhZmVfbm9pb21tdV9tb2RlCkVPRgoJY2htb2QgK3ggL2V0Yy9yYy5kL3JjLmxvY2FsCgoJcm0gLXJmICRCVUlMRF9ESVIKfQoKY29uZmlndXJlX21hY2hpbmUgKCkKewoJc3VkbyBybSAtZiAvZXRjL2NuaS9uZXQuZC8xMC1hd3MuY29uZmxpc3QKCXN1ZG8gbW9kcHJvYmUgdWlvCglpZiBbIHgkKGxzbW9kIHwgYXdrICd7IHByaW50ICQxIH0nIHwgZ3JlcCBpZ2JfdWlvKSA9PSB4IF07IHRoZW4KCQlidWlsZF9hbmRfaW5zdGFsbF9pZ2JfdWlvCgkJc3VkbyBpbnNtb2QgL2xpYi9tb2R1bGVzLyQodW5hbWUgLXIpL2tlcm5lbC9kcml2ZXJzL3Vpby9pZ2JfdWlvLmtvIHdjX2FjdGl2YXRlPTEKCWZpCgoJIyBjb25maWd1cmUgaHVnZXBhZ2VzIGFuZCBwZXJzaXN0IHRoZSBjb25maWcgYWNyb3NzIHJlYm9vdHMKCXN1ZG8gc3lzY3RsIC13IHZtLm5yX2h1Z2VwYWdlcz0ke0hVR0VQQUdFU30KCWlmIFsgLWYgL3N5cy9mcy9jZ3JvdXAvaHVnZXRsYi9rdWJlcG9kcy9odWdldGxiLjJNQi5saW1pdF9pbl9ieXRlcyBdOyB0aGVuCgkJZWNobyAkKChIVUdFUEFHRVMgKiAyICogMTAyNCAqIDEwMjQpKSB8IHRlZSAvc3lzL2ZzL2Nncm91cC9odWdldGxiL2t1YmVwb2RzL2h1Z2V0bGIuMk1CLmxpbWl0X2luX2J5dGVzCglmaQoJZWNobyAidm0ubnJfaHVnZXBhZ2VzPSR7SFVHRVBBR0VTfSIgPj4gL2V0Yy9zeXNjdGwuY29uZgp9Cgpjb25maWd1cmVfbWFjaGluZQpjb25maWd1cmVfZHBka19pbnRlcnJ1cHRfbW9kZV9zdXBwb3J0CgotLT09TVlCT1VOREFSWT09LS0K",
    "SecurityGroupIds": ["$SSH_SECURITY_GROUP_ID", "$CLUSTER_SECURITY_GROUP_ID"]
  }
}
EOF

### Create EC2 launch template
echo
echo "Creating EC2 launch template..."
aws ec2 create-launch-template --launch-template-name $LT_NAME --cli-input-json file://./lt.json 1>./lt_output.log 2>./lt_error.log
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

echo; echo
echo "Deploying calico/VPP CNI..."
echo
kubectl apply -f $CALICO_VPP_YAML


### yaml to create EKS managed nodegroup with launch template
cat << EOF >> ./nodegroup.yaml
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig
metadata:
  name: $CLUSTER_NAME
  region: $REGION
managedNodeGroups:
- name: $NODEGROUP_NAME
  desiredCapacity: 2
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
echo "    INSTANCE_TYPE=$INSTANCE_TYPE"
echo "    INSTANCE_NUM=$INSTANCE_NUM"
echo "    CALICO_VPP_YAML=$CALICO_VPP_YAML"
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
echo "   aws ec2 delete-security-group --group-id $SSH_SECURITY_GROUP_ID"
#echo "   aws ec2 delete-vpc --vpc-id $VPC_ID"
echo
echo "These commands are saved in \"./cleanup_eks_cluster.sh\" script in $CUR_DIR and you"
echo "can just execute the script to do the cleanup."
cat << EOF > ./cleanup_eks_cluster.sh
#!/bin/bash
eksctl delete nodegroup --region=$REGION --cluster=$CLUSTER_NAME --name=$NODEGROUP_NAME
aws ec2 delete-launch-template --launch-template-name $LT_NAME
eksctl delete cluster --region=$REGION --name=$CLUSTER_NAME
aws ec2 delete-security-group --group-id $SSH_SECURITY_GROUP_ID
EOF

# Done
exit 0
